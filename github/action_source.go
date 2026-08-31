package github

import (
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/getplumber/plumber/internal/ir"
)

// This file analyses a third-party action's OWN source to decide
// whether the action fetches and runs mutable remote code at runtime.
// Pinning the action by commit SHA (ISSUE-701) does not cover this: the
// pinned action can still pull an install script from `main` of another
// repo, so the code actually executed changes with nothing committed
// where the pin can see it (the anchore/scan-action → grype case).

// movingRefAlt is the alternation of ref names whose content changes over
// time (as opposed to a version tag `vX.Y` or a 40-hex commit SHA). It is
// not exhaustive — an author can name a branch anything — but it covers
// the common cases plus the "rename around the list" evasions.
const movingRefAlt = `main|master|HEAD|develop|trunk|latest|stable|release|dev|edge|nightly|canary|next|snapshot`

var (
	// ghContent matches the GitHub hosts that serve raw per-ref file
	// BYTES (fetchable and pipe-able). github.com/<o>/<r>/raw is the same
	// mutable content as raw.githubusercontent.com — swapping host was the
	// first reported bypass. `blob` is deliberately excluded: it is the
	// HTML page, not the raw bytes, so a blob URL is a doc link, not a
	// fetch source (it caused a comment-link false positive).
	ghContent = `(?:raw\.githubusercontent\.com/[^/\s"']+/[^/\s"']+|github\.com/[^/\s"']+/[^/\s"']+/raw|gist\.githubusercontent\.com/[^/\s"']+/[^/\s"']+)`
	pathChars = `[^\s"'),;>]*`
	scriptExt = `\.(?:sh|bash|zsh|py|pl|rb|ps1)\b`
	interp    = `(?:(?:ba|z)?sh|python[0-9.]*|ruby|perl|pwsh|node)`

	// --- exec tier: remote code fetched from a moving ref and run, in the open ---

	// reExecMoving: a SCRIPT fetched from a moving ref on any github
	// content host — the extension implies it is executed.
	reExecMoving = regexp.MustCompile(ghContent + `/(?:` + movingRefAlt + `)/` + pathChars + scriptExt)
	// rePipeShell: a remote fetch piped straight into an interpreter.
	rePipeShell = regexp.MustCompile(`(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?` + interp + `\b`)
	// reDownloadRun: fetch a MUTABLE-ref content URL to a file, then run
	// it (the download-then-run bypass of the pipe form). The moving-ref
	// URL requirement keeps this off legitimate installers that download a
	// versioned release asset (e.g. releases/download/<version>/…) and
	// verify a checksum — those are not mutable-remote-exec.
	//
	// The run clause is anchored to a statement start — a separator
	// (`\n`, `;`, `&&`, `|`), optional `sudo …`, then an interpreter with
	// a `\b` word boundary and an argument, OR `source`/`./x`/`chmod +x`.
	// Without the anchor and boundary the old `interp\s+\S` matched the
	// "sh" inside `git push` on any line after the download (`\s` also
	// crossed newlines), so a `-o versions.json` fetch followed by
	// `git push` was mis-reported as exec. The gap is bounded (`.{0,400}?`)
	// so the fetch and the run must be near each other.
	reDownloadRun = regexp.MustCompile(`(?s)(?:curl|wget)\b[^\n]*` + ghContent + `/(?:` + movingRefAlt + `)/[^\n]*\s-[oO]\b.{0,400}?(?:\n|;|&&|\|)[ \t]*(?:sudo\s+(?:-\S+\s+)*)?(?:` + interp + `\b[ \t]+\S|source[ \t]+\S|\./\S|chmod[ \t]+\+x)`)

	// --- obfuscated tier: the fetch/exec is hidden (base64/decode + run) ---
	// No legitimate action needs to obfuscate what it runs, so this is
	// treated as the strongest signal (critical). Requires a decode
	// feeding an execution sink, not a bare base64 (which is often a
	// legitimate token/file encode).

	// reObfPipe: a decode piped into an interpreter (base64 -d | sh).
	reObfPipe = regexp.MustCompile(`(?:base64\s+(?:-d|-D|--decode)|openssl\s+(?:base64|enc)\b[^\n]*-d|xxd\s+-r|rev\b)[^\n|]*\|\s*(?:sudo\s+)?` + interp + `\b`)
	// reObfEval: eval/exec of a decoded string (eval "$(… base64 -d …)",
	// eval(atob(…)), new Function(atob(…)), exec(Buffer.from(x,'base64')).
	// The window between the sink and the decode is `[^)\n]{0,40}` — it
	// must stay INSIDE the sink's argument list (no `)`), so the decode is
	// an argument of the sink, not merely an adjacent statement. A wider
	// `[^\n]{0,60}` window raised a critical on benign minified bundles
	// where standard `new Function("return this")()` boilerplate sits next
	// to a routine `Buffer.from(x,"base64")` input decode on one line.
	reObfEval = regexp.MustCompile(`(?:eval|new\s+Function|child_process[^\n]{0,40}exec)\s*\(?[^)\n]{0,40}(?:atob\s*\(|Buffer\.from\s*\([^)]*['"]base64|base64\s+(?:-d|--decode))`)
	reEvalSub = regexp.MustCompile(`\beval\b[^\n]{0,20}\$\([^\n]*(?:base64\s+(?:-d|--decode)|xxd\s+-r)`)

	// reChecksum: an integrity check on a downloaded artifact. Its
	// presence means the author pinned the CONTENT (a mutable-ref fetch
	// that verifies a hash aborts if the upstream changes), so an
	// otherwise-flagged exec is downgraded. Best-effort: the check may
	// cover a different file, but it signals the author cares.
	reChecksum = regexp.MustCompile(`(?i)\b(?:sha(?:256|512)sum\s+(?:-c|--check)|shasum\s+-a\s+(?:256|512)|openssl\s+dgst\s+-sha(?:256|512)|cosign\s+verify|gpg\s+--verify|--checksum\b|slsa-verifier\s+verify)`)

	// reInterpLocalScript matches a pipe whose interpreter runs a LOCAL
	// script file as its first argument (`… | python3 scripts/gen.py`).
	// There the fetched remote content is the interpreter's stdin (data),
	// and the code actually executed is the committed local script — not
	// remote exec. `sh -s`, `python3 -`, `| sh` (no arg) do NOT match, so
	// a genuine `curl … | sh` stays exec.
	reInterpLocalScript = regexp.MustCompile(`\|\s*(?:sudo\s+(?:-\S+\s+)*)?` + interp + `[ \t]+(?:-\S+[ \t]+)*([^\s|]+\.(?:sh|bash|py|rb|pl|js))\b`)
	// rePinnedSource matches a fetch URL path segment that pins the
	// CONTENT: a 40-hex commit SHA, `refs/tags/…`, a `releases/download/…`
	// asset, or a dotted version segment (`/v1.2.3/`). A bare `/v2/` is NOT
	// matched — on raw content it is ref-ambiguous with a branch named
	// `v2` (ISSUE-402), so it stays exec. A pinned pipe is downgraded to
	// the low `data` tier: it is exactly what the ISSUE-714 remediation
	// recommends, so surfacing it as high would contradict the fix, and
	// re-pushable tags/assets stay recorded rather than clean.
	rePinnedSource = regexp.MustCompile(`(?i)/(?:[0-9a-f]{40}|refs/tags/|releases/download/|v?\d+(?:\.\d+)+)/`)

	// reDataMoving: a DATA manifest pulled from a moving ref that steers
	// a later binary download (docker/actions-toolkit release manifest).
	reDataMoving = regexp.MustCompile(ghContent + `/(?:` + movingRefAlt + `)/` + pathChars + `\.(?:json|ya?ml|txt|xml)\b`)
	// reRef extracts the moving ref token from a matched URL.
	reRef = regexp.MustCompile(ghContent + `/(` + movingRefAlt + `)/`)
	// reMain extracts the node entrypoint from an action.yml `main:`.
	reMain = regexp.MustCompile(`(?m)^\s*main:\s*['"]?([^\s'"]+)`)
	// reUsing / reImage read the action.yml `runs:` block. A docker action
	// (`using: docker`) executes a container, so its code lives in a
	// Dockerfile or a docker:// image rather than a JS entrypoint.
	reUsing = regexp.MustCompile(`(?m)^\s*using:\s*['"]?([A-Za-z0-9]+)`)
	reImage = regexp.MustCompile(`(?m)^\s*image:\s*['"]?([^\s'"]+)`)
)

// entrypointCandidates are the usual hand-written and bundled source
// locations to inspect in addition to the declared `main:`.
var entrypointCandidates = []string{"action.js", "index.js", "dist/index.js", "src/index.js"}

// ScanActionSource inspects an action's fetched source files (path →
// content) and returns the strongest mutable-remote-exec signal, or nil
// when nothing mutable is found. Tiers, strongest first:
//
//	obfuscated — decode-then-exec / eval(atob): hiding is the finding (critical)
//	exec       — a script fetched from a moving ref and run, no checksum (high)
//	data       — a mutable manifest, OR an exec that DOES verify a checksum
//	             (content-pinned, materially safer) — recorded, not surfaced
//
// Files are scanned in sorted order so the reported hit is deterministic.
func ScanActionSource(files map[string]string) *ir.MutableRemoteExec {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	// Pass 0 — obfuscated tier (decode/eval-then-exec). Highest signal:
	// nothing legitimate needs to hide what it runs.
	for _, name := range names {
		content := files[name]
		for _, re := range []*regexp.Regexp{reObfPipe, reEvalSub, reObfEval} {
			if m := re.FindString(content); m != "" {
				return &ir.MutableRemoteExec{Tier: "obfuscated", URL: snippet(m), File: name}
			}
		}
	}
	// Pass 1 — exec tier (fetch a script from a moving ref and run it).
	// If a checksum verification appears NEAR the fetch (same short shell
	// block), the content is pinned, so downgrade to the low "data" tier.
	// Proximity matters: a `sha256` string elsewhere in a large bundled
	// dist/index.js is library noise, not integrity of THIS fetch.
	//
	// The `curl … | interp` pipe is classified by the URL and the
	// interpreter's arguments (see classifyPipeMatch): a pipe whose remote
	// source is content-pinned drops to `data`, and a pipe that merely
	// feeds a local committed script is skipped entirely.
	for _, name := range names {
		content := files[name]
		if hit := scanPipeShell(content, name); hit != nil {
			return hit
		}
		for _, re := range []*regexp.Regexp{reExecMoving, reDownloadRun} {
			loc := re.FindStringIndex(content)
			if loc == nil {
				continue
			}
			m := content[loc[0]:loc[1]]
			tier := "exec"
			if checksumNear(content, loc[0], loc[1]) {
				tier = "data"
			}
			return &ir.MutableRemoteExec{Tier: tier, URL: snippet(m), Ref: matchedRef(m), File: name}
		}
	}
	// Pass 2 — data tier (mutable manifest steering a download).
	for _, name := range names {
		if m := reDataMoving.FindString(files[name]); m != "" {
			return &ir.MutableRemoteExec{Tier: "data", URL: m, Ref: matchedRef(m), File: name}
		}
	}
	return nil
}

// scanPipeShell finds the first `curl … | interp` pipe in content that
// represents remote execution and returns its finding, or nil when every
// pipe is either a local-script feed (skipped) — the executed code is
// committed, not remote. A pipe from a content-pinned source, or one
// verified by a nearby checksum, is downgraded to the low `data` tier;
// otherwise it is `exec`. FindAll is used so a benign local-script pipe
// earlier in the file does not mask a real remote-exec pipe after it.
func scanPipeShell(content, name string) *ir.MutableRemoteExec {
	for _, loc := range rePipeShell.FindAllStringIndex(content, -1) {
		line := enclosingLine(content, loc[0])
		if pipeExecutesLocalScript(line) {
			continue // remote content is stdin; the run target is a local file
		}
		m := content[loc[0]:loc[1]]
		tier := "exec"
		if pipeSourcePinned(line) || checksumNear(content, loc[0], loc[1]) {
			tier = "data"
		}
		return &ir.MutableRemoteExec{Tier: tier, URL: snippet(m), Ref: matchedRef(m), File: name}
	}
	return nil
}

// enclosingLine returns the text of the line containing byte index idx,
// without the surrounding newlines. Used to classify a pipe by its whole
// command (the URL before the pipe and the interpreter args after it),
// not just the fragment rePipeShell matched.
func enclosingLine(content string, idx int) string {
	start := strings.LastIndexByte(content[:idx], '\n') + 1
	rest := content[idx:]
	if end := strings.IndexByte(rest, '\n'); end >= 0 {
		return content[start : idx+end]
	}
	return content[start:]
}

// pipeExecutesLocalScript reports whether a `… | interp <local-script>`
// pipe runs a committed local script (the fetched content is data on the
// interpreter's stdin). A remote script argument (`http…`) does not count.
func pipeExecutesLocalScript(line string) bool {
	m := reInterpLocalScript.FindStringSubmatch(line)
	return m != nil && !strings.Contains(m[1], "://")
}

// pipeSourcePinned reports whether the fetch URL on this line pins its
// content (SHA / refs/tags / release asset / dotted version), so piping
// it to a shell is not MUTABLE remote exec.
func pipeSourcePinned(line string) bool {
	return rePinnedSource.MatchString(line)
}

// checksumNear reports whether an integrity check appears within a small
// window around the fetch at [start,end) — close enough to plausibly
// verify that fetch, not a stray `sha256` elsewhere in a bundle.
func checksumNear(content string, start, end int) bool {
	const window = 300
	lo := start - window
	if lo < 0 {
		lo = 0
	}
	hi := end + window
	if hi > len(content) {
		hi = len(content)
	}
	return reChecksum.MatchString(content[lo:hi])
}

// snippet trims and caps a matched fragment for the reported URL field.
func snippet(m string) string {
	m = strings.TrimSpace(m)
	if len(m) > 120 {
		m = m[:120]
	}
	return m
}

func matchedRef(url string) string {
	if sm := reRef.FindStringSubmatch(url); len(sm) == 2 {
		return sm[1]
	}
	return ""
}

// entrypointPaths returns the source paths worth inspecting for an
// action, given its action.yml: the declared node entrypoint plus the
// usual hand-written/bundled locations.
func entrypointPaths(actionYML string) []string {
	paths := []string{}
	if sm := reMain.FindStringSubmatch(actionYML); len(sm) == 2 {
		paths = append(paths, sm[1])
	}
	for _, c := range entrypointCandidates {
		if !contains(paths, c) {
			paths = append(paths, c)
		}
	}
	return paths
}

func contains(s []string, v string) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}
	return false
}

// scanActionDefinition scans an action given its action.yml text and a
// function that fetches a sibling file (path relative to the action's
// directory). It handles all three action flavors:
//
//   - JS / composite: the declared entrypoint plus the `run:` steps in
//     action.yml.
//   - docker with `image: docker://<ref>`: a pre-built image. A tag not
//     pinned by digest is mutable code (the SHA pin on the action does
//     not reach it) → exec. A digest-pinned image is immutable → ok.
//   - docker with `image: Dockerfile`: the RUN lines of the Dockerfile
//     are scanned with the same logic (curl|sh, obfuscation, …).
//
// fetchRel reports the STATUS of a sibling-file read, not just success. A
// file that could not be FETCHED is not a file that does not exist: folding
// the two together omits the entrypoint from the scan and grades the action
// clean, which is the opposite of what an unreadable source should mean. The
// action definition itself has always made this distinction; its siblings
// now do too.
func scanActionDefinition(actionYML, ymlKey string, fetchRel func(rel string) (string, fetchStatus)) *ir.MutableRemoteExec {
	files := map[string]string{ymlKey: actionYML}
	dir := path.Dir(ymlKey) // "" for a root action, the subpath for a nested one
	key := func(rel string) string {
		if dir == "." || dir == "" {
			return rel
		}
		return path.Join(dir, rel)
	}
	// fetchDisabled is deliberate (the offline switch) and stays silent;
	// only a genuine failure downgrades the verdict.
	unverified := func(rel string) *ir.MutableRemoteExec {
		return &ir.MutableRemoteExec{Tier: "unverified", File: key(rel)}
	}

	if u := reUsing.FindStringSubmatch(actionYML); len(u) == 2 && strings.EqualFold(u[1], "docker") {
		img := ""
		if m := reImage.FindStringSubmatch(actionYML); len(m) == 2 {
			img = m[1]
		}
		if rest, ok := strings.CutPrefix(img, "docker://"); ok {
			if tier := dockerImageTier(rest); tier != "" {
				return &ir.MutableRemoteExec{Tier: tier, URL: img, File: ymlKey}
			}
			return nil // digest-pinned image is immutable
		}
		df := img
		if df == "" || strings.EqualFold(df, "dockerfile") {
			df = "Dockerfile"
		}
		src, st := fetchRel(df)
		switch st {
		case fetchOK:
			files[key(df)] = src
		case fetchError:
			return unverified(df)
		}
		return ScanActionSource(files)
	}

	for _, p := range entrypointPaths(actionYML) {
		src, st := fetchRel(p)
		switch st {
		case fetchOK:
			files[key(p)] = src
		case fetchError:
			return unverified(p)
		}
	}
	return ScanActionSource(files)
}

// dockerImageTier grades a `docker://` image reference by how immutable the
// content it pulls actually is. A digest (`@sha256:…`) is content-addressed and
// immutable -> "" (clean). A moving tag (`latest`, none, or any non-version
// tag) can be re-pointed at will -> "exec" (high). A semver-style version tag
// is conventionally frozen but the registry still lets the publisher re-push it
// -> "data" (low, recorded but not surfaced as high), consistent with how the
// script tiers treat a checksum-verified fetch.
func dockerImageTier(rest string) string {
	if strings.Contains(rest, "@sha256:") {
		return ""
	}
	tag := ""
	if i := strings.LastIndex(rest, ":"); i > strings.LastIndex(rest, "/") {
		tag = rest[i+1:]
	}
	if tag == "" || strings.EqualFold(tag, "latest") {
		return "exec"
	}
	if reVersionTag.MatchString(tag) {
		return "data"
	}
	return "exec"
}

// reVersionTag matches a conventional semver-ish image tag (v1, 1.2.3, v8.7.0).
var reVersionTag = regexp.MustCompile(`^v?\d+(?:\.\d+)*$`)

// fetchStatus distinguishes "file absent" (not an action / subpath) from
// "could not reach it" (network, rate limit) so the caller can emit an
// explicit could-not-verify finding instead of a silent pass whose
// result would vary by CI environment.
type fetchStatus int

const (
	fetchOK       fetchStatus = iota // content returned
	fetchMissing                     // 404: the file is not there
	fetchError                       // network / rate limit / HTTP error
	fetchDisabled                    // offline switch: abstain silently
)

// rawFetcher fetches a single file's text from an action repo at a ref.
type rawFetcher func(owner, repo, ref, path string) (text string, status fetchStatus)

// firstPartyOwners are the action owners trusted as extensions of the
// platform itself; their source is not fetched (saves network, and a
// GitHub-owned action fetching from GitHub is not the threat here).
var firstPartyOwners = map[string]bool{"actions": true, "github": true}

// resolveMutableExec returns the mutable-remote-exec signal for a
// third-party action, memoised per `uses:` value so an action reused
// across jobs is fetched once. First-party and unparseable refs are
// skipped (nil).
func resolveMutableExec(uses string, cache map[string]*ir.MutableRemoteExec) *ir.MutableRemoteExec {
	if v, ok := cache[uses]; ok {
		return v
	}
	var mre *ir.MutableRemoteExec
	if owner, repo, subpath, ref, ok := splitActionRefWithSubpath(uses); ok && !firstPartyOwners[strings.ToLower(owner)] {
		mre = analyzeActionMutableExec(httpRawFetcher, owner, repo, ref, subpath)
	}
	cache[uses] = mre
	return mre
}

// splitActionRefWithSubpath parses `owner/repo[/subpath]@ref`. subpath is
// the in-repo directory of a composite/nested action ("" for a root
// action). Reusable-workflow calls (`…/.github/workflows/x.yml@ref`) and
// local/docker refs are rejected (ok=false) — they are not actions whose
// source we scan.
func splitActionRefWithSubpath(uses string) (owner, repo, subpath, ref string, ok bool) {
	if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "docker://") {
		return "", "", "", "", false
	}
	at := strings.Index(uses, "@")
	if at < 0 {
		return "", "", "", "", false
	}
	head, tail := uses[:at], uses[at+1:]
	parts := strings.SplitN(head, "/", 3)
	if len(parts) < 2 {
		return "", "", "", "", false
	}
	if len(parts) == 3 {
		subpath = parts[2]
	}
	if strings.HasSuffix(subpath, ".yml") || strings.HasSuffix(subpath, ".yaml") {
		return "", "", "", "", false // reusable workflow call, not an action
	}
	return parts[0], parts[1], subpath, tail, true
}

// analyzeActionMutableExec fetches an action's action.yml and entrypoint
// at the pinned ref and scans them. subpath is the action's in-repo
// directory ("" for a root action); action.yml and the declared
// entrypoint are resolved relative to it, so composite/nested actions
// (github/codeql-action/init, home-assistant/actions/hassfest) are
// covered too. Returns nil when the action has no action.yml
// (Docker-Hub action) or nothing mutable is found.
func analyzeActionMutableExec(fetch rawFetcher, owner, repo, ref, subpath string) *ir.MutableRemoteExec {
	ymlPath := path.Join(subpath, "action.yml")
	actionYML, st := fetch(owner, repo, ref, ymlPath)
	if st == fetchError {
		return &ir.MutableRemoteExec{Tier: "unverified", File: ymlPath}
	}
	if st != fetchOK {
		ymlPath = path.Join(subpath, "action.yaml")
		actionYML, st = fetch(owner, repo, ref, ymlPath)
		if st == fetchError {
			return &ir.MutableRemoteExec{Tier: "unverified", File: ymlPath}
		}
		if st != fetchOK {
			return nil // missing (not an action / subpath) or offline → silent
		}
	}
	return scanActionDefinition(actionYML, ymlPath, func(rel string) (string, fetchStatus) {
		return fetch(owner, repo, ref, path.Join(subpath, rel))
	})
}

// ScanLocalSelfAction checks whether the scanned repository is itself a
// GitHub Action (root action.yml/action.yaml) whose own source fetches
// mutable remote code, reading the action definition and entrypoint from
// the local checkout. Returns nil when the repo is not an action or
// nothing mutable is found. This is the producer-side check: scanning an
// action's own repo must flag the action it publishes.
func ScanLocalSelfAction(rootDir string) *ir.MutableRemoteExec {
	actionYML, ok := readLocalFile(rootDir, "action.yml")
	if !ok {
		actionYML, ok = readLocalFile(rootDir, "action.yaml")
		if !ok {
			return nil
		}
	}
	return scanActionDefinition(actionYML, "action.yml", func(rel string) (string, fetchStatus) {
		// A local read has no transport to fail: an unreadable path here is
		// an absent file, which is a real answer.
		src, ok := readLocalFile(rootDir, rel)
		if !ok {
			return "", fetchMissing
		}
		return src, fetchOK
	})
}

func readLocalFile(rootDir, rel string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(rootDir, filepath.FromSlash(rel)))
	if err != nil {
		return "", false
	}
	return string(b), true
}

// ScanRemoteSelfAction is the remote counterpart of ScanLocalSelfAction:
// it fetches the scanned repo's own root action.yml + entrypoint over raw
// content and scans them. Used on the --project (upstream-fetch) path.
func ScanRemoteSelfAction(owner, repo, ref string) *ir.MutableRemoteExec {
	return analyzeActionMutableExec(httpRawFetcher, owner, repo, ref, "")
}

// httpRawFetcher reads file text from raw.githubusercontent.com. It
// serves github.com-hosted public actions; GitHub Enterprise Server
// hosts and private repos are out of scope for this first iteration and
// simply return ok=false (the control abstains rather than guesses).
var rawHTTPClient = &http.Client{Timeout: 20 * time.Second}

// rawFetchToken returns a GitHub token for raw content reads, using the
// same precedence as the metadata client's env inputs. Empty when none
// is set (anonymous read).
func rawFetchToken() string {
	for _, k := range []string{EnvMetadataToken, "GH_TOKEN", "GITHUB_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func httpRawFetcher(owner, repo, ref, path string) (string, fetchStatus) {
	// Respect the offline switch the test suite (and air-gapped runs)
	// use to keep the collector network-free.
	if v := os.Getenv(EnvDisableGitHubAPI); v == "1" || v == "true" {
		return "", fetchDisabled
	}
	if ref == "" {
		ref = "HEAD"
	}
	url := "https://raw.githubusercontent.com/" + owner + "/" + repo + "/" + ref + "/" + path
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fetchError
	}
	// An authenticated request lifts the anonymous rate limit, which a
	// repo with many third-party actions can otherwise hit (turning real
	// findings into could-not-verify). Public content, so any read token
	// works; private repos need it. Falls back to anonymous.
	if tok := rawFetchToken(); tok != "" {
		req.Header.Set("Authorization", "token "+tok)
	}
	resp, err := rawHTTPClient.Do(req)
	if err != nil {
		return "", fetchError
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return "", fetchMissing
	}
	if resp.StatusCode != http.StatusOK {
		return "", fetchError // 403 rate-limit, 5xx, … → could not verify
	}
	// Cap the read: bundled dist/ files can be a few MB; refuse anything
	// absurd to bound memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return "", fetchError
	}
	return string(body), fetchOK
}
