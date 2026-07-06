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
	reDownloadRun = regexp.MustCompile(`(?s)(?:curl|wget)\b[^\n]*` + ghContent + `/(?:` + movingRefAlt + `)/[^\n]*\s-[oO]\b.*?(?:\n|;)[^\n;]*(?:` + interp + `\s+\S|chmod\s+\+x)`)

	// --- obfuscated tier: the fetch/exec is hidden (base64/decode + run) ---
	// No legitimate action needs to obfuscate what it runs, so this is
	// treated as the strongest signal (critical). Requires a decode
	// feeding an execution sink, not a bare base64 (which is often a
	// legitimate token/file encode).

	// reObfPipe: a decode piped into an interpreter (base64 -d | sh).
	reObfPipe = regexp.MustCompile(`(?:base64\s+(?:-d|-D|--decode)|openssl\s+(?:base64|enc)\b[^\n]*-d|xxd\s+-r|rev\b)[^\n|]*\|\s*(?:sudo\s+)?` + interp + `\b`)
	// reObfEval: eval/exec of a decoded string (eval "$(… base64 -d …)",
	// eval(atob(…)), new Function(atob(…)), exec(Buffer.from(x,'base64')).
	reObfEval = regexp.MustCompile(`(?:eval|new\s+Function|child_process[^\n]{0,40}exec)\s*\(?[^\n]{0,60}(?:atob\s*\(|Buffer\.from\s*\([^)]*['"]base64|base64\s+(?:-d|--decode))`)
	reEvalSub = regexp.MustCompile(`\beval\b[^\n]{0,20}\$\([^\n]*(?:base64\s+(?:-d|--decode)|xxd\s+-r)`)

	// reChecksum: an integrity check on a downloaded artifact. Its
	// presence means the author pinned the CONTENT (a mutable-ref fetch
	// that verifies a hash aborts if the upstream changes), so an
	// otherwise-flagged exec is downgraded. Best-effort: the check may
	// cover a different file, but it signals the author cares.
	reChecksum = regexp.MustCompile(`(?i)\b(?:sha(?:256|512)sum\s+(?:-c|--check)|shasum\s+-a\s+(?:256|512)|openssl\s+dgst\s+-sha(?:256|512)|cosign\s+verify|gpg\s+--verify|--checksum\b|slsa-verifier\s+verify)`)

	// reDataMoving: a DATA manifest pulled from a moving ref that steers
	// a later binary download (docker/actions-toolkit release manifest).
	reDataMoving = regexp.MustCompile(ghContent + `/(?:` + movingRefAlt + `)/` + pathChars + `\.(?:json|ya?ml|txt|xml)\b`)
	// reRef extracts the moving ref token from a matched URL.
	reRef = regexp.MustCompile(ghContent + `/(` + movingRefAlt + `)/`)
	// reMain extracts the node entrypoint from an action.yml `main:`.
	reMain = regexp.MustCompile(`(?m)^\s*main:\s*['"]?([^\s'"]+)`)
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
	for _, name := range names {
		content := files[name]
		for _, re := range []*regexp.Regexp{reExecMoving, rePipeShell, reDownloadRun} {
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
	files := map[string]string{ymlPath: actionYML}
	for _, p := range entrypointPaths(actionYML) {
		full := path.Join(subpath, p)
		if src, st := fetch(owner, repo, ref, full); st == fetchOK {
			files[full] = src
		}
	}
	return ScanActionSource(files)
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
	files := map[string]string{"action.yml": actionYML}
	for _, p := range entrypointPaths(actionYML) {
		if src, ok := readLocalFile(rootDir, p); ok {
			files[p] = src
		}
	}
	return ScanActionSource(files)
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
