package github

import (
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
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

	// reLiteralDigest: a bare 64-hex-character token, the shape of a
	// SHA-256 digest written out in full rather than invoked through a
	// `-c`/`--check` flag (an inline string comparison against the
	// downloaded file's computed hash). Its mere presence near a fetch
	// is already a strong signal: nothing else legitimately produces a
	// 64-hex token next to a download.
	reLiteralDigest = regexp.MustCompile(`(?i)\b[0-9a-f]{64}\b`)

	// reStepBoundary: the start of a YAML list item ("- name:", "- run:",
	// "- uses:", and the like): the unit stepRanges reads "step" as, so
	// a guard or a verification never crosses this boundary.
	reStepBoundary = regexp.MustCompile(`(?m)^[ \t]*-[ \t]`)

	// reGuardCheck: the DIRECT short-circuit form of a preinstalled-tool
	// guard-check, with no leading `if`/`!` (`command -v X`, `which X`,
	// `type X`, `[ -x path ]`, `test -x path`). Anchored (`^`) so
	// sameLineGuard can only match it at the very start of the LHS it
	// extracted: a NEGATED check (`! command -v X || fetch`) inverts
	// the semantics (the fetch then runs exactly when X IS present),
	// so sameLineGuard strips the LHS to the start of the command
	// first (past `(`/`{`/whitespace) and refuses a leading `!` before
	// ever trying this regex. The tool name stops at a shell
	// metacharacter (`;`, `)`, `&`, `|`) or whitespace.
	reGuardCheck = regexp.MustCompile(`(?i)^(?:` +
		`command\s+-v\s+([^;)&|\s]+)` +
		`|which\s+([^;)&|\s]+)` +
		`|type\s+([^;)&|\s]+)` +
		`|\[\s*-x\s+([^;)&|\s]+?)\s*\]` +
		`|test\s+-x\s+([^;)&|\s]+))`)

	// reYAMLRunKey: the YAML list/key prefix a single-line `- run:
	// command -v X || fetch` step writes its command after. Stripped
	// from the LHS before reGuardCheck runs, since the anchor otherwise
	// sees "- run: command -v X" and never matches at position 0.
	reYAMLRunKey = regexp.MustCompile(`^-?\s*run:\s*['"]?`)

	// reIfGuardCheck: the NEGATED form an `if` condition wraps a fetch
	// with (`if ! command -v X`, `if ! which X`, `if ! type X`,
	// `if [ ! -x path ]` / `if ! [ -x path ]`).
	reIfGuardCheck = regexp.MustCompile(`(?i)` +
		`!\s*command\s+-v\s+([^;)&|\s]+)` +
		`|!\s*which\s+([^;)&|\s]+)` +
		`|!\s*type\s+([^;)&|\s]+)` +
		`|\[\s*!\s*-x\s+([^;)&|\s]+?)\s*\]` +
		`|!\s*\[\s*-x\s+([^;)&|\s]+?)\s*\]` +
		`|test\s+!\s*-x\s+([^;)&|\s]+)`)

	// reIfKeyword: the `if`/`then`/`else`/`elif`/`fi` keywords
	// ifBlockGuard walks to track block nesting AND where the `then`
	// branch of a negated check ends, matched as whole shell words.
	reIfKeyword = regexp.MustCompile(`\b(if|then|else|elif|fi)\b`)

	// reLineContinuation: a shell `\` line continuation. Replaced with
	// spaces of the SAME length before the same-line guard check runs,
	// so a continued line reads as one logical line with no position
	// shift for callers that already computed an offset against the
	// unjoined text.
	reLineContinuation = regexp.MustCompile(`\\\r?\n`)

	// reVerifyCommand: an actual integrity CHECK, not just a hash
	// computation: sha256sum/sha512sum -c|--check, shasum -a 256/512
	// -c|--check, gpg --verify, cosign verify-blob. A bare `shasum -a
	// 256 file` (no -c/--check) only PRINTS a hash; it checks nothing,
	// so it must never count as a verification on its own.
	reVerifyCommand = regexp.MustCompile(`(?i)\b(?:sha(?:256|512)sum\s+(?:-c|--check)\b|shasum\s+-a\s+(?:256|512)\s+(?:-c|--check)\b|gpg\s+--verify\b|cosign\s+verify-blob\b)`)

	// reVerifyFileArg extracts the sums-file argument of a
	// `sha256sum`/`shasum -a 256/512` CHECK command (the word right
	// after `-c`/`--check`): sumsFileNamesDownload then decides
	// whether that sums file was actually written in this step with
	// the downloaded file's own name in it.
	reVerifyFileArg = regexp.MustCompile(`(?i)(?:sha(?:256|512)sum\s+(?:-c|--check)|shasum\s+-a\s+(?:256|512)\s+(?:-c|--check))\s+(\S+)`)

	// reRedirectTarget: a shell `>`/`>>` redirect's target file,
	// matched wherever it appears on a line.
	reRedirectTarget = regexp.MustCompile(`>>?\s*(\S+)`)

	// reHashOfFilePipedToGrep: `sha256sum <file>`/`shasum -a 256/512
	// <file>` (computing the ACTUAL file's hash) piped into `grep`,
	// which then checks that output against an expected digest named
	// as grep's own argument: a genuine check, unlike a bare `echo` of
	// the expected digest that feeds nothing.
	reHashOfFilePipedToGrep = regexp.MustCompile(`(?i)(?:sha(?:256|512)sum|shasum\s+-a\s+(?:256|512))\s+\S+[^\n]*\|\s*grep\b`)

	// reHeredocRedirect: a heredoc write (`cat > sums <<EOF`, `tee
	// sums <<-'EOF'`), capturing the write target and the terminating
	// marker: sumsFileNamesDownload reads the heredoc BODY (the lines
	// between this one and the line that is exactly the marker) for a
	// literal digest naming the downloaded file, since both can sit on
	// a body line rather than the write line itself.
	reHeredocRedirect = regexp.MustCompile(`>\s*(\S+)\s*<<-?\s*['"]?(\w+)['"]?`)

	// reDownloadTarget: the local file a `curl`/`wget` download saves
	// to (`-o file`, `-O`, `--output[-document] file`).
	reDownloadTarget = regexp.MustCompile(`(?i)(?:-o\s*|--output(?:-document)?[\s=])(\S+)`)

	// reFetchURLForFile: a bare http(s) URL, used to derive the file a
	// plain `wget <url>` (no -O) saves as: the URL's own basename.
	reFetchURLForFile = regexp.MustCompile(`https?://[^\s|;)'"]+`)

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
	// nothing legitimate needs to hide what it runs. No guard or
	// verification concept applies here: hiding the fetch IS the
	// finding, whatever runs it or checks it afterward.
	for _, name := range names {
		content := files[name]
		for _, re := range []*regexp.Regexp{reObfPipe, reEvalSub, reObfEval} {
			if m := re.FindString(content); m != "" {
				return &ir.MutableRemoteExec{Tier: "obfuscated", URL: snippet(m), File: name}
			}
		}
	}

	// Pass 1 — exec tier (fetch a script from a moving ref and run it).
	// Every fetch across every file and step is collected, never just
	// the first: the anchor this signal feeds is suppressed only when
	// EVERY one of them is guarded or verified (fetchHit.isProtected),
	// so a second, unguarded curl|sh must never be hidden behind a
	// first, guarded one. Guard and verification checks are scoped to
	// a single step's own text (stepRanges), so neither ever reads a
	// guard, or a checksum, from a different step.
	var hits []fetchHit
	for _, name := range names {
		content := files[name]
		for _, rng := range stepRanges(content) {
			hits = append(hits, scanStepFetches(content[rng[0]:rng[1]], name)...)
		}
	}
	if result := strongestExecHit(hits); result != nil {
		return result
	}

	// Pass 2 — data tier (mutable manifest steering a download).
	for _, name := range names {
		if m := reDataMoving.FindString(files[name]); m != "" {
			return &ir.MutableRemoteExec{Tier: "data", URL: m, Ref: matchedRef(m), File: name}
		}
	}
	return nil
}

// fetchHit is one remote-exec signal found within a single step's own
// text: its tier (already downgraded to "data" when content-pinned or
// checksum-verified nearby, the pre-existing proximity check), the
// guard (if any) that wraps it and whether its own downloaded file (if
// any) is verified, both scoped to this step alone.
type fetchHit struct {
	tier, url, ref, sourceFile string
	guard                      string
	verified                   bool
}

// isProtected reports whether this single hit, on its own, would never
// actually execute: guarded (whether the guarded tool is actually
// preinstalled on a given job's runner is decided later, downstream,
// by control/trust.go's suppressed + runners.Preinstalled; a non-empty
// guard here is a candidate) or verified.
func (h fetchHit) isProtected() bool {
	return h.guard != "" || h.verified
}

// strongestExecHit reduces every fetchHit collected across an action's
// source into the one ir.MutableRemoteExec ScanActionSource reports:
// the first "exec"-tier hit (scan order) gives the reported Tier/URL/
// Ref/File, and DownloadGuard/DownloadVerified are only ever populated
// when EVERY "exec"-tier hit is individually protected (isProtected),
// never just the reported one, so one unguarded, unverified fetch
// keeps the whole action's anchor alive even when another fetch in the
// same source is fully guarded. nil when hits is empty.
func strongestExecHit(hits []fetchHit) *ir.MutableRemoteExec {
	if len(hits) == 0 {
		return nil
	}
	var execHits []fetchHit
	for _, h := range hits {
		if h.tier == "exec" {
			execHits = append(execHits, h)
		}
	}
	if len(execHits) == 0 {
		// Every hit individually downgraded to "data" (content-pinned
		// or checksum-verified nearby): report the first as before,
		// recorded but never a finding on its own. Its own guard and
		// verified are carried too, informationally: a "data"-tier
		// signal never anchors a path on its own either way (the
		// downstream policy only looks at tier=="exec"), but it stays
		// accurate for a caller reading the field directly.
		h := hits[0]
		return &ir.MutableRemoteExec{
			Tier: h.tier, URL: h.url, Ref: h.ref, File: h.sourceFile,
			DownloadGuard: h.guard, DownloadVerified: h.verified,
		}
	}
	reported := execHits[0]
	result := &ir.MutableRemoteExec{Tier: "exec", URL: reported.url, Ref: reported.ref, File: reported.sourceFile}
	for _, h := range execHits {
		if !h.isProtected() {
			return result
		}
	}
	result.DownloadGuard = reported.guard
	result.DownloadVerified = reported.verified
	return result
}

// scanStepFetches finds every exec-tier remote-exec signal within one
// step's own text (stepText: either a real YAML step, or the whole
// file when it carries no step markers at all), tagging each with its
// own guard and verification, computed purely against stepText so
// neither ever crosses into another step.
func scanStepFetches(stepText, name string) []fetchHit {
	var hits []fetchHit
	for _, loc := range rePipeShell.FindAllStringIndex(stepText, -1) {
		line := enclosingLine(stepText, loc[0])
		if pipeExecutesLocalScript(line) {
			continue // remote content is stdin; the run target is a local file
		}
		m := stepText[loc[0]:loc[1]]
		tier := "exec"
		if pipeSourcePinned(line) || checksumNear(stepText, loc[0], loc[1]) {
			tier = "data"
		}
		hits = append(hits, fetchHit{
			tier: tier, url: snippet(m), ref: matchedRef(m), sourceFile: name,
			guard: guardFor(stepText, loc[0]),
			// A pipe-to-shell has no file to verify at all: the
			// fetched bytes ARE the executed code, nothing is ever
			// written to disk for a checksum to cover.
			verified: false,
		})
	}
	for _, re := range []*regexp.Regexp{reExecMoving, reDownloadRun} {
		for _, loc := range re.FindAllStringIndex(stepText, -1) {
			m := stepText[loc[0]:loc[1]]
			tier := "exec"
			if checksumNear(stepText, loc[0], loc[1]) {
				tier = "data"
			}
			file := downloadedFileFor(enclosingLine(stepText, loc[0]))
			hits = append(hits, fetchHit{
				tier: tier, url: snippet(m), ref: matchedRef(m), sourceFile: name,
				guard:    guardFor(stepText, loc[0]),
				verified: file != "" && fileVerifiedInStep(stepText, enclosingLineStart(stepText, loc[0]), file),
			})
		}
	}
	return hits
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

// enclosingLineStart is the byte offset of the start of the line
// containing idx: fileVerifiedInStep uses it to recognize, and
// exclude, the download line itself.
func enclosingLineStart(content string, idx int) int {
	return strings.LastIndexByte(content[:idx], '\n') + 1
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
// verify that fetch, not a stray `sha256` elsewhere in a bundle. Used
// only for the pre-existing exec/data TIER downgrade (content-pinning),
// never for DownloadVerified, which reads a specific downloaded file's
// own verification instead (fileVerifiedInStep).
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

// stepRanges returns the [start,end) byte ranges of every step (YAML
// list item, reStepBoundary) in content, or a single range covering
// the whole content when it has no step markers at all (a Dockerfile
// RUN block, a bundled JS file): a file with no steps IS one step, and
// the guard and verification checks below must never cross a step
// boundary.
func stepRanges(content string) [][2]int {
	locs := reStepBoundary.FindAllStringIndex(content, -1)
	if len(locs) == 0 {
		return [][2]int{{0, len(content)}}
	}
	ranges := make([][2]int, len(locs))
	for i, l := range locs {
		end := len(content)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		ranges[i] = [2]int{l[0], end}
	}
	return ranges
}

// joinContinuations replaces every shell `\<newline>` line continuation
// in s with spaces of the SAME length: a continued line then reads as
// one logical line (no real newline splits it) with every other byte
// offset in s unchanged, so a caller's own position (computed against
// the unjoined text) still lands correctly.
func joinContinuations(s string) string {
	return reLineContinuation.ReplaceAllStringFunc(s, func(m string) string {
		return strings.Repeat(" ", len(m))
	})
}

// guardFor reports the preinstalled-tool guard (if any) that wraps the
// fetch at stepText[fetchPos:], within this step only: either the
// fetch is the right-hand side of the same `||` as a guard-check, on
// the same logical line (a `\` continuation joined first), or it sits
// inside the `then`/`fi` body of an `if ! <guard-check>`-shaped block
// (if/then/fi nesting tracked). "" when neither holds: a guard
// elsewhere in the step that does not actually gate this fetch (an
// unrelated `command -v docker || exit 1`, or a guard in a different
// step entirely) never counts.
func guardFor(stepText string, fetchPos int) string {
	joined := joinContinuations(stepText)
	if tool := sameLineGuard(joined, commandStart(joined, fetchPos)); tool != "" {
		return tool
	}
	return ifBlockGuard(joined, fetchPos)
}

// commandStart is the position of the `curl`/`wget` keyword that
// starts the fetch command fetchPos falls within, on the same line:
// for a pipe-to-shell match, fetchPos already IS that position (the
// regex match starts at the keyword), but for a download-then-run or
// a moving-ref-script match, fetchPos lands inside the URL, after the
// keyword: walking back to the keyword is what lets sameLineGuard see
// the `||` that actually precedes the whole fetch command, not just
// whatever text happens to sit right before the URL. Falls back to
// fetchPos itself when no earlier keyword is found on the line (the
// pipe-to-shell case, and any other shape this does not expect).
func commandStart(joined string, fetchPos int) int {
	lineStart := strings.LastIndexByte(joined[:fetchPos], '\n') + 1
	lower := strings.ToLower(joined[lineStart:fetchPos])
	best := -1
	for _, kw := range []string{"curl", "wget"} {
		if i := strings.LastIndex(lower, kw); i > best {
			best = i
		}
	}
	if best < 0 {
		return fetchPos
	}
	return lineStart + best
}

// sameLineGuard checks whether the command at joined[pos:] is
// immediately preceded (modulo trailing whitespace) by `||`, whose
// left-hand side (back to the start of the line, or the previous `;`
// or `&&`) is a guard-check (reGuardCheck), anchored at the very start
// of the command (past any leading whitespace, `(` or `{`): the
// direct short-circuit form `command -v X || <fetch>`. A leading `!`
// on that command (`! command -v X || <fetch>`) is a NEGATED check: it
// inverts the semantics (the fetch then runs exactly when X IS
// present), so it is refused before reGuardCheck ever runs, never
// matched as a guard.
func sameLineGuard(joined string, pos int) string {
	lineStart := strings.LastIndexByte(joined[:pos], '\n') + 1
	before := strings.TrimRight(joined[lineStart:pos], " \t")
	if !strings.HasSuffix(before, "||") {
		return ""
	}
	lhs := strings.TrimRight(before[:len(before)-2], " \t")
	cut := 0
	if i := strings.LastIndex(lhs, ";"); i+1 > cut {
		cut = i + 1
	}
	if i := strings.LastIndex(lhs, "&&"); i+2 > cut {
		cut = i + 2
	}
	cond := strings.TrimLeft(lhs[cut:], " \t({")
	cond = reYAMLRunKey.ReplaceAllString(cond, "")
	if strings.HasPrefix(cond, "!") {
		return ""
	}
	return guardCheckTool(reGuardCheck, cond)
}

// guardCheckTool extracts the tool (or the path whose basename is the
// tool) a guard-check regex matched in cond, "" when it did not match
// at all.
func guardCheckTool(re *regexp.Regexp, cond string) string {
	m := re.FindStringSubmatch(cond)
	if m == nil {
		return ""
	}
	for _, g := range m[1:] {
		if g != "" {
			return toolBasename(g)
		}
	}
	return ""
}

// toolBasename is the final path segment of s: a guard naming a path
// ("[ -x /usr/local/bin/rustup ] ||") checks for the tool at that path,
// so its basename is the tool.
func toolBasename(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// ifBlockGuard scans joined for the nearest enclosing `if !
// <guard-check>; then ... fi` block (if/then/fi nesting tracked, by
// counting `if` and `fi` as whole shell words) whose GUARDED BODY (its
// own `then` up to the first `else`/`elif`/`fi` at the SAME nesting
// depth, never further) contains fetchPos, and returns the
// guarded tool. An `else`/`elif` branch of a negated check runs
// exactly when the tool IS present (the opposite of what the `then`
// branch's absence-guard means), so a fetch there is never guarded,
// whatever the condition says. "" when fetchPos is not inside such a
// guarded body at all, or the innermost block enclosing it is not a
// guard-check (an ordinary `if` with unrelated logic never counts).
func ifBlockGuard(joined string, fetchPos int) string {
	type openIf struct {
		condStart, condEnd, thenPos, thenEnd int
	}
	var stack []openIf
	best := ""
	bestSpan := -1

	for _, m := range reIfKeyword.FindAllStringSubmatchIndex(joined, -1) {
		switch joined[m[2]:m[3]] {
		case "if":
			stack = append(stack, openIf{condStart: m[1]})
		case "then":
			if len(stack) == 0 {
				continue
			}
			top := &stack[len(stack)-1]
			if top.thenPos == 0 {
				top.condEnd, top.thenPos = m[0], m[1]
			}
		case "else", "elif":
			if len(stack) == 0 {
				continue
			}
			top := &stack[len(stack)-1]
			// Only the FIRST else/elif after this block's own then
			// ends its guarded body; a nested if's own else/elif (a
			// different, inner stack entry) never reaches here.
			if top.thenPos != 0 && top.thenEnd == 0 {
				top.thenEnd = m[0]
			}
		case "fi":
			if len(stack) == 0 {
				continue
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if top.thenPos == 0 {
				continue // no `then` yet: malformed, ignore
			}
			end := top.thenEnd
			if end == 0 {
				end = m[0] // no else/elif: the guarded body runs to `fi`
			}
			if fetchPos < top.thenPos || fetchPos >= end {
				continue // the fetch is not in the guarded (then) body
			}
			span := end - top.thenPos
			if bestSpan != -1 && span >= bestSpan {
				continue // a previously found, more tightly enclosing block wins
			}
			if tool := guardCheckTool(reIfGuardCheck, joined[top.condStart:top.condEnd]); tool != "" {
				best, bestSpan = tool, span
			}
		}
	}
	return best
}

// downloadedFileFor is the local file a `curl`/`wget` command on line
// saves its download to: the `-o`/`-O`/`--output[-document]` target,
// or, for a bare `wget <url>` with none of those, the URL's own
// basename. "" when line names no such file at all (a programmatic
// reference with nothing to verify on disk).
func downloadedFileFor(line string) string {
	if m := reDownloadTarget.FindStringSubmatch(line); len(m) == 2 {
		return path.Base(strings.Trim(m[1], `"'`))
	}
	if strings.Contains(strings.ToLower(line), "wget") {
		if u := reFetchURLForFile.FindString(line); u != "" {
			return path.Base(strings.TrimRight(u, "/"))
		}
	}
	return ""
}

// fileVerifiedInStep reports whether file, downloaded by the line
// starting at downloadLineStart, is checked against a checksum or
// signature elsewhere in stepText (the CURRENT step only, never a
// later one), in one of three shapes:
//
//   - a literal 64-hex digest on a line, AFTER the download line, that
//     also names the file AND feeds an actual check on that same line
//     (digestFeedsCheck): piped into `sha256sum -c`/`shasum -a
//     256/512 -c`/`--check`, a `grep` of a real `sha256sum
//     <file>`/`shasum <file>` computation, an `=`/`==`/`!=` comparison
//     inside `[`/`[[`/`test`, or `cosign verify-blob`/`gpg --verify`.
//     A bare `echo` of the expected digest, with none of those, proves
//     nothing: it never counts. A container image digest
//     (`@sha256:<hex>`) never counts either, and neither does a digest
//     on the download line itself (its own URL, or a coincidental
//     trailing token, naming the file right there is not a
//     verification of it);
//   - `gpg --verify`/`cosign verify-blob` naming the file on its own
//     line;
//   - `sha256sum`/`shasum -a 256/512 -c <sums>`, accepted only when
//     <sums> was itself WRITTEN in this step, by a line (or a heredoc
//     body line) that carries a LITERAL digest of its own and also
//     names the file: a sums file self-generated by computing the
//     hash at runtime (`sha256sum file > sums`), or fetched from a
//     remote source (any write line that itself fetches), is never
//     pinned: only a digest already present in the step's own source
//     is. This closes the co-occurrence fallback ("a verify command
//     anywhere in the step and the file name anywhere in the step")
//     that could never fail, since the download line itself always
//     names the file.
//
// Whatever the shape, the check counts only on a line strictly between
// the download line and the first line that runs the file (a shell or
// interpreter given the file, `./file`, `source file`, `chmod +x
// file`): a digest checked after the code already ran, or a signature
// verified before the file exists, proves nothing about what executed.
// When no later line runs the file the window stays open to the end
// of the step. The file is always matched as a whole shell token: a
// digest of nodejs.tar.gz is no verification of a file called node.
func fileVerifiedInStep(stepText string, downloadLineStart int, file string) bool {
	if file == "" {
		return false
	}
	runLineStart := firstRunLineStart(stepText, downloadLineStart, file)
	inWindow := func(lineStart int) bool {
		return lineStart > downloadLineStart && (runLineStart < 0 || lineStart < runLineStart)
	}
	for _, loc := range reLiteralDigest.FindAllStringIndex(stepText, -1) {
		if isContainerImageDigest(stepText, loc[0]) {
			continue
		}
		lineStart := enclosingLineStart(stepText, loc[0])
		if !inWindow(lineStart) {
			continue // on or before the download line, or once the file already ran
		}
		// A digest inside a trailing shell comment proves nothing: only
		// the code before the comment is read.
		code := stripShellComment(enclosingLine(stepText, loc[0]))
		if loc[0]-lineStart >= len(code) {
			continue
		}
		digest := stepText[loc[0]:loc[1]]
		if namesFile(code, file) && digestFeedsCheck(code, digest) {
			return true
		}
	}
	offset := 0
	for _, line := range strings.Split(stepText, "\n") {
		lineStart := offset
		offset += len(line) + 1
		if !inWindow(lineStart) || !reVerifyCommand.MatchString(line) {
			continue
		}
		lower := strings.ToLower(line)
		if (strings.Contains(lower, "gpg") || strings.Contains(lower, "cosign")) && namesFile(line, file) {
			return true
		}
		if sums := sumsFileArg(line); sums != "" && sumsFileNamesDownload(stepText, sums, file) {
			return true
		}
	}
	return false
}

// namesFile reports whether text names file as a whole shell token:
// preceded by the start of the text, whitespace, a quote, `=` or a
// path separator, and followed by the end, whitespace, a quote or a
// shell separator. `nodejs.tar.gz` does not name `node`.
func namesFile(text, file string) bool {
	re := regexp.MustCompile(`(?:^|[\s"'=/])` + regexp.QuoteMeta(file) + `(?:$|[\s"';|&)])`)
	return re.MatchString(text)
}

// firstRunLineStart is the start offset of the first line after the
// download line that runs file: a shell or interpreter given the file
// (optionally through sudo and with a leading path), `./file`,
// `source file` or `chmod +x file`. -1 when no later line runs it.
func firstRunLineStart(stepText string, downloadLineStart int, file string) int {
	quoted := regexp.QuoteMeta(file)
	re := regexp.MustCompile(`(?:^|[\s;&|(])(?:` +
		`(?:sudo\s+(?:-\S+\s+)*)?(?:bash|sh|zsh|dash|ksh|source|\.|python3?|node|perl|ruby|chmod\s+\+x)\s+(?:\S*/)?` + quoted +
		`|\./` + quoted +
		`)(?:$|[\s;&|)])`)
	offset := 0
	for _, line := range strings.Split(stepText, "\n") {
		lineStart := offset
		offset += len(line) + 1
		if lineStart <= downloadLineStart {
			continue
		}
		if re.MatchString(stripShellComment(line)) {
			return lineStart
		}
	}
	return -1
}

// digestFeedsCheck reports whether line, which already carries a
// literal digest naming file, actually CHECKS that digest against
// something, rather than merely printing it: piped into (or compared
// by) sha256sum/shasum -c, a grep of a real hash computation, an `=`/
// `==`/`!=` comparison inside `[`/`[[`/`test` with digest itself as
// one of its operands (digestIsComparisonOperand), or gpg/cosign.
func digestFeedsCheck(line, digest string) bool {
	return reVerifyCommand.MatchString(line) ||
		reHashOfFilePipedToGrep.MatchString(line) ||
		digestIsComparisonOperand(line, digest)
}

// isFetchLine reports whether line itself fetches something (curl or
// wget): a sums file written by such a line is never pinned, whatever
// else it might coincidentally contain.
func isFetchLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "curl") || strings.Contains(lower, "wget")
}

// isContainerImageDigest reports whether the literal-digest match at
// stepText[pos:] is immediately preceded by "@sha256:" (a container
// image reference pinned by digest, never a downloaded file's
// checksum).
func isContainerImageDigest(stepText string, pos int) bool {
	const lookback = len("@sha256:")
	lo := pos - lookback
	if lo < 0 {
		lo = 0
	}
	return strings.HasSuffix(strings.ToLower(stepText[lo:pos]), "@sha256:")
}

// sumsFileArg extracts the sums-file argument of a `sha256sum`/
// `shasum` CHECK command (reVerifyCommand already matched line), ""
// when the command is gpg/cosign (handled separately) or carries no
// argument at all.
func sumsFileArg(line string) string {
	m := reVerifyFileArg.FindStringSubmatch(line)
	if len(m) != 2 {
		return ""
	}
	return strings.Trim(m[1], `"'`)
}

// sumsFileNamesDownload reports whether sums was itself written,
// somewhere in stepText, by a line (or a heredoc body line) that
// carries a LITERAL digest of its own and names file, on a write that
// is not itself a fetch: only a digest already present in the step's
// own source pins the sums file. A line that merely computes the
// digest at runtime (`sha256sum file > sums`) or fetches it from a
// moving ref (`curl .../file.sha256 > sums`) never counts, even when
// it happens to name the file too (a fetched sums file's own URL path
// can coincidentally contain the file's name).
func sumsFileNamesDownload(stepText, sums, file string) bool {
	for _, line := range strings.Split(stepText, "\n") {
		if isFetchLine(line) {
			continue
		}
		for _, m := range reRedirectTarget.FindAllStringSubmatch(line, -1) {
			if strings.Trim(m[1], `"'`) == sums && namesFile(line, file) && reLiteralDigest.MatchString(line) {
				return true
			}
		}
	}
	return heredocSumsFileNamesDownload(stepText, sums, file)
}

// heredocSumsFileNamesDownload is sumsFileNamesDownload's heredoc
// form: `cat > sums <<MARKER` / `tee sums <<-'MARKER'`, followed by a
// body (every line up to the one that is exactly MARKER, trimmed)
// that, taken together, carries a literal digest and names file. The
// write line itself is never a fetch, same as the plain-redirect form.
func heredocSumsFileNamesDownload(stepText, sums, file string) bool {
	lines := strings.Split(stepText, "\n")
	for i, line := range lines {
		if isFetchLine(line) {
			continue
		}
		m := reHeredocRedirect.FindStringSubmatch(line)
		if m == nil || strings.Trim(m[1], `"'`) != sums {
			continue
		}
		marker := m[2]
		var body []string
		for j := i + 1; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == marker {
				break
			}
			body = append(body, lines[j])
		}
		bodyText := strings.Join(body, "\n")
		if namesFile(bodyText, file) && reLiteralDigest.MatchString(bodyText) {
			return true
		}
	}
	return false
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
		if !slices.Contains(paths, c) {
			paths = append(paths, c)
		}
	}
	return paths
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
