# CLI <> Platform rows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Platform-mode jobs on a root-owned checkout keep all their controls (#464); an enabled but unconfigured control is `not_evaluable` with reason `config_required` instead of a vacuous pass (#459); the CLI fetches the platform's dismissed issues, marks matching findings, excludes them from its score and pushes the marker (#447).

**Architecture:** Three independent changes on the existing lanes: one git helper in `utils`, one marking pass next to the existing not_evaluable marks, and one match-and-mark pass between fingerprint stamping and scoring, fed by a new `/context` field and a new exported hash in the shared identity recipe.

**Tech Stack:** Go 1.26, logrus, OPA findings, `make test` / `make lint` (golangci-lint v2) / `make deadcode`.

**Spec:** `docs/superpowers/specs/2026-09-10-cli-platform-rows-design.md`

## Global Constraints

- Conventional commits (no commitlint here, but the release notes are generated from them; every feat/fix bumps a patch); a commit body line `Closes #<n>` for the issue the commit resolves. No em dash character anywhere. Never edit `CHANGELOG.md` (semantic-release writes it).
- `go test ./...`, `go vet ./...`, `make lint` (0 issues), `make deadcode` (the two pre-existing findings `configuration/schema.go` and gofmt on `gitlab/request.go` are known; add nothing new) before every commit. Tests are fast here (no database); run the whole suite.
- Frozen finding-status vocabulary `pass | fail | not_evaluable`; `dismissed` is an orthogonal boolean, never a status.
- `identity.RecipeVersion` stays 4; `Of`, `Fingerprint`, `canonical()` and `Pairs()` are not modified (a change re-keys every finding).
- `opaengine.Finding.MarshalJSON` output is unchanged (the platform hashes it).
- `ComputePlumberScore` is unchanged; only its INPUT (the code counts) changes.
- Every new test's doc comment names the issue it pins (`#464`, `#459`, `#447`).

---

### Task 1: git safe.directory and diagnostics on a root-owned checkout (#464)

**Files:**
- Modify: `utils/gitremote.go` (`DetectGitRemote`, `DetectGitRepoRoot`, `DetectGitHeadSHA`)
- Modify: `templates/plumber.yml` (script block, ~:210-220)
- Test: `utils/gitremote_safedir_test.go` (new), `cmd/platform_push_test.go` only if it parses the template (grep first)

- [ ] **Step 1: Write the failing tests**

```go
package utils

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

// TestGitCommand_NamesTheDirectoryAsSafe pins #464: every git shell-out passes the inspected
// directory as protected safe.directory configuration, so a checkout owned by another uid (the
// GitLab docker executor clones as root, the image runs as uid 65532) is readable without a
// global git config the image does not carry. The one directory, never '*'.
func TestGitCommand_NamesTheDirectoryAsSafe(t *testing.T) {
	cmd := gitCommand("/builds/group/project", "rev-parse", "--show-toplevel")
	want := []string{"git", "-c", "safe.directory=/builds/group/project", "rev-parse", "--show-toplevel"}
	if strings.Join(cmd.Args, " ") != strings.Join(want, " ") {
		t.Fatalf("argv = %q, want %q", cmd.Args, want)
	}
	if cmd.Dir != "/builds/group/project" {
		t.Fatalf("Dir = %q, want the inspected directory", cmd.Dir)
	}
}

// TestDetectGitRepoRoot_LogsTheGitErrorAtWarn pins #464: a git failure is no longer silent. A
// fake git on PATH exits 128 with the dubious-ownership message; the caller still gets "" (its
// contract) and the first stderr line is logged at Warn so the job log explains the degraded run.
func TestDetectGitRepoRoot_LogsTheGitErrorAtWarn(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "git")
	script := "#!/bin/sh\necho \"fatal: detected dubious ownership in repository at '/builds/x'\" >&2\nexit 128\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	hook := test.NewGlobal()
	defer hook.Reset()
	logrus.SetLevel(logrus.DebugLevel)

	if got := DetectGitRepoRoot(); got != "" {
		t.Fatalf("repo root = %q, want empty on git failure", got)
	}
	var found bool
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel && strings.Contains(e.Message, "dubious ownership") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no Warn entry naming the git error; entries: %+v", hook.AllEntries())
	}
	_ = exec.Command // keep the import honest if the fake needs it
}
```

Check how `utils` logs today (`grep -n logrus utils/*.go`); if the package uses a package-level logger variable, log through it so the hook sees it. Adapt the assertion to the actual message format you choose (it must contain the stderr text).

- [ ] **Step 2: Run to verify failure**

Run: `go test ./utils/ -run 'TestGitCommand_NamesTheDirectoryAsSafe|TestDetectGitRepoRoot_LogsTheGitErrorAtWarn' -count=1`
Expected: FAIL (`gitCommand` undefined; no Warn entry).

- [ ] **Step 3: Implement**

In `utils/gitremote.go`:

```go
// gitCommand builds a git invocation scoped to dir with dir declared as safe.directory (#464).
// -c is protected configuration, so git honors safe.directory from it even when the repository
// is owned by another uid (the GitLab docker executor clones $CI_PROJECT_DIR as root while the
// image runs as uid 65532); git >= 2.35.2 otherwise refuses with "detected dubious ownership".
// The single inspected directory is named, never '*': the trust decision stays as narrow as the
// question being asked.
func gitCommand(dir string, args ...string) *exec.Cmd {
	full := append([]string{"-c", "safe.directory=" + dir}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	return cmd
}

// runGit runs a gitCommand and returns its trimmed stdout. On failure it logs the first stderr
// line at Warn (#464): before this, a dubious-ownership refusal and "not a git repository" were
// indistinguishable to every caller, and platform mode silently lost five controls on the
// default executor with nothing in the job log to explain it.
func runGit(dir string, args ...string) (string, error) {
	cmd := gitCommand(dir, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		first := strings.SplitN(strings.TrimSpace(stderr.String()), "\n", 2)[0]
		logrus.WithFields(logrus.Fields{"dir": dir, "args": strings.Join(args, " ")}).
			Warnf("git %s failed: %s", strings.Join(args, " "), first)
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
```

`DetectGitRemote`: `dir, _ := os.Getwd()`; `remoteURL, err := runGit(dir, "remote", "get-url", "origin")`; keep the nil contract. `DetectGitRepoRoot`: `runGit(cwd, "rev-parse", "--show-toplevel")`. `DetectGitHeadSHA(repoRoot)`: `runGit(repoRoot, "rev-parse", "HEAD")`. If `utils` deliberately avoids logrus today, use the same logger the rest of the package uses; the requirement is a Warn with the stderr line.

`templates/plumber.yml` script block, before `plumber analyze`:

```yaml
    # The docker executor clones $CI_PROJECT_DIR as root while this image runs as uid 65532;
    # git refuses a repository owned by another uid unless it is declared safe (#464). The CLI
    # also declares it per invocation; this line covers a custom image whose git predates that.
    - if command -v git >/dev/null 2>&1 && [ -n "${CI_PROJECT_DIR:-}" ]; then git config --global --add safe.directory "$CI_PROJECT_DIR"; fi
```

- [ ] **Step 4: Run, lint, commit**

Run: `go test ./... -count=1 && go vet ./... && make lint && make deadcode`
Expected: PASS, 0 lint issues, deadcode unchanged.

```bash
git add utils/gitremote.go utils/gitremote_safedir_test.go templates/plumber.yml
git commit -m "fix(platform): declare the checkout safe for git and log git failures, so a root-owned clone keeps its controls

Closes #464"
```

---

### Task 2: unconfigured controls are not_evaluable (#459)

**Files:**
- Modify: `configuration/schema.go` (new `IsUnconfigured`), `control/lanes.go` (new reason + `MarkUnconfiguredControls`, call in `ReEvaluateForConfig`), `control/task.go:~1103` (call after `MarkOwnCollectionGaps`), the GitHub task's result finalization (`control/task_github.go`: find where the GitHub `AnalysisResult` is completed; add the same call with `GitHubControls(conf.PlumberConfig)` and `configuration.ProviderGitHub`), `docs/scoring.md` (Inputs section).
- Test: `configuration/unconfigured_test.go`, `control/unconfigured_test.go`.

**Interfaces:**
- Produces: `configuration.IsUnconfigured(pc *PlumberConfig, provider, controlName string) bool`; `control.ReasonConfigRequired = "config_required"`; `control.MarkUnconfiguredControls(result *AnalysisResult, entries []ControlEntry, pc *configuration.PlumberConfig, provider string)`.

- [ ] **Step 1: Failing tests**

```go
package configuration

import "testing"

// TestIsUnconfigured pins #459: a RequiresConfig control enabled with no substantive field is
// unconfigured; one substantive field, a non-RequiresConfig control, a disabled control and a
// nil block are not.
func TestIsUnconfigured(t *testing.T) {
	requires := firstRequiresConfigControl(t) // helper: first ControlsCatalog() entry with RequiresConfig, plus its provider
	pcBare := plumberConfigWith(t, requires.Provider, requires.Name, map[string]any{"enabled": true})
	if !IsUnconfigured(pcBare, requires.Provider, requires.Name) {
		t.Errorf("#459: %s with enabled:true only must be unconfigured", requires.Name)
	}
	pcSet := plumberConfigWith(t, requires.Provider, requires.Name, substantiveExample(t, requires.Name))
	if IsUnconfigured(pcSet, requires.Provider, requires.Name) {
		t.Errorf("#459: %s with a substantive field set must not be unconfigured", requires.Name)
	}
	plain := firstControlWhere(t, func(e ControlMeta) bool { return !e.RequiresConfig })
	pcPlain := plumberConfigWith(t, plain.Provider, plain.Name, map[string]any{"enabled": true})
	if IsUnconfigured(pcPlain, plain.Provider, plain.Name) {
		t.Errorf("#459: a control that asserts something unconfigured is never unconfigured")
	}
	pcOff := plumberConfigWith(t, requires.Provider, requires.Name, map[string]any{"enabled": false})
	if IsUnconfigured(pcOff, requires.Provider, requires.Name) {
		t.Error("#459: a disabled control is skipped, not unconfigured")
	}
	if IsUnconfigured(&PlumberConfig{}, requires.Provider, requires.Name) {
		t.Error("#459: an absent block is skipped, not unconfigured")
	}
}
```

Write the three helpers in the test file by building a `PlumberConfig` through the YAML loader the package already tests with (grep `yaml.Unmarshal` in `configuration/*_test.go`), and `substantiveExample` from `ConfigSchemaFor(name)`: pick the first non-`enabled` field and give it a non-zero value of its type (string "x", integer 1, bool true, array `["x"]`, object `{}` is NOT non-zero: for an object field recurse to its first leaf).

`control/unconfigured_test.go`: build an `AnalysisResult` and entries for a RequiresConfig control enabled bare; call `MarkUnconfiguredControls`; assert `result.NotEvaluable[name] == ReasonConfigRequired`, `StatusFor(entry, result, 0) == StatusError`, and that a first-reason already present (`MarkNotEvaluable(name, ReasonLaneNotServed)` before) is kept. A second test through `ReEvaluateForConfig` with two policies (bare and configured) asserting only the bare one is marked; model it on the existing `ReEvaluateForConfig` tests (grep them).

- [ ] **Step 2: Run to verify failure**

Run: `go test ./configuration/ ./control/ -run 'TestIsUnconfigured|Unconfigured' -count=1`
Expected: compile failure.

- [ ] **Step 3: Implement**

`configuration/schema.go`:

```go
// IsUnconfigured reports whether controlName is enabled in pc but asserts nothing because none of
// its substantive fields is set (#459): the control is RequiresConfig in the catalog, its block is
// present and enabled, and every field other than `enabled` is at its zero value (nil pointer,
// empty slice or map, "", 0, false; a nested struct is zero when all of its fields are). The field
// enumeration is the SAME reflection the catalog exports (reflectControlSchemas), so a field the
// schema shows is a field this check reads. False for a control that is not RequiresConfig, is
// disabled, or has no block: those are "asserts something" or "skipped", never "unconfigured".
func IsUnconfigured(pc *PlumberConfig, provider, controlName string) bool {
	if pc == nil {
		return false
	}
	meta, ok := controlMetaFor(provider, controlName) // ControlsCatalog() lookup by provider+name
	if !ok || !meta.RequiresConfig {
		return false
	}
	block := controlBlock(pc, provider, controlName) // reflect.Value of the config struct pointer, or invalid
	if !block.IsValid() || block.IsNil() {
		return false
	}
	if en, ok := block.Interface().(interface{ IsEnabled() bool }); !ok || !en.IsEnabled() {
		return false
	}
	return substantiveFieldsAreZero(block.Elem())
}
```

Implement `controlBlock` by walking `ControlsConfig`'s fields with `yamlName(f) == controlName` (the same loop `reflectControlSchemas` runs; factor the per-provider `ControlsConfig` access from `pc` the way `GitLabControls`/`GitHubControls` reach it), and `substantiveFieldsAreZero` with `reflect.Value.IsZero()` per field skipping the field whose yaml name is `enabled`, recursing into struct-typed fields.

`control/lanes.go`:

```go
// ReasonConfigRequired: the control is enabled but none of its substantive configuration fields is
// set, so it asserts nothing (#459, platform decision-queue row 19: honest not_evaluable, never a
// vacuous pass). Which controls can be in this state is authored truth (configuration.ControlMeta
// .RequiresConfig); which fields count is the catalog's own reflected schema.
const ReasonConfigRequired = "config_required"

// MarkUnconfiguredControls flags every non-skipped RequiresConfig control whose enabled block sets
// no substantive field (#459). Runs AFTER the lane-gap marks: a lane gap is the more specific
// explanation and MarkNotEvaluable keeps the first reason.
func MarkUnconfiguredControls(result *AnalysisResult, entries []ControlEntry, pc *configuration.PlumberConfig, provider string) {
	if result == nil || pc == nil {
		return
	}
	for _, e := range entries {
		if e.Skipped {
			continue
		}
		if configuration.IsUnconfigured(pc, provider, e.ControlName) {
			result.MarkNotEvaluable(e.ControlName, ReasonConfigRequired)
		}
	}
}
```

Call sites: `control/task.go` right after `markPlatformLaneGaps(result, conf)` (~:1105): `MarkUnconfiguredControls(result, GitLabControls(conf.PlumberConfig), conf.PlumberConfig, configuration.ProviderGitLab)`; the GitHub task's finalization with `GitHubControls`/`ProviderGitHub`; `ReEvaluateForConfig` after `markPlatformLaneGapsFor` and before `DropNotEvaluableFindings`: `MarkUnconfiguredControls(&scopedResult, entriesFor(provider, pc), pc, provider)` (use the existing per-provider entries builder the function or its callers already use).

`docs/scoring.md` "Inputs: per-code counts": add "An enabled control none of whose substantive configuration fields is set is not evaluated (`not_evaluable`, reason `config_required`) and contributes nothing: a policy made of unconfigured controls does not score 100, it scores over nothing (#459)."

- [ ] **Step 4: Run, lint, commit**

Run: `go test ./... -count=1 && go vet ./... && make lint && make deadcode`

```bash
git add configuration/schema.go configuration/unconfigured_test.go control/lanes.go control/unconfigured_test.go control/task.go control/task_github.go docs/scoring.md
git commit -m "feat(scoring): report an enabled but unconfigured control as not_evaluable (config_required) instead of a vacuous pass

Closes #459"
```

---

### Task 3: dismissed issues: wire type, platform hash, match and mark (#447, part 1)

**Files:**
- Modify: `internal/platform/types.go` (`DismissedIssue`, `ProjectContext.DismissedIssues`), `finding/identity/identity.go` (`PlatformHash`), `internal/engine/opa/engine.go` (`Finding.Dismissed`, exported `IdentityInput()` if `identityInput` must be reachable from `control`), `control/dismissed.go` (new: `MarkDismissed`)
- Test: `internal/platform/types_test.go` (decode), `finding/identity/platformhash_test.go`, `control/dismissed_test.go`

**Interfaces:**
- Produces: `platform.DismissedIssue{IdentityHash string; RecipeVersion int; ControlType string}`; `identity.PlatformHash(f Finding) (hash string, version int, ok bool)`; `opaengine.Finding.Dismissed bool`; `control.MarkDismissed(findings []opaengine.Finding, served []platform.DismissedIssue) int`.

- [ ] **Step 1: Failing tests**

`finding/identity/platformhash_test.go`:

```go
// TestPlatformHash_MatchesThePlatformDigest pins #447: PlatformHash is sha256 hex over
// json.Marshal(fields.Pairs()), the platform's own issueident.Hash by construction, so a
// dismissed issue served by identity_hash matches the CLI's finding without a second recipe.
func TestPlatformHash_MatchesThePlatformDigest(t *testing.T) {
	f := Finding{Code: "ISSUE-103", File: ".gitlab-ci.yml", Job: "build", Message: "m", Data: map[string]any{"image": "nginx:latest"}}
	fields, ok := Of(f)
	if !ok {
		t.Fatal("fixture must have a code")
	}
	pairs, _ := json.Marshal(fields.Pairs())
	sum := sha256.Sum256(pairs)
	want := hex.EncodeToString(sum[:])
	got, version, ok := PlatformHash(f)
	if !ok || got != want || version != RecipeVersion {
		t.Fatalf("PlatformHash = (%q, %d, %v), want (%q, %d, true)", got, version, ok, want, RecipeVersion)
	}
	if _, _, ok := PlatformHash(Finding{}); ok {
		t.Error("a codeless finding has no identity and no platform hash")
	}
}
```

Also a golden: hard-code the `want` value you observe for that exact fixture as a second assertion with a comment "wire-stable: the platform stores this digest; changing Pairs() or the marshal is a recipe bump".

`control/dismissed_test.go`: served list with (a) a matching entry for a finding of code X, (b) an entry with `RecipeVersion: 3` for another finding (skipped), (c) an entry whose `ControlType` names a different control (never compared), (d) a codeless finding; assert exactly the one match is marked and `MarkDismissed` returns 1; an empty served list marks nothing.

`internal/platform/types_test.go`: decode a `/context` JSON with and without `dismissed_issues`; the field is nil when absent and populated when present (three fields).

- [ ] **Step 2: Run to verify failure**

Run: `go test ./finding/identity/ ./control/ ./internal/platform/ -run 'PlatformHash|Dismissed' -count=1`
Expected: compile failure.

- [ ] **Step 3: Implement**

`finding/identity/identity.go`:

```go
// PlatformHash returns the digest the platform stores as an issue's identity_hash (its own
// issueident.Hash): sha256 hex over json.Marshal(Of(f).Pairs()), full length, plus the recipe
// version the fields were selected under. ok is false for a codeless finding. Distinct from
// Fingerprint (the truncated export identifier over canonical()): the two never had to agree
// on a hash, only on the field selection, and this function exists so the CLI can match the
// platform's served dismissed_issues (#447) without a second recipe.
func PlatformHash(f Finding) (hash string, version int, ok bool) {
	fields, ok := Of(f)
	if !ok {
		return "", 0, false
	}
	pairs, err := json.Marshal(fields.Pairs())
	if err != nil {
		return "", 0, false
	}
	sum := sha256.Sum256(pairs)
	return hex.EncodeToString(sum[:]), fields.Version, true
}
```

`internal/platform/types.go`:

```go
// DismissedIssue is one entry of ProjectContext.DismissedIssues: the match key for a finding the
// platform has in status Dismissed (#447). IdentityHash is the platform's full sha256 hex over
// the shared recipe's Pairs() (identity.PlatformHash); RecipeVersion is the recipe the hash was
// computed under and versions never mix; ControlType rides along as a cheap pre-filter, never
// part of the key.
type DismissedIssue struct {
	IdentityHash  string `json:"identity_hash"`
	RecipeVersion int    `json:"recipe_version"`
	ControlType   string `json:"control_type"`
}
```

and `DismissedIssues []DismissedIssue \`json:"dismissed_issues"\`` on `ProjectContext`.

`internal/engine/opa/engine.go`: `Dismissed bool \`json:"-"\`` on `Finding` with the doc "set by control.MarkDismissed when the platform served this finding's identity as dismissed (#447); never emitted by MarshalJSON (the platform hashes that object) and never a status: pass|fail|not_evaluable is frozen"; export `func (f Finding) IdentityInput() identity.Finding` (rename `identityInput` or add a public wrapper) so `control` can compute the hash.

`control/dismissed.go`:

```go
// MarkDismissed sets Dismissed on every finding whose platform identity matches a served
// dismissed issue (#447) and returns how many it marked. Entries served under another recipe
// version are skipped (honest non-suppression, never a cross-version match); control_type is
// used only to avoid hashing a finding against entries of other controls. A codeless finding
// has no identity and never matches. The marker is a claim about what /context served; the
// platform's stored issue status stays the authority.
func MarkDismissed(findings []opaengine.Finding, served []platform.DismissedIssue) int {
	if len(served) == 0 {
		return 0
	}
	byControl := map[string]map[string]struct{}{}
	for _, d := range served {
		if d.RecipeVersion != identity.RecipeVersion {
			continue
		}
		set, ok := byControl[d.ControlType]
		if !ok {
			set = map[string]struct{}{}
			byControl[d.ControlType] = set
		}
		set[d.IdentityHash] = struct{}{}
	}
	marked := 0
	for i := range findings {
		set, ok := byControl[LookupCode(ErrorCode(findings[i].Code)).ControlName]
		if !ok {
			continue
		}
		hash, _, ok := identity.PlatformHash(findings[i].IdentityInput())
		if !ok {
			continue
		}
		if _, hit := set[hash]; hit {
			findings[i].Dismissed = true
			marked++
		}
	}
	return marked
}
```

Verify `LookupCode`'s exact name and return shape (`control/codes.go`) and whether `control` may import `internal/platform` without a cycle (`configuration` already imports it; `control` imports `configuration`; check with `go build ./...`).

- [ ] **Step 4: Run, lint, commit**

Run: `go test ./... -count=1 && go vet ./... && make lint && make deadcode` (MarkDismissed has no caller yet: if deadcode flags it, note that Task 4 wires it and add the exemption only if the target fails the build; otherwise proceed.)

```bash
git add internal/platform/types.go internal/platform/types_test.go finding/identity/identity.go finding/identity/platformhash_test.go internal/engine/opa/engine.go control/dismissed.go control/dismissed_test.go
git commit -m "feat(platform): decode dismissed_issues, add the platform identity hash and mark matching findings"
```

---

### Task 4: dismissed findings: wire the mark, exclude from the score, push the marker, show it (#447, part 2)

**Files:**
- Modify: `cmd/analyze_shared.go` (call `MarkDismissed` after each `StampFingerprints`, ~:37 and ~:455, when `conf.PlatformRun != nil && conf.PlatformRun.Context != nil`), `control/scoring.go` (`forEachIssueCode` skips `Dismissed`), `control/lanes.go` (`ReEvaluateForConfig`: call `MarkDismissed` on `scopedResult.Findings` with `conf.PlatformRun.Context.DismissedIssues` when available, and skip dismissed in its count loop), `cmd/platform_push.go` (`platformFinding.Dismissed`, set on the fail branch), `cmd/analyze_shared.go` (`findingGroup.Dismissed int`), `cmd/render_details.go` (tag), `docs/platform-push-testing.md`.
- Test: `control/scoring_dismissed_test.go`, `cmd/platform_push_test.go` (extend), a renderer test next to the existing ones.

- [ ] **Step 1: Failing tests**

`control/scoring_dismissed_test.go`: an `AnalysisResult` with two fail findings of the same code, one `Dismissed`; `AggregateIssueCodeCounts` returns 1 for that code; `CriticalIssueCodesSorted` still lists the code if the other finding is live (document: dismissed findings are out of the score, the code is still "present" only if a live finding carries it: apply the skip in `forEachIssueCode` so both agree). `ReEvaluateForConfig` test: with a served dismissed entry matching one of the scoped findings, the returned score equals the score of the same result without that finding (compute both).

`cmd/platform_push_test.go`: a fail finding with `Dismissed: true` produces a `platformFinding` with `Status: "fail"` and `Dismissed: true`; the request golden (grep the existing goldens in `docs/platform-push-testing.md` and the test fixtures) shows `"dismissed":true` on that entry and is absent on the others.

Renderer test: a control with one live and one dismissed finding renders the dismissed one with a `dismissed` tag and the failed count reads 1.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./control/ ./cmd/ -run 'Dismissed' -count=1`
Expected: FAIL (counts 2; no marker; no tag).

- [ ] **Step 3: Implement**

`control/scoring.go`:

```go
func forEachIssueCode(result *AnalysisResult, fn func(ErrorCode)) {
	if result == nil {
		return
	}
	for _, f := range result.Findings {
		if f.Dismissed { // #447: out of the score like not_evaluable, never counted as pass
			continue
		}
		fn(ErrorCode(f.Code))
	}
}
```

`ReEvaluateForConfig`: after `scopedResult.DropNotEvaluableFindings()`: `if conf.PlatformRun != nil && conf.PlatformRun.Context != nil { MarkDismissed(scopedResult.Findings, conf.PlatformRun.Context.DismissedIssues) }`, and `if f.Dismissed { continue }` in its count loop. `cmd/analyze_shared.go`: the same guard-and-call right after each `StampFingerprints`. `platformFinding`: `Dismissed bool \`json:"dismissed,omitempty"\``; in `platformFindingsFor`'s fail branch set it from `f.Dismissed` (extend `decoratedPlatformFinding` or set the field after). `findingGroup.Dismissed int` counted where the group is built; `render_details.go`: in `renderFailedControl`, print each dismissed finding's line with a trailing ` [dismissed on the platform]` and exclude them from the count shown for the control (read how the count is derived; keep `StatusFor` untouched). `docs/platform-push-testing.md`: one paragraph on the marker and how to see it in a captured request.

- [ ] **Step 4: Run, lint, commit**

Run: `go test ./... -count=1 && go vet ./... && make lint && make deadcode`

```bash
git add cmd/analyze_shared.go control/scoring.go control/lanes.go cmd/platform_push.go cmd/render_details.go control/scoring_dismissed_test.go cmd/platform_push_test.go cmd/*_test.go docs/platform-push-testing.md
git commit -m "feat(platform): exclude platform-dismissed findings from the score, push the dismissed marker and show it

Closes #447"
```

---

### Task 5: README and handover notes

**Files:**
- Modify: `README.md` (platform mode section: one sentence each on the safe.directory behavior, `config_required`, and dismissed findings), `docs/superpowers/specs/2026-09-10-cli-platform-rows-design.md` (a "Shipped" line naming the four commits).

- [ ] **Step 1: Edit and commit**

```bash
git add README.md docs/superpowers/specs/2026-09-10-cli-platform-rows-design.md
git commit -m "docs(platform): document the safe checkout, config_required and dismissed findings"
```

## Self-review notes

- Spec coverage: s1 -> Task 1; s2 -> Task 2; s3 -> Tasks 3, 4; s4 -> Task 5 plus the `Closes` trailers.
- Type consistency: `identity.PlatformHash(f Finding) (string, int, bool)` used in Task 3's `MarkDismissed`; `opaengine.Finding.Dismissed` read by Task 4's `forEachIssueCode`, `platformFindingsFor` and the renderer; `platform.DismissedIssue` fields match the platform contract (`identity_hash`, `recipe_version`, `control_type`).
- Plan-time uncertainties flagged in place: the `utils` logger, the GitHub task's finalization site, `LookupCode`'s shape and the `control` -> `internal/platform` import direction, whether the exporters serialize through `MarshalJSON`.
