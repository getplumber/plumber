# CLI <> Platform rows: non-root checkout, unconfigured controls, dismissal propagation (design)

Date: 2026-09-10. Scope: the open-source CLI only (`getplumber/plumber`). Closes #464, #459, #447. The
platform side of each item is already live or needs only a pin bump (noted per section).

Rows 2 (#448), 3 (#449) and 12 (#454) of the platform's decision queue were checked against
v0.4.57 before this spec: the identity declarations table is exhaustive and guarded
(`finding/identity/parity_test.go`), `DeriveIncludeJobs` compares project paths with
`strings.EqualFold` since commit 81322b0, and the catalog export (#458, v0.4.56) is the source of
truth the docs site consumes. Nothing remains for them in this repo.

## s1. Platform mode on a root-owned checkout (#464)

**The fact.** The image runs as uid 65532 (`Dockerfile`: `USER plumber`), the GitLab docker
executor clones `$CI_PROJECT_DIR` as root, and git 2.35.2+ refuses the repository ("detected
dubious ownership"). `utils.DetectGitRemote`, `DetectGitRepoRoot` and `DetectGitHeadSHA`
(`utils/gitremote.go`) shell out to git and return nil or "" on ANY error, so `conf.GitRepoRoot`
is empty and `conf.CheckoutIsAnalyzedProject` is false. Downstream: `computeLocalCIDigest`
(`cmd/platform_mode.go:83`) refuses the digest and the run is treated as divergent (resolve
endpoint instead of the free cache hit), `useCheckoutInPlatformMode` (`control/task.go:814`) is
false so the CI file is fetched anonymously and 404s on a private project, and
`ConfigAndIncludesAgree` (`internal/platform/run.go:133`) is false so every include-attribution
control reports `include_attribution_unavailable`. Five controls lost on every platform-mode job
on the default executor, silently.

**Design.** Two independent levers, both applied.

1. **CLI, self-healing.** Every git shell-out in `utils/gitremote.go` goes through one helper
   `gitCommand(dir string, args ...string) *exec.Cmd` that prepends `-c safe.directory=<dir>`
   where `dir` is the absolute working directory being inspected (the process cwd for the two
   detection calls, `repoRoot` for the HEAD read). `-c` is protected configuration, so git honors
   it for `safe.directory`; naming the one directory, never `*`, keeps the trust decision narrow.
   On failure the helper captures stderr and logs at Warn: `git <args> failed in <dir>: <stderr
   first line>`, so "not a git repository" and "dubious ownership" stop being indistinguishable.
   The three callers keep their nil/"" contract.
2. **Component template, belt and braces. DROPPED** (whole-branch security review,
   2026-09-10). The line `git config --global --add safe.directory "$CI_PROJECT_DIR"` was added
   to `templates/plumber.yml` before `plumber analyze` and then removed again: lever 1 is the
   complete fix (`-c` is protected configuration, so any git that enforces ownership honours it,
   which makes the "custom image whose git predates that" case empty), while a global `--add`
   costs real safety. It appends on every job, forever, on a shell executor with a persistent
   HOME, and a project that shadows `CI_PROJECT_DIR` with `*` writes a permanent global wildcard
   into the runner's git config, trusting every repository it will ever check out. Only lever 1
   ships.

**Out of scope.** `ResolvedConfig.Includes` (the resolve endpoint's `includes` are not decoded and
`ConfigAndIncludesAgree` is snapshot-only): a separate ask, tracked on #464's last paragraph, not
this batch.

**Tests.** A unit test that the helper's argv is exactly `git -c safe.directory=<dir> <args>`, and
one that an EMPTY dir omits the argument entirely (an empty value resets git's safe list rather
than adding to it); a unit test that a failing git (a fake `git` on PATH exiting 128 with stderr)
logs the stderr line at Warn and the caller still returns nil; a unit test that a credential in a
remote URL is redacted out of that log line; the existing `utils` detection tests unchanged. No
template test: lever 2 is dropped, so the template is unchanged by this batch.

## s2. Unconfigured controls score honestly (#459)

**The fact.** `configuration.ControlMeta.RequiresConfig` (`configuration/registry.go:62`,
14 controls) is authored truth that a bare `enabled: true` block asserts nothing, but the runtime
ignores it: the control runs through Rego with zero-valued fields, produces zero findings, and
`ComputePlumberScore` scores 100 (`control/scoring.go:175`: no denominator, an empty count map is
100). A fresh policy therefore governs nothing while looking green.

**Ruling (platform decision queue row 19, 2026-09-07).** Empty or absent config on a
`RequiresConfig` control yields `not_evaluable`, zero points, out of the denominator, with a
machine-readable reason. No platform-side band-aid; the platform surfaces the reason.

**Design.**

- New reason constant in `control/lanes.go`: `ReasonConfigRequired = "config_required"`, doc: the
  control is enabled but none of its substantive fields is set, so it asserts nothing.
- `configuration.IsUnconfigured(pc *PlumberConfig, provider, controlName string) bool`: true iff
  the control is `RequiresConfig` in `ControlsCatalog()`, its config pointer is non-nil and
  `IsEnabled()`, and every field of the config struct other than `enabled` is at its zero value
  (reflection over the struct: nil pointer, empty slice or map, "", 0, false; nested structs
  recurse). Lives next to `reflectControlSchemas` (`configuration/schema.go`) so the field
  enumeration is the one the catalog exports (a field the schema exports is a field this check
  reads).
- `control.MarkUnconfiguredControls(result *AnalysisResult, entries []ControlEntry, pc
  *configuration.PlumberConfig, provider string)`: for each non-skipped entry with
  `IsUnconfigured`, `MarkNotEvaluable(name, ReasonConfigRequired)`. Called at the three sites
  that already mark lane gaps: the GitLab task (`control/task.go:1103`, next to
  `MarkOwnCollectionGaps`), the GitHub task's equivalent (`control/task_github.go`, find where
  its not_evaluable marks or `MarkOwnCollectionGaps` run), and `ReEvaluateForConfig`
  (`control/lanes.go`, with the SCOPED policy's `pc`, since each platform policy has its own
  config). First-reason-wins is preserved by calling it AFTER the lane-gap marks (a lane gap is
  the more specific explanation).
- No change to `ComputePlumberScore`: a not_evaluable control has no findings and `StatusFor`
  already reports `StatusError`, which the push maps to `not_evaluable` with `{"reason":
  "config_required"}` (`cmd/platform_push.go:420,434`). The terminal "Not evaluated" bucket
  prints the reason already; the CSV/OCSF surfaces read `result.NotEvaluable` directly.
- Docs: `docs/scoring.md` gains a sentence in "Inputs" (an enabled control with no substantive
  configuration is not evaluated and does not count); the README's controls section, if it lists
  `requires_config`, points at it.

**Platform side.** The stored reason is served verbatim; the pin bump to the release carrying
this adopts the behavior (row 19's "ships with the CLI pin bump"). No contract change.

**Tests.** `IsUnconfigured` table test over: a RequiresConfig control with `enabled: true` only
(true), the same with one substantive field set (false), a non-RequiresConfig control with
`enabled: true` only (false), disabled (false), nil (false). An end-to-end analysis test where a
RequiresConfig control is enabled bare: `StatusFor` is `StatusError`, the push finding is
`not_evaluable` with reason `config_required` (assert the "Not evaluated" bucket carries it and
no `pass` finding exists for it). `ReEvaluateForConfig` with two policies, one bare and one configured:
only the bare one is marked.

## s3. Dismissal propagation, the CLI half (#447)

**The fact.** The platform serves `ProjectContext.dismissed_issues` (`[{identity_hash,
recipe_version, control_type}]`, capped 1000, always present) and accepts an optional
`dismissed: true` on a pushed finding (orthogonal to `pass|fail|not_evaluable`). The CLI decodes
neither: `internal/platform.ProjectContext` has no field and `cmd/platform_push.go`'s
`platformFinding` has no marker. The platform's `identity_hash` is `sha256hex(json.Marshal(
fields.Pairs()))` over `identity.Of(identity.FromMap(finding data))` (platform `issueident.Hash`);
`recipe_version` is `identity.RecipeVersion` (4).

**Design.**

- **Wire.** `internal/platform.DismissedIssue{IdentityHash string; RecipeVersion int;
  ControlType string}` and `ProjectContext.DismissedIssues []DismissedIssue
  json:"dismissed_issues"` (absent decodes to nil, treated as empty).
- **Shared recipe, one more exported function.** `finding/identity.PlatformHash(f Finding)
  (hash string, version int, ok bool)`: `Of(f)`, then `sha256` hex over
  `json.Marshal(fields.Pairs())`, version `RecipeVersion`. Byte-identical to the platform's
  `issueident.Hash` by construction (same input, same marshal, same digest); a golden test pins
  one fixture's hash so a later change to `Pairs()` or the marshal breaks loudly. The platform
  will delegate `issueident.Hash` to it on its next pin bump (platform follow-up, not this repo).
- **Match and mark.** `opaengine.Finding` gains `Dismissed bool` (`json:"-"`, NOT emitted by
  `MarshalJSON`: the marker rides the push envelope, not the finding data the platform hashes).
  `control.MarkDismissed(findings []opaengine.Finding, served []platform.DismissedIssue) int`:
  builds a set of `(hash, version)` from the served entries whose `RecipeVersion ==
  identity.RecipeVersion` (others skipped, honest non-suppression), pre-filters by
  `ControlType == LookupCode(f.Code).ControlName` (cheap, not part of the key), computes
  `identity.PlatformHash(f.identityInput())` and sets `Dismissed` on a match; returns the count.
  Called once on `result.Findings` in the platform-mode analysis path after `StampFingerprints`
  and before scoring (`cmd/analyze_shared.go` ~:37 and ~:455), and in `ReEvaluateForConfig`
  on the scoped findings (the served list is the same; it must be reachable from `conf`:
  thread `conf.PlatformRun.Context.DismissedIssues`, read how `PlatformRun` exposes the
  `RunContext`). Standalone mode: nothing served, nothing marked.
- **Score.** `AggregateIssueCodeCounts` skips `Dismissed` findings; `ReEvaluateForConfig`'s own
  count loop skips them too. Out of the denominator like `not_evaluable`, never counted as pass.
  `ComputePlumberScore` itself is unchanged.
- **Push.** `platformFinding` gains `Dismissed bool json:"dismissed,omitempty"`;
  `platformFindingsFor` sets it from the finding on the `StatusFailed` branch. A control whose
  every finding is dismissed still reports those findings as `fail` with the marker (never
  omitted, never `pass`: omitting would read as Fixed platform-side).
- **Display.** `findingGroup` (`cmd/analyze_shared.go`) gains `Dismissed int`; the terminal
  renderer (`cmd/render_details.go`) prints dismissed findings inside the control's section
  with a `dismissed` tag and excludes them from the failed count; `StatusFor` is unchanged (a
  control with only dismissed findings still has `findingCount > 0` and reads failed on the
  console: the platform's issue status is the authority; the score is what the marker changes).
  JSON/CSV/OCSF: the finding carries `dismissed: true` in the CLI's own exports (add it to
  `MarshalJSON` ONLY for those exporters? No: keep `MarshalJSON` unchanged for hash stability and
  add the field in the exporters' own row builders where they already add `fingerprint`; if an
  exporter serializes the finding through `MarshalJSON` directly, leave it and note it).

**Sequencing.** No flag day: the platform accepts the marker today and excludes Dismissed issues
from its own recompute by stored status, so a CLI that marks and excludes agrees with the
platform card. The platform pin bump adopts `PlatformHash` and this scoring input change together.

**Tests.** `PlatformHash` golden; `MarkDismissed` table (match, version mismatch skipped, control
prefilter, codeless finding never matches, empty served list); `AggregateIssueCodeCounts` skips
dismissed; `ReEvaluateForConfig` skips dismissed; push payload carries `dismissed: true` on the
fail entry and the request golden (the platform push testing doc, `docs/platform-push-testing.md`)
updated; renderer shows the tag.

## s4. Records

Each fix is one conventional commit whose body says `Closes #<n>`; the CHANGELOG is generated by
semantic-release. `docs/platform-push-testing.md` and `docs/scoring.md` updated where s2/s3 say.
The platform's decision queue rows 17 and 19 flip to SHIPPED, and rows 2, 3, 12 to "resolved
upstream (#458, 81322b0)", in the platform pin-bump PR that follows the release.

## Shipped

- `c3e3fba` - declare the checkout safe for git per invocation and log git failures.
- `6a29251` - stop the safedir logrus leak and log "not a git repository" at Debug, other
  failures at Warn.
- `6db7d07` - report an enabled but unconfigured `RequiresConfig` control as `not_evaluable`
  (`config_required`) instead of a vacuous pass.
- `9653a9f` - correct the #459 score claim, recurse nested config blocks in `IsUnconfigured`,
  and mark GitHub unconfigured controls before report assembly.
- `8c40f16` - decode `dismissed_issues` from the platform context, add `identity.PlatformHash`,
  and mark matching findings `Dismissed`.
- `0ee25ac` - mirror the push-side raw-code fallback in the dismissed control key.
- `4875154` - exclude dismissed findings from the score, push the `dismissed` marker, and show
  it in the terminal renderer.
- `0f650cc` - stamp per-policy findings before dismissed matching, add the CSV/OCSF dismissed
  markers.

Two follow-ups are open, not in this repo:

1. **Platform fix for `dismissed_issues.recipe_version`.** The field is served from the
   platform's `hash_version` today; the CLI matches served entries on the recipe version per the
   contract (`identity.RecipeVersion`), so the platform side needs to serve the recipe version,
   not the hash version, for the match to hold as the two evolve independently.
2. **Whether a policy with no evaluable control should have its score withheld.** Open on the
   platform's decision queue (also noted in `docs/scoring.md`): today such a policy can still
   read 100 while every one of its controls is `not_evaluable`.
