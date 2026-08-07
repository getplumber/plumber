# Design: `Finding.Job` means a job

Date: 2026-08-07
Status: approved, not yet implemented
Context: getplumber/plumber #403, PR #404

## Problem

`Finding.Job` is a first-class input to the finding-identity recipe. The hashed
string is:

```
sha256( code \n file \n job \n subject [\n step] )[:16]
```

Ten finding blocks put something that is not a job into that field: a branch
name, an include source, or a required template/component path. The value is
therefore load-bearing for identity while being mislabelled everywhere it
surfaces.

The codebase already knows this. `cmd/csv.go` names its column `context` rather
than `job`, with the comment "some rules put a branch / include path / file
there instead, so the header avoids the false claim `job` would make when the
value isn't a job". `cmd/legacy_json.go` passes `""` as the output key for the
branch and two include blocks, hiding the value in JSON while the hash keeps
using it.

The consequence that forces the issue: as long as identity leans on the
overloaded `job`, the field cannot be corrected without re-keying findings a
second time.

## Evidence

An audit of all 77 finding blocks (66 distinct codes) in `policies/*.rego`,
grouped by the expression assigned to `"job"`:

| Expression | Blocks | Is it a job? |
| --- | --- | --- |
| `job.name`, `sig.job`, `jobname` | 57 | yes |
| key absent | 10 | not applicable, repository-level |
| `required` | 5 | no, a required template/component path |
| `inc.source` | 3 | no, an include source |
| `branch.name` | 2 | no, a branch |

The unit of change is the finding block, not the control code: ISSUE-402 has two
blocks, and only its GitLab include block is affected. Its GitHub step-level
block uses `job.name` and is correct.

Consumers of `Finding.Job`:

| Consumer | Use |
| --- | --- |
| identity recipe | third hashed segment, always |
| `cmd/legacy_json.go` | per-block output key, `"job"` or `""` to hide |
| `cmd/legacy_json.go:541` | **load-bearing**: builds `nonCompliantBranches` by keying on `f.Job` |
| `cmd/csv.go` | the `context` column |
| `cmd/ocsf.go` | `rec["job"]`, already guarded by `if f.Job != ""` |
| `internal/engine/opa` `enrichFindingsWithJobLocation` | looks up `byName[f.Job]` to resolve file/line/step |
| `cmd/sarif.go` `sarifCodeSpanJob` | re-quotes the job name inside the message |
| sorting | `cmd/legacy_json.go:230`, `cmd/render_details.go:432` |

`cmd/glsast.go` looks like a second identity (`code|file|job|message`) but is
derived from `Fingerprint`, falling back to that string only for unstamped
findings. It is not a divergent path.

## Decisions

1. **`Finding.Job` is the name of a CI job, empty when the finding is not about
   a job.** Rejected alternative: rename the field to `context` and let it stay
   polymorphic. The value is duplicated in the subject key, so `context` would
   preserve a field carrying no unique information, and the platform would get a
   polymorphic key instead of a typed one.
2. **All ten blocks are fixed in this change**, not only the five whose value is
   currently exposed in JSON. Doing half leaves the field polymorphic and
   re-keys the rest a second time under a later version.
3. **`job` is dropped from outputs, not replaced by a derived display value.**
   Rejected alternative: compute a render-time `context` (job, else the subject
   value) so flat formats keep a pointer. The CSV `context` cell goes empty for
   these rows, which is accepted.
4. **`componentName` leaves the subject-key priority list.** It is emitted by
   ISSUE-402/403 as `object.get(inc, "componentName", "")`, so it is empty for
   any include that is not a component, and it duplicates a segment of the
   source. Once those blocks emit `includePath` it can never win the subject.
   It stays in the payload as informational data.
5. **Regression guard is per-control test pins**, not a source scanner or a
   runtime invariant. Each of the ten blocks gets a pin asserting both its
   subject key and that `job` is empty.

## Design

### Per-block changes

"Absent" below means the Rego rule omits the `"job"` key from the finding
object entirely, which yields `Finding.Job == ""` after unmarshalling. No rule
emits `"job": ""`.

| Block | `job` today | after | Subject key | Key status |
| --- | --- | --- | --- | --- |
| ISSUE-501 `branch_unprotected` | `branch.name` | absent | `branchName` | exists |
| ISSUE-505 `branch_non_compliant` | `branch.name` | absent | `branchName` | exists |
| ISSUE-402 GitLab include block | `inc.source` | absent | `includePath` | new |
| ISSUE-403 `includes_outdated` | `inc.source` | absent | `includePath` | new |
| ISSUE-404 `includes_forbidden_version` | `inc.source` | absent | `includePath` | added earlier in PR #404 |
| ISSUE-405 `template_missing` | `required` | absent | `templatePath` | added earlier in PR #404 |
| ISSUE-406 `template_overridden` | `required` | absent | `templatePath` | added earlier in PR #404 |
| ISSUE-408 `component_missing` | `required` | absent | `componentPath` | renamed from `componentName` |
| ISSUE-409 `component_overridden` | `required` | absent | `componentPath` | renamed from `componentName` |
| ISSUE-417 `required_actions` | `required` | absent | `requiredAction` | new, replaces the unlisted `required` |

ISSUE-401 `hardcoded_jobs` is deliberately not in this set: its `job` is a real
job name. Its `hardcodedJob` key remains a duplicate of `job`, whose only
purpose is to keep identity off the prose message.

### Recipe

`finding/identity`'s priority list becomes:

```
uses, branchName, includePath, templatePath, componentPath, requiredAction,
image, serviceImage, link, tag, variableName, hardcodedJob, scriptLine, detail
```

`componentName` is removed. The ordering rule is unchanged: most specific wins,
so a full include source outranks a bare component name.

The selection algorithm does not change. `RecipeVersion` stays at **2**: this
change ships in the same release as the re-key already in PR #404, so the whole
affected set moves exactly once.

### Output changes

- No JSON builder changes are needed. `projectFinding` already guards
  `if f.Job != "" && jobKey != ""`, so the `job` key disappears from those issue
  objects as soon as the rules stop emitting it. Each object keeps its
  structured subject key and its `identity` block, so no information is lost.
  A test pins that the key is gone for one affected block, since the behaviour
  now depends on rule output rather than on the builder's argument.
- `cmd/legacy_json.go:541` reads `f.Data["branchName"]` instead of `f.Job` when
  building `nonCompliantBranches`. Without this, every branch keys on `""` and
  no branch receives the full protection-settings shape.
- `cmd/csv.go`: the `context` column is empty for these rows. Its comment,
  which currently documents the overload, is rewritten to state that `context`
  is a job name or empty.
- `cmd/ocsf.go`: no change. It already omits the key when `Job` is empty.
- `cmd/sarif.go`: no change. `sarifCodeSpanJob` already returns the message
  unchanged when `Job` is empty, so those messages lose the code span around
  the name. Accepted as cosmetic.
- `enrichFindingsWithJobLocation`: no change. The lookup already fails for these
  findings because the value never matches a job name, so emptying it changes
  no behaviour.

### Identity consequences

All ten blocks re-key once. Six of them are already re-keying in PR #404.

ISSUE-402 (GitLab block), ISSUE-403 and ISSUE-417 have no working structured
subject today, so their identity rides entirely on prose. Fixing them removes
the same defect #403 exists to remove; they were missed in the issue's list.

Four deliberate collapses, consistent with the reasoning already documented
for the DNF group index:

- ISSUE-405, ISSUE-408 and ISSUE-417 carry no `file`, so identity becomes
  `code + required path`. Two DNF groups requiring the same path share one
  fingerprint.
- ISSUE-404 loses the ref from identity, which lived only in the prose. The
  same include pinned to two different forbidden refs is one finding.
- ISSUE-403 and the ISSUE-402 GitLab block: identity is now
  `code + file + includePath`. `inc.source` excludes the ref, so the same
  include source pinned at two different refs produced two fingerprints
  before this change and produces one after it.
- ISSUE-406 and ISSUE-409: identity is now `code + templatePath` (or
  `componentPath`) alone. The prose message embedded the overridden-job
  count, so two includes matching the same required path with different
  override counts now share one fingerprint.

Consumer-facing consequence: for any of these four, a single report can
contain two issue entries that share one `fingerprint` and one identical
`identity.fields`.

## Non-goals

- Pruning the `componentName` payload key from ISSUE-402/403, or emitting it
  only for component includes. It is pre-existing output and a separate
  contract decision.
- Any change to the selection algorithm in `finding/identity`.
- Any change to `Finding.Job` for the 57 blocks where it is a genuine job name.

## Testing

- `assertSubjectKey` in `policies/rules_test.go` gains an assertion that `job`
  is empty, and every one of the ten blocks gets a pin pairing its subject key
  with that emptiness. This is the regression guard from decision 5.
- Tests that currently key on `f.Job` for affected controls are switched to the
  structured value: `TestIssue405_TemplateMissing`,
  `TestIssue408_ComponentMissing`, and the ISSUE-501/ISSUE-505 assertions.
- A JSON test that `projectFinding` emits no `job` key for a finding that is not
  about a job. The behaviour now depends on rule payload rather than on the
  builder's argument, so it is pinned rather than assumed.
- Unit tests for the extracted `nonCompliantBranchNames` helper, covering both a
  payload carrying `branchName` and one without it. `cmd` has no test that
  builds the branch block itself, so the helper is the automated guard for the
  load-bearing aggregation; the assembled block shape is checked end to end
  against the real GitLab project, which produces ISSUE-505 findings.
- Golden fingerprint tests in `finding/identity` are untouched: the algorithm
  does not change.
- End-to-end: re-run the old-versus-new comparison over the six GitHub
  repositories and the GitLab instance used earlier in PR #404, confirming that
  only the intended blocks move.

## Risks

- The branch aggregation is the one genuinely load-bearing use of `Job`. If the
  replacement misses, the JSON branch shape silently degrades rather than
  failing loudly, which is why it gets its own test.
- Consumers reading `issues[].job` from the four affected JSON blocks lose that
  key. They can read the structured subject key or the `identity` block in the
  same object.
