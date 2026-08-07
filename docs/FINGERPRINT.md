# Finding fingerprint

Every finding carries a `fingerprint`: a short, stable identifier for that one
finding. It answers "is this the same problem as last run, a new one, or is it
gone", which the control name alone cannot tell you.

The two identifiers serve different questions:

| Identifier | Answers |
| --- | --- |
| `controlName` + `status` | How is this check doing on this run? |
| `fingerprint` | Is this particular finding still there? |

## One recipe, two consumers

The valuable part is not the hash, it is the **selection**: which fields
identify one finding instance across runs. Plumber hashes that selection into
the short `fingerprint` its export formats carry. A consumer grouping findings
into long-lived issues needs the same selection, but as data it can store and
query rather than an opaque hash.

Both read it from one place, the public package
[`finding/identity`](../finding/identity), so they cannot drift:

| API | Returns |
| --- | --- |
| `identity.Of(f)` | the identity **field set** as data (`Fields`, with `Pairs()` for the ordered key/value pairs) |
| `identity.Fingerprint(f)` | the short hash of exactly what `Of` selected |
| `identity.SubjectKeys()` | the subject-key priority list below |
| `identity.RecipeVersion` | the version of the selection |
| `identity.FromMap(m)` | a finding read back from Plumber's serialized JSON, when that JSON is a whole finding rather than an exported issue entry (see below) |

The two sides never have to agree on a hash, only on the selection.

### The recipe version

`identity.RecipeVersion` is currently **2**. Store it next to anything you key
off the selection.

It tracks identity **outcomes**, not just the code in the package, so it moves
in two cases:

| Change | Example |
| --- | --- |
| The algorithm changes | a new subject key, a reordering of the priority list, a field entering or leaving the identity |
| A control changes what it emits | a rule starts or stops emitting a subject key, moving its findings between prose identity and structured identity |

The second case is the one that hides: nothing in `finding/identity` changes,
so its tests stay green while real fingerprints move. The per-control pins in
`policies/rules_test.go` are what fire there, and a failure in one of them is
the prompt to bump.

**Treat a bump as a breaking change, made deliberately.** A re-keyed finding
reads downstream as the old issue disappearing and a new one appearing in its
place. A consumer that stores the field set can see what moved; a consumer
holding only the hash (SARIF, OCSF, CSV) cannot, and this constant is its only
signal.

| Version | What changed |
| --- | --- |
| 1 | The recipe as first shipped. |
| 2 | Eleven finding blocks that had no structured key, or that smuggled their subject through the `job` field, now name what they are about: ISSUE-401 (`hardcodedJob`), ISSUE-402 GitLab / ISSUE-403 / ISSUE-404 (`includePath`), ISSUE-405 / ISSUE-406 (`templatePath`), ISSUE-408 / ISSUE-409 (`componentPath`), ISSUE-417 (`requiredAction`), and ISSUE-501 / ISSUE-505 keep `branchName` while dropping `job`. Ten of the eleven also dropped `job`; ISSUE-401's `job` is a real job name and was kept. The algorithm is unchanged; their fingerprints are not. |

The SARIF `partialFingerprints["plumber/v1"]` key is the name of that SARIF
entry, not the recipe version. It stays at `v1` across bumps, because renaming
it would make Code Scanning treat every alert as new, which is the opposite of
what the entry is for.

## How it is computed

```
fingerprint = sha256( code \n file \n job \n subject [\n step] )  -> hex, first 16 chars
```

The `step` segment is appended only when the finding has one, so findings
without a step keep the identifier they would have had without it.

### The paths

```
Finding as emitted by the rule
  code, message, job, file, line
  + structured payload: uses, branchName, tag, variableName, ...
    |
    v
[1] does it have a code?
    |
    +-- no  --------------------------------->  no fingerprint
    |
   yes
    |
    v
[2] resolve the step name                            (GitHub only)
    match the finding's line to the job's actions,
    take that step's `name:`
    the line is used to LOOK UP only, it is never hashed
    |
    v
[3] pick the subject
    |
    +-- carries one of: uses, branchName, includePath, templatePath,
    |   componentPath, requiredAction, image, serviceImage, link, tag,
    |   variableName, hardcodedJob, scriptLine, detail?
    |
    +-- yes -->  subject = "key=value"     first match only, rest ignored
    |                                      survives a message rewording
    |
    +-- no  -->  subject = message         fallback, tied to the wording
    |
    v
[4] hash
    id = code \n file \n job \n subject
    if a step name was found:  id = id \n step
    fingerprint = sha256(id) as hex, first 16 chars
```

### Inputs

| Input | In the hash | Why |
| --- | --- | --- |
| `code` | yes | The issue identity (`ISSUE-701`) |
| `file` | yes | Where the finding lives, stable across edits |
| `job` | yes | The CI job the finding sits in, empty when the finding is not about a job (see below) |
| subject | yes | What the rule flagged (see below) |
| `step` | yes, when present | Separates two steps in one job using the same action |
| `line` | no | Moves whenever unrelated code above the finding is edited |
| `url` | no | Derived from the line, so it inherits the drift |
| `advisories` | no | Grows as new CVEs are published |
| `latestVersion` | no | Moves whenever upstream cuts a release |
| `metadata` | no | Refetched from the API on every run |
| `reasons`, `status` | no | Track current settings rather than identity |

### The job segment

`job` is the name of a CI job. It is empty when the finding is not about a job:
a branch, an include, a required template, component or action. Those findings
identify on their subject key instead. Before recipe version 2 several rules
put a branch name, an include source or a required path in this field, which
made identity depend on a mislabelled value.

### The subject

The subject is what the finding is *about*, taken from the rule's structured
payload rather than its prose. This is what makes the fingerprint survive a
message rewording.

**Exactly one key becomes the subject.** The list below is a priority order:
the first key the finding carries is used, and every other key is ignored, even
when present. The key name is part of the hashed string, so two different keys
holding the same value cannot collide.

| Priority | Key | Example value |
| --- | --- | --- |
| 1 | `uses` | `grafana/shared-workflows/actions/get-vault-secrets@main` |
| 2 | `branchName` | `main` |
| 3 | `includePath` | `gitlab.example.com/components/sast/sast` |
| 4 | `templatePath` | `templates/go/go` |
| 5 | `componentPath` | `components/sast/sast` |
| 6 | `requiredAction` | `org/sast-scan` |
| 7 | `image` | `golang:1.25` (a Dockerfile `FROM` base) |
| 8 | `serviceImage` | `docker:27-dind` |
| 9 | `link` | `registry.gitlab.com/security-products/secrets:7` |
| 10 | `tag` | `latest` |
| 11 | `variableName` | `CI_DEBUG_TRACE` |
| 12 | `hardcodedJob` | `deploy-prod` |
| 13 | `scriptLine` | `curl -sSL https://example.com/i.sh \| bash` |
| 14 | `detail` | `allow_failure: true masks scan failures` |
| fallback | `message` | used only when the finding carries none of the above |

The list is `identity.SubjectKeys()`; the fallback reports itself as the key
`message`, which is not a member of the list: a rule can only fall back to it,
never select it.

Worked example. This real finding carries both `link` and `tag`:

```json
{ "code": "ISSUE-103",
  "link": "registry.gitlab.com/security-products/secrets:7",
  "tag": "7" }
```

`link` has the higher priority, so the subject is
`link=registry.gitlab.com/security-products/secrets:7` and `tag` contributes
nothing to the hash.

The order is deliberate: the most specific value wins. If `tag` outranked
`link`, every image tagged `latest` in a project would share the subject
`tag=latest` and collide, whereas the full reference keeps `grafana/vale:latest`
and `nginx:latest` apart.

Two consequences of only one key being used:

- A rule that emits several structured fields still has just one of them
  carrying identity. What matters is that its top-priority key is the most
  specific one, not how many keys it emits.
- `detail` holds prose, so a rule that reaches it stays sensitive to that
  wording. It sits last because it only applies when nothing more structural
  exists, and it is still narrower than the full `message`, which also embeds
  the job name.

## Cases

### A rule with a structured subject

The common case. Two different actions in the same job are told apart by their
`uses` value, with no help from the message:

```
ISSUE-701  job=release  uses=grafana/shared-workflows/actions/get-vault-secrets@main
ISSUE-701  job=release  uses=grafana/grafana-github-actions-go/community-release@main
```

Rewording the rule's message later does not change either fingerprint.

### The same action used twice in one job

Here `code`, `file`, `job` and the subject are all identical, so the step name
is the only thing left. Plumber reads it from the step's `name:` in the
workflow:

```
ISSUE-713  check-frontend-test-coverage.yml  step=Delete old coverage comment if not affected
ISSUE-713  check-frontend-test-coverage.yml  step=Post PR comment
```

The step name is recovered by matching the finding's line against the job's
actions during collection. The line is reliable inside a single scan, but only
the resulting name is hashed, so the identifier still survives line drift.

### A rule with no structured subject

A rule that emits only the canonical fields has the message as its subject,
which still discriminates but ties the identifier to the wording:

```
ISSUE-803  job=build  message="job \"build\" runs with overly broad permissions ..."
```

`identity.Of` reports these as `Subject.Key == "message"` and
`SubjectFromMessage == true`, so a consumer can tell prose-based identity apart
from the structured kind and know which findings a copy-edit would re-key.

Giving such a rule a structured payload moves it to the subject path and
changes its fingerprints once. Recipe version 2 changed eleven finding blocks
in total (see the version table above); ten of those also dropped the `job`
field, and nine of the eleven moved off prose identity onto a structured
subject key for the first time: the required-template (ISSUE-405, ISSUE-406)
and required-component (ISSUE-408, ISSUE-409) controls now emit `templatePath`
/ `componentPath`, hardcoded-jobs (ISSUE-401) emits `hardcodedJob`,
forbidden-include-version (ISSUE-404) and required-actions (ISSUE-417) emit
`includePath` / `requiredAction`, and the GitLab include block of ISSUE-402
plus ISSUE-403 emit `includePath`. The remaining two of the eleven,
ISSUE-501 and ISSUE-505, already had `branchName` as their subject before this
version; they only dropped `job`, so they are not part of the nine.

Four collapses were introduced along the way, each dropping one input from
identity on purpose:

- The DNF group index (ISSUE-405 / ISSUE-408 / ISSUE-417), which shifts
  whenever a user reorders `requiredGroups`.
- The forbidden `ref` (ISSUE-404), since the same include drifting from one
  forbidden version to another is the same unresolved problem.
- The ref (ISSUE-403 and the ISSUE-402 GitLab block): identity is now
  `code + file + includePath`. `inc.source` excludes the ref, so the same
  include source pinned at two different refs produced two fingerprints
  before this version and produces one now.
- The overridden-job count (ISSUE-406 and ISSUE-409): identity is now
  `code + templatePath` (or `componentPath`) alone. The prose message
  embedded that count, so two includes matching the same required path with
  different override counts now share one fingerprint.

Each of these is a deliberate narrowing, not a bug: the consumer-facing
consequence is that a single report can contain two issue entries that share
one `fingerprint` and one identical `identity.fields`. Group by the
fingerprint rather than assuming one row per value (see Limits and stability
below).

### A repository-level finding

Controls that evaluate repository settings rather than a file have no `file`,
and their subject comes from the payload:

```
ISSUE-505  file=""  branchName=main
```

Two branches produce different fingerprints because `branchName` differs; this
finding is not about a job, so `job` is empty and contributes nothing to the
hash.

### A finding with no code

Codeless findings get no fingerprint, since there is nothing stable to report
against. None currently exist.

## Where the value appears

One computation, read by every writer, so the same finding carries the same
value in whichever format a consumer reads:

| Format | Location |
| --- | --- |
| JSON (`--output`) | `fingerprint` on each issue entry, next to the `identity` block below |
| CSV (`--csv`) | `fingerprint` column |
| SARIF (`--sarif`) | `partialFingerprints["plumber/v1"]` |
| GitLab SAST (`--glsast`) | an `identifiers[]` entry of type `plumber-fingerprint` |
| OCSF (`--ocsf`) | `fingerprint` on each `unmapped.plumber_findings[]` record |

The GitLab SAST vulnerability `id` is derived from the same line-independent
identity, so GitLab tracks a vulnerability across pipelines instead of treating
an edited file as new findings.

## Limits and stability

- A fingerprint is a **tracking identity, not a primary key**. Two steps in one
  job that reference the same action with no `name:` are indistinguishable and
  share a fingerprint. Group by it; do not assume one row per value.
- Rules on the message fallback stay sensitive to their own wording.
- **A subject key holding a non-string is skipped, not coerced**, and the
  finding drops to the message fallback. A JSON round trip turns a numeric
  `tag: 7` into a float64, so this is reachable from real payload. Both sides
  of the recipe read it the same way, so the CLI and a consumer still agree;
  `subjectFromMessage` is what makes the degradation visible. Coercing would be
  the better answer, but it would re-key every finding it applies to, so it is
  a `RecipeVersion` decision rather than a free fix.
- **A coded finding with no subject key and no message** is identified by
  `code`, `file` and `job` alone, so every such finding of that control in one
  job shares a fingerprint. Deterministic, and the narrowest identity the
  recipe produces.
- `scriptLine` holds the script text, not a line number, so blank lines and
  re-indentation elsewhere in the file do not affect it. One rule
  (`unverified_scripts`, ISSUE-411) stores the line untrimmed, so leading or
  trailing whitespace on that one line is part of its identity;
  `unsafe_variable_expansion` trims first.
- **Changing the recipe changes every value.** Adding an input, reordering the
  subject keys, giving a control a subject key it did not have, or rewording a
  fallback rule's message all shift the identifiers, which a consumer reads as
  findings resolving and reappearing. Treat the recipe as a contract, and bump
  `identity.RecipeVersion` with it. Rewording a fallback rule is the one case
  the version cannot express finding by finding: it re-keys only that rule's
  findings, so weigh it against the churn before doing it.

The selection lives in `finding/identity` (`Of`, `Fingerprint`, `SubjectKeys`,
`RecipeVersion`), a public package, so a consumer outside this module derives
the same identity Plumber does. `internal/engine/opa` reads it through
`Finding.Identity()` and `StampFingerprints`, which stamps the hash once per
run, immediately after findings are finalized.

### Reading the identity from Plumber's output

Every issue entry in the JSON report (`--output`) carries the field set that
was selected for it, so a consumer stores it directly instead of re-deriving
it:

```json
{
  "code": "ISSUE-701",
  "fingerprint": "250f3b7fb7136386",
  "job": "build_debian/build",
  "uses": "element-hq/packages.element.io@master",
  "identity": {
    "version": 2,
    "subjectFromMessage": false,
    "fields": [
      { "key": "code",  "value": "ISSUE-701" },
      { "key": "file",  "value": ".github/workflows/build_debian.yaml" },
      { "key": "job",   "value": "build_debian/build" },
      { "key": "uses",  "value": "element-hq/packages.element.io@master" }
    ]
  }
}
```

Read `fields` and `version` together. When `RecipeVersion` moves, the stored
version is what tells you which findings need re-keying rather than treating
them as gone. `subjectFromMessage` marks the findings whose identity is still
tied to their rule's prose, so a copy-edit re-keys them.

The block exists because the issue entry itself is a trimmed shape: it drops
`message`, `file` and `line` (see `projectFinding` in `cmd/legacy_json.go`), so
those inputs are not recoverable from the entry, and neither format that keeps
them (`--ocsf`) keeps the structured payload. **Reading the `identity` block is
the supported way to derive a finding's identity from Plumber output**; running
`identity.FromMap` over an exported issue entry is not, because the entry is not
a whole finding.

### Deriving the identity in Go

For a consumer holding a complete finding (all canonical fields plus the
structured payload) rather than an exported issue entry:

```go
import "github.com/getplumber/plumber/finding/identity"

fields, ok := identity.Of(identity.FromMap(whole))
if ok {
    pairs := fields.Pairs()    // the selected key/value pairs, in order
    v := fields.Version        // the RecipeVersion that produced them
    _, _ = pairs, v
}
```
