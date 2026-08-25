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
| `identity.Declared(code)` | a code's declared identity field names, in hash order (see The declared fields below) |
| `identity.DeclaredCodes()` | every code that has a declaration |
| `identity.SubjectKeys()` | **deprecated**: the retired v3 subject-key priority list; recipe v4 does not consult it |
| `identity.RecipeVersion` | the version of the selection |
| `identity.FromMap(m)` | a finding read back from Plumber's serialized JSON, when that JSON is a whole finding rather than an exported issue entry (see below) |

The two sides never have to agree on a hash, only on the selection.

### The recipe version

`identity.RecipeVersion` is currently **4**. Store it next to anything you key
off the selection.

It tracks identity **outcomes**, not just the code in the package, so it moves
in two cases:

| Change | Example |
| --- | --- |
| A declaration changes | `finding/identity/declarations.go` gains, drops or reorders a field for some code |
| A control stops emitting a field its declaration names | the rule stops setting a `Data` key its declaration still lists, so that pair renders empty (`key=`) where it used to carry a value |

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
| 3 | `file` is normalized to a repository-relative path before hashing. It was previously the collector's absolute path, so the same finding carried a different identity depending on whether it was scanned on a laptop or on a runner. Every finding whose file was recorded absolutely is re-keyed once. |
| 4 | Per-code declarations (`finding/identity/declarations.go`) replace the global subject-key priority list: every registered code now names its own ordered identity fields instead of the recipe picking one field by priority at hash time. The canonical form is uniformly `key=value` per declared field, where v3 rendered `code` / `file` / `job` / `step` bare and only the subject as `key=value`; every fingerprint value changed at this bump, even for the codes whose selected fields did not change. No registered code keys on its prose: the 29 GitHub controls that measured onto `message` were moved onto the subject their rule emits (`uses`, `variableName`, `condition`, `ecosystem`) or onto canonical coordinates alone (`{file, job}`, `{file}`, or the `{}` per-repository singleton) where the finding is inherently one per job, per file, or per repository. The `message` fallback remains only as the backstop for an undeclared code, which the parity test makes unreachable. |

The SARIF `partialFingerprints["plumber/v1"]` key is the name of that SARIF
entry, not the recipe version. It stays at `v1` across bumps, because renaming
it would make Code Scanning treat every alert as new, which is the opposite of
what the entry is for.

## How it is computed

```
fingerprint = sha256( code \n key1=value1 \n key2=value2 \n ... )  -> hex, first 16 chars
```

`key1=value1, key2=value2, ...` are the declared fields of the finding's code
(`finding/identity/declarations.go`), in declared order, each rendered as
`key=value` even when the value is empty (`key=`). There is no conditional
segment: a declared field always contributes a pair, present or not, so two
findings of the same code either agree on every pair or differ on at least
one.

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
    only matters if the code declares "step" (see [3])
    |
    v
[3] look up the declaration
    decl = declarations[code]                (finding/identity/declarations.go)
    for each name in decl, in order:
      "file", "job", "message"  -->  read the finding's canonical field
      anything else              -->  read finding.Data[name]
      render "name=value"                    (absent or non-string value -> "name=")
    |
    v
[4] hash
    id = code \n pair_1 \n pair_2 \n ... \n pair_n     (declared order)
    fingerprint = sha256(id) as hex, first 16 chars
```

### Inputs

| Input | In the hash | Why |
| --- | --- | --- |
| `code` | always | The issue identity (`ISSUE-701`); every declaration hashes on it, unlabeled |
| `file` | when declared | Reserved name, reads the canonical field; where the finding lives, stable across edits |
| `job` | when declared | Reserved name, reads the canonical field; the CI job the finding sits in, empty when the finding is not about a job (see below) |
| `message` | backstop only | Reserved name, reads the canonical field; the identity of an **undeclared** code, unreachable while the parity test is green. No registered code declares it (see The message fallback below) |
| any other declared name | when declared | Read from the rule's structured `Data` payload: `uses`, `step`, `branchName`, `variableName`, `condition`, `ecosystem`, and so on (see The declared fields below) |
| `line` | no | Moves whenever unrelated code above the finding is edited |
| `url` | no | Derived from the line, so it inherits the drift |
| `advisories` | no | Grows as new CVEs are published |
| `latestVersion` | no | Moves whenever upstream cuts a release |
| `metadata` | no | Refetched from the API on every run |
| `reasons`, `status` | no | Track current settings rather than identity |

### The job segment

`job` is a reserved declared name: a code whose declaration names it reads
the finding's canonical `Job` field rather than the `Data` payload bag. Most
codes declare it, but nothing in the mechanism requires it: the repository-
and file-level GitHub checks whose finding is not about a job leave it out
(`{file}` for ISSUE-418 / ISSUE-601, `{file, ecosystem}` for the dependabot
checks, the `{}` singleton for ISSUE-903 / ISSUE-904 / ISSUE-905), and a code
whose declaration does not name `job` does not hash on it at all.

For a code that does declare it, `job` is empty when the finding is not about
a job: a branch, an include, a required template, component or action. An
empty declared value still renders as the pair `job=` (an empty value renders
`key=`, per the formula above): it is present in the hash, it just does not
distinguish one such finding from another. Before recipe version 2 several
rules put a branch name, an include source or a required path in this field,
which made identity depend on a mislabelled value; those controls now declare
a proper field for it instead.

### The declared fields

Identity is no longer picked at hash time from a global list. Each registered
code declares its identity fields once, as an ordered list, in
[`finding/identity/declarations.go`](../finding/identity/declarations.go):

```go
var declarations = map[string][]string{
    "ISSUE-102": {"file", "job", "link"},
    "ISSUE-701": {"file", "job", "uses", "step"},
    // one entry per registered code
}
```

`identity.Of` looks up the finding's code in this table and renders exactly
those fields, in that order. Three names are reserved and read the finding's
canonical fields: `file`, `job` and `message`. Every other name (`uses`,
`branchName`, `step`, `variableName`, `condition`, `ecosystem`, and so on)
reads the rule's structured `Data` payload instead.

There is no priority search and no single-subject selection anymore. v3 kept
one global list and used the first key a finding happened to carry, discarding
every other key the finding carried, even when present. v4 has no list to
search: only the one code's declaration, and every field it names contributes
a pair, not just the first one found.

Worked example. ISSUE-102 declares `{file, job, link}`, so the separate `tag`
data key is never a candidate for its identity, even on a finding that carries
one:

```json
{ "code": "ISSUE-102", "job": "scan",
  "link": "registry.gitlab.com/security-products/secrets:7",
  "tag": "7" }
```

hashes on `link=registry.gitlab.com/security-products/secrets:7`; `tag`
contributes nothing, not because it lost a priority contest, but because
ISSUE-102's declaration does not name it. A code that needed both would
declare `{"file", "job", "link", "tag"}` and hash on both pairs.

An **empty declaration** (`{}`) is valid and means the code is a per-repository
singleton: identity is the code alone, so every finding of that code in one
repository collapses onto one fingerprint (see Limits and stability below).
Three codes declare it, the repository-level GitHub checks whose finding is
"this repository is missing X" and fires at most once per scan: ISSUE-903 (no
dependency updater), ISSUE-904 (no SAST scanner) and ISSUE-905 (no
`SECURITY.md`). Their `file` would otherwise be an arbitrary first workflow,
which reorders as workflows are added or removed, so the code alone is the
stable identity.

Look up a code's declaration with `identity.Declared(code)`; list every
declared code with `identity.DeclaredCodes()`.

#### The message fallback

`message` is a reserved declarable name, but **no registered code declares
it**. It exists only as the backstop `identity.Of` falls to for a code with no
declaration at all: that finding hashes on `code` + `message` and is reported
with `SubjectFromMessage == true`. The parity test
(`finding/identity/parity_test.go`) requires every registered code to have a
declaration, so the backstop is unreachable in production; it is a defensive
path, not an identity anything ships on.

Earlier in recipe v4, 29 GitHub controls keyed on `message` as a placeholder
while their structured subject was settled. They no longer do. Each was moved
onto the subject its rule already computes, or onto canonical coordinates
where the finding has no sub-finding subject:

| Now keyed on | Codes |
| --- | --- |
| `uses` (the reusable-workflow / action ref) | ISSUE-302, ISSUE-306 |
| `variableName` (the bound env var) | ISSUE-209 |
| `condition` (the `if:` expression) | ISSUE-210, ISSUE-211, ISSUE-212 |
| `ecosystem` (the dependabot ecosystem) | ISSUE-901, ISSUE-902 |
| `{file, job}` (one finding per job) | ISSUE-207, ISSUE-208, ISSUE-213, ISSUE-214, ISSUE-215, ISSUE-303, ISSUE-305, ISSUE-308, ISSUE-309, ISSUE-419, ISSUE-420, ISSUE-704, ISSUE-712, ISSUE-801, ISSUE-802, ISSUE-803 |
| `{file}` (one finding per workflow file) | ISSUE-418, ISSUE-601 |
| `{}` (one finding per repository) | ISSUE-903, ISSUE-904, ISSUE-905 |

Rewording any rule's prose no longer re-keys a registered finding.

## Cases

### A rule with a structured subject

The common case. ISSUE-701 declares `{file, job, uses, step}`, so two
different actions in the same job are told apart by their `uses` value, with
no help from the message:

```
ISSUE-701  job=release  uses=grafana/shared-workflows/actions/get-vault-secrets@main
ISSUE-701  job=release  uses=grafana/grafana-github-actions-go/community-release@main
```

(`file=` and `step=` also ride along in the real hash; both are identical
between these two findings, so they are elided above.) Rewording the rule's
message later does not change either fingerprint: ISSUE-701's declaration
does not name `message`.

### The same action used twice in one job

Here `code`, `file`, `job` and `uses` are all identical, so the step name is
the only declared field left to tell the two findings apart. ISSUE-713
declares a trailing `step`; Plumber reads its value from the step's `name:`
in the workflow:

```
ISSUE-713  file=check-frontend-test-coverage.yml  step=Delete old coverage comment if not affected
ISSUE-713  file=check-frontend-test-coverage.yml  step=Post PR comment
```

(`job=` and `uses=` are identical between the two and elided above.) The step
name is recovered by matching the finding's line against the job's actions
during collection. The line is reliable inside a single scan, but only the
resulting name is hashed, so the identifier still survives line drift.

### A rule identified by its coordinates alone

Some controls have no sub-finding subject: the finding is about the whole job
and fires at most once per job, so there is nothing to point to beyond the job
itself. These declare just `{file, job}`, and the rule's prose is not part of
the identity. ISSUE-803 (excessive workflow permissions) is one:

```
ISSUE-803  file=.github/workflows/ci.yml  job=build
```

The same job cannot produce two ISSUE-803 findings, so `{file, job}` is a
complete identity; two `write-all` jobs in different workflows differ on
`file`. `identity.Of` reports `SubjectFromMessage == false`, and rewording the
rule's message does not move the fingerprint. Coarser variants exist for
findings that are one per file (`{file}`: ISSUE-418, ISSUE-601) or one per
repository (the `{}` singleton: ISSUE-903, ISSUE-904, ISSUE-905).

Moving a rule from prose onto a structured payload changes its declaration and
re-keys its findings once. Recipe version 2 did this for eleven finding blocks
under the selection mechanism of that time
(see the version table above); ten of those also dropped the `job` field, and
nine of the eleven moved off prose identity onto a structured key for the
first time: the required-template (ISSUE-405, ISSUE-406) and
required-component (ISSUE-408, ISSUE-409) controls now emit `templatePath` /
`componentPath`, hardcoded-jobs (ISSUE-401) emits `hardcodedJob`,
forbidden-include-version (ISSUE-404) and required-actions (ISSUE-417) emit
`includePath` / `requiredAction`, and the GitLab include block of ISSUE-402
plus ISSUE-403 emit `includePath`. The remaining two of the eleven,
ISSUE-501 and ISSUE-505, already had `branchName` as their subject before this
version; they only dropped `job`, so they are not part of the nine. Every one
of these keys is still what its code declares under v4.

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
and their identity comes from the payload instead. ISSUE-505 declares
`{file, job, branchName}`:

```
ISSUE-505  file=  job=  branchName=main
```

Two branches produce different fingerprints because `branchName` differs;
this finding is about neither a file nor a job, so `file` and `job` both
render as their constant empty pair and neither distinguishes one such
finding from another.

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
- **Key on (project, fingerprint), never the fingerprint alone.** A code with
  an empty declaration, or one whose declared fields all render empty for a
  given finding, is a per-project singleton (see The declared fields above):
  its fingerprint is identical across every project that produces one. A
  consumer storing fingerprints from more than one project must scope by
  project too, or two unrelated projects' findings of the same singleton code
  collide.
- **No registered rule keys on its prose.** `message` is reserved but declared
  by no code, so rewording a rule cannot re-key a registered finding; prose
  identity survives only in the backstop for an undeclared code, which the
  parity test makes unreachable (see The message fallback above).
- **A rule keys on a stable coordinate, not a renameable or mutable label.**
  ISSUE-502 (a merge-request approval rule requiring too few approvals) keys on
  the approval rule's GitLab **ID** (`approvalRuleId`), not its user-facing
  name: renaming the rule leaves the fingerprint unchanged, and only deleting
  and recreating it (a new ID) re-keys it. This corrects the legacy platform,
  which keyed the same control on the renameable rule name. The container-image
  controls follow the same discipline — ISSUE-101/103 key on the tagless image
  repository (`imageRepo`), not the mutable tag — so a routine tag or name
  change never re-keys a finding. ISSUE-504, a per-project singleton, keys on
  `code` alone (the platform's identity was likewise empty).
- **A declared field holding a non-string is skipped, not coerced**, and
  renders as an empty pair, the same as an absent key. A JSON round trip turns
  a numeric `tag: 7` into a float64, so this is reachable from real payload.
  Both sides of the recipe read it the same way, so the CLI and a consumer
  still agree. Coercing would be the better answer, but it would re-key every
  finding it applies to, so it is a `RecipeVersion` decision rather than a
  free fix.
- **A coded finding whose declared fields all render empty** is identified by
  `code` plus whichever reserved fields its declaration names (typically
  `file` and `job`), so every such finding of that control in one job shares
  a fingerprint. Deterministic, and the narrowest identity the recipe
  produces.
- `scriptLine` holds the script text, not a line number, so blank lines and
  re-indentation elsewhere in the file do not affect it. One rule
  (`unverified_scripts`, ISSUE-411) stores the line untrimmed, so leading or
  trailing whitespace on that one line is part of its identity;
  `unsafe_variable_expansion` trims first.
- **Changing the recipe changes every value.** Adding a field to a code's
  declaration, reordering one, or dropping a field a control stopped emitting
  all shift the identifiers, which a consumer reads as findings resolving and
  reappearing. Treat each declaration as a contract, and bump
  `identity.RecipeVersion` when one changes.

The selection lives in `finding/identity` (`Of`, `Fingerprint`, `Declared`,
`DeclaredCodes`, `RecipeVersion`, and the deprecated `SubjectKeys`), a public
package, so a consumer outside this module derives the same identity Plumber
does. `internal/engine/opa` reads it through `Finding.Identity()` and
`StampFingerprints`, which stamps the hash once per run, immediately after
findings are finalized.

### Reading the identity from Plumber's output

Every issue entry in the JSON report (`--output`) carries the field set that
was selected for it, so a consumer stores it directly instead of re-deriving
it:

```json
{
  "code": "ISSUE-701",
  "fingerprint": "93da63ca890b307b",
  "job": "build_debian/build",
  "uses": "element-hq/packages.element.io@master",
  "identity": {
    "version": 4,
    "subjectFromMessage": false,
    "fields": [
      { "key": "code",  "value": "ISSUE-701" },
      { "key": "file",  "value": ".github/workflows/build_debian.yaml" },
      { "key": "job",   "value": "build_debian/build" },
      { "key": "uses",  "value": "element-hq/packages.element.io@master" },
      { "key": "step",  "value": "" }
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
