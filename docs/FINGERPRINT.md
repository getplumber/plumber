# Finding fingerprint

Every finding carries a `fingerprint`: a short, stable identifier for that one
finding. It answers "is this the same problem as last run, a new one, or is it
gone", which the control name alone cannot tell you.

The two identifiers serve different questions:

| Identifier | Answers |
| --- | --- |
| `controlName` + `status` | How is this check doing on this run? |
| `fingerprint` | Is this particular finding still there? |

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
    +-- carries one of: uses, branchName, componentName, image,
    |   serviceImage, link, tag, variableName, scriptLine, detail?
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
| `job` | yes | The job, branch, or include scope |
| subject | yes | What the rule flagged (see below) |
| `step` | yes, when present | Separates two steps in one job using the same action |
| `line` | no | Moves whenever unrelated code above the finding is edited |
| `url` | no | Derived from the line, so it inherits the drift |
| `advisories` | no | Grows as new CVEs are published |
| `latestVersion` | no | Moves whenever upstream cuts a release |
| `metadata` | no | Refetched from the API on every run |
| `reasons`, `status` | no | Track current settings rather than identity |

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
| 3 | `componentName` | `secret-detection` |
| 4 | `image` | `golang:1.25` (a Dockerfile `FROM` base) |
| 5 | `serviceImage` | `docker:27-dind` |
| 6 | `link` | `registry.gitlab.com/security-products/secrets:7` |
| 7 | `tag` | `latest` |
| 8 | `variableName` | `CI_DEBUG_TRACE` |
| 9 | `scriptLine` | `curl -sSL https://example.com/i.sh \| bash` |
| 10 | `detail` | `allow_failure: true masks scan failures` |
| fallback | `message` | used only when the finding carries none of the above |

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

Roughly a third of the rules emit only the canonical fields. Their subject is
the message, which still discriminates but ties the identifier to the wording:

```
ISSUE-401  job=leak-repro-214  message="job \"leak-repro-214\" is hardcoded ..."
```

Giving such a rule a structured payload moves it to the subject path and
changes its fingerprints once.

### A repository-level finding

Controls that evaluate repository settings rather than a file have no `file`,
and their subject comes from the payload:

```
ISSUE-505  file=""  job=main  branchName=main
```

Two branches produce different fingerprints because `branchName` and `job`
differ.

### A finding with no code

Codeless findings get no fingerprint, since there is nothing stable to report
against. None currently exist.

## Where the value appears

One computation, read by every writer, so the same finding carries the same
value in whichever format a consumer reads:

| Format | Location |
| --- | --- |
| JSON (`--output`) | `fingerprint` on each issue entry |
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
- `scriptLine` holds the script text, not a line number, so blank lines and
  re-indentation elsewhere in the file do not affect it. One rule
  (`unverified_scripts`, ISSUE-411) stores the line untrimmed, so leading or
  trailing whitespace on that one line is part of its identity;
  `unsafe_variable_expansion` trims first.
- **Changing the recipe changes every value.** Adding an input, reordering the
  subject keys, or rewording a fallback rule's message all shift the
  identifiers, which a consumer reads as findings resolving and reappearing.
  Treat the recipe as a contract.

The computation lives in `internal/engine/opa/engine.go`
(`computeFingerprint`, `fingerprintSubject`, `StampFingerprints`) and is
stamped once per run, immediately after findings are finalized.
