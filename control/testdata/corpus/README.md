# Labelled corpus for the contextual score

Each directory is one case of the precision gate (`TestCorpus` in
`control/corpus_test.go`). The labels are written by hand from the
contextual score specification, never copied from the tool's output: the
point of the corpus is to catch the engine disagreeing with the model it
implements.

## Layout

```
<case>/
  github/*.yml        workflow files as captured, read by the GitHub collector
  gitlab/*.yml        or one merged GitLab CI configuration (includes inlined,
                      extends resolved, as GitLab's lint endpoint returns it)
  plumber.yaml        optional: the repository's own .plumber.yaml; the
                      shipped default configuration is used otherwise
  expected.json       provenance, recorded facts and labels
```

Captured files are kept verbatim, third-party ones and this repository's
own alike (`plumber-own-ci` captures our workflows and `.plumber.yaml`),
including their comments. They may carry characters the repository's own
text never uses, em dashes among them, by design: a sweep must not "fix"
a fixture.

## expected.json

| Field | Meaning |
|---|---|
| `source` | the repository URL, or `reconstruction of <incident>` when the original files cannot be fetched |
| `commit` | the 40-hex commit the files were captured at (empty for a reconstruction) |
| `captured` | the capture date |
| `group` | `incident`, `clean` or `own` (spec section 7) |
| `visibility`, `defaultBranch`, `branches`, `settingsVariables` | the facts the CLI would otherwise fetch from the provider; `settingsVariables` absent means "not known" |
| `environments`, `environmentsKnown` | the deployment environments and their protection rules (`requiredReviewers`, `reviewers`, `preventSelfReview`, `waitTimer`, `branchPolicy`), as the environments lane maps the API answer; `environmentsKnown` false or absent means the lane could not read them |
| `workflowStates`, `workflowStatesKnown` | each workflow's state keyed by its `.github/workflows/<file>` path, as the workflows listing answers it; the harness derives `actionsDisabled` from it the way a run does |
| `defaultTokenWrite`, `defaultTokenSource` | the repository's default `GITHUB_TOKEN` write (`true`, `false`) and how it was established (`log`, `effect`); absent means unknown |
| `actionMetadata` | what the metadata lane would answer for an action, keyed by the step's `uses` text as written (`ir.ActionMetadata`: `repoArchived`, `refKind`, `redirectedOwner`, `advisories`, `advisorySeverities`, `mutableRemoteExec` with its `downloadGuard` or `downloadVerified`, ...); set on every step using it |
| `note` | why the labels are what they are, in a sentence or two |
| `pending` | the open question the case waits on: the labels follow the spec as written and the engine disagrees because the spec itself is contradictory or silent |
| `expect.paths` | paths that must each match at least one assembled path: `entryKind` and `tier` always, `job` (the path's first job), `subjectContains`, `reachKind`, `state`, `actor` (who the entry says can make the job run: `outsider`, `maintainer_approved`, `same_repo`, `insider`, `unknown`), `sentenceContains` and `sentenceOmits` (fragments the sentence must not carry) when set |
| `expect.ceilings` | bounds per entry subject: no assembled path whose subject contains `subjectContains` (and, when set, of entry kind `entryKind` and first job `job`) may rank above `tier`; `tier` `none` admits no path at all |
| `expect.maxTier` | the strongest path's tier, or `none` when no path may assemble |
| `expect.noPathAbove` | no path may rank above this tier |
| `expect.noPathSubjects` | entry subjects no path may start from (a fragment the subject contains) |
| `expect.letter`, `expect.letterAtLeast` | the contextual score's letter, exactly or as a floor |

A pending case that fails is skipped with the reason and the full path list
printed; a pending case that passes fails, so a marker never outlives the
question it names.

One expectation can be pending on its own: an entry of `expect.paths` or
`expect.ceilings` with a `pending` sentence is checked alone, a miss is
logged with the sentence, and a match fails the case (the marker must go);
every other label of the case is checked as usual. Prefer it to the
case-level `pending`, which skips the whole case and so hides whatever else
the case would have caught.

Every GitHub case goes through the two passes a real run makes once its
provider lanes are read: `ir.MarkInert` (jobs that cannot run: a disabled
workflow, a retired runner label, no trigger, a reusable workflow nobody
calls, a condition pinned to another repository) and `ir.ClassifyGates`
(who can make each privileged job run), whether or not the case records a
provider fact.

## The Radar cases of 2026-10-15

The `radar-2026-10-15-<org>-<repo>` cases record the attack paths the
Radar reported on 2026-10-14 for sixteen GitHub organisations, as they were
challenged one organisation at a time on 2026-10-15: each path a challenger
judged false or overstated at Critical or High, each path judged real at
Critical, and the false negatives found while judging. One case per
repository: the workflows of `.github/workflows` at the last commit of the
default branch before 2026-10-15 (`commit`), the environments as the
challenge saved them (fetched once otherwise), the workflow states, and the
default token only where the challenge established it from a run log or a
bot-authored write. `note` names each judged path's verdict and its cause.
The labels follow the verdict: a path judged real keeps its tier
(`expect.paths`), a path judged overstated is bounded by the tier the
challenge argued (`expect.ceilings`, or an exact path when the challenge
named one), a path judged false is bounded at Medium (no false path at
Critical or High), or admits no path at all when the job cannot run or no
outsider reaches it. A verdict corrected after reading the captured
workflows says so in its note. A `pending` sentence, on the expectation it
is about, names either a defect of the engine (the recorded facts are
there, the engine still assembles what the verdict proved wrong) or a point
where the spec rules against the verdict; the sentence says which.

To add one: take the repository's paths from the Radar inventory, write the
verdict and its label, capture the workflows at the scanned commit and the
API answers the CLI's lanes read (environments, workflow states, the token
default when it can be established), write `expected.json` from the
verdict before running the case, then run `go test ./control -run
'TestCorpus/radar'` and either fix a label the evidence does not support
(saying so in `note`) or mark the expectation that misses `pending` with
the reason.

## What a case does not cover

The run is offline: no action metadata (stars, advisories, archived state,
ref kind lookups) beyond what `actionMetadata` records, and no project
settings beyond the recorded facts. A control that needs those facts
behaves as it does when the API is unreachable. Local composite actions
(`./.github/actions/...`) are not captured.
