# Labelled corpus for scoring-v4

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
| `note` | why the labels are what they are, in a sentence or two |
| `pending` | the open ruling the case waits on (`QUESTIONS row N`): the labels follow the spec as written and the engine disagrees because the spec itself is contradictory or silent |
| `expect.paths` | paths that must each match at least one assembled path: `entryKind`, `tier` and `job` always, `subjectContains`, `reachKind`, `state`, `sentenceContains` and `sentenceOmits` (fragments the sentence must not carry) when set |
| `expect.maxTier` | the strongest path's tier, or `none` when no path may assemble |
| `expect.noPathAbove` | no path may rank above this tier |
| `expect.letter`, `expect.letterAtLeast` | the scoring-v4 letter, exactly or as a floor |

A pending case that fails is skipped with its ruling and the full path list
printed; a pending case that passes fails, so a marker never outlives its
ruling.

## What a case does not cover

The run is offline: no action metadata (stars, advisories, archived state,
ref kind lookups) and no project settings beyond the recorded facts. A
control that needs those facts behaves as it does when the API is
unreachable.
