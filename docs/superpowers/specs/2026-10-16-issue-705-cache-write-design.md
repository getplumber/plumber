# ISSUE-705 rework: untrusted triggers must not write the cache

Issue: getplumber/plumber#533.

## Why

ISSUE-705 used to flag release or publish jobs that restore a cache whose key
is not scoped to the release ref. Its premise was that GitHub Actions caches
are shared across branches. They are not. GitHub isolates caches by ref: a run
restores caches from its own ref and from the default branch only.

GitHub also restricts cache writes by trigger
([dependency caching](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)):

- Only `push`, `workflow_dispatch`, `repository_dispatch`, `delete`,
  `registry_package`, `page_build` and `schedule` can create or overwrite
  caches in the default branch's scope.
- Any other event that resolves to the default branch (`pull_request_target`,
  `issue_comment`, `workflow_run`, ...) gets read-only cache access by
  default.
- `cache-mode` (`read`, `write`, `write-only`, `none`) can be declared at
  workflow level or job level; the job value wins. Declaring `write` or
  `write-only` on a low-trust trigger
  [bypasses the restriction](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching#bypassing-the-default-untrusted-trigger-cache-restriction)
  and reintroduces cache poisoning: code in that run can write caches every
  default-branch run restores.

The old rule fired on repositories with no path from a pull request to the
release cache, and a maintainer could disprove it with one paragraph of
GitHub's documentation.

## Goals

- ISSUE-705 (High) fires on a job when:
  1. its effective triggers include an event outside the safe set, and
  2. its effective `cache-mode` grants write (`write` or `write-only`).
- Safe set: GitHub's seven trusted triggers, plus `pull_request`,
  `pull_request_review`, `pull_request_review_comment`, `release` and
  `merge_group`. These never resolve to the default branch (the review events
  run on the pull request's merge ref), so they write only to their own ref's
  scope.
- Effective `cache-mode`: the job's own, else the workflow's. A
  `workflow_call` job takes its callers' triggers.
- A workflow or a job can be exempted to accept the risk. An exempted job
  that would have fired is skipped, but it is listed in the output, the same
  way as `containerImageMustNotUseForbiddenTags.exemptImages`.
- The rule is short and easy to explain.

## Non-goals

- Release or publish detection, cache key scoping, and per-action cache
  semantics are all gone. ISSUE-717 (the verify-manually variant) is
  retired.
- Job `if:` narrowing is not applied. `cache-mode` is a static grant, and an
  exemption covers the rare narrowed job.

## Expressions (probed on github.com, 2026-10-16)

| `cache-mode` value | GitHub |
|---|---|
| `read` | accepted, enforced ("cache write denied: token has no writable scopes") |
| `${{ 'write' }}` | accepted; the run saved a cache |
| `${{ github.event_name == 'issue_comment' && 'write' \|\| 'read' }}` | invalid workflow file |
| `${{ vars.X \|\| 'write' }}` | invalid workflow file |
| `${{ inputs.mode \|\| 'write' }}` | invalid workflow file |

Only context-free expressions are accepted, so the value cannot vary per run.
The parser resolves an effective mode as follows:

- A literal is taken as is.
- A context-free expression is `write` when one of its quoted strings is
  `write` or `write-only`. It is `read` when all of its quoted strings are
  `read` or `none`.
- An expression that reads a context makes the file invalid. GitHub never
  runs it, so the effective mode is unknown and the rule stays silent.

## Configuration

The control key is renamed from `releaseWorkflowsMustNotRestoreUntrustedCache`
to `untrustedTriggersMustNotWriteCache`:

```yaml
github:
  controls:
    untrustedTriggersMustNotWriteCache:
      enabled: true
      exemptWorkflows: []   # workflow file-name globs, e.g. triage.yml
      exemptJobs: []        # <workflow>/<job> globs, e.g. triage/label
```

These fields are removed: `publishActions`, `cacheActions`,
`publishScriptPatterns`, `publishScriptExcludePatterns` and `allowedJobs`.

If a config still uses the old key, plumber warns that it is ignored and
points to `plumber config migrate`. The migrate command renames the key and
drops the removed fields, listing each change.

The situation module's publish inventory is no longer read from this config.
It becomes built-in, with the same lists as the shipped default config.

## Attack paths

The ISSUE-705 entry is now the writer job W. The path enters at W and reaches
every live job that restores a cache in the default-branch scope. A path
exists only when another path already enters W, because some attacker code
has to run in the writing run. The path's tier is capped at that path's
ceiling.

Situation's cache facts become aware of `cache-mode`:

- A job saves under a scope only if its mode and trigger allow it.
- A `write-only` or `none` job restores nothing.

## Identity

The ISSUE-705 identity becomes `{file, job}`, and `RecipeVersion` goes from 6
to 7.
