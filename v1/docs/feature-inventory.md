# Feature inventory

Every command, flag, output format and `.plumber.yaml` key of the CLI on `release/v1`, with a
proposed decision for each: keep, merge, deprecate or remove. It answers
[getplumber/monorepo#683](https://github.com/getplumber/monorepo/issues/683).

The decisions are applied as each command is rewritten under `v1/`, in the order of
[project-structure.md](project-structure.md) (rule 2 of [AGENTS.md](../AGENTS.md) forbids editing
`cmd/`). Bugs found on the way are listed at the end; they are fixed on `main`, like any fix
outside `v1/`.

Column meanings:

- Docs: where a user can read about it. "help" means only the `--help` text.
- Rows: the rows of the v1 suite that run it (`test/local` test and row names, or `e2e` for the
  rows of `test/e2e`). `TestHelpFlag` rows are left out, since every command has one.
- Users: the integrations that pass it: the GitHub Action (`action.yml`), the GitLab component
  (`templates/plumber.yml`, through `PLUMBER_ANALYZE_*` variables) and the self-scan workflow
  (`.github/workflows/plumber-action.yml`).

## Commands

| Command | Defined in | Docs | Rows | Decision | Why |
|---|---|---|---|---|---|
| `analyze [TARGET]` | `cmd/analyze_gitlab.go` | README | `TestAnalyze/*`, e2e | keep | The product. |
| `capabilities` | `cmd/capabilities.go` | README | `TestRoot/capabilities` | keep | Parent of `defaults`. |
| `capabilities defaults` | `cmd/capabilities.go` | README, `docs/PBOM.md` | `TestRoot/capabilities-defaults` | keep | Starting point for the `capabilities` key. |
| `catalog` | `cmd/catalog.go` | none | `TestRoot/catalog` | keep, document | The platform and the docs site read its JSON (comment at `cmd/catalog.go:21`). README never names it. |
| `completion <shell>` | cobra | help | `TestCompletion/*` | keep | Built into cobra, costs nothing. |
| `config` | `cmd/config.go` | README | `TestConfig/config` | keep | Parent of the config subcommands. |
| `config view` | `cmd/config.go` | help | `TestConfig/config-view-*` | keep, absorb `resolve` | Shows the effective config. |
| `config resolve` | `cmd/config_resolve.go` | help | `TestConfig/config-resolve*` | merge into `view` | Same loading and marshalling as `view`; it only adds `-o`. `view -o FILE` (no color) covers it. |
| `config diff` | `cmd/config.go` | help | `TestConfig/config-diff*` | keep, fix | Compares raw keys with the default and ignores `extends`, so an overlay shows every missing key as removed. |
| `config generate` | `cmd/config.go` | README | `TestConfig/config-generate*` | keep | Full commented template; `--overlay` writes the minimal starter. |
| `config init` | `cmd/init.go` | README | `TestConfig/config-init-*` | keep | Interactive counterpart of `generate --overlay`. Refuses to run without a TTY or when `CI` is set. |
| `config migrate` | `cmd/config_migrate.go` | `docs/plumber-yaml-v2-migration.md` | `TestConfig/config-migrate*` | keep, align flags | Needed while v1 files exist. Flags differ from its siblings (see below). |
| `config slim` | `cmd/config_slim.go` | help | `TestConfig/config-slim*` | keep | Inverse of `resolve`. |
| `config validate` | `cmd/config.go` | README | `TestConfig/config-validate-*` | keep | |
| `explain [CODE \| -a N]` | `cmd/explain.go`, `cmd/explain_attack.go` | README | `TestExplain/*` | keep | |
| `score-compare` | `cmd/score_compare.go` | `docs/scoring-v4-migration.md` | `TestScoreCompare/*` | remove | Hidden. Its own comment calls it "a Radar operational tool, not a user-facing analyze workflow" (`cmd/score_compare.go:378`). It belongs in an internal tool. |
| `version` | `cmd/version.go` | README | `TestRoot/version*` | keep, add `--version` | `plumber --version` is an unknown flag today (`TestRoot/version-flag-unsupported`); cobra's `Version` field gives it for free. |
| `help` | cobra | help | `TestRoot/help*` | keep | |

### Flags of commands other than `analyze`

| Flag | Commands | Decision | Why |
|---|---|---|---|
| `-v`, `--verbose` (global) | all | keep | |
| `--no-descriptions` | `completion <shell>` | keep | cobra built-in. |
| `-c`, `--config` | `config view/diff/resolve/slim/validate` | keep | |
| `--no-color` | `config view/diff` | keep | |
| `--explain` | `config view` | keep | Prints its lines in random order; the row sorts them (known quirk). |
| `--fail-warnings` | `config validate` | keep | Same meaning as on `analyze`. |
| `-o`, `--output`; `-f`, `--force`; `--overlay` | `config generate/init/resolve/slim` | keep | |
| `--input`, `--output`, `--in-place` | `config migrate` | deprecate `--input`, add `-c/--config` and `-o` | Every other config subcommand reads its file with `-c/--config` and writes with `-o`. |
| `--all`, `--list`, `--json` | `explain` | keep | `--all --json` overlaps `catalog` on issue codes only; `catalog` also carries controls and schemas. |
| `-a`, `--attack`; `--project`; `--provider`; `--run` | `explain` | keep | |
| `--input`, `--output` | `score-compare` | remove | With the command. |

## `analyze` flags

Every `analyze` flag also reads `PLUMBER_ANALYZE_<FLAG>` (the map at `cmd/analyze_gitlab.go:631`).
The GitLab component relies on this and passes nothing on the command line. Keep it.

| Flag | Docs | Rows | Users | Decision | Why |
|---|---|---|---|---|---|
| `--gitlab-url` | help | | component | keep | |
| `--github-url` | help | | Action | keep | GitHub Enterprise Server. |
| `--project` | help | `analyze-*-no-token` | Action, component | keep | |
| `--provider` | help | `analyze-bad-provider` | | keep | Needed when the host doesn't tell. |
| `--branch` | help | e2e | component | keep | |
| `--config` | help | `analyze-missing-config` | Action, component | keep | |
| `--min-points`, `--min-score` | README, `docs/scoring.md` | `analyze-bad-min-*` | Action, component | keep | The score gate. |
| `--threshold` | `docs/scoring.md` (deprecated) | `analyze-bad-threshold` | Action and component pass it when not 100 | remove | Deprecated since the gate moved to the score (2026-07-09). It already prints a warning (`cmd/analyze_gitlab.go:710`). Drop it from the Action and the component first. |
| `--print` | help | | component | keep | |
| `-o`, `--output` | README | e2e | Action, component, self-scan | keep | |
| `--csv` | README, `docs/FINGERPRINT.md` | | | keep | Documented, no integration passes it. |
| `--ocsf` | README, `docs/OCSF.md` | | | keep | Same. |
| `--sarif` | README | | Action (uploaded to Code Scanning), self-scan | keep | |
| `--glsast` | README | | component | keep, warn on GitHub | Written on GitHub too, where nothing reads a GitLab SAST report. |
| `--pbom`, `--pbom-cyclonedx` | README, `docs/PBOM.md` | | Action, component | keep | |
| `--mr-comment` | none | | component | keep, warn on GitHub | GitLab only. On GitHub it is ignored without a word (`provider/github.go:149`). |
| `--badge` | none | | component | keep, warn on GitHub | Same as `--mr-comment`. |
| `--ci-config-path` | help | | component | keep, warn on GitHub | Only the GitLab path reads it. |
| `--score` | `docs/scoring.md`, `docs/PBOM.md` (deprecated) | | component (input documented as a no-op) | remove | Does nothing: the banner is on by default (`cmd/analyze_shared.go:471`). Its help still describes behavior. |
| `--score-point` | help | | Action (`score: true`), component, self-scan | keep | The only live score-display flag once `--score` goes. A rename to `--score-details` could come with the removal of `--score`. |
| `--score-profile` | `docs/scoring.md`, `docs/scoring-v4-migration.md` | `analyze-bad-score-profile` | | keep | `v4` is the default. Drop `v3` once Radar no longer compares the two; until then nothing to do. |
| `--score-push`, `--score-endpoint` | README (through inputs) | | Action, component | keep | |
| `--platform`, `--platform-allow-http` | `docs/platform-push-testing.md` | `analyze-platform-plain-http` | Action, component | keep | |
| `--controls`, `--skip-controls` | help | `analyze-unknown-*`, e2e | Action, component | keep | |
| `--no-controls` | README | `analyze-no-controls-with-controls` | | keep | PBOM-only runs. |
| `--fail-warnings` | README | | Action, component, self-scan | keep | |
| `--resolve-depth N` (new) | none yet | | | add, default 0 | Fetches imported actions, reusable workflows, includes and components down to N levels. Today every run resolves them; the rewrite makes a run static by default ([analyze-flow.md](analyze-flow.md)). |
| `--sanity` (new) | none yet | | | add, default `false` | Reads branch protection, rulesets and project settings. Today every run reads them. The e2e rows 501 and 505 (both providers) and 503, 506 and 601 (GitLab) need it. |

The long help of `analyze` has a hand-written "Optional flags" list next to cobra's own list. It has
drifted: it lacks `--csv`, `--ocsf`, `--sarif`, `--glsast`, `--platform` and
`--platform-allow-http`, and it describes `--badge` and `--mr-comment` differently from the flag
usage. Proposed: delete the hand-written list and keep the examples and exit codes.

## Output formats

| Output | Format | Docs | Users | Decision | Why |
|---|---|---|---|---|---|
| Text report on stdout | | README | everyone | keep | |
| `--output` JSON | no schema version key; `cliVersion` and `plumberScore.profileId` | README, several docs | Action, component, `explain --run` | keep, add a schema version | Consumers can't tell report shapes apart today. |
| v0.2.x per-control blocks in the JSON (`*Result`, `cmd/legacy_json*.go`) | same file as `--output` | none | unknown | deprecate (to confirm) | Spliced into the JSON outside platform mode; the flat `findings` array is deleted to make room (`cmd/analyze_gitlab.go:1197`). Needs an owner to say who still reads them before a date is set. |
| CSV | `cmd/csv.go` | README | | keep | |
| OCSF | OCSF 1.8.0 | `docs/OCSF.md` | | keep | |
| SARIF | 2.1.0 | README | Action | keep | |
| GitLab SAST | schema 15.0.4 | README | component | keep | |
| PBOM | `pbomVersion` 1.0.0 | `docs/PBOM.md` | Action, component | keep | |
| PBOM CycloneDX | CycloneDX 1.5 | `docs/PBOM.md` | Action, component | keep | |
| Run cache (`<user cache>/plumber/runs`) | same bytes as `--output` | `docs/scoring.md` | `explain -a` | keep | Written on every run. |
| MR comment, badge | GitLab API | none | component | keep | |
| Score push | hosted score service | README (through inputs) | Action, component | keep | |
| Platform push | contract `schema_version: 1` | `docs/platform-push-testing.md` | Action, component | keep | |

## `.plumber.yaml` keys

| Key | Docs | Decision | Why |
|---|---|---|---|
| `version` | README, migration doc | keep | |
| `extends: plumber:default` | README, default config comments | keep, document in the migration doc | |
| `gitlab.controls`, `github.controls` | README, `docs/GITLAB_ISSUES.md`, `docs/GITHUB_ISSUES.md` | keep | |
| `<provider>.auth.requireAuth` | none | remove | Parsed (`configuration/plumberconfig.go:303`) and never read. |
| `capabilities` | `docs/PBOM.md`, default config comments | keep | Ignored in platform mode. |
| top-level `controls` (schema v1) | migration doc | remove (turn into an error) | Converted with a warning that already says v1 support will be removed; the migration doc promises rejection in 1.0.0. `config migrate` handles the upgrade. |
| top-level `engine` | migration doc | remove (turn into an error) | Ignored with a warning today. Goes with `controls`. |
| `includePlumberDefaults` (per control) | default config comments | keep | Only on the two allowlist controls, only with `extends`. |
| `releaseWorkflowsMustNotRestoreUntrustedCache` (renamed) | `docs/GITHUB_ISSUES.md` | keep the warning, remove with v1 | `config migrate` renames it. |
| `pipelineMustNotLeakSecretsInConfig` (removed control) | `docs/GITHUB_ISSUES.md` | keep the warning, remove with v1 | |

Controls themselves are out of scope here: 24 GitLab and 25 GitHub controls ship, and 27 GitHub
controls are benched in `configuration/registry.go`. Their future belongs to the control work.

## Deprecation path

Each removal follows the same path: one release where the item still works and prints a warning
on stderr naming its replacement, then removal, with a `CHANGELOG.md` entry in both releases. Items
already warning today skip the first step.

| Item | Warning release | Removal | Golden rows that change |
|---|---|---|---|
| `analyze --threshold` | already warns | next release, after the Action and component stop passing it | `TestAnalyze/analyze-bad-threshold` (removed or turned into an unknown-flag row), `TestHelpFlag/help-flag-analyze` |
| `analyze --score` | add the warning | the release after | `TestHelpFlag/help-flag-analyze` |
| `score-compare` | none needed: hidden, no user outside Radar | next release, once Radar has its own tool | `TestScoreCompare/*` and `TestHelpFlag/help-flag-score-compare` removed; `TestExplain` keeps its inputs under a new folder name |
| `config resolve` | prints "use `config view -o`" | the release after | `TestConfig/config-resolve*`, `TestHelpFlag/help-flag-config-resolve`, `help-flag-config`, `help-flag-config-view` |
| `config migrate --input` | add the warning, accept `-c/--config` | the release after | `TestHelpFlag/help-flag-config-migrate` |
| `auth.requireAuth` | none needed: it never did anything | next release | none |
| top-level `controls` and `engine` | already warn | 1.0.0, as the migration doc says | `TestConfig/config-validate-legacy` (becomes an error); `TestConfig/config-migrate*` unchanged |
| v0.2.x blocks in the JSON | once an owner confirms no consumer | the release after | e2e goldens (their `report` loses the blocks) |

## Follow-up during the rewrite

1. Apply the decisions above, one issue each, in the order of the deprecation table.
2. Delete the hand-written flag list from the `analyze` long help.
3. Add `--version`, the JSON schema version key and the GitHub warnings for `--glsast`,
   `--mr-comment`, `--badge` and `--ci-config-path`.
4. Document `catalog` in the README, and `extends` and `capabilities` in the migration doc.
5. Static by default: the Action and the component get inputs for `--resolve-depth` and
   `--sanity` at the switch step, and the release notes say that a run no longer reads imports or
   settings unless asked.

## Bugs found, to fix on `main`

- Unknown top-level keys of `.plumber.yaml` are ignored without a warning
  (`ValidateKnownKeys` only walks `controls`); `docs/plumber-yaml-v2-migration.md:116` says they warn.
- `controlsConfigIsZero` (`configuration/v1_to_v2.go:70`) checks 25 of the 42 control fields, so a v1
  file whose `controls:` only holds GitHub controls is not converted and gets no warning.
- `docs/plumber-yaml-v2-migration.md` lists `pipelineMustIncludeComponent` as a GitHub example (it is
  GitLab only) and calls 0.3.x current.
- `templates/plumber.yml:47` mentions a `sarif_file` input the component doesn't have.
- The comments at `configuration/plumberconfig.go:220` and `:276` describe an `enabledControls`
  allowlist and an "absent means enabled" rule that the code doesn't have.
