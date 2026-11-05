# v1: the CLI refactoring

Instructions for AI coding agents and people working on the Plumber CLI refactoring,
tracked in [getplumber/monorepo#640](https://github.com/getplumber/monorepo/issues/640).

## Code style

Write current, idiomatic Go for the version in `go.mod`, and keep it readable and simple. Before you
write or change Go code, run the use-modern-go skill
([`.agents/skills/use-modern-go/SKILL.md`](../.agents/skills/use-modern-go/SKILL.md)):

```sh
sh .agents/skills/use-modern-go/scripts/run-tool.sh list --file-path <file.go>
```

Read the whole output and follow the guidelines it returns, even where nearby code uses an older
pattern. An agent that cannot load skills reads the file and runs the script.

Run the humanizer skill ([`.agents/skills/humanizer/SKILL.md`](../.agents/skills/humanizer/SKILL.md)) on the
documentation you write: Markdown, commit messages and PR descriptions. An agent that cannot load
skills reads the file and applies it.

## Rules

1. Everything for the refactoring goes in `v1/`: code, tests, fixtures, golden files and docs.
   The CLI code stays where it is until step 4 of #640 moves it.
2. Don't create, modify or delete anything outside `v1/`, except in `.agents/`, `.claude/`,
   `.github/` and `skills-lock.json`, for the wiring listed under "Wiring outside `v1/`". In those
   places, leave the files that come from `main` as they are and add new ones instead, like
   `.github/workflows/v1.yml`. The only edit allowed in a file from `main` is the
   `branches: [main]` filter on the `pull_request` trigger of its workflows. If something outside
   `v1/` needs a fix, fix it on `main` and the next sync brings it. The `scope` job of
   `.github/workflows/v1.yml` fails a PR that changes other paths.
3. Branch from `v1` and open PRs against `v1`, never `main`:
   `git fetch origin && git switch -c <branch> origin/v1`.
4. A maintainer merges `main` into `v1` by hand, through a PR:
   `git switch -c sync/main-into-v1 origin/v1 && git merge origin/main`, then `gh pr create --base v1`.
   `.github/workflows/v1.yml` runs the suite on that PR. A red result means a command, flag, output
   format or control changed on `main`: add or refresh the rows before merging. On a conflict in a
   workflow's `pull_request` trigger, keep v1's `branches: [main]`.
5. `main_test.go` has `TestMain` and the shared helpers, and `integration_test.go` has the rows
   (`localCases`). Each CLI input has one table row. When you add or change a command, a flag, an
   output format or an exit code, add or update its row in the same PR. `TestCoverage` fails when
   a command or flag of the binary has no row.
6. Rows cover every input that makes no backend request (`version`, `--help`, `catalog`,
   `explain`, `capabilities`, `config …`, `score-compare`, `completion`, usage errors, and
   `analyze` inputs rejected before any request). They run with no token and every proxy pointed
   at a closed port, so a row that tries the network fails.
7. Read the diff of every golden file you change. `UPDATE=1` rewrites them; explain each change
   in the PR.
8. Run `make -C v1 lint` before you open a PR. It must report 0 issues. Use the golangci-lint
   version `.github/workflows/v1.yml` pins (v2.15.0). Fix what it reports. A `//nolint` names one
   linter and says why.

## Commands

From the repository root (`v1/Makefile`):

```sh
make -C v1 test-integration            # rows + coverage guard. Offline, no token. Run before every push.
make -C v1 test-integration UPDATE=1   # rewrite the golden files (review the diff)
make -C v1 lint                        # golangci-lint with v1/.golangci.yml. Run before every PR.
```

`make test` (`go test ./...`) does not run this suite because its files have the `cli` build tag.

## Layout

```
v1/
  AGENTS.md, CLAUDE.md, README.md
  Makefile                       targets test-integration and lint
  .golangci.yml                  golangci-lint v2 config for v1/ (`cli` build tag)
  main_test.go                   TestMain (builds the binary, reads the command tree), row type, golden helpers
  integration_test.go            rows `localCases`, `untested`, TestIntegration, TestCoverage
  testdata/
    inputs/                      files copied into a row's work dir (configs, analyze reports)
    golden/local/                one <row>.golden per row: command, exit code, stdout, stderr, files
```

## Adding a case

- New CLI input with no backend request: add a `run(...)` row to `localCases` and put input files
  in `testdata/inputs/`.
- Input that cannot be tested here because it writes to a real project or needs CI OIDC, a
  platform or a provider: add it to `untested` in `integration_test.go` with the reason. Every
  entry is an input this suite does not cover, so add one only when there is no other way.

## Wiring outside `v1/`

- `.github/workflows/v1.yml`: the only CI of `v1`, on pushes and PRs to `v1`. Jobs: build and
  unit tests (`go build ./...`, `go test ./...`), the CLI suite, golangci-lint on `v1/`
  through `golangci/golangci-lint-action` (same version and arguments as `make -C v1 lint`), and
  `scope`, which checks the paths a PR changes (rule 2). `scope` skips `sync/` branches of this
  repository, because a sync from `main` changes files everywhere.
- `branches: [main]` on the `pull_request` trigger of `plumber-action.yml`,
  `claude-pr-checks.yml`, `install-channels.yml` and `scripts-test.yml`, so they don't run on PRs
  to `v1`. GitHub reads a PR's workflows from the PR's own tree and has no per-branch switch, so
  this filter is the only way. `ci.yml` and `codeql.yml` already have it; `release.yml` and
  `scorecard.yml` don't run on PRs.
- `.agents/skills/`, symlinked from `.claude/skills/`, and `skills-lock.json`: the humanizer skill
  (MIT, see its `LICENSE`) and the use-modern-go skill (JetBrains/go-modern-guidelines).

## Known CLI quirks the suite records

Goldens record current behavior, quirks included. Fix a quirk on `main`; the next sync brings the
fix to `v1` and the golden diff shows it.
- `plumber --version` is an unknown flag (exit 2); only `plumber version` works.
- `config view --explain` prints its provenance lines in random order (map iteration in
  `cmd/config_explain.go`), so its row compares sorted lines.
- `config view` with no `.plumber.yaml` exits 0 and shows the defaults.

## Issues

- #640 refactoring (tracking), #641 step 1 local suite, #651 step 2 E2E suite.
