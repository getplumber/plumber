# v1: the CLI refactoring

Instructions for AI coding agents and people working on the Plumber CLI refactoring,
tracked in [getplumber/monorepo#640](https://github.com/getplumber/monorepo/issues/640).

## Code style

Write Go that follows the [Google Go Style Guide](https://google.github.io/styleguide/go/guide) and [Google best practices](https://google.github.io/styleguide/go/best-practices). Keep it readable and simple.

Run the humanizer skill ([`.claude/skills/humanizer/SKILL.md`](../.claude/skills/humanizer/SKILL.md)) on every
comment and every piece of documentation you write: code comments, Markdown, commit messages and PR
descriptions. An agent that cannot load skills reads the file and applies it.

## Rules

1. Everything for the refactoring goes in `v1/`: tests, fixtures, golden files and docs.
   Outside `v1/` there is only wiring that cannot live here, listed below.
   The CLI code stays where it is until step 4 of #640 moves it.
2. Branch from `v1` and open PRs against `v1`, never `main`:
   `git fetch origin && git switch -c <branch> origin/v1`.
3. `.github/workflows/v1-sync.yml` merges `main` into `v1` every day. It opens or updates the PR
   from `sync/main-into-v1` to `v1` with the result of the suite. A red result means a command,
   flag, output format or control changed on `main`: add or refresh the rows before merging.
4. `main_test.go` has `TestMain` and the shared helpers, and `integration_test.go` has the rows
   (`localCases`). Each CLI input has one table row. When you add or change a command, a flag, an
   output format or an exit code, add or update its row in the same PR. `TestCoverage` fails when
   a command or flag of the binary has no row.
5. Rows cover every input that makes no backend request (`version`, `--help`, `catalog`,
   `explain`, `capabilities`, `config …`, `score-compare`, `completion`, usage errors, and
   `analyze` inputs rejected before any request). They run with no token and every proxy pointed
   at a closed port, so a row that tries the network fails.
6. Read the diff of every golden file you change. `UPDATE=1` rewrites them; explain each change
   in the PR.

## Commands

```sh
make test-integration            # rows + coverage guard. Offline, no token. Run before every push.
make test-integration UPDATE=1   # rewrite the golden files (review the diff)
```

`make test` (`go test ./...`) does not run this suite because its files have the `cli` build tag.

## Layout

```
v1/
  AGENTS.md, CLAUDE.md, README.md
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

- `Makefile`: target `test-integration`.
- `.github/workflows/ci.yml`: job `cli-local`, run on PRs to `v1`.
- `.github/workflows/v1-sync.yml`: the daily merge of `main` into `v1`. A copy also lives on
  `main`, because scheduled workflows only run from the default branch.
- `CONTRIBUTING.md`: one paragraph pointing here.
- `.claude/skills/humanizer/` and `skills-lock.json`: the humanizer skill (MIT, see its `LICENSE`).

## Known CLI quirks the suite records

Goldens record current behavior, quirks included. Fix a quirk on `main`; the daily sync brings the
fix to `v1` and the golden diff shows it.
- `plumber --version` is an unknown flag (exit 2); only `plumber version` works.
- `config view --explain` prints its provenance lines in random order (map iteration in
  `cmd/config_explain.go`), so its row compares sorted lines.
- `config view` with no `.plumber.yaml` exits 0 and shows the defaults.

## Issues

- #640 refactoring (tracking), #641 step 1 local suite, #651 step 2 E2E suite.
