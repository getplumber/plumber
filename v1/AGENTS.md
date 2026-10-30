# v1: the CLI refactoring

Context for AI coding agents (and humans) working on the refactoring of the Plumber CLI,
tracked in [getplumber/monorepo#640](https://github.com/getplumber/monorepo/issues/640).

## Rules

1. **Everything for the refactoring goes in `v1/`.** Tests, fixtures, golden files, docs.
   Outside `v1/`, only wiring that cannot live here, and each piece is listed below.
   The CLI code itself stays where it is until step 4 of #640 moves it.
2. **Work starts from the `v1` branch, and PRs target `v1`, never `main`.**
   `git fetch origin && git switch -c <branch> origin/v1`.
3. **`main` is merged into `v1` every day** by `.github/workflows/v1-sync.yml`, which opens or
   updates the PR `sync/main-into-v1` → `v1` with the result of the suite. When it is red, a
   command, flag, output format or control changed on `main`: add or refresh the rows below
   before merging it.
4. **One test file: `v1/cli_test.go`.** One table row per CLI input. When you add or change
   a command, a flag, an output format or an exit code, add or update its row in the same PR.
   `TestCLICoverage` fails when a command or flag of the binary has no row.
5. **Local vs E2E.**
   - *local* rows cover every input that makes **no backend request** (`version`, `--help`,
     `catalog`, `explain`, `capabilities`, `config …`, `score-compare`, `completion`, usage
     errors, and `analyze` inputs rejected before any request). They run with no token and
     every proxy pointed at a closed port: a local row that tries the network fails.
   - *e2e* rows cover every input that **calls GitHub or GitLab**. They run against the
     fixture repositories, one branch per case. **No fakes, no recorded API responses.**
6. **Golden files are reviewed, never refreshed blindly.** `UPDATE=1` rewrites them; read the
   diff and explain it in the PR.

## Commands

```sh
make test-integration            # local rows + coverage guard. Offline, no token. Run before every push.
make test-integration UPDATE=1   # rewrite local golden files (review the diff)
make test-e2e                    # e2e rows. Needs PLUMBER_E2E_GITHUB_TOKEN and PLUMBER_E2E_GITLAB_TOKEN
make test-e2e UPDATE=1           # rewrite e2e golden files
v1/testdata/e2e/sync.sh          # push v1/testdata/e2e/<provider>/<case>/ to the fixture repos
```

`make test` (`go test ./...`) does not run this suite: `cli_test.go` has the `cli` build tag.
E2E rows skip when their token is missing; `PLUMBER_E2E_REQUIRED=1` turns the skip into a failure (CI).

## Layout

```
v1/
  AGENTS.md, CLAUDE.md, README.md
  cli_test.go                    the suite: table `cases`, `untested`, coverage guard, golden helpers
  testdata/
    inputs/                      files copied into a row's work dir (configs, analyze reports)
    golden/local/, golden/e2e/   one <row>.golden per row: command, exit code, stdout, stderr, files
    e2e/<provider>/<case>/       content of branch <case> of the fixture repository
    e2e/sync.sh                  pushes each case as a parentless commit with a fixed date (stable SHAs)
```

Fixture repositories (edit the content in `v1/testdata/e2e/`, never in the repos):
- GitHub: https://github.com/getplumber-examples/plumber-cli-e2e (Actions disabled; `main` is
  protected with one required review, admins bypass it so `sync.sh` can update the index)
- GitLab: https://gitlab.com/getplumber/examples/plumber-cli-e2e (public; shared runners disabled so
  no pipeline ever runs; CI/CD stays enabled because Plumber reads the merged configuration through
  the GitLab API; `main` is protected by default)

Project settings (branch protection, variables, approvals) are part of the fixture: every case
branch sees them. Changing them changes the goldens of every row.

## Rate limits

- One `make test-e2e` run costs about 1,600 GitHub API requests (5,000/hour per token). Two runs
  an hour per token is the budget: combine flags in a row when they do not interfere.
- gitlab.com throttles (429) when analyses run in parallel: GitLab rows run one at a time.
- A throttled run (`429 Too Many Requests`, `API rate limit exceeded`) is retried up to 3 times,
  one minute apart, then fails the row. It never reaches a golden file.

## Adding a case

- New CLI input with no backend request: add a `run(...)` row; put input files in `testdata/inputs/`.
- New input that calls a provider: add an `onGitHub(...)` / `onGitLab(...)` row. If it needs new
  pipeline content, add `testdata/e2e/<provider>/<case>/`, run `sync.sh`, then `make test-e2e UPDATE=1`.
- An input that cannot be tested (it writes to a real project, needs CI OIDC or a platform):
  add it to `untested` with the reason. Each entry is a gap; keep the list short.

## Wiring outside `v1/`

- `Makefile`: targets `test-integration` and `test-e2e`.
- `.github/workflows/ci.yml`: runs on PRs to `v1`; jobs `cli-local` and `cli-e2e`.
- `.github/workflows/v1-sync.yml`: daily merge of `main` into `v1` (also on `main`, because
  scheduled workflows only run from the default branch).
- `CONTRIBUTING.md`: one paragraph pointing here.

## Known CLI quirks the suite records

Goldens record today's behavior, quirks included. Fix them on `main`; the daily sync brings the fix
and the golden diff shows it.
- `plumber --version` is an unknown flag (exit 2); only `plumber version` works.
- `config view --explain` prints its provenance lines in random order (map iteration in
  `cmd/config_explain.go`); its row compares sorted lines.
- `config view` with no `.plumber.yaml` exits 0 and shows the defaults.

## Issues

- #640 refactoring (tracking), #641 step 1 local suite, #651 step 2 E2E suite.
