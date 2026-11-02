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
4. `main_test.go` has `TestMain` and the shared helpers, and `e2e_test.go` has the rows
   (`e2eCases`). Each CLI input that calls a provider has one table row. When you add or change
   such an input, add or update its row in the same PR.
5. Rows cover every input that calls GitHub or GitLab. They run against the fixture repositories,
   one branch per case. Do not add fakes or recorded API responses.
6. Read the diff of every golden file you change. `UPDATE=1` rewrites them; explain each change
   in the PR.

## Commands

```sh
make test-e2e                    # e2e rows. Needs PLUMBER_E2E_GITHUB_TOKEN and PLUMBER_E2E_GITLAB_TOKEN
make test-e2e UPDATE=1           # rewrite the golden files (review the diff)
v1/testdata/e2e/sync.sh          # push v1/testdata/e2e/<provider>/<case>/ to the fixture repos
```

`make test` (`go test ./...`) does not run this suite because its files have the `cli` build tag.
Rows skip when their token is missing; CI sets `PLUMBER_E2E_REQUIRED=1` to make that a failure.

## Layout

```
v1/
  AGENTS.md, CLAUDE.md, README.md
  main_test.go                   TestMain (builds the binary), row type, golden helpers
  e2e_test.go                    rows `e2eCases`, tokens, clone, rate-limit retry, TestE2E
  testdata/
    inputs/                      files copied into a row's work dir (configs)
    golden/e2e/                  one <row>.golden per row: command, exit code, stdout, stderr, files
    e2e/<provider>/<case>/       content of branch <case> of the fixture repository
    e2e/sync.sh                  pushes each case as a parentless commit with a fixed date (stable SHAs)
```

Edit fixture content in `v1/testdata/e2e/`, never in the fixture repositories:
- GitHub: https://github.com/getplumber-examples/plumber-cli-e2e. Actions are disabled. `main`
  requires one review; admins bypass it so `sync.sh` can update the index.
- GitLab: https://gitlab.com/getplumber/examples/plumber-cli-e2e. The project is public, with
  shared runners disabled so no pipeline runs. CI/CD stays enabled because Plumber reads the merged
  configuration through the GitLab API. `main` is protected by default.

Every case branch sees the project settings (branch protection, variables, approvals), so changing
a setting changes the goldens of every row.

## Rate limits

- One `make test-e2e` run costs about 1,600 GitHub API requests, and a token gets 5,000 an hour.
  That allows two runs an hour per token, so combine flags in a row when they do not interfere.
- gitlab.com returns 429 when analyses run in parallel, so GitLab rows run one at a time.
- A throttled run (`429 Too Many Requests`, `API rate limit exceeded`) is retried up to 3 times,
  one minute apart, and then fails the row. Its output never reaches a golden file.

## Adding a case

Add an `onGitHub(...)` or `onGitLab(...)` row to `e2eCases`. If it needs new pipeline content, add
`testdata/e2e/<provider>/<case>/`, run `sync.sh`, then `make test-e2e UPDATE=1`.

## Wiring outside `v1/`

- `Makefile`: target `test-e2e`.
- `.github/workflows/ci.yml`: job `cli-e2e`, run on PRs to `v1`.
- `.github/workflows/v1-sync.yml`: the daily merge of `main` into `v1`. A copy also lives on
  `main`, because scheduled workflows only run from the default branch.
- `CONTRIBUTING.md`: one paragraph pointing here.
- `.claude/skills/humanizer/` and `skills-lock.json`: the humanizer skill (MIT, see its `LICENSE`).

## Issues

- #640 refactoring (tracking), #641 step 1 local suite, #651 step 2 E2E suite.
