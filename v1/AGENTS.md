# v1: the CLI refactoring

Instructions for AI coding agents and people working on the Plumber CLI refactoring,
tracked on the [CLI Refactoring board](https://github.com/orgs/getplumber/projects/1/views/18).

## Code style

Write current, idiomatic Go for the version in `go.mod`, and keep it readable and simple. Before you
write or change Go code, run the use-modern-go skill
([`.agents/skills/use-modern-go/SKILL.md`](../.agents/skills/use-modern-go/SKILL.md)):

```sh
sh .agents/skills/use-modern-go/scripts/run-tool.sh list --file-path <file.go>
```

Read the whole output and follow the guidelines it returns, even where nearby code uses an older
pattern. An agent that cannot load skills reads the file and runs the script.

For what the skill doesn't cover (naming, error messages, doc comments, API shape and tests), follow
the [Google Go Style Guide](https://google.github.io/styleguide/go/guide) and its
[Style Decisions](https://google.github.io/styleguide/go/decisions) and
[Best Practices](https://google.github.io/styleguide/go/best-practices). Where the two disagree, the
skill wins: use the newer API even where nearby code doesn't, and compare errors with `errors.Is`,
which `errorlint` requires.

Rego follows the [Rego style guide](https://github.com/open-policy-agent/rego-style-guide).
`regal lint` must report no violation, and policies are tested in Rego with `opa test`, never from
Go. The details are under "Policies" in [`docs/project-structure.md`](docs/project-structure.md#policies).

Run the humanizer skill ([`.agents/skills/humanizer/SKILL.md`](../.agents/skills/humanizer/SKILL.md)) on the
documentation you write: Markdown, commit messages and PR descriptions. An agent that cannot load
skills reads the file and applies it.

## Rules

1. Everything for the refactoring goes in `v1/`: code, tests, fixtures, golden files and docs.
   The CLI is rewritten under `v1/`, as `docs/project-structure.md` describes, and imports
   nothing from the packages at the repository root. The old code stays where it is until the
   last step of that rewrite deletes it. `v1/pkg/` is the API the platform backend imports; its
   rules are in the same doc.
2. Don't create, modify or delete anything outside `v1/`, except in `.agents/`, `.claude/`,
   `.github/` and `skills-lock.json`, for the wiring listed under "Wiring outside `v1/`". In those
   places, leave the files that come from `main` as they are and add new ones instead, like
   `.github/workflows/v1.yml`. The only edit allowed in a file from `main` is the
   `branches: [main]` filter on the `pull_request` trigger of its workflows. If something outside
   `v1/` needs a fix, fix it on `main` and the next sync brings it. The `scope` job of
   `.github/workflows/v1.yml` fails a PR that changes other paths. From step 1 of the rewrite
   (`docs/project-structure.md`), `go.mod` and `go.sum` are an exception for additions only: a new
   requirement and its `go.sum` lines, never a version change of a dependency `main` has, so syncs
   from `main` still merge cleanly.
3. Branch from `release/v1` and open PRs against `release/v1`, never `main`:
   `git fetch origin && git switch -c <branch> origin/release/v1`.
4. A maintainer merges `main` into `release/v1` by hand, through a PR:
   `git switch -c sync/main-into-release-v1 origin/release/v1 && git merge origin/main`, then `gh pr create --base release/v1`.
   `.github/workflows/v1.yml` runs the suite on that PR. A red result means a command, flag, output
   format or control changed on `main`: add or refresh the rows before merging. On a conflict in a
   workflow's `pull_request` trigger, keep release/v1's `branches: [main]`.
5. The suite is a firewall for the refactoring, not a coverage gate: a row exists because a
   behavior is worth protecting. It has two packages, `test/local` and `test/e2e`, and every file
   is a `_test.go`. Each package has its own copy of the code they share (building the binary, the
   sandbox, the text diff), because a test file can't be imported by another package. In
   `test/local`, each file is one command group with its own table-driven test (`TestConfig` in
   `config_test.go`, and so on). When you add or change a command, a flag, an output format or an
   exit code, add or update its row in the same PR.
6. Local rows only cover inputs that make no backend request (`version`, `--help`, `catalog`,
   `explain`, `capabilities`, `config …`, `score-compare`, `completion`, usage errors, and
   `analyze` inputs rejected before any request). They run with no token and every proxy pointed
   at a closed port, so a row that tries the network fails. The e2e tests (`test/e2e`) are one test
   per ISSUE code, run against the provider's fixture repository with a token, behind the `e2e`
   build tag (see "e2e rows").
7. Every row has a golden file: `test/local/testdata/golden/<Test>/<name>.yaml`, or
   `test/e2e/testdata/<provider>/golden/<Test>/<name>.yaml`. A row without one fails.
8. Run `make -C v1 lint` before you open a PR. It must report 0 issues. Use the golangci-lint
   version `.github/workflows/v1.yml` pins (v2.15.0). Fix what it reports. A `//nolint` names one
   linter and says why.
9. Every change belongs to an issue: one issue per change, one PR per issue. Issues live in
   `getplumber/monorepo`, on the [board](https://github.com/orgs/getplumber/projects/1/views/18)
   with the Topic "CLI Refactoring", and each one explains its work. Open one with `/open-issue`, which first checks that it is really needed.
10. After a PR merges into `release/v1`, check its issue against what merged. `Closes` does nothing
    here because `release/v1` is not the default branch, so close the issue by hand when everything
    is done. Anything missing becomes a new issue.

## External contributors

An external contributor doesn't run the local or e2e tests themselves. When their change is about
an ISSUE code, they provide a workflow example that raises it, and a maintainer turns it into a
fixture branch and a test.

## Commands

From the repository root (`v1/Makefile`):

```sh
make -C v1 test-integration   # test/local. Offline, no token. Run before every push.
make -C v1 test-e2e-github    # TestGitHub* of test/e2e. Needs GITHUB_TOKEN (or GH_TOKEN) exported, see "e2e rows".
make -C v1 test-e2e-gitlab    # TestGitLab* of test/e2e. Needs GITLAB_TOKEN exported, see "e2e rows".
make -C v1 test-e2e           # all of test/e2e, both tokens.
make -C v1 lint               # golangci-lint with v1/.golangci.yml. Run before every PR.
```

After a change that only touches one provider, run its target. Run one test with
`go test -tags cli,e2e -run TestGitHubIssue102 ./test/e2e` (from `v1/`). The e2e tests fail when
their token isn't exported, even though the fixture repositories are public: plumber needs a
token to analyze a remote repository. They have the `e2e` build tag, so `test-integration` never
runs them.

`make test` (`go test ./...`) does not run this suite because its files have the `cli` build tag.

## Layout

```
v1/
  AGENTS.md, CLAUDE.md, README.md
  Makefile                       targets test-integration, test-e2e(-github|-gitlab) and lint
  .golangci.yml                  golangci-lint v2 config for v1/ (`cli` and `e2e` build tags)
  docs/
    analyze-flow.md              sequence diagrams of the rewritten analyze
    drafts/
      repository-graph.md        not adopted: a repository graph as the Rego input, and when to move to it
    feature-inventory.md         every command, flag, output and config key, with keep/drop decisions
    project-structure.md         comparison with kubectl, helm, golangci-lint and terraform, target layout, public API,
                                 configuration, documentation, rewrite order
  test/
    local/                       package local: every input that makes no backend request
      main_test.go               package doc, TestMain (builds the binary)
      run_test.go                row type `cliCase`, runCase
      sandbox_test.go            sandbox: work dir, home, env (offline), runPlumber, normalize, newGolden
      golden_test.go             golden struct (stdout, stderr, files), readGolden, cmp
      root_test.go               TestRoot: help, version, catalog, capabilities, unknown command or flag
      analyze_test.go            TestAnalyze: analyze inputs rejected before any request
      completion_test.go         TestCompletion
      config_test.go             TestConfig
      explain_test.go            TestExplain
      score_compare_test.go      TestScoreCompare
      help_test.go               TestHelpFlag: one --help row per command
      testdata/
        inputs/                  files copied into a row's work dir (configs, analyze reports)
        golden/                  one folder per test, one <row>.yaml per row (struct `golden`)
    e2e/                         package e2e: one test per ISSUE code; every file has the `e2e` tag
      main_test.go               package doc, TestMain, githubTarget and gitlabTarget
      run_test.go                row type `e2eCase`, runE2E, token
      sandbox_test.go            sandbox (a copy of local's, online: the token, no proxies)
      golden_test.go             golden struct (command, exit, report), readGolden, readReport, cmp
      retry_test.go              reruns a throttled call
      github_test.go             TestGitHubIssue<number>: one test per code, one row per configuration
      gitlab_test.go             TestGitLabIssue<number>: the same on GitLab
      testdata/
        github/inputs/           configs of the GitHub rows
        github/golden/           one folder per test, one <row>.yaml per row
        gitlab/inputs/  gitlab/golden/
```

## Adding a case

- Add a row to the table of the command's file in `test/local` and put input files in
  `test/local/testdata/inputs/`. A new command group gets its own `<group>_test.go`.
- A new command also gets a `--help` row in `help_test.go`, so a flag lost later shows in a golden
  diff.
- Add its golden file, `test/local/testdata/golden/<Test>/<name>.yaml`.
- When you remove a row, delete its golden file: nothing else reports it.
- An ISSUE code that a provider must raise is an e2e row (next section). Inputs that need a
  platform or CI OIDC have no row yet.

## e2e rows

The e2e tests check the ISSUE codes on real providers. A row runs
`plumber analyze <fixture repo> --branch issue-<number> --controls <control> -o report.json`
against `getplumber-examples/plumber-cli-e2e` (GitHub) or `getplumber/examples/plumber-cli-e2e`
(GitLab). It covers a code that its fixture raises from its own files and settings. It runs one
control and fetches nothing from another repository: no remote action, reusable workflow, include
or component. A GitHub row costs about 7 API requests.

The fixtures are the `issue-<number>` branches of the fixture repositories, and the project
doesn't keep a copy: edit a branch there, then refresh its golden files.

Both providers have the same shape, in `test/e2e`:

- Each code has its own test, `TestGitHubIssue<number>` in `github_test.go` or
  `TestGitLabIssue<number>` in `gitlab_test.go`. Its table has one `e2eCase` row per
  configuration, as in `test/local`: `default` with no config, otherwise named after the config in
  `testdata/<provider>/inputs/`. Each row runs through `runE2E`.
- A row is compared on its report, not on its terminal output, because the text shows some
  findings (102, 103, 204, 207, 209, 411) only as attack paths, with no code. The golden file,
  `testdata/<provider>/golden/<Test>/<row>.yaml`, has `command`, `exit` and `report`: the row's
  `report.json` with its keys sorted, normalized, and without `plumberConfig` (the config dump,
  the same in every row).
- To add a code: create its `issue-<number>` branch on the fixture repository, with a comment that
  names the code, add its test to the provider's file, and write the golden file from a run you
  have read.
- Rows 501 and 505 (both providers) and 503, 506 and 601 (GitLab) also read the fixture projects'
  settings. Keep `main` protected without code owner approval on both. On GitLab, keep merge
  commits, let committers approve and link no security policy project.
  Reading those settings takes more than a read-only token: on GitHub, Administration read on the
  fixture repository (admin access for a classic token); on GitLab, the `read_api` scope and the
  Maintainer role on the fixture project. With less, these rows run but report the settings as
  unknown, and their goldens differ.
- The e2e tests run one at a time, never in parallel: gitlab.com throttles (429) as soon as two
  analyses run at once. In CI, a concurrency group per provider keeps one run active at a time.
  The CLI retries a throttled GitLab request itself (`gitlab/retry.go`), and the runner reruns a
  row up to 3 times, a minute apart, when the CLI runs out of retries or GitHub's secondary rate
  limit stops it. A run that wrote its report and exited 0 or 1 is never rerun. GitHub's hourly
  API limit fails the row at once: waiting a minute wouldn't help. A whole GitHub run takes about
  120 API requests. The provider targets allow 30 minutes each, `test-e2e` 60 minutes for both.

### ISSUE codes the e2e suite doesn't test

Some of these could get a row later:

| Why | Codes |
|---|---|
| Benched in `configuration/registry.go`: the control never runs | GitHub 208, 210-215, 303, 305, 306, 308, 418-422, 704, 706, 708, 709, 711, 712, 901-905 |
| Needs a remote action (its metadata, source or upstream refs), often `actions/checkout` | GitHub 307, 310, 402, 701, 702, 703, 705, 707, 713, 716, 802, 804 |
| Needs a remote include, component or template | GitLab 402, 403, 404, 406, 409, 414 |
| Needs a CI/CD variable on the fixture project | GitLab 201, 202 |
| Needs GitLab Premium approval rules | GitLab 502, 504 |
| Never raised on GitHub: the GitHub parser doesn't fill `job.Services` (a CLI bug, fix it on `main`) | GitHub 412, 413 |

Also missing:

- CI doesn't run the e2e suites yet: both jobs of `v1.yml` are off (`if: false && …`). After a
  change that can affect a provider, run its target locally (`make -C v1 test-e2e-github` or
  `test-e2e-gitlab`).
- The daily run that monorepo#651 asks for. GitHub runs scheduled workflows on the default branch
  only, so `v1.yml` can't schedule it on `release/v1`.

## Wiring outside `v1/`

- `.github/workflows/v1.yml`: the only CI of `release/v1`, on pushes and PRs to `release/v1`. Jobs: build and
  unit tests (`go build ./...`, `go test ./...`), the CLI suite, one e2e job per provider (off for
  now with `if: false && …`; on, each passes its `PLUMBER_E2E_<PROVIDER>_TOKEN` secret as
  `GITHUB_TOKEN` or `GITLAB_TOKEN` and skips fork PRs), golangci-lint on `v1/`
  through `golangci/golangci-lint-action` (same version and arguments as `make -C v1 lint`), and
  `scope`, which checks the paths a PR changes (rule 2). `scope` skips `sync/` branches of this
  repository, because a sync from `main` changes files everywhere.
- `branches: [main]` on the `pull_request` trigger of `plumber-action.yml`,
  `claude-pr-checks.yml`, `install-channels.yml` and `scripts-test.yml`, so they don't run on PRs
  to `release/v1`. GitHub reads a PR's workflows from the PR's own tree and has no per-branch switch, so
  this filter is the only way. `ci.yml` and `codeql.yml` already have it; `release.yml` and
  `scorecard.yml` don't run on PRs.
- `.agents/skills/`, symlinked from `.claude/skills/`, and `skills-lock.json`: the humanizer skill
  (MIT, see its `LICENSE`) and the use-modern-go skill (JetBrains/go-modern-guidelines).

## Known CLI quirks the suite records

Goldens record current behavior, quirks included. Fix a quirk on `main`; the next sync brings the
fix to `release/v1` and the golden diff shows it.
- `plumber --version` is an unknown flag (exit 2); only `plumber version` works.
- `config view --explain` prints its provenance lines in random order (map iteration in
  `cmd/config_explain.go`), so its row compares sorted lines.
- `config view` with no `.plumber.yaml` exits 0 and shows the defaults.
- GitHub ISSUE-410 says a job is weakened by `allow_failure: true`, the GitLab keyword, when the
  workflow sets `continue-on-error: true` (`TestGitHubIssue410/default`).

## Issues

- The [board](https://github.com/orgs/getplumber/projects/1/views/18) lists every issue of the refactoring.
