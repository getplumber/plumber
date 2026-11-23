# v1: CLI refactoring

The Plumber CLI is being refactored ([CLI Refactoring board](https://github.com/orgs/getplumber/projects/1/views/18)).
This directory holds its test suite, which runs the built `plumber` binary on every CLI input and
compares the output with golden files.

- Branch from `release/v1` and open your PR against `release/v1`.
- Run `make -C v1 test-integration` before pushing. It needs no token and no network.
- `make -C v1 test-e2e-github` and `make -C v1 test-e2e-gitlab` run the ISSUE code tests against the
  provider's fixture repository, with a token for that provider. `make -C v1 test-e2e` runs both.
- If you change an output on purpose, edit its golden file by hand and explain the diff in the PR.
- Start AI coding agents from `v1/`, so they load its instructions before they create a branch.

The rules, the layout and how to add a case are in [AGENTS.md](AGENTS.md).
