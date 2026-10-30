# v1: CLI refactoring

The Plumber CLI is being refactored ([getplumber/monorepo#640](https://github.com/getplumber/monorepo/issues/640)).
This directory holds the safety net for it: a test suite that runs the built `plumber` binary on every
CLI input and compares its output with golden files.

- Branch from `v1` and open your PR against `v1`.
- Run `make test-integration` before pushing. It needs no token and no network.
- Run `make test-e2e` when you touch anything that calls GitHub or GitLab. It needs
  `PLUMBER_E2E_GITHUB_TOKEN` and `PLUMBER_E2E_GITLAB_TOKEN` (read-only).
- Changed an output on purpose? `make test-integration UPDATE=1` (or `test-e2e`) and review the diff.

The rules, the layout and how to add a case are in [AGENTS.md](AGENTS.md).
