# v1: CLI refactoring

The Plumber CLI is being refactored ([getplumber/monorepo#640](https://github.com/getplumber/monorepo/issues/640)).
This directory holds its test suite, which runs the built `plumber` binary on every CLI input that
calls GitHub or GitLab and compares the output with golden files.

- Branch from `v1` and open your PR against `v1`.
- Run `make test-e2e` when you touch anything that calls GitHub or GitLab. It needs
  `PLUMBER_E2E_GITHUB_TOKEN` and `PLUMBER_E2E_GITLAB_TOKEN` (read-only).
- If you change an output on purpose, run `make test-e2e UPDATE=1` and review the diff.

The rules, the layout and how to add a case are in [AGENTS.md](AGENTS.md).
