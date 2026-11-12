# v1: CLI refactoring

The Plumber CLI is being refactored ([getplumber/monorepo#640](https://github.com/getplumber/monorepo/issues/640)).
This directory holds its test suite, which runs the built `plumber` binary on every CLI input and
compares the output with golden files.

- Branch from `release/v1` and open your PR against `release/v1`.
- Run `make -C v1 test-integration` before pushing. It needs no token and no network.
- If you change an output on purpose, edit its golden file by hand and explain the diff in the PR.
- Start AI coding agents from `v1/`, so they load its instructions before they create a branch.

The rules, the layout and how to add a case are in [AGENTS.md](AGENTS.md).
