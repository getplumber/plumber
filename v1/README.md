# v1: CLI refactoring

The Plumber CLI is being refactored ([getplumber/monorepo#640](https://github.com/getplumber/monorepo/issues/640)).
This directory holds its test suite, which runs the built `plumber` binary on every CLI input and
compares the output with golden files.

- Branch from `v1` and open your PR against `v1`.
- Run `make -C v1 test-integration` before pushing. It needs no token and no network.
- If you change an output on purpose, run `make -C v1 test-integration UPDATE=1` and review the diff.

The rules, the layout and how to add a case are in [AGENTS.md](AGENTS.md).
