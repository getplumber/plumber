@AGENTS.md

## Claude Code notes

- Before claiming a change is done, run `make test-integration` and paste the result. Run
  `make test-e2e` too when the change touches provider calls or `analyze`.
- Never run `UPDATE=1` to make a red suite green without reading the golden diff and saying in
  the PR why each change is expected.
- Branch from `origin/v1` and open PRs against `v1` (`gh pr create --base v1`).
