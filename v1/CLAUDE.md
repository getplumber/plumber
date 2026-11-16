@AGENTS.md

## Claude Code notes

- Before claiming a change is done, run `make -C v1 test-integration` and paste the result.
- Before opening a PR, run `make -C v1 lint` and paste the result. It must say `0 issues.`
- If a change seems to need a path that rule 2 forbids, stop and ask.
- Never edit a golden file to make a red suite green without reading its diff and saying in the
  PR why each change is expected.
