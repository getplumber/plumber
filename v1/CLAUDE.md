@AGENTS.md

## Claude Code notes

- Before editing Go code, invoke the `use-modern-go` skill.
- Before claiming a change is done, run `make -C v1 test-integration` and paste the result.
- Before opening a PR, run `make -C v1 lint` and paste the result. It must say `0 issues.`
- Don't touch anything outside `v1/` except `.agents/`, `.claude/`, `.github/` and
  `skills-lock.json` (rule 2 in AGENTS.md). If a change seems to need it, stop and ask.
- Never run `UPDATE=1` to make a red suite green without reading the golden diff and saying in
  the PR why each change is expected.
- Branch from `origin/v1` and open PRs against `v1` (`gh pr create --base v1`).
