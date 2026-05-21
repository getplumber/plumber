# github-env-injection — flag `run:` steps that append user-controlled
# content to $GITHUB_ENV or $GITHUB_PATH. These two files are sticky:
# every subsequent step of the job reads the variables/PATH entries
# they define. An attacker who can influence the appended value
# (PR title, issue body, fork branch name, ...) can override
# `NODE_OPTIONS`, front-load a malicious directory on PATH, and hijack
# later tool invocations — exfiltrating secrets when the workflow runs
# under a secret-bearing trigger (pull_request_target, workflow_run).
#
# The check fires when a script line writes to $GITHUB_ENV or
# $GITHUB_PATH AND the line contains a GitHub template expression
# known to carry user input (github.event.*, github.head_ref,
# github.pull_request.*). The env: binding pattern stays quiet —
# `echo "VAR=$SAFE_BIND" >> $GITHUB_ENV` with SAFE_BIND coming from
# an `env:` block is not matched because the expression is not on the
# same line as the redirect.
package github_env_injection

import rego.v1

# Expressions GitHub considers attacker-influenceable under fork-based
# triggers. Same list as the template-injection policy (ISSUE-207);
# any value under `github.event.*` or `github.head_ref` can be
# replaced by a PR author.
unsafe_patterns := [
	`\${{\s*github\.event\.`,
	`\${{\s*github\.head_ref\s*}}`,
	`\${{\s*github\.pull_request\.`,
]

# sink_patterns are regex patterns matching a shell redirect that
# writes into one of the two special GitHub files. Covers both the
# `$GITHUB_ENV` and `${GITHUB_ENV}` forms, plus the rarer `tee`-style
# variant.
sink_patterns := [
	`>>\s*\$\{?GITHUB_ENV\}?`,
	`>\s*\$\{?GITHUB_ENV\}?`,
	`>>\s*\$\{?GITHUB_PATH\}?`,
	`>\s*\$\{?GITHUB_PATH\}?`,
	`\btee\s+-a\s+\$\{?GITHUB_ENV\}?`,
	`\btee\s+-a\s+\$\{?GITHUB_PATH\}?`,
]

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	script := job.scripts[j]
	_writes_to_github_file(script)
	_has_unsafe_expression(script)
	finding := {
		"code":     "ISSUE-209",
		"severity": "critical",
		"message":  sprintf("job %q writes a user-controlled template expression into $GITHUB_ENV or $GITHUB_PATH — an attacker can hijack later steps", [job.name]),
		"job":      job.name,
	}
}

_writes_to_github_file(line) if {
	regex.match(sink_patterns[_], line)
}

_has_unsafe_expression(line) if {
	regex.match(unsafe_patterns[_], line)
}
