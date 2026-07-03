# template-injection-vars — flag `run:` scripts that expand a
# maintainer-adjacent template directly into the shell. Distinct
# from ISSUE-207 (template-injection) which targets PR-author-
# controlled `github.event.*` / `github.head_ref` — here the
# sources are:
#
#   - `vars.*`    — repo / org / environment variables set by
#                   maintainers. Exploitable on a maintainer
#                   account compromise or a misconfigured
#                   organisation-level variable.
#   - `inputs.*`  — reusable-workflow inputs. When the reusable
#                   workflow is called from a fork-influenceable
#                   trigger (e.g. a caller workflow that proxies
#                   `github.event.*` into inputs), the surface
#                   flips to PR-author-controlled.
#   - `github.event.inputs.*` — the legacy input context. It is only
#                   flagged under a trigger where the value can carry
#                   fork / caller influence (`workflow_call`,
#                   `pull_request_target`); a `workflow_dispatch`-only
#                   workflow takes its inputs from the maintainer who
#                   pressed "Run", so it stays silent to avoid noise.
#
# Confidence is lower than ISSUE-207; severity stays at "low".
# The fix is the same for both: bind the value through `env:`
# first, then dereference the shell variable from the `run:` body
# so expansion quotes the value instead of concatenating it as
# code.
package template_injection_vars

import rego.v1

unsafe_patterns := [
	`\$\{\{\s*vars\.`,
	`\$\{\{\s*inputs\.`,
]

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	script := job.scripts[j]
	some k
	regex.match(unsafe_patterns[k], script)
	finding := {
		"code":     "ISSUE-215",
		"severity": "low",
		"message":  sprintf("job %q expands a maintainer-adjacent template (`vars.*` or `inputs.*`) directly into a shell script — bind through `env:` and reference $VAR instead", [job.name]),
		"job":      job.name,
	}
}

# Triggers under which `github.event.inputs.*` can carry caller- or
# fork-influenced values. `workflow_dispatch` alone is intentionally
# excluded: its inputs come from the maintainer who launched the run.
gated_input_triggers := {"workflow_call", "pull_request_target"}

# `github.event.inputs.*` expanded into a shell body, but only when the
# job runs under a trigger from gated_input_triggers. This is the legacy
# input context the `inputs.*` pattern above does not reach (the
# `github.event.` prefix sits between `${{` and `inputs.`).
deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	_has_gated_input_trigger(job)
	script := job.scripts[j]
	regex.match(`\$\{\{\s*github\.event\.inputs\.`, script)
	finding := {
		"code":     "ISSUE-215",
		"severity": "low",
		"message":  sprintf("job %q expands `github.event.inputs.*` directly into a shell script under a caller-/fork-influenceable trigger — bind through `env:` and reference $VAR instead", [job.name]),
		"job":      job.name,
	}
}

_has_gated_input_trigger(job) if {
	some t in job.triggers
	gated_input_triggers[t]
}
