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
#   - `github.event.inputs.*` — the legacy spelling of the same input
#                   context, reached separately because the
#                   `github.event.` prefix sits between `${{` and
#                   `inputs.`.
#
# Deliberately NOT gated by trigger. An earlier revision fired this one
# only under `workflow_call` / `pull_request_target`, on the reasoning
# that a `workflow_dispatch`-only workflow takes its inputs from the
# maintainer who pressed "Run". That produced two verdicts for one
# value: in a dispatch-only workflow `${{ inputs.version }}` was
# flagged by the pattern above while `${{ github.event.inputs.version }}`
# on the next line was not. Same input, same author, same risk.
#
# The gate was also wrong on its own terms. `github.event.inputs` is
# the workflow_dispatch payload; a `pull_request_target` event carries
# no `inputs` key at all, so that arm matched an expression that is
# always empty - the false-positive class ISSUE-207 explicitly refuses
# to match. And a called workflow inherits `github.event` from the
# caller's originating event, so under `workflow_call` the value IS the
# dispatch payload the gate meant to exempt.
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
	# The legacy input context. Same value as `inputs.*`, written the
	# older way; the `github.event.` prefix sits between `${{` and
	# `inputs.`, so the pattern above never reaches it.
	`\$\{\{\s*github\.event\.inputs\.`,
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
		"message":  sprintf("job %q expands a maintainer-adjacent template (`vars.*`, `inputs.*` or `github.event.inputs.*`) directly into a shell script — bind through `env:` and reference $VAR instead", [job.name]),
		"job":      job.name,
	}
}
