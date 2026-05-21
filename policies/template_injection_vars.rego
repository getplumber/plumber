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
