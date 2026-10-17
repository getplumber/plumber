# undocumented-permissions — flag jobs that run with no explicit
# `permissions:` block at either the workflow or job level. When
# neither layer declares permissions, the GITHUB_TOKEN falls back to
# the repository-wide default — often `contents: write` or
# `read-all` — and every step gets more authority than it needs.
# Any compromise (unpinned action, template-injection, cache
# poisoning) inherits that default.
#
# The collector materialises the effective permissions on each job:
# job-level first, falling back to workflow-level. When both are
# absent, `permissions` is nil / missing from the JSON, which is
# exactly what this policy looks for.
#
# GitHub Actions only — the `permissions:` keyword does not exist in
# GitLab CI, so applying this rule there would flag every GitLab job
# as a false positive.
package undocumented_permissions

import rego.v1

deny contains finding if {
	input.pipeline.provider == "github"
	some i
	job := input.pipeline.jobs[i]
	# A job of a workflow called in another repository runs with the token
	# its calling job gives it, and the calling job is judged by its own
	# finding (monorepo spec 2026-10-16 section 5, plan ruling 15).
	not job.nested
	not job.permissions
	finding := {
		"code":     "ISSUE-801",
		"severity": "medium",
		"message":  sprintf("job %q runs with no explicit `permissions:` block — the GITHUB_TOKEN inherits the repository default scope", [job.name]),
		"job":      job.name,
	}
}
