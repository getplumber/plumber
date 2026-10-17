# excessive-permissions — flag pipeline jobs whose effective permissions
# block grants blanket write access. For GitHub Actions this is
# `permissions: write-all` set either at workflow level (propagated to
# every job by the collector) or at the job level.
#
# Stricter forms (e.g. { contents: read, packages: write }) are out of
# scope for now — a later iteration may accept a per-rule allow-list of
# permitted scopes. This policy has no runtime configuration yet.
package excessive_permissions

import rego.v1

deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	# A job of a workflow called in another repository runs with the token
	# its calling job gives it, and the calling job is judged by its own
	# finding (monorepo spec 2026-10-16 section 5, plan ruling 15).
	not job.nested
	job.permissions == "write-all"
	finding := {
		"code":     "ISSUE-803",
		"severity": "high",
		"message":  sprintf("job %q runs with overly broad permissions: \"write-all\"", [job.name]),
		"job":      job.name,
	}
}
