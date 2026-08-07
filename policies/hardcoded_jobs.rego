# hardcoded-jobs — flag pipeline jobs defined directly in the project
# .gitlab-ci.yml instead of sourced from a reviewed include, template
# or component. Hardcoded jobs escape the approval/versioning flow
# that governs shared CI assets, making them a common blind spot for
# supply-chain governance.
package hardcoded_jobs

import rego.v1

deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	job.originKind == "hardcoded"
	finding := {
		"code":     "ISSUE-401",
		"severity": "medium",
		"message":  sprintf("job %q is hardcoded (not sourced from include/component/template)", [job.name]),
		"job":      job.name,
		# hardcodedJob names what this finding is about, so its identity is the
		# job rather than the wording of the message above (finding/identity).
		# Not "jobName": that was a v0.2.x output alias for `job`, retired on
		# purpose, and reviving the key would confuse JSON consumers.
		"hardcodedJob": job.name,
	}
}
