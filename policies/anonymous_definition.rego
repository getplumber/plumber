# anonymous-definition — flag GitHub Actions workflow files that omit
# the top-level `name:` field. Without an explicit name, GitHub uses
# the file path as the display identifier in the Actions UI, PR
# checks, the required-status-check settings on branch protections,
# and the audit log. Renaming the file later silently breaks any
# required-check binding that references the old path, giving the
# appearance of a passing gate when nothing is actually running.
#
# The policy emits once per workflow file (not once per job) by
# deduplicating on originFile before building the findings set.
package anonymous_definition

import rego.v1

deny contains finding if {
	input.pipeline.provider == "github"
	some file in _anonymous_workflow_files
	finding := {
		"code":     "ISSUE-601",
		"severity": "low",
		"message":  sprintf("workflow file %q has no top-level `name:` — GitHub falls back to the file path", [file]),
		"file":     file,
	}
}

_anonymous_workflow_files contains file if {
	# json:",omitempty" drops the field from the serialised IR when
	# the workflow has no name, so we test for absence with `not`
	# rather than `== ""`.
	some i
	job := input.pipeline.jobs[i]
	not job.workflowName
	job.originFile != ""
	file := job.originFile
}
