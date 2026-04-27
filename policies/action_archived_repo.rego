# action-archived-repo — flag workflow steps that reference an action
# whose GitHub repository is archived. Archived repos no longer
# receive maintenance; any existing vulnerability stays open and the
# project has no path for future security patches.
#
# Driven by the collector's API-resolved metadata. When the metadata
# is missing (gh not authenticated, offline run, non-GitHub action)
# the policy stays silent: we never raise a finding on the absence of
# positive evidence.
package action_archived_repo

import rego.v1

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	action := job.uses[j]
	action.metadata.repoArchived == true
	finding := {
		"code":     "ISSUE-108",
		"severity": "high",
		"message":  sprintf("job %q references %q whose upstream repository is archived — no security patches are coming", [job.name, action.uses]),
		"job":      job.name,
		"line":     object.get(action, "line", 0),
	}
}
