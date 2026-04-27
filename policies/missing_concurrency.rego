# missing-concurrency — flag GitHub Actions workflows that declare no
# `concurrency:` block at either the workflow level or on any of
# their jobs. Concurrent triggers on the same ref (rebases,
# force-pushes, CI retries) then race on caches, artefact uploads,
# and external state, and — worse — can deploy stale output by
# overtaking a newer run. Declaring concurrency (usually
# grouped by `${{ github.workflow }}-${{ github.ref }}`) makes the
# later run the one that lands.
#
# The policy aggregates by originFile: a workflow is fine as soon as
# ONE of its jobs — or the workflow header — declares concurrency.
package missing_concurrency

import rego.v1

deny contains finding if {
	input.pipeline.provider == "github"
	some file in _workflow_files_missing_concurrency
	finding := {
		"code":     "ISSUE-602",
		"severity": "medium",
		"message":  sprintf("workflow file %q declares no concurrency group — concurrent runs will race on caches, deploys and artefacts", [file]),
		"file":     file,
	}
}

_workflow_files_missing_concurrency contains file if {
	# Collect every workflow file seen, then subtract the ones that
	# are covered either at workflow or job level.
	some i
	job := input.pipeline.jobs[i]
	file := job.originFile
	file != ""
	not _workflow_covered(file)
}

_workflow_covered(file) if {
	some i
	job := input.pipeline.jobs[i]
	job.originFile == file
	job.workflowHasConcurrency
}

_workflow_covered(file) if {
	some i
	job := input.pipeline.jobs[i]
	job.originFile == file
	job.jobHasConcurrency
}
