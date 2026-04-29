# debug-trace — flag pipeline jobs that enable CI debug tracing. When
# CI_DEBUG_TRACE=true (or the newer CI_DEBUG_SERVICES=true) is set,
# GitLab Runner prints every environment variable, including masked
# secrets, to the job log — a well-documented secret-leak path.
#
# Parity with the legacy Go control (controlGitlabPipelineDebugTrace.go):
#   - Variable name comparison is case-insensitive.
#   - Truthy values are `true`, `1`, `yes` (case-insensitive, trimmed).
#   - The control is a no-op unless the user populates
#     `pipelineMustNotEnableDebugTrace.forbiddenVariables` in
#     .plumber.yaml — there is no built-in default list. This matches
#     the legacy GetConf path that disables the control when the
#     forbiddenVariables list is empty.
package debug_trace

import rego.v1

deny contains finding if {
	count(input.config.debugTrace.forbiddenVariables) > 0
	some i
	job := input.pipeline.jobs[i]
	some var_name in input.config.debugTrace.forbiddenVariables
	some k, v in job.variables
	upper(k) == upper(var_name)
	_is_truthy(v)
	finding := {
		"code":         "ISSUE-203",
		"severity":     "critical",
		"message":      sprintf("%s = %q (job %q)", [k, v, job.name]),
		"job":          job.name,
		"variableName": k,
		"value":        v,
		"location":     job.name,
	}
}

# Pipeline-level globals (`variables:` at the top of .gitlab-ci.yml)
# apply to every job, so emit one finding for the pipeline rather than
# duplicating per job.
deny contains finding if {
	count(input.config.debugTrace.forbiddenVariables) > 0
	some var_name in input.config.debugTrace.forbiddenVariables
	some k, v in input.pipeline.globalVariables
	upper(k) == upper(var_name)
	_is_truthy(v)
	finding := {
		"code":         "ISSUE-203",
		"severity":     "critical",
		"message":      sprintf("%s = %q (global variables)", [k, v]),
		"variableName": k,
		"value":        v,
		"location":     "global",
	}
}

_is_truthy(v) if lower(trim_space(v)) == "true"

_is_truthy(v) if lower(trim_space(v)) == "1"

_is_truthy(v) if lower(trim_space(v)) == "yes"
