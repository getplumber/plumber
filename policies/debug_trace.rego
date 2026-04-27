# debug-trace — flag pipeline jobs that enable CI debug tracing. When
# CI_DEBUG_TRACE=true (or the newer CI_DEBUG_SERVICES=true) is set,
# GitLab Runner prints every environment variable, including masked
# secrets, to the job log — a well-documented secret-leak path.
#
# The list of forbidden variable names is configurable in
# .plumber.yaml under
# pipelineMustNotEnableDebugTrace.forbiddenVariables.
package debug_trace

import rego.v1

deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	some var_name in _forbidden_variables
	_variable_enabled(job.variables, var_name)
	finding := {
		"code":         "ISSUE-203",
		"severity":     "critical",
		"message":      sprintf("job %q enables %q, which prints secret values to the job log", [job.name, var_name]),
		"job":          job.name,
		"variableName": var_name,
		"value":        job.variables[var_name],
		"location":     job.name,
	}
}

# Pipeline-level globals (`variables:` at the top of .gitlab-ci.yml)
# apply to every job, so emit one finding for the pipeline rather than
# duplicating per job.
deny contains finding if {
	some var_name in _forbidden_variables
	_variable_enabled(input.pipeline.globalVariables, var_name)
	finding := {
		"code":         "ISSUE-203",
		"severity":     "critical",
		"message":      sprintf("pipeline-level global variable %q is enabled, which prints secret values to every job's log", [var_name]),
		"variableName": var_name,
		"value":        input.pipeline.globalVariables[var_name],
		"location":     "global",
	}
}

_forbidden_variables := vars if {
	vars := input.config.debugTrace.forbiddenVariables
	count(vars) > 0
} else := ["CI_DEBUG_TRACE", "CI_DEBUG_SERVICES"]

_variable_enabled(vars, name) if {
	vars[name] == "true"
}
