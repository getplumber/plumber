# job-variable-override — flag jobs that define (and therefore
# override) a variable that should only live in the platform settings
# (GitLab CI/CD Settings > Variables, GitHub repository secrets, …).
# The authoritative list ships in .plumber.yaml under
# pipelineMustNotOverrideJobVariables.variables.
#
# The policy reads job.localVariables — the `variables:` block the
# project author wrote directly in .gitlab-ci.yml — never the merged
# Variables map. This way variables shipped by an upstream component
# or template stay out of scope (only the user's deliberate override
# matters), while a user-authored override on a job inherited from a
# component (e.g. `secret_detection: { variables: { SAST_DISABLED:
# true } }`) still fires. Mirrors the legacy raw-conf scan in
# controlGitlabPipelineJobVariablesOverride.go.
package job_variable_override

import rego.v1

deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	some var_name in _protected_variables
	job.localVariables[var_name]
	finding := {
		"code":         "ISSUE-205",
		"severity":     "critical",
		"message":      sprintf("%s = %q (job %q)", [var_name, job.localVariables[var_name], job.name]),
		"job":          job.name,
		"variableName": var_name,
		"value":        job.localVariables[var_name],
		"location":     job.name,
	}
}

# Pipeline-level globals override the platform-only contract just as
# job-level definitions do. Emit once per protected variable defined
# at the global block.
deny contains finding if {
	some var_name in _protected_variables
	input.pipeline.globalVariables[var_name]
	finding := {
		"code":         "ISSUE-205",
		"severity":     "critical",
		"message":      sprintf("%s = %q (global variables)", [var_name, input.pipeline.globalVariables[var_name]]),
		"variableName": var_name,
		"value":        input.pipeline.globalVariables[var_name],
		"location":     "global",
	}
}

_protected_variables := vars if {
	vars := input.config.jobVariablesOverride.protectedVariables
	count(vars) > 0
} else := []
