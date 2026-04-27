# job-variable-override — flag jobs that define (and therefore
# override) a variable that should only live in the platform settings
# (GitLab CI/CD Settings > Variables, GitHub repository secrets, …).
# The authoritative list ships in .plumber.yaml under
# pipelineMustNotOverrideJobVariables.variables.
#
# Only jobs declared directly in the project's `.gitlab-ci.yml`
# (originKind == "hardcoded") are checked: imported components and
# templates legitimately set their own variables, and flagging those
# would punish projects for using upstream catalogs they do not
# author.
package job_variable_override

import rego.v1

deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	not _job_from_imported_origin(job)
	some var_name in _protected_variables
	job.variables[var_name]
	finding := {
		"code":         "ISSUE-205",
		"severity":     "critical",
		"message":      sprintf("job %q defines %q, which must be set in the platform settings only", [job.name, var_name]),
		"job":          job.name,
		"variableName": var_name,
		"value":        job.variables[var_name],
		"location":     job.name,
	}
}

# Imported origins: jobs that come from an upstream component or
# template. Those legitimately set their own variables and the
# project author has no way to override them at the YAML level.
_job_from_imported_origin(job) if job.originKind == "component"

_job_from_imported_origin(job) if job.originKind == "template"

# Pipeline-level globals override the platform-only contract just as
# job-level definitions do. Emit once per protected variable defined
# at the global block.
deny contains finding if {
	some var_name in _protected_variables
	input.pipeline.globalVariables[var_name]
	finding := {
		"code":         "ISSUE-205",
		"severity":     "critical",
		"message":      sprintf("pipeline-level global variable %q overrides a platform-only setting", [var_name]),
		"variableName": var_name,
		"value":        input.pipeline.globalVariables[var_name],
		"location":     "global",
	}
}

_protected_variables := vars if {
	vars := input.config.jobVariablesOverride.protectedVariables
	count(vars) > 0
} else := []
