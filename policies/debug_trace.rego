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
		"code":            "ISSUE-203",
		"severity":        "critical",
		"message":         sprintf("%s = %q (job %q)", [k, v, job.name]),
		"job":             job.name,
		"variableName":    k,
		"value":           v,
		"valueProvenance": "ci_file",
		"location":        job.name,
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
		"code":            "ISSUE-203",
		"severity":        "critical",
		"message":         sprintf("%s = %q (global variables)", [k, v]),
		"variableName":    k,
		"value":           v,
		"valueProvenance": "ci_file",
		"location":        "global",
	}
}

_is_truthy(v) if lower(trim_space(v)) == "true"

_is_truthy(v) if lower(trim_space(v)) == "1"

_is_truthy(v) if lower(trim_space(v)) == "yes"

# GitHub hardening: a forbidden debug toggle referenced via `${{ }}`
# in committed `env:` cannot be proven off at scan time (org/repo
# Variables may set it true at runtime). Complements the literal-
# truthy rule above; does not apply to GitLab CI variable syntax.
deny contains finding if {
	input.pipeline.provider == "github"
	count(input.config.debugTrace.forbiddenVariables) > 0
	some i
	job := input.pipeline.jobs[i]
	some var_name in input.config.debugTrace.forbiddenVariables
	some k, v in job.variables
	upper(k) == upper(var_name)
	not _is_truthy(v)
	_is_expression(v)
	finding := {
		"code":            "ISSUE-203",
		"severity":        "critical",
		"message":         sprintf("%s uses a GitHub expression %q (job %q) — debug logging cannot be verified off statically", [k, v, job.name]),
		"job":             job.name,
		"variableName":    k,
		"value":           v,
		"valueProvenance": "ci_file",
		"location":        job.name,
	}
}

# GitHub hardening: enabling debug via $GITHUB_ENV in a `run:` step
# bypasses static `env:` scanning. Match any configured forbidden
# name on the same line as a GITHUB_ENV redirect.
deny contains finding if {
	input.pipeline.provider == "github"
	count(input.config.debugTrace.forbiddenVariables) > 0
	some i, j
	job := input.pipeline.jobs[i]
	script := job.scripts[j]
	some var_name in input.config.debugTrace.forbiddenVariables
	_writes_to_github_env(script)
	_script_mentions_var(script, var_name)
	finding := {
		"code":         "ISSUE-203",
		"severity":     "critical",
		"message":      sprintf("job %q writes %q to $GITHUB_ENV — enables runner debug logging for subsequent steps", [job.name, var_name]),
		"job":          job.name,
		"variableName": var_name,
		"location":     job.name,
	}
}

_is_expression(v) if regex.match(`\$\{\{`, v)

_github_env_sink_patterns := [
	`>>\s*\$\{?GITHUB_ENV\}?`,
	`>\s*\$\{?GITHUB_ENV\}?`,
	`\btee\s+-a\s+\$\{?GITHUB_ENV\}?`,
]

_writes_to_github_env(line) if {
	regex.match(_github_env_sink_patterns[_], line)
}

_script_mentions_var(line, var_name) if {
	regex.match(sprintf(`(?i)\b%s\b`, [var_name]), line)
}
