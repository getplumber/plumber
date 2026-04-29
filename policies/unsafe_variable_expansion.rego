# unsafe-variable-expansion — flag pipeline scripts that pipe or
# re-parse an attacker-controlled CI variable through a shell. The
# classic sinks are `eval`, `sh -c`, `bash -c`, `dash/zsh/ksh -c`,
# `envsubst|xargs` chains, and shell sourcing (`source` /
# `. file`). When the variable carried into those sinks is one of the
# user-influenceable CI variables (CI_COMMIT_MESSAGE,
# CI_COMMIT_BRANCH, etc.), an attacker pushing a crafted commit or
# branch name can execute arbitrary shell code.
#
# Parity with the legacy Go control:
#   - The pattern list mirrors controlGitlabPipelineVariableInjection.go
#     verbatim (eval, *sh -c, envsubst|sh, xargs sh|bash, source, dot
#     sourcing).
#   - Empty/comment lines are skipped before re-parse detection.
#   - Variable detection enforces a word boundary on the unbraced
#     `$VAR` form, mirroring the legacy regex
#     `\$(?:\{VAR\}|VAR(?:[^a-zA-Z0-9_]|$))`. So `$CI_COMMIT_MESSAGE`
#     matches but `$CI_COMMIT_MESSAGE_OTHER` does not.
#
# Config:
#   input.config.unsafeVariableExpansion.dangerousVariables = ["CI_COMMIT_MESSAGE", …]
#   input.config.unsafeVariableExpansion.allowedPatterns    = ["safe pattern", …]
package unsafe_variable_expansion

import rego.v1

shell_reparse_patterns := [
	`\beval\b`,
	`\b(sh|bash|dash|zsh|ksh)\s+-c\b`,
	`\benvsubst\b.*\|\s*(sh|bash|dash|zsh)`,
	`\bxargs\s+(sh|bash)\b`,
	`\bsource\b`,
	`^\s*\.(\s|$)`,
]

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	line := job.scripts[j]
	trimmed := trim_space(line)
	trimmed != ""
	not startswith(trimmed, "#")
	_has_shell_reparse(trimmed)
	var_name := _dangerous_variable_in_line(line)
	not _is_allowed(line)
	block := _script_block(job, j)
	finding := {
		"code":         "ISSUE-204",
		"severity":     "high",
		"message":      sprintf("$%s in job '%s' %s: %s", [var_name, job.name, block, trimmed]),
		"job":          job.name,
		"variableName": var_name,
		"scriptLine":   trimmed,
		"scriptBlock":  block,
	}
}

# _script_block returns the block label ("before_script", "script",
# "after_script") for the script line at index `j`. Falls back to
# "script" when the collector did not populate ScriptBlocks (older
# fixtures, non-GitLab providers).
_script_block(job, j) := block if {
	block := job.scriptBlocks[j]
	block != ""
} else := "script"

_has_shell_reparse(line) if {
	regex.match(shell_reparse_patterns[_], line)
}

_dangerous_variable_in_line(line) := name if {
	some candidate in input.config.unsafeVariableExpansion.dangerousVariables
	_variable_used(line, candidate)
	name := candidate
}

# Match ${VAR} (braced — exact name).
_variable_used(line, name) if {
	regex.match(sprintf(`\$\{%s\}`, [name]), line)
}

# Match $VAR followed by a non-word boundary or end-of-line. Mirrors
# the legacy `\$VAR(?:[^a-zA-Z0-9_]|$)` form so `$CI_COMMIT_MESSAGE`
# is flagged but `$CI_COMMIT_MESSAGE_OTHER` is not.
_variable_used(line, name) if {
	regex.match(sprintf(`\$%s($|[^a-zA-Z0-9_])`, [name]), line)
}

_is_allowed(line) if {
	pattern := input.config.unsafeVariableExpansion.allowedPatterns[_]
	regex.match(pattern, line)
}
