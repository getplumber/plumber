# unsafe-variable-expansion — flag pipeline scripts that pipe or
# re-parse an attacker-controlled CI variable through a shell. The
# classic sinks are `eval`, `sh -c`, `bash -c`, `dash/zsh/ksh -c`,
# and `envsubst|xargs` chains. When the variable carried into those
# sinks is one of the user-influenceable CI variables
# (CI_COMMIT_MESSAGE, CI_COMMIT_BRANCH, etc.), an attacker pushing a
# crafted commit or branch name can execute arbitrary shell code.
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
]

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	line := job.scripts[j]
	_has_shell_reparse(line)
	var_name := _dangerous_variable_in_line(line)
	not _is_allowed(line)
	finding := {
		"code":         "ISSUE-204",
		"severity":     "high",
		"message":      sprintf("job %q re-parses attacker-influenced variable %q through a shell", [job.name, var_name]),
		"job":          job.name,
		"variableName": var_name,
		"scriptLine":   line,
		"scriptBlock":  _script_block(job, j),
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

_variable_used(line, name) if {
	contains(line, sprintf("$%s", [name]))
}

_variable_used(line, name) if {
	contains(line, sprintf("${%s", [name]))
}

_is_allowed(line) if {
	regex.match(input.config.unsafeVariableExpansion.allowedPatterns[_], line)
}
