# insecure-commands — detect workflows that re-enable the deprecated
# GitHub Actions workflow commands (`::set-env::`, `::add-path::`).
# These commands were disabled by GitHub after CVE-2020-15228 because
# they let attacker-controlled log output rewrite the running job's
# environment and PATH from inside a step. Turning them back on via
# `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` re-introduces the exact
# injection sink a mitigation was deployed to close.
package insecure_commands

import rego.v1

deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	_insecure_commands_enabled(job.variables)
	finding := {
		"code":     "ISSUE-208",
		"severity": "high",
		"message":  sprintf("job %q re-enables deprecated workflow commands via ACTIONS_ALLOW_UNSECURE_COMMANDS (CVE-2020-15228)", [job.name]),
		"job":      job.name,
	}
}

_insecure_commands_enabled(vars) if {
	vars["ACTIONS_ALLOW_UNSECURE_COMMANDS"] == "true"
}
