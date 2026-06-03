# unsafe-github-context-dump — flag workflows that serialise the
# whole `github` context (or `github.event`) with `toJson(...)` and
# hand it to a script, env binding, or action input. The resulting
# JSON carries every user-controllable field GitHub exposes; any
# downstream consumer (log, third-party action, HTTP header) then
# sees a payload that is trivially shell-injectable under privileged
# triggers (`pull_request_target`, `workflow_run`).
#
# Mirror of ISSUE-309 (overprovisioned-secrets) applied to the
# github context. Severity is high rather than critical: the
# github context does not carry long-lived tokens like `secrets`
# does, but it can still be weaponised into shell injection.
package unsafe_github_context_dump

import rego.v1

# Matches toJson(github), toJson(github.event), and whitespace-
# permissive variants. Case-insensitive because GitHub accepts both
# `toJson` and `toJSON`.
context_dump_pattern := `(?i)to\s*json\s*\(\s*github(\.event)?\s*\)`

deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	_job_dumps_github(job)
	finding := {
		"code":     "ISSUE-213",
		"severity": "high",
		"message":  sprintf("job %q serialises the entire `github` context via toJson(github) — pass specific fields by name instead", [job.name]),
		"job":      job.name,
	}
}

_job_dumps_github(job) if {
	some k
	regex.match(context_dump_pattern, job.scripts[k])
}

_job_dumps_github(job) if {
	some _, value in job.variables
	regex.match(context_dump_pattern, value)
}

_job_dumps_github(job) if {
	some k
	action := job.uses[k]
	some _, value in action.with
	is_string(value)
	regex.match(context_dump_pattern, value)
}
