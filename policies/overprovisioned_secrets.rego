# overprovisioned-secrets — flag workflows that serialise the entire
# GitHub Actions `secrets` context with `toJson(secrets)` /
# `toJSON(secrets)` and pass it into a step. The JSON payload contains
# every repository, organisation and environment secret the job has
# access to; once the string lands in a run script, an env binding or
# a `with:` input it can leak through logs, third-party actions, or
# whatever downstream consumer the step invokes. Even a single
# `echo "$SECRETS"` has been enough in past incidents — GitHub's log
# redaction works on known secret values, not on a JSON blob derived
# from them.
#
# The policy looks at three sinks:
#   - job scripts        (jobs.<name>.steps[].run)
#   - job env bindings   (jobs.<name>.env + steps[].env rolled up)
#   - action inputs      (jobs.<name>.steps[].with[*])
# A finding fires as soon as one of them references the full secrets
# context. Scoped references like `${{ secrets.NPM_TOKEN }}` are
# ignored — they name a specific secret and are the intended pattern.
package overprovisioned_secrets

import rego.v1

# Matches `toJson(secrets)`, `toJSON(secrets)`, and their whitespace-
# permissive variants. The wrapping `${{ }}` is not required for the
# match — some workflows build the string with `fromJSON(toJson(...))`
# chains and we want to catch those too.
secrets_dump_pattern := `(?i)to\s*json\s*\(\s*secrets\s*\)`

deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	_job_dumps_secrets(job)
	finding := {
		"code":     "ISSUE-301",
		"severity": "critical",
		"message":  sprintf("job %q exports the entire secrets context via toJson(secrets) — pass secrets by name instead", [job.name]),
		"job":      job.name,
	}
}

_job_dumps_secrets(job) if {
	some k
	regex.match(secrets_dump_pattern, job.scripts[k])
}

_job_dumps_secrets(job) if {
	some _, value in job.variables
	regex.match(secrets_dump_pattern, value)
}

_job_dumps_secrets(job) if {
	some k
	action := job.uses[k]
	some _, value in action.with
	is_string(value)
	regex.match(secrets_dump_pattern, value)
}
