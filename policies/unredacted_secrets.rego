# unredacted-secrets — flag workflows that deserialise a secret via
# fromJSON and reference one of its sub-fields. GitHub's runtime log
# redaction works on known secret strings (those declared in the
# secrets store). Once `fromJSON(secrets.X).y` evaluates, the inner
# field is a brand-new string the runtime has never seen, so every
# subsequent print / log / HTTP header leaks it verbatim.
#
# The check looks for the pattern `fromJSON(secrets.…).<field>` across
# scripts, env bindings and `with:` inputs. The bare
# `fromJSON(secrets.X)` form that stays inside an opaque object — no
# `.y` dereference on the same line — is not flagged; only the
# projection leaks.
package unredacted_secrets

import rego.v1

# Whitespace tolerated around fromJSON / secrets; trailing `.ident`
# required so the bare `fromJSON(secrets.X)` with no projection stays
# silent. Case-insensitive for the fromJSON keyword since GitHub
# accepts both `fromJson` and `fromJSON`.
unredacted_pattern := `(?i)fromJSON\s*\(\s*secrets\.[A-Za-z_][A-Za-z0-9_]*\s*\)\s*\.[A-Za-z_]`

deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	_job_unredacts_secrets(job)
	finding := {
		"code":     "ISSUE-303",
		"severity": "high",
		"message":  sprintf("job %q dereferences a secret via fromJSON — GitHub cannot redact the resulting sub-fields from job logs", [job.name]),
		"job":      job.name,
	}
}

_job_unredacts_secrets(job) if {
	some k
	regex.match(unredacted_pattern, job.scripts[k])
}

_job_unredacts_secrets(job) if {
	some _, value in job.variables
	regex.match(unredacted_pattern, value)
}

_job_unredacts_secrets(job) if {
	some k
	action := job.uses[k]
	some _, value in action.with
	is_string(value)
	regex.match(unredacted_pattern, value)
}
