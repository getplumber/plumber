# security-jobs-weakened — flag pipeline jobs that match the security
# job naming convention (SAST, Secret Detection, Dependency Scanning,
# …) and are silently weakened via allow_failure: true or
# when: manual. These settings let broken or skipped scans look like
# a passing pipeline, defeating the guardrail they provide.
#
# Config:
#   input.config.securityJobsWeakened.securityJobPatterns = ["*-sast", …]
#   input.config.securityJobsWeakened.allowFailureMustBeFalse = true
#   input.config.securityJobsWeakened.whenMustNotBeManual    = true
package security_jobs_weakened

import rego.v1

# A single security job can be weakened in more than one way at once
# (e.g. job-level `when: manual` AND a `rules:` override that pins
# `when: manual`). Each weakening signal is its own deny rule so the
# Rego set semantics produces one finding per (job, reason) pair
# without tripping the function-determinism check we hit when these
# branches were collapsed into a single `_weakening_reason(job)`
# function.

deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	_is_security_job(job.name)
	input.config.securityJobsWeakened.allowFailureMustBeFalse == true
	job.allowFailure == true
	reason := "allow_failure: true masks scan failures"
	finding := {
		"code":     "ISSUE-410",
		"severity": "high",
		"message":  sprintf("security job %q is weakened: %s", [job.name, reason]),
		"job":      job.name,
		"detail":   reason,
	}
}

deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	_is_security_job(job.name)
	input.config.securityJobsWeakened.whenMustNotBeManual == true
	job.when == "manual"
	reason := "when: manual prevents the scan from running automatically"
	finding := {
		"code":     "ISSUE-410",
		"severity": "high",
		"message":  sprintf("security job %q is weakened: %s", [job.name, reason]),
		"job":      job.name,
		"detail":   reason,
	}
}

# Rules-block weakening: an unconditional `- when: never` (or
# `manual`) inside the job's rules block neutralises the scan. Two
# project-side signals qualify a job as "redefined":
#   - originKind in {"hardcoded", "local", "project"}: the job was
#     declared by the project's own files.
#   - overridden == true: the job comes from an upstream
#     component/template but the project locally redefined keys.
# Vanilla upstream-only definitions (e.g. SAST template's deprecated
# bandit-sast) carry `when: never` legitimately and are skipped.
deny contains finding if {
	some i
	job := input.pipeline.jobs[i]
	_is_security_job(job.name)
	input.config.securityJobsWeakened.rulesMustNotBeRedefined == true
	_rules_redefined_by_project(job)
	some j
	rule := job.rules[j]
	w := rule.when
	_blocking_when(w)
	reason := sprintf("rules overridden with 'when: %s', job will not run", [w])
	finding := {
		"code":     "ISSUE-410",
		"severity": "high",
		"message":  sprintf("security job %q is weakened: %s", [job.name, reason]),
		"job":      job.name,
		"detail":   reason,
	}
}

_is_security_job(name) if {
	pattern := input.config.securityJobsWeakened.securityJobPatterns[_]
	glob.match(pattern, null, name)
}

# A job's rules are "redefined by the project" when either
#   - the job is locally authored (hardcoded / local / project file)
#     and ships with a rules: block, or
#   - the job is overridden from an upstream component/template and
#     the override list explicitly mentions `rules`.
# Vanilla upstream rules — even with a `when: never` line for a
# deprecated analyzer — must NOT count as a project-side weakening.
_rules_redefined_by_project(job) if {
	job.originKind == "hardcoded"
}

_rules_redefined_by_project(job) if {
	job.originKind == "local"
}

_rules_redefined_by_project(job) if {
	job.originKind == "project"
}

_rules_redefined_by_project(job) if {
	job.overridden == true
	some k
	job.overriddenKeys[k] == "rules"
}

_blocking_when("never")

_blocking_when("manual")

