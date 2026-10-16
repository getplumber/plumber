# cache-poisoning — flag jobs granted cache write on an untrusted trigger.
#
# GitHub isolates caches by ref: a run restores caches saved for its own
# ref and for the default branch. Only push, workflow_dispatch,
# repository_dispatch, delete, registry_package, page_build and schedule
# runs can create or overwrite caches in the default branch's scope; any
# other event that runs on the default branch (pull_request_target,
# issue_comment, workflow_run...) gets read-only cache access. An explicit
# cache-mode: write or write-only, on the job or its workflow, lifts that
# restriction: code running in such a run (a comment body, a pull
# request's head, an upstream run's artifact) can write caches every
# default-branch run restores.
#
# pull_request (and its review events), release and merge_group never run
# on the default branch: they write only their own ref's scope, which no
# default-branch run reads, so they are safe as well.
#
# The parser resolves the effective cache-mode (the job's own, else the
# workflow's) into job.cacheMode.effective. GitHub accepts an expression
# there only when it reads no context, so the value is the same on every
# run; an expression reading one makes the workflow file invalid and
# resolves to "", which never fires.
#
# Config (input.config.untrustedTriggersMustNotWriteCache):
#   exemptWorkflows: globs on the workflow file name ("triage.yml")
#   exemptJobs:      globs on the job name ("<workflow>/<job>")
# An exempted job is accepted risk: skipped here, listed in the output.
package cache_poisoning

import rego.v1

# cache_write_safe_triggers: the events allowed to write the cache,
# GitHub's trusted triggers plus the events that write their own ref only.
cache_write_safe_triggers := {
	"push", "workflow_dispatch", "repository_dispatch", "delete",
	"registry_package", "page_build", "schedule",
	"pull_request", "pull_request_review", "pull_request_review_comment",
	"release", "merge_group",
}

_cfg := object.get(input, ["config", "untrustedTriggersMustNotWriteCache"], {})

deny contains finding if {
	some job in input.pipeline.jobs
	decl := job.cacheMode
	decl.effective in {"write", "write-only"}
	risky := sort({t | some t in _effective_triggers(job); not t in cache_write_safe_triggers})
	count(risky) > 0
	not _exempt(job)
	finding := {
		"code": "ISSUE-705",
		"severity": "high",
		"message": sprintf("job %q runs on %s with cache-mode: %s%s, which lifts GitHub's read-only cache access for these events: code in such a run can write caches that default-branch runs restore. Set cache-mode: read on this job", [job.name, concat(", ", risky), decl.value, _where(decl)]),
		"job": job.name,
		"line": decl.line,
		"subject": _subject(job, decl),
		"cacheMode": decl.value,
		"cacheModeLevel": decl.level,
		"triggers": risky,
	}
}

_where(decl) := " (set on the workflow)" if decl.level == "workflow"

else := ""

# One declaration, one fix: a workflow-level cache-mode is the workflow's,
# a job-level one the job's.
_subject(job, decl) := _basename(job.originFile) if decl.level == "workflow"

else := job.name

# _effective_triggers: the job's own events; a reusable workflow
# (workflow_call) runs under each caller's events instead.
_effective_triggers(job) := {t | some t in object.get(job, "triggers", []); t != "workflow_call"} | {t |
	"workflow_call" in object.get(job, "triggers", [])
	some c in object.get(job, "callers", [])
	some t in object.get(c, "triggers", [])
}

_exempt(job) if {
	some pattern in object.get(_cfg, "exemptWorkflows", [])
	glob.match(pattern, null, _basename(object.get(job, "originFile", "")))
}

_exempt(job) if {
	some pattern in object.get(_cfg, "exemptJobs", [])
	glob.match(pattern, null, job.name)
}

_basename(path) := regex.replace(path, `^.*/`, "")
