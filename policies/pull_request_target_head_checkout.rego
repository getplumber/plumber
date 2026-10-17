# pull-request-target-head-checkout — flag the precise vector behind
# the March 2025 tj-actions/changed-files compromise (CVE-2025-30066):
# a workflow triggered by `pull_request_target` that calls
# actions/checkout with a `ref:` pointing at the PR head
# (github.event.pull_request.head.sha, github.head_ref, …).
#
# pull_request_target already fires the broader dangerous-triggers
# check (ISSUE-802) — this rule pinpoints the exploitable
# configuration where base-repo secrets AND fork-controlled code
# coexist in the same run. The severity is critical and distinct so
# an operator can prioritise it above the general trigger warning.
#
# A job-level `if:` that restricts execution to same-repository
# (non-fork) pull requests neutralises the exploit (fork-controlled
# code never runs), but the guard is read off the condition's text, so
# it downgrades the finding rather than suppressing it: the finding is
# still emitted, marked `forkGuard: true`, and control.MarkGatedFindings
# prices it Low with the gate note, the route of every gated finding.
package pull_request_target_head_checkout

import rego.v1
import data.lib.provenance

# Refs known to resolve to attacker-controlled content under a
# pull_request_target trigger.
fork_ref_patterns := [
	`github\.event\.pull_request\.head\.sha`,
	`github\.event\.pull_request\.head\.ref`,
	`github\.head_ref`,
	`github\.event\.number`,
]

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	_under_pull_request_target(job)
	action := job.uses[j]
	startswith(action.uses, "actions/checkout@")
	ref := action.with.ref
	is_string(ref)
	_ref_points_at_pr_head(ref)
	finding := object.union(object.union({
		"code":     "ISSUE-804",
		"severity": "critical",
		"message":  provenance.message(sprintf("job %q runs under pull_request_target AND checks out the PR head (ref=%q) \u2014 base-repo secrets and fork-controlled code in the same run (tj-actions / CVE-2025-30066 pattern)", [job.name, ref]), action),
		"job":      job.name,
		"uses":     action.uses,
		"ref":      ref,
		"line":     object.get(action, "line", 0),
	}, _fork_guard_fields(job, action)), provenance.fields(action))
}

# _fork_guard_fields marks a finding whose job carries a fork guard; a
# job without one keeps the finding's original shape.
default _fork_guard_fields(_, _) := {}

_fork_guard_fields(job, action) := {"forkGuard": true} if _has_fork_guard(job, action)

_under_pull_request_target(job) if {
	some t in job.triggers
	t == "pull_request_target"
}

_ref_points_at_pr_head(ref) if {
	some p in fork_ref_patterns
	regex.match(p, ref)
}

# fork_guard_patterns are `if:`-condition fragments that restrict a
# job to same-repository (non-fork) pull requests. When any of the
# job's conditions carries one, fork-controlled code never executes
# under pull_request_target and the exploit does not apply.
fork_guard_patterns := [
	`head\.repo\.full_name\s*==\s*github\.repository`,
	`github\.repository\s*==\s*[^=]*head\.repo\.full_name`,
	`head\.repo\.fork\s*==\s*false`,
	`head\.repo\.fork\s*!=\s*true`,
	`!\s*github\.event\.pull_request\.head\.repo\.fork`,
]

# Only the conditions that gate the checkout count: the job-level if:,
# which gates every step, and the checkout step's own if:. A guard on
# another step (a deploy after the build) gates nothing the checked-out
# code runs, so job.conditions, which flattens every step's if:, is not
# read here.
_has_fork_guard(job, action) if {
	some cond in [object.get(job, "if", ""), object.get(action, "if", "")]
	cond != ""
	some p in fork_guard_patterns
	regex.match(p, cond)
}
