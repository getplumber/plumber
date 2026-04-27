# pull-request-target-head-checkout — flag the precise vector behind
# the March 2025 tj-actions/changed-files compromise (CVE-2025-30066):
# a workflow triggered by `pull_request_target` that calls
# actions/checkout with a `ref:` pointing at the PR head
# (github.event.pull_request.head.sha, github.head_ref, …).
#
# pull_request_target already fires the broader dangerous-triggers
# check (ISSUE-414) — this rule pinpoints the exploitable
# configuration where base-repo secrets AND fork-controlled code
# coexist in the same run. The severity is critical and distinct so
# an operator can prioritise it above the general trigger warning.
package pull_request_target_head_checkout

import rego.v1

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
	finding := {
		"code":     "ISSUE-415",
		"severity": "critical",
		"message":  sprintf("job %q runs under pull_request_target AND checks out the PR head (ref=%q) — base-repo secrets and fork-controlled code in the same run (tj-actions / CVE-2025-30066 pattern)", [job.name, ref]),
		"job":      job.name,
		"line":     object.get(action, "line", 0),
	}
}

_under_pull_request_target(job) if {
	some t in job.triggers
	t == "pull_request_target"
}

_ref_points_at_pr_head(ref) if {
	some p in fork_ref_patterns
	regex.match(p, ref)
}
