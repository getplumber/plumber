# dangerous-triggers — flag jobs that are genuinely EXPLOITABLE through
# a GitHub Actions trigger that combines attacker-controlled input with
# privileged secrets. The finding fires only when a job runs under such
# a trigger AND checks out fork / PR-controlled code: untrusted code
# then executes with the base repository's secrets and token.
#
# The dangerous events all grant the workflow the base repo's secrets
# while being influenceable by users who are NOT trusted (PR authors,
# issue commenters, fork maintainers, anonymous viewers):
#
#   - pull_request_target / workflow_run — secret-bearing regardless of
#     the source PR or workflow's trust boundary.
#   - issue_comment / pull_request_review / pull_request_review_comment
#     / discussion / discussion_comment — fired by an unprivileged
#     commenter or reviewer, run with secrets on the default branch.
#   - gollum (wiki edit) / fork — triggered by any contributor.
#
# Subscribing to one of these triggers is NOT flagged on its own:
# labelling, milestone, comment and notification workflows legitimately
# need them and are safe as long as they never check out untrusted
# code. The check fires only on the exploitable combination, and
# abstains when a job-level `if:` restricts execution to same-
# repository (non-fork) pull requests.
#
# This is the March 2025 tj-actions/changed-files vector
# (CVE-2025-30066). ISSUE-804 reports the same head-checkout pattern
# specifically for pull_request_target; this rule generalises it to
# the whole dangerous-trigger family.
package dangerous_triggers

import rego.v1

dangerous_events := {
	"pull_request_target",
	"workflow_run",
	"issue_comment",
	"pull_request_review",
	"pull_request_review_comment",
	"discussion_comment",
	"discussion",
	"gollum",
	"fork",
}

# Refs that resolve to fork / PR-controlled content. Checking one of
# these out under a dangerous trigger runs untrusted code with the
# base repository's privileges.
untrusted_ref_patterns := [
	`github\.event\.pull_request\.head\.sha`,
	`github\.event\.pull_request\.head\.ref`,
	`github\.head_ref`,
	`github\.event\.workflow_run\.head_sha`,
	`github\.event\.workflow_run\.head_branch`,
]

# `if:`-condition fragments that restrict a job to same-repository
# (non-fork) pull requests, which neutralises the exploit.
fork_guard_patterns := [
	`head\.repo\.full_name\s*==\s*github\.repository`,
	`github\.repository\s*==\s*[^=]*head\.repo\.full_name`,
	`head\.repo\.fork\s*==\s*false`,
	`head\.repo\.fork\s*!=\s*true`,
	`!\s*github\.event\.pull_request\.head\.repo\.fork`,
]

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	trigger := job.triggers[j]
	dangerous_events[trigger]
	_checks_out_untrusted_code(job)
	not _has_fork_guard(job)
	finding := {
		"code":     "ISSUE-802",
		"severity": "critical",
		"message":  sprintf("job %q runs under the dangerous trigger %q and checks out fork-controlled code — untrusted code executes with the base repo's secrets (CVE-2025-30066 pattern)", [job.name, trigger]),
		"job":      job.name,
	}
}

# A job checks out untrusted code when an actions/checkout step pins
# its `ref:` to a fork / PR-controlled value.
_checks_out_untrusted_code(job) if {
	some action in job.uses
	startswith(action.uses, "actions/checkout@")
	ref := action.with.ref
	is_string(ref)
	some p in untrusted_ref_patterns
	regex.match(p, ref)
}

_has_fork_guard(job) if {
	some cond in job.conditions
	some p in fork_guard_patterns
	regex.match(p, cond)
}
