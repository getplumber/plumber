# bot-conditions — flag workflows that gate behaviour on a spoofable
# actor or bot identity check (`github.actor`,
# `github.triggering_actor`, `github.event.sender.login`, ...). Those
# fields reflect whoever opened / synchronised the PR, not a verified
# bot identity. A contributor who registers a GitHub account named
# `dependabot[bot]` (or uses a fork trick on the right trigger) can
# satisfy `if: github.actor == 'dependabot[bot]'` and ride through
# whatever elevated path the workflow gates on it.
#
# The policy scans every `if:` expression attached to the job (job-
# level + each step's) for comparisons against known bot logins or
# for direct use of the actor/sender fields in an equality check.
package bot_conditions

import rego.v1

# spoofable_login_patterns match the most common bot accounts projects
# gate on. Adding a trusted internal user here does NOT make the check
# safe — the policy fires on the pattern regardless of the specific
# value, the list is only used for severity framing / messaging.
spoofable_fields := [
	`github\.actor`,
	`github\.triggering_actor`,
	`github\.event\.sender\.login`,
	`github\.event\.pusher\.name`,
	`github\.event\.pull_request\.user\.login`,
	`github\.event\.head_commit\.author\.name`,
]

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	cond := job.conditions[j]
	_has_spoofable_actor_check(cond)
	finding := {
		"code":     "ISSUE-210",
		"severity": "high",
		"message":  sprintf("job %q gates on a spoofable actor/bot check — %q cannot be trusted for privileged paths", [job.name, cond]),
		"job":      job.name,
	}
}

_has_spoofable_actor_check(cond) if {
	some field in spoofable_fields
	regex.match(sprintf(`%s\s*==`, [field]), cond)
}

_has_spoofable_actor_check(cond) if {
	some field in spoofable_fields
	regex.match(sprintf(`==\s*[^!=]*%s`, [field]), cond)
}
