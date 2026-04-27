# dangerous-triggers — flag pipeline jobs reachable through a GitHub
# Actions trigger that combines attacker-controlled input with
# privileged secrets. The two primary offenders are:
#
#   - pull_request_target: runs with the base repo's secrets AND token
#     while being trivially influenceable by an unprivileged PR author.
#   - workflow_run: triggered by the completion of another workflow,
#     likewise secret-bearing regardless of the source workflow's
#     trust boundary.
#
# Severity is intentionally "critical". In March 2025 the
# tj-actions/changed-files compromise (CVE-2025-30066) exploited
# exactly this pattern — pull_request_target plus an explicit checkout
# of the PR head — and exfiltrated secrets from hundreds of projects,
# including aquasecurity/trivy. The finding flags the attack surface
# whether or not the workflow checks out fork code today: the moment a
# later edit introduces such a checkout, secrets leak, and the trigger
# is the prerequisite that makes the pivot possible.
#
# Finer-grained risk signals (explicit fork checkout, script injection
# from `github.event.*`) can be added in follow-up iterations.
package dangerous_triggers

import rego.v1

dangerous_events := {"pull_request_target", "workflow_run"}

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	trigger := job.triggers[j]
	dangerous_events[trigger]
	finding := {
		"code":     "ISSUE-414",
		"severity": "critical",
		"message":  sprintf("job %q is reachable via the dangerous trigger %q", [job.name, trigger]),
		"job":      job.name,
	}
}
