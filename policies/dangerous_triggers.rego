# dangerous-triggers — flag pipeline jobs reachable through a GitHub
# Actions trigger that combines attacker-controlled input with
# privileged secrets. Every event in the set below grants the workflow
# access to the base repository's secrets while being influenceable by
# users who are NOT trusted (PR authors, issue commenters, fork
# maintainers, anonymous viewers).
#
#   - pull_request_target: runs with the base repo's secrets AND token
#     while being trivially influenceable by an unprivileged PR author.
#   - workflow_run: triggered by the completion of another workflow,
#     likewise secret-bearing regardless of the source workflow's
#     trust boundary.
#   - issue_comment: any user with read access can fire this by leaving
#     a comment on an issue; the workflow runs on the default branch
#     with full secrets. Documented attack vector behind multiple
#     "comment-triggered code execution" advisories.
#   - pull_request_review / pull_request_review_comment: same shape as
#     issue_comment but on a PR — runs with secrets, fired by an
#     unprivileged reviewer/commenter.
#   - discussion_comment / discussion: GitHub Discussions equivalent
#     of issue_comment; same secret-access semantics.
#   - gollum: wiki edit; any contributor can trigger from the wiki UI.
#   - fork: anyone can fork a public repo, so a workflow keyed on this
#     event runs on attacker-influenceable input by definition.
#
# Severity is intentionally "critical". In March 2025 the
# tj-actions/changed-files compromise (CVE-2025-30066) exploited
# exactly this pattern — pull_request_target plus an explicit checkout
# of the PR head — and exfiltrated secrets from hundreds of projects,
# including aquasecurity/trivy. The finding flags the attack surface
# whether or not the workflow checks out fork code today: the moment a
# later edit introduces such a checkout, secrets leak, and the trigger
# is the prerequisite that makes the pivot possible.
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

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	trigger := job.triggers[j]
	dangerous_events[trigger]
	finding := {
		"code":     "ISSUE-802",
		"severity": "critical",
		"message":  sprintf("job %q is reachable via the dangerous trigger %q", [job.name, trigger]),
		"job":      job.name,
	}
}
