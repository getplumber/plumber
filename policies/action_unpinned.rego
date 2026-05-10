# action-unpinned — flag GitHub Actions workflow steps whose `uses:`
# reference is not pinned by a 40-character commit SHA. Tag and branch
# refs ("v4", "main") are mutable: an attacker who compromises the
# action's repository can retag them to point at arbitrary code, which
# then executes inside the caller workflow with its secrets. This is
# the vector behind the March 2025 tj-actions/changed-files compromise
# (CVE-2025-30066).
#
# Config (optional):
#   input.config.actionsMustBePinnedByCommitSha.trustedOwners = ["actions", "github"]
#     Owners whose actions are exempt from the pin requirement. Only
#     owners inside the repository's own trust boundary should be
#     listed — "actions" and "github" cover the first-party GitHub-
#     owned actions that any workflow already executes implicitly.
#   input.config.actionsMustBePinnedByCommitSha.allowLocal = true
#     When true, local actions (`uses: ./.github/actions/foo`) are
#     exempt. They live in the same repository, so there is no
#     additional trust boundary to worry about.
package action_unpinned

import rego.v1

deny contains finding if {
	# Only run when the user opted in. The default is off: pin-by-SHA is
	# a supply-chain best practice, but also a non-trivial operational
	# change — noisy output before the user has chosen the policy would
	# train them to ignore real findings.
	input.config.actionsMustBePinnedByCommitSha
	some i, j
	job := input.pipeline.jobs[i]
	use := job.uses[j]
	ref := _ref_of(use.uses)
	not _is_sha(ref)
	not _is_local(use.uses)
	not _is_trusted_owner(use.uses)
	finding := {
		"code":     "ISSUE-104",
		"severity": "high",
		"message":  sprintf("job %q references action %q with a mutable ref — pin by commit SHA instead", [job.name, use.uses]),
		"job":      job.name,
		"line":     object.get(use, "line", 0),
	}
}

# Job-level reusable-workflow calls (`jobs.<id>.uses:
# owner/repo/.github/workflows/x.yml@ref`) are subject to the same
# pin-by-SHA rule: a mutable ref on a reusable workflow has the same
# supply-chain blast radius as a step-level action ref. The IR field
# reusableWorkflowUses (omitempty) carries the raw string when the
# job is a reusable-workflow call.
deny contains finding if {
	input.config.actionsMustBePinnedByCommitSha
	some i
	job := input.pipeline.jobs[i]
	use := object.get(job, "reusableWorkflowUses", "")
	use != ""
	ref := _ref_of(use)
	not _is_sha(ref)
	not _is_local(use)
	not _is_trusted_owner(use)
	finding := {
		"code":     "ISSUE-104",
		"severity": "high",
		"message":  sprintf("job %q calls reusable workflow %q with a mutable ref — pin by commit SHA instead", [job.name, use]),
		"job":      job.name,
	}
}

# _ref_of returns the substring after "@" in "owner/repo@ref".
# Returns "" when the string has no "@" — which we treat as
# unpinned (a bare "owner/repo" defaults to the repo's default
# branch and is also a supply-chain risk).
_ref_of(uses) := ref if {
	idx := indexof(uses, "@")
	idx >= 0
	ref := substring(uses, idx + 1, -1)
} else := ""

# _is_sha is true when ref is exactly 40 lowercase hex characters.
_is_sha(ref) if {
	regex.match(`^[0-9a-f]{40}$`, ref)
}

# Local actions ("./.github/actions/foo", "./foo") live in the
# repository itself — no external trust boundary.
_is_local(uses) if {
	startswith(uses, "./")
}

_is_local(uses) if {
	startswith(uses, "/")
}

# Docker-image action refs ("docker://gcr.io/…") are covered by the
# container-image policies, not this one.
_is_local(uses) if {
	startswith(uses, "docker://")
}

_is_trusted_owner(uses) if {
	some trusted in input.config.actionsMustBePinnedByCommitSha.trustedOwners
	startswith(uses, sprintf("%s/", [trusted]))
}
