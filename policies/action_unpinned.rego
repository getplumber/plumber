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
# Local actions (`uses: ./.github/actions/foo`) are always exempt
# regardless of config — they live in the same repository as the
# caller, so there is no additional external trust boundary to
# worry about.
# A tag backed by an immutable GitHub release is accepted as pinned
# (see _is_immutable_release_tag), for steps and reusable workflows.
# When the branch commits a workflow dependency lockfile
# (.github/workflows/actions.lock), the runner executes the commits it
# records for the repository's own steps, so those are accepted (#542,
# see _lockfile_covers). Reusable workflows are not in the lockfile
# schema: a reusable-workflow call is always judged, and so are the
# steps of a job appended from another repository's reusable workflow.
package action_unpinned

import rego.v1
import data.lib.provenance

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
	not _is_own_repo(use.uses)
	not _is_trusted_owner(use.uses)
	not _is_immutable_release_tag(object.get(use, "metadata", {}))
	not _lockfile_covers(job)
	base := {
		"code":     "ISSUE-701",
		"severity": "high",
		"message":  provenance.message(sprintf("job %q references action %q with a mutable ref \u2014 pin by commit SHA instead", [job.name, use.uses]), use),
		"job":      job.name,
		"uses":     use.uses,
		"line":     object.get(use, "line", 0),
	}
	finding := object.union(object.union(object.union(base, _archived_tag_fields(use)), _redirected_owner_fields(use)), provenance.fields(use))
}

# _archived_tag_fields and _redirected_owner_fields are additive: a
# reference with neither signal keeps the finding exactly as it read
# before trust followed the party that can change the code, not the
# party the workflow merely names.
default _archived_tag_fields(_) := {}

_archived_tag_fields(use) := {"archivedTag": true} if _is_archived_tag(use)

# _is_archived_tag: the action's repository is archived and the pinned
# ref is a tag: nobody can retag it any more, so the reference is
# immutable in practice even though it is not pinned to a commit SHA.
_is_archived_tag(use) if {
	meta := object.get(use, "metadata", {})
	object.get(meta, "repoArchived", false) == true
	object.get(meta, "refKind", "") == "tag"
}

# _is_immutable_release_tag: the ref is a tag backed by an immutable
# GitHub release (#421). Such a tag can never be moved or deleted, so
# it carries the same integrity guarantee as a commit SHA. Only the
# exact released tag qualifies: a floating major (v4) has no release
# behind it and keeps being flagged. A same-named branch disqualifies
# the tag (refIsAmbiguous): the branch could win resolution and it is
# mutable. No metadata (no token, API disabled, lookup failed) means
# the exemption never applies, so the control fails closed.
_is_immutable_release_tag(meta) if {
	object.get(meta, "refKind", "") == "tag"
	object.get(meta, "refIsImmutableRelease", false) == true
	not object.get(meta, "refIsAmbiguous", false)
}

# _lockfile_covers: the steps of this job run at the commits the scanned
# branch's workflow lockfile records (#542). Only the repository's own
# jobs qualify, its same-repo reusable workflows included: a job appended
# from another repository's reusable workflow (nested) is governed by that
# repository's lockfile, which is not read yet, so its steps keep being
# judged. The Go counter (control/github_stats.go lockfileCovers) mirrors
# this predicate.
_lockfile_covers(job) if {
	input.pipeline.workflowLockfilePath
	not object.get(job, "nested", false)
}

# _reusable_call_suffix names the gap on a reusable-workflow call when the
# branch has a lockfile: the call itself is never locked.
default _reusable_call_suffix := ""

_reusable_call_suffix := ", which workflow lockfiles do not cover" if input.pipeline.workflowLockfilePath

default _redirected_owner_fields(_) := {}

_redirected_owner_fields(use) := {"redirectedOwner": owner} if {
	meta := object.get(use, "metadata", {})
	owner := object.get(meta, "redirectedOwner", "")
	owner != ""
}

# Job-level reusable-workflow calls (`jobs.<id>.uses:
# owner/repo/.github/workflows/x.yml@ref`) are subject to the same
# pin-by-SHA rule: a mutable ref on a reusable workflow has the same
# supply-chain blast radius as a step-level action ref. The IR field
# reusableWorkflowUses (omitempty) carries the raw string when the
# job is a reusable-workflow call. A workflow lockfile never covers the
# call (reusable workflows are not in its schema), so this rule has no
# lockfile exemption.
deny contains finding if {
	input.config.actionsMustBePinnedByCommitSha
	some i
	job := input.pipeline.jobs[i]
	use := object.get(job, "reusableWorkflowUses", "")
	use != ""
	ref := _ref_of(use)
	not _is_sha(ref)
	not _is_local(use)
	not _is_own_repo(use)
	not _is_trusted_owner(use)
	not _is_immutable_release_tag(object.get(job, "reusableWorkflowMetadata", {}))
	finding := object.union({
		"code":     "ISSUE-701",
		"severity": "high",
		"message":  provenance.message(sprintf("job %q calls reusable workflow %q with a mutable ref%s \u2014 pin by commit SHA instead", [job.name, use, _reusable_call_suffix]), job),
		"job":      job.name,
		"uses":     use,
	}, provenance.fields(job))
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

# _is_sha is true when ref is exactly 40 hex characters. Git and the
# GitHub API resolve SHAs case-insensitively, so an uppercase pin is
# still an immutable pin; lowercase before matching so it is not
# misreported as a mutable ref (keeps ISSUE-701 findings aligned with
# the Go isShaPinned counter, which also matches case-insensitively).
_is_sha(ref) if {
	regex.match(`^[0-9a-f]{40}$`, lower(ref))
}

# Local actions ("./.github/actions/foo", "./foo") live in the
# repository itself — no external trust boundary.
_is_local(uses) if {
	startswith(uses, "./")
}

_is_local(uses) if {
	startswith(uses, "/")
}

# The "$/" form some workflows write a path inside the repository in.
_is_local(uses) if {
	startswith(uses, "$/")
}

# _is_own_repo: the reference names the scanned repository itself by
# its canonical owner/repo (input.pipeline.projectPath, compared
# case-insensitively): it changes only with a commit in the repository,
# so it is no third-party reference to pin. Abstains when projectPath
# is unknown.
_is_own_repo(uses) if {
	own := lower(object.get(input.pipeline, "projectPath", ""))
	own != ""
	head := split(split(uses, "@")[0], "/")
	count(head) >= 2
	lower(concat("/", [head[0], head[1]])) == own
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
