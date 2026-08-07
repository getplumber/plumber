# stale-action-ref — flag workflow steps pinned to a SHA that is
# behind the action's latest upstream release. Stale pins miss
# security fixes and dependency bumps shipped in later tags. Low
# severity — not every project must track latest, but visibility on
# the gap lets Dependabot (or the maintainer) plan refreshes.
#
# Runs only when the collector resolved both the pinned ref and the
# latest release's SHA. Tag pins that happen to equal the latest
# stay silent — they are already up-to-date.
package stale_action_ref

import rego.v1

sha_pattern := `^[0-9a-f]{40}$`

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	action := job.uses[j]
	action.metadata
	action.metadata.latestReleaseSha != ""
	ref := _ref_of(action.uses)
	pinned := _pinned_sha(ref, action.metadata)
	pinned != ""
	pinned != action.metadata.latestReleaseSha
	finding := {
		"code":     "ISSUE-709",
		"severity": "low",
		"message":  sprintf("job %q pins %q behind the latest release %q — refresh to pick up upstream security fixes", [job.name, action.uses, action.metadata.latestTag]),
		"job":      job.name,
		"uses":     action.uses,
		"line":     object.get(action, "line", 0),
	}
}

# _pinned_sha returns the SHA the current ref resolves to. For a SHA
# pin, that's the ref itself, lowercased so the comparison against the
# API's lowercase latestReleaseSha treats an uppercase pin like its
# lowercase equivalent; for a tag pin, metadata.tagSha carries the
# resolved value.
#
# A pin naming an annotated tag OBJECT is a third case (ISSUE-401): the
# ref is SHA-shaped but designates the tag object, not the commit, so
# the collector records the dereferenced commit in refCommitSha and
# that is what compares against latestReleaseSha. The SHA-pin clause
# below excludes it so the two never disagree on one action.
_pinned_sha(_, meta) := lower(meta.refCommitSha) if {
	meta.refCommitSha != ""
}

_pinned_sha(ref, meta) := lower(ref) if {
	regex.match(sha_pattern, lower(ref))
	object.get(meta, "refCommitSha", "") == ""
}

_pinned_sha(_, meta) := meta.tagSha if {
	meta.tagSha != ""
	meta.refKind == "tag"
}

_ref_of(uses) := ref if {
	idx := indexof(uses, "@")
	idx >= 0
	ref := substring(uses, idx + 1, -1)
}
