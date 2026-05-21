# ref-version-mismatch — flag `@<sha> # vX.Y.Z` pins where the SHA
# does not correspond to the tag named in the trailing comment. The
# comment is the reviewer's trust signal; if the SHA says one version
# and the comment says another, the review is misled.
#
# Uses the collector's API-resolved metadata: when the collector sees
# a trailing comment with a version token, it queries the upstream
# repository for the SHA that version resolves to (CommentTagSha).
# The policy compares that SHA to the one actually pinned in `uses:`.
#
# Two ruled cases:
#   1. Pinned ref is a SHA, comment names a version, the version
#      resolves to a different SHA. The classic mismatch.
#   2. Pinned ref is a tag, the comment names a different version.
#      Caught by string comparison; the API data is not needed here
#      so the rule still fires in degraded (offline) mode.
package ref_version_mismatch

import rego.v1

sha_pattern := `^[0-9a-f]{40}$`
version_comment_pattern := `^\s*v?(\d+(?:\.\d+)*(?:-[A-Za-z0-9.-]+)?)\s*$`

# Case 1 — SHA pin, comment-named tag resolved to a different SHA.
deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	action := job.uses[j]
	action.metadata
	action.metadata.commentVersion != ""
	action.metadata.commentTagSha != ""
	ref := _ref_of(action.uses)
	regex.match(sha_pattern, ref)
	action.metadata.commentTagSha != ref
	finding := {
		"code":     "ISSUE-708",
		"severity": "medium",
		"message":  sprintf("job %q pins %q but comment %q names tag %q which resolves to %q — reviewers will misread the version", [job.name, action.uses, action.comment, action.metadata.commentVersion, action.metadata.commentTagSha]),
		"job":      job.name,
		"line":     object.get(action, "line", 0),
	}
}

# Case 2 — tag pin, comment names a different tag. Offline-safe.
deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	action := job.uses[j]
	action.comment != ""
	action.metadata.refKind == "tag"
	ref := _ref_of(action.uses)
	cv := _comment_version(action.comment)
	cv != ""
	_strip_v(ref) != _strip_v(cv)
	finding := {
		"code":     "ISSUE-708",
		"severity": "medium",
		"message":  sprintf("job %q pins tag %q with comment %q — ref and comment name different versions", [job.name, action.uses, action.comment]),
		"job":      job.name,
		"line":     object.get(action, "line", 0),
	}
}

_ref_of(uses) := ref if {
	idx := indexof(uses, "@")
	idx >= 0
	ref := substring(uses, idx + 1, -1)
}

_comment_version(comment) := v if {
	m := regex.find_all_string_submatch_n(version_comment_pattern, comment, 1)
	count(m) > 0
	v := m[0][0]
}

_strip_v(s) := trimmed if {
	trimmed := trim_prefix(s, "v")
}
