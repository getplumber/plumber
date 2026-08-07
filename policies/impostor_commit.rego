# impostor-commit — flag workflow steps pinned to a 40-character
# SHA that does not resolve in the action's upstream repository:
# a typo (the runner silently falls back to the default branch), or
# a commit that was removed or never pushed upstream.
#
# Scope note: this does NOT detect a fork-network "impostor commit"
# (one pushed to a fork of the upstream repo). GitHub serves those
# with HTTP 200 from the parent, so they read as present; this rule
# flags only SHAs the API reports as absent (404 / 422).
#
# Scope note: a pin naming the SHA of an annotated tag OBJECT is not an
# impostor. Those SHAs 422 on the commits endpoint but dereference
# through git/tags to a commit in the same repository, so the collector
# resolves them (refExists, refCommitSha) and refKnownAbsent stays false.
#
# Requires the collector to have resolved the action's GitHub
# metadata. The rule fires only on refKnownAbsent, which the collector
# sets ONLY when the upstream API confirms the commit is absent (a
# 404 / 422 for a readable repo). A SHA that could not be verified
# (private repo, rate limit, network error) leaves refKnownAbsent false
# (omitted) and stays silent, so we never flag a valid SHA we merely
# failed to reach.
package impostor_commit

import rego.v1

sha_pattern := `^[0-9a-f]{40}$`

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	action := job.uses[j]
	ref := _ref_of(action.uses)
	# Git / the GitHub API resolve SHAs case-insensitively, so an
	# uppercase or mixed-case 40-hex pin is still a SHA. Lowercase before
	# matching so it cannot dodge the check (the collector already
	# confirmed the commit absent regardless of case).
	regex.match(sha_pattern, lower(ref))
	action.metadata.refKnownAbsent == true
	finding := {
		"code":     "ISSUE-707",
		"severity": "critical",
		"message":  sprintf("job %q pins action %q to a commit SHA that does not exist in the upstream repository (typo, or a commit removed or never pushed upstream)", [job.name, action.uses]),
		"job":      job.name,
		"uses":     action.uses,
		"line":     object.get(action, "line", 0),
	}
}

_ref_of(uses) := ref if {
	idx := indexof(uses, "@")
	idx >= 0
	ref := substring(uses, idx + 1, -1)
}
