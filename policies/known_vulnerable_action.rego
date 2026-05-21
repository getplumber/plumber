# known-vulnerable-action — flag action references that carry a
# published GitHub Advisory Database entry. The collector queries
# `/advisories?ecosystem=actions&affects=<owner>/<repo>` once per
# repo and caches the result, so finding the N callers of a single
# compromised action costs one API call.
#
# The policy emits one finding per (job, action) pair whose
# Advisories slice is non-empty. The message quotes each GHSA
# identifier alongside its advisory URL on the GitHub Advisory
# Database — the terminal renderer turns the URL into a clickable
# link. Severity is critical: a workflow running a known-
# vulnerable action version inherits the published vulnerability
# class with the full blast radius of the job's permissions and
# secrets.
#
# The collector filters advisories by `vulnerable_version_range` when
# the pinned ref resolves to a semver tag. Unresolvable commit SHAs
# conservatively match any advisory for that owner/repo. Use
# `--skip-controls actionsMustNotCarryKnownCVEs` after upgrading and
# re-pinning if you need a temporary waiver.
package known_vulnerable_action

import rego.v1

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	action := job.uses[j]
	action.metadata
	count(action.metadata.advisories) > 0
	finding := {
		"code":       "ISSUE-703",
		"severity":   "critical",
		"message":    sprintf("job %q references %q — published advisories: %s", [job.name, action.uses, _format_advisories(action.metadata.advisories)]),
		"job":        job.name,
		"uses":       action.uses,
		"advisories": action.metadata.advisories,
		"line":       object.get(action, "line", 0),
	}
}

# _format_advisories renders each GHSA ID next to its canonical
# advisory URL so reviewers can open the page with a single click
# from the terminal. Example output for two IDs:
#
#   GHSA-mrrh-fwg8-r2c3 (https://github.com/advisories/GHSA-mrrh-fwg8-r2c3),
#   GHSA-abcd-efgh-ijkl (https://github.com/advisories/GHSA-abcd-efgh-ijkl)
_format_advisories(ids) := out if {
	decorated := [link |
		some id in ids
		link := sprintf("%s (https://github.com/advisories/%s)", [id, id])
	]
	out := concat(", ", decorated)
}
