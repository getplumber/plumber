# ref-confusion — flag action references whose symbolic name exists
# upstream as BOTH a tag and a branch. GitHub Actions resolves tags
# first, so the reference works today; but the ambiguity is a
# supply-chain landmine: a maintainer who later ships a breaking
# change on the branch, a workflow typo that drops the expected
# ref prefix, or a tag deletion, each silently swaps which of the
# two revisions executes.
#
# The collector does the cross-existence probe via the GitHub API.
# When the probe returns RefIsAmbiguous=true, we emit the finding.
# Degraded mode (no API auth) leaves the field zero-valued and the
# rule stays silent to avoid false positives.
package ref_confusion

import rego.v1

deny contains finding if {
	some i, j
	job := input.pipeline.jobs[i]
	action := job.uses[j]
	action.metadata.refIsAmbiguous == true
	finding := {
		"code":     "ISSUE-710",
		"severity": "medium",
		"message":  sprintf("job %q references %q — the ref name resolves as both a tag AND a branch upstream, which revision runs is ambiguous", [job.name, action.uses]),
		"job":      job.name,
		"line":     object.get(action, "line", 0),
	}
}
