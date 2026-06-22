# ref-confusion (ISSUE-710) — flag external CI references whose symbolic
# name exists upstream as BOTH a tag and a branch. Covers two surfaces:
#   - GitHub Actions `uses:` refs (jobs[].uses[].metadata.refIsAmbiguous)
#   - GitLab `include:` project `ref:` / component `@version` refs
#     (includes[].refIsAmbiguous)
# The platform resolves tags first, so the reference works today; but the
# ambiguity is a supply-chain landmine: a maintainer who later ships a
# breaking change on the branch, a typo that drops the expected ref prefix,
# or a tag deletion, each silently swaps which of the two revisions runs.
#
# Both surfaces are API-backed: the collector does the cross-existence
# probe and sets RefIsAmbiguous=true only on a confirmed tag+branch
# double-hit. Degraded mode (no API auth / failed probe) leaves the field
# zero-valued and the rule stays silent to avoid false positives.
package ref_confusion

import rego.v1

# GitHub: a `uses:` action ref that resolves as both a tag and a branch.
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

# GitLab: an `include:` (project ref: or component @version) whose ref
# resolves as both a tag and a branch in the source project.
deny contains finding if {
	some i
	inc := input.pipeline.includes[i]
	inc.refIsAmbiguous == true
	finding := {
		"code":                  "ISSUE-710",
		"severity":              "medium",
		"message":               sprintf("%s pins ref '%s' — it resolves as both a tag AND a branch in the source project, so which revision runs is ambiguous; pin to a commit SHA to disambiguate", [inc.source, inc.ref]),
		"job":                   inc.source,
		"file":                  object.get(inc, "originFile", ""),
		"line":                  object.get(inc, "originLine", 0),
		"version":               inc.ref,
		"gitlabIncludeLocation": inc.source,
		"gitlabIncludeType":     inc.kind,
		"nested":                object.get(inc, "nested", false),
		"componentName":         object.get(inc, "componentName", ""),
		"originHash":            object.get(inc, "originHash", 0),
	}
}
