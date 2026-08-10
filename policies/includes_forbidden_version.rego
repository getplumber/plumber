# includes-forbidden-version — flag pipeline includes whose pinned
# version appears in the .plumber.yaml's forbiddenVersions list (for
# example branch names like "main" or "master", which are
# rolling-release pointers rather than immutable refs).
#
# Parity with the legacy Go control:
#   - Hardcoded jobs are skipped (origins without a pinnable version).
#   - Patterns support wildcard semantics via glob.match (matches the
#     legacy go-wildcard.Match behaviour: `*` and `?`).
#   - When defaultBranchIsForbiddenVersion is true, the project's
#     default branch (carried on the IR pipeline) joins the
#     forbidden list.
package includes_forbidden_version

import rego.v1

deny contains finding if {
	some i
	inc := input.pipeline.includes[i]
	inc.kind != "hardcoded"
	inc.ref != ""
	_version_is_forbidden(inc.ref)
	finding := {
		"code":     "ISSUE-404",
		"severity": "medium",
		"message":  sprintf("%s uses forbidden version '%s'", [inc.source, inc.ref]),
		# No "job": an include is not a job. includePath names what this finding
		# is about and is what the identity recipe selects (finding/identity).
		# The ref stays out: the same include drifting from one forbidden
		# version to another is the same unresolved problem.
		"includePath": inc.source,
	}
}

_version_is_forbidden(ref) if {
	pattern := input.config.includesForbiddenVersions.forbiddenVersions[_]
	glob.match(pattern, null, ref)
}

_version_is_forbidden(ref) if {
	input.config.includesForbiddenVersions.defaultBranchIsForbiddenVersion == true
	input.pipeline.defaultBranch != ""
	ref == input.pipeline.defaultBranch
}
