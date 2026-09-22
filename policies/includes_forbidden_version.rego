# includes-forbidden-version — flag pipeline includes whose pinned
# version appears in the .plumber.yaml's forbiddenVersions list (for
# example branch names like "main" or "master", which are
# rolling-release pointers rather than immutable refs).
#
# Parity with the legacy Go control:
#   - Hardcoded jobs are skipped (origins without a pinnable version).
#   - Patterns support wildcard semantics via glob.match (matches the
#     legacy go-wildcard.Match behaviour: `*` and `?`).
#   - Unless defaultBranchIsForbiddenVersion is explicitly false, the
#     project's default branch (carried on the IR pipeline) joins the
#     forbidden list: the unset key means true (ruling R6).
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
		"message":  sprintf("The include `%s` uses the forbidden version `%s`.", [inc.source, inc.ref]),
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
	_default_branch_is_forbidden
	input.pipeline.defaultBranch != ""
	ref == input.pipeline.defaultBranch
}

# Unset means true (ruling R6 of the 2026-09-22 issues-page review): an
# include pinned to the branch that moves under you is what this control
# exists to catch, so the operator opts OUT explicitly. The Go projection
# (control/task.go, IsDefaultBranchForbidden) sends the effective value;
# this default keeps the rule honest for any other caller.
_default_branch_is_forbidden if {
	object.get(input.config.includesForbiddenVersions, "defaultBranchIsForbiddenVersion", true) == true
}
