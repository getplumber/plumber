# includes-forbidden-version — flag pipeline includes whose pinned
# version appears in the .plumber.yaml's forbiddenVersions list (for
# example branch names like "main" or "master", which are
# rolling-release pointers rather than immutable refs).
package includes_forbidden_version

import rego.v1

deny contains finding if {
	some i
	inc := input.pipeline.includes[i]
	inc.ref != ""
	_version_is_forbidden(inc.ref)
	finding := {
		"code":     "ISSUE-404",
		"severity": "medium",
		"message":  sprintf("include %q pins a forbidden version %q", [inc.source, inc.ref]),
		"job":      inc.source,
	}
}

_version_is_forbidden(ref) if {
	ref == input.config.includesForbiddenVersions.forbiddenVersions[_]
}

_version_is_forbidden(ref) if {
	input.config.includesForbiddenVersions.defaultBranchIsForbiddenVersion == true
	ref == "main"
}

_version_is_forbidden(ref) if {
	input.config.includesForbiddenVersions.defaultBranchIsForbiddenVersion == true
	ref == "master"
}

_version_is_forbidden(ref) if {
	input.config.includesForbiddenVersions.defaultBranchIsForbiddenVersion == true
	ref == "HEAD"
}
