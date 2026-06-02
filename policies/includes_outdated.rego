# includes-outdated — flag pipeline includes that are pinned to a
# version older than the latest one advertised upstream (Plumber
# template registry or GitLab component catalogue). The collector
# resolves the latest version ahead of time and exposes it on the
# include as `current`; when `ref != current` (and both are
# populated) the include is out of date.
package includes_outdated

import rego.v1

deny contains finding if {
	some i
	inc := input.pipeline.includes[i]
	inc.ref != ""
	inc.current != ""
	inc.ref != inc.current
	not _ref_is_forbidden_version(inc.ref)
	_is_semver_like(inc.ref)
	not _ref_is_partial_semver_prefix(inc.ref, inc.current)
	finding := {
		"code":                  "ISSUE-403",
		"severity":              "medium",
		"message":               sprintf("%s uses version '%s' (latest: %s)", [inc.source, inc.ref, inc.current]),
		"job":                   inc.source,
		"file":                  object.get(inc, "originFile", ""),
		"line":                  object.get(inc, "originLine", 0),
		"version":               inc.ref,
		"latestVersion":         inc.current,
		"gitlabIncludeLocation": inc.source,
		"gitlabIncludeType":     inc.kind,
		"nested":                object.get(inc, "nested", false),
		"componentName":         object.get(inc, "componentName", ""),
		"originHash":            object.get(inc, "originHash", 0),
	}
}

# A ref pinned to a configured forbidden version (e.g. `main`,
# `master`, `HEAD`) is already flagged by ISSUE-404. Comparing it to
# the latest semver release is a category error — the user is asking
# for a mutable ref by design, so "outdated" is meaningless. Mirrors
# the legacy IsUpToDate behaviour where mutable refs were treated as
# up-to-date.
_ref_is_forbidden_version(ref) if {
	some forbidden in input.config.includesForbiddenVersions.forbiddenVersions
	glob.match(forbidden, null, ref)
}

# Outdated comparison only makes sense for refs that look like a
# version number. Mutable branch/tag pointers (`main`, `master`,
# `HEAD`, `develop`, ...) have no meaningful "latest" — they ARE the
# tip of a branch — so we skip them regardless of user config. A
# semver-like ref optionally starts with `v`, then a numeric major
# component, optional minor/patch parts, and an optional pre-release
# or build suffix.
_is_semver_like(ref) if regex.match(`^v?\d+(\.\d+)*([-+].*)?$`, ref)

# A partial semver ref (major-only "@1" or major.minor "@1.2") tracks
# the latest release within that prefix in GitLab component semantics.
# "@1" is always up to date when the latest is "1.x.y", so comparing it
# to "1.2.4" would be a false positive. Strip the optional leading "v",
# split on ".", and check that every segment of ref matches the
# corresponding segment of current while current has more segments.
_ref_is_partial_semver_prefix(ref, current) if {
	ref_norm := regex.replace(ref, `^v`, "")
	current_norm := regex.replace(current, `^v`, "")
	ref_parts := split(ref_norm, ".")
	current_parts := split(current_norm, ".")
	count(ref_parts) < count(current_parts)
	every i, part in ref_parts {
		part == current_parts[i]
	}
}
