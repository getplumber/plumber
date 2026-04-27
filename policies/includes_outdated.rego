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
	finding := {
		"code":                  "ISSUE-403",
		"severity":              "medium",
		"message":               sprintf("include %q pinned to %q; latest is %q", [inc.source, inc.ref, inc.current]),
		"job":                   inc.source,
		"version":               inc.ref,
		"latestVersion":         inc.current,
		"gitlabIncludeLocation": inc.source,
		"gitlabIncludeType":     inc.kind,
		"nested":                object.get(inc, "nested", false),
		"componentName":         object.get(inc, "componentName", ""),
		"originHash":            object.get(inc, "originHash", 0),
	}
}
