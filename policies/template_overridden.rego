# template-overridden — flag pipelines that import a required CI/CD
# template but redefine some of its jobs with forbidden CI/CD keys
# (script, image, rules, …). The match set comes from
# pipelineMustIncludeTemplate.requiredGroups and the per-origin
# overridden-job list is populated by the collector (same regex as the
# legacy Go control).
package template_overridden

import rego.v1

deny contains finding if {
	input.config.pipelineMustIncludeTemplate
	groups := input.config.pipelineMustIncludeTemplate.requiredGroups
	count(groups) > 0
	some i, j, k
	group := groups[i]
	required := group[j]
	inc := input.pipeline.includes[k]
	_is_template_kind(inc.kind)
	_paths_match(inc, required)
	count(inc.overriddenJobs) > 0
	finding := {
		"code":     "ISSUE-406",
		"severity": "high",
		"message":  sprintf("required template %q is imported but %d of its job(s) are overridden locally", [required, count(inc.overriddenJobs)]),
		"job":      required,
	}
}

_is_template_kind(kind) if {
	kind != "component"
	kind != "hardcoded"
	kind != ""
}

_paths_match(inc, required) if {
	inc.path != ""
	inc.path == required
}

_paths_match(inc, required) if {
	inc.altPath != ""
	inc.altPath == required
}

_paths_match(inc, required) if {
	inc.source != ""
	inc.source == required
}
