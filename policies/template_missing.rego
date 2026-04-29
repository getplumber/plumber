# template-missing — flag pipelines that do not include every CI/CD
# template required by pipelineMustIncludeTemplate.requiredGroups.
# Templates can be pulled via `include: { project: … }`, via
# `include: { template: … }`, or via Plumber-augmented metadata; the
# collector normalises each origin's path(s) for comparison. The
# hardcoded origin is always skipped — it represents the project's own
# .gitlab-ci.yml body, not an imported template.
package template_missing

import rego.v1

deny contains finding if {
	input.config.pipelineMustIncludeTemplate
	groups := input.config.pipelineMustIncludeTemplate.requiredGroups
	count(groups) > 0
	not _any_group_satisfied(groups)
	some i, j
	group := groups[i]
	required := group[j]
	not _template_present(required)
	finding := {
		"code":     "ISSUE-405",
		"severity": "high",
		"message":  sprintf("required template %q is missing from the pipeline (group %d)", [required, i]),
		"job":      required,
	}
}

# DNF: only emit findings when no group is fully satisfied.
_any_group_satisfied(groups) if {
	some i
	group := groups[i]
	count(group) > 0
	every required in group {
		_template_present(required)
	}
}

_template_present(required) if {
	some k
	inc := input.pipeline.includes[k]
	_is_template_kind(inc.kind)
	_paths_match(inc, required)
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
