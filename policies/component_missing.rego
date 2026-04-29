# component-missing — flag pipelines that do not include every CI/CD
# component required by the user's
# pipelineMustIncludeComponent.requiredGroups policy. The list is in
# DNF (Disjunctive Normal Form): a group is an AND, the outer slice is
# an OR. One finding is emitted per missing component per group so the
# report explains exactly which slot stayed empty — the Go control
# behaves the same way.
package component_missing

import rego.v1

deny contains finding if {
	input.config.pipelineMustIncludeComponent
	groups := input.config.pipelineMustIncludeComponent.requiredGroups
	count(groups) > 0
	not _any_group_satisfied(groups)
	some i, j
	group := groups[i]
	required := group[j]
	not _component_present(required)
	finding := {
		"code":     "ISSUE-408",
		"severity": "high",
		"message":  sprintf("required component %q is missing from the pipeline (group %d)", [required, i]),
		"job":      required,
	}
}

# A DNF group is satisfied when every required component in it is
# present. The whole policy is satisfied as soon as ANY group is —
# that's the OR of the outer slice.
_any_group_satisfied(groups) if {
	some i
	group := groups[i]
	count(group) > 0
	every required in group {
		_component_present(required)
	}
}

_component_present(required) if {
	some k
	inc := input.pipeline.includes[k]
	inc.kind == "component"
	_paths_match(inc, required)
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
