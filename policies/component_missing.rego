# component-missing — flag pipelines that do not include every CI/CD
# component required by the user's
# pipelineMustIncludeComponent.requiredGroups policy. The list is in
# DNF (Disjunctive Normal Form): a group is an AND, the outer slice is
# an OR. One finding is emitted per evaluation, carrying every group's
# missing components, so the report shows each way out of it at once.
package component_missing

import rego.v1

deny contains finding if {
	input.config.pipelineMustIncludeComponent
	groups := input.config.pipelineMustIncludeComponent.requiredGroups
	count(groups) > 0
	not _any_group_satisfied(groups)
	missing := [_missing_in_group(group) | some group in groups]
	finding := {
		"code":     "ISSUE-408",
		"severity": "high",
		"message":  sprintf("no required component group is satisfied: %s", [_groups_text(missing)]),
		# One finding per evaluation, not one per missing component: the policy
		# that failed is "include one of these groups", and the components are
		# what it is still waiting for. They travel as data, one list per
		# alternative in config order. No "job" and no "file": a missing
		# component is neither, and no single path names this finding.
		"missingGroups": missing,
	}
}

# The entries of one alternative the pipeline does not include, config order kept.
_missing_in_group(group) := [required |
	some required in group
	not _component_present(required)
]

# _groups_text renders `group 0 missing "a", "b"; group 1 missing "c"`.
_groups_text(missing) := concat("; ", [text |
	some i in numbers.range(0, count(missing) - 1)
	text := sprintf("group %d missing %s", [i, _entries_text(missing[i])])
])

_entries_text(entries) := concat(", ", [sprintf("%q", [entry]) | some entry in entries])

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
