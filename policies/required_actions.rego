# required-actions — flag GitHub Actions workflows that do not
# reference every action or reusable workflow required by the
# user's workflowMustIncludeRequiredActions.requiredGroups policy.
# Mirrors component_missing.rego on the GitLab side: requiredGroups
# is in DNF (Disjunctive Normal Form), where each inner group is
# an AND and the outer slice is an OR. The whole policy is
# satisfied as soon as ANY group is fully present. One finding is
# emitted per evaluation, carrying every group's missing entries,
# so the report shows each way out of it at once.
#
# GitHub has two ways to "include" something external in a
# workflow, and this rule covers both transparently so the user
# does not have to declare which is which:
#
#   1. Action references at the step level:
#        steps:
#          - uses: org/sast-scan@v2
#      Stored in the IR as Job.Uses[].Uses, with `@<ref>` appended.
#
#   2. Reusable workflow calls at the job level:
#        jobs:
#          security:
#            uses: org/sast-scan/.github/workflows/scan.yml@v2
#      Stored in the IR as Job.ReusableWorkflowUses, also with
#      `@<ref>` appended.
#
# Matching is by `owner/repo[/path]` prefix and ref-agnostic.
# A required entry of `org/sast-scan` is satisfied by:
#   uses: org/sast-scan@v2
#   uses: org/sast-scan@abc123…
#   uses: org/sast-scan/composite@v1
#   jobs.x.uses: org/sast-scan/.github/workflows/scan.yml@v1
# but NOT by `uses: org/sast-scan-fork@v2` (the slash guard
# prevents accidental prefix collisions on owner/repo names that
# share a prefix).
package required_actions

import rego.v1

deny contains finding if {
	input.config.workflowMustIncludeRequiredActions
	groups := input.config.workflowMustIncludeRequiredActions.requiredGroups
	count(groups) > 0
	not _any_group_satisfied(groups)
	missing := [_missing_in_group(group) | some group in groups]
	finding := {
		"code":     "ISSUE-417",
		"severity": "high",
		"message":  sprintf("no required action or reusable workflow group is satisfied: %s", [_groups_text(missing)]),
		# One finding per evaluation, not one per missing entry: the policy that
		# failed is "reference one of these groups", and the entries are what it
		# is still waiting for. They travel as data, one list per alternative in
		# config order. No "job" and no "file": a missing action is neither, and
		# no single entry names this finding.
		"missingGroups": missing,
	}
}

# The entries of one alternative no workflow references, config order kept.
_missing_in_group(group) := [required |
	some required in group
	not _required_present(required)
]

# _groups_text renders `group 0 missing "a", "b"; group 1 missing "c"`.
_groups_text(missing) := concat("; ", [text |
	some i in numbers.range(0, count(missing) - 1)
	text := sprintf("group %d missing %s", [i, _entries_text(missing[i])])
])

_entries_text(entries) := concat(", ", [sprintf("%q", [entry]) | some entry in entries])

# Outer-OR satisfied when at least one inner-AND is.
_any_group_satisfied(groups) if {
	some i
	group := groups[i]
	count(group) > 0
	every required in group {
		_required_present(required)
	}
}

# Step-level action: `uses: owner/repo[/path]@<ref>` collected on
# every job's steps. The ref is stripped before comparison so the
# user can bump pinned SHAs without rewriting the policy.
_required_present(required) if {
	some i, k
	job := input.pipeline.jobs[i]
	ref := job.uses[k].uses
	_ref_matches(ref, required)
}

# Job-level reusable workflow call: `jobs.<name>.uses:` lives in a
# separate IR field so it does not collide with the action list
# above.
_required_present(required) if {
	some i
	job := input.pipeline.jobs[i]
	job.reusableWorkflowUses != ""
	_ref_matches(job.reusableWorkflowUses, required)
}

# _ref_matches returns true when the `uses:` reference matches the
# required string ref-agnostically. The reference is stripped of
# its `@<ref>` suffix and then compared two ways:
#   - exact match: `org/repo` == `org/repo`
#   - prefix-with-slash: `org/repo/scan` starts with `org/repo/`
# The slash guard prevents `org/repo-other` from accidentally
# matching `org/repo`.
_ref_matches(reference, required) if {
	normalized := _strip_ref(reference)
	normalized == required
}

_ref_matches(reference, required) if {
	normalized := _strip_ref(reference)
	startswith(normalized, sprintf("%s/", [required]))
}

_strip_ref(reference) := stripped if {
	parts := split(reference, "@")
	stripped := parts[0]
}
