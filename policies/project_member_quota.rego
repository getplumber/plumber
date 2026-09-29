# project-member-quota: flag a role whose member count falls outside the
# configured bounds. Too many Owners or Maintainers widens who can change the
# project's settings and protected branches; too few of a role thins out the
# review and recovery capacity a policy expects. The operator sets any subset
# of eight bounds (ownerMin, ownerMax, maintainerMin, maintainerMax,
# developerMin, developerMax, totalMin, totalMax); an unset bound asserts
# nothing, and every bound is inclusive.
#
# One finding per violated role, keyed on the role name alone (owner,
# maintainer, developer, total): the count is data, not identity, so a change
# in how far outside the quota a role sits does not re-key the finding. This
# is the v1 platform's identity for the same control.
#
# GitLab-only: reads input.pipeline.projectMembers, projected from the members
# collection (gitlab/gitlab_ir.go::buildMemberCounts). Everyone with effective
# access is counted once at their highest level, access-token bots excluded.
# input.pipeline.projectMembersKnown is false when the listing could not be
# read (a 403/404, the page cap, a degraded snapshot lane); the rule abstains
# then, so the control reports not-evaluable, not a verdict.
package project_member_quota

import rego.v1

# _roles maps each role to the count it reads and the bound keys it honours.
_roles := {
	"owner": {"count": "owners", "one": "owner", "many": "owners", "min": "ownerMin", "max": "ownerMax"},
	"maintainer": {"count": "maintainers", "one": "maintainer", "many": "maintainers", "min": "maintainerMin", "max": "maintainerMax"},
	"developer": {"count": "developers", "one": "developer", "many": "developers", "min": "developerMin", "max": "developerMax"},
	"total": {"count": "total", "one": "member", "many": "members", "min": "totalMin", "max": "totalMax"},
}

# _role_counts yields each role, its spec, the quota block and the count, but
# only on a GitLab run whose member counts were read.
_role_counts contains [role, spec, cfg, n] if {
	input.pipeline.provider == "gitlab"
	input.pipeline.projectMembersKnown
	cfg := object.get(input.config, "numberOfProjectMembersMustRespectQuota", {})
	some role, spec in _roles
	n := object.get(object.get(input.pipeline, "projectMembers", {}), spec.count, 0)
}

deny contains finding if {
	some [role, spec, cfg, n] in _role_counts
	_above_max(n, cfg, spec)
	maximum := cfg[spec.max]
	finding := object.union({
		"code": "ISSUE-507",
		"severity": "medium",
		"message": sprintf("The project has %s, above the quota maximum of %d.", [_count_phrase(n, spec), maximum]),
		"role": role,
		"currentCount": n,
	}, _bounds(cfg, spec))
}

# The max finding wins when inverted bounds (min > max, which the platform
# does not validate) put a count on both wrong sides: one finding per role.
deny contains finding if {
	some [role, spec, cfg, n] in _role_counts
	minimum := cfg[spec.min]
	n < minimum
	not _above_max(n, cfg, spec)
	finding := object.union({
		"code": "ISSUE-507",
		"severity": "medium",
		"message": sprintf("The project has %s, below the quota minimum of %d.", [_count_phrase(n, spec), minimum]),
		"role": role,
		"currentCount": n,
	}, _bounds(cfg, spec))
}

_above_max(n, cfg, spec) if {
	n > cfg[spec.max]
}

# _bounds carries the bounds the operator actually set, and only those, so a
# reader of the finding sees the quota as configured rather than a fabricated
# zero for an unset side.
_bounds(cfg, spec) := object.union(_bound("authorizedMin", cfg, spec.min), _bound("authorizedMax", cfg, spec.max))

_bound(name, cfg, key) := {name: cfg[key]}

_bound(name, cfg, key) := {} if not cfg[key]

# _count_phrase keeps the count reading as English rather than "1 owners".
_count_phrase(n, spec) := sprintf("%d %s", [n, spec.one]) if {
	n == 1
} else := sprintf("%d %s", [n, spec.many])
