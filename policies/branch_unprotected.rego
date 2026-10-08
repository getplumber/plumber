# branch-unprotected — flag repository branches whose name matches a
# protection requirement set in .plumber.yaml (either one of the
# declared namePatterns or the project's default branch when
# defaultMustBeProtected is on) but for which the provider reports no
# matching branch-protection rule.
package branch_unprotected

import rego.v1

deny contains finding if {
	some i
	branch := input.pipeline.branches[i]
	branch.protected == false
	_branch_must_be_protected(branch.name)
	finding := {
		"code":     "ISSUE-501",
		"severity": "critical",
		"message":  sprintf("Branch `%s` is not protected.", [branch.name]),
		# No "job": a branch is not a job. branchName names what this finding is
		# about and is what the identity recipe selects (finding/identity).
		"type":       "unprotected",
		"branchName": branch.name,
		# occurrenceSeverity: what this branch's finding deserves, the
		# registered severity above staying the code's own: critical on the
		# default branch, which every push-triggered workflow runs on, high
		# on any other branch.
		"defaultBranch":      _is_default_branch(branch.name),
		"occurrenceSeverity": _occurrence_severity(branch.name),
	}
}

_is_default_branch(name) if {
	name == object.get(input.pipeline, "defaultBranch", "")
} else := false

# A branch is high only when it is known not to be the default one: with
# the default branch unknown, every branch may be it.
_occurrence_severity(name) := "high" if {
	object.get(input.pipeline, "defaultBranch", "") != ""
	not _is_default_branch(name)
} else := "critical"

_branch_must_be_protected(name) if {
	input.config.branchMustBeProtected.defaultMustBeProtected
	name == input.pipeline.defaultBranch
}

_branch_must_be_protected(name) if {
	some pattern in input.config.branchMustBeProtected.namePatterns
	glob.match(pattern, null, name)
}
