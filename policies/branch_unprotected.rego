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
		"code":       "ISSUE-501",
		"severity":   "critical",
		"message":    sprintf("branch %q must be protected", [branch.name]),
		"job":        branch.name,
		"type":       "unprotected",
		"branchName": branch.name,
	}
}

_branch_must_be_protected(name) if {
	input.config.branchMustBeProtected.defaultMustBeProtected
	name == input.pipeline.defaultBranch
}

_branch_must_be_protected(name) if {
	some pattern in input.config.branchMustBeProtected.namePatterns
	glob.match(pattern, null, name)
}
