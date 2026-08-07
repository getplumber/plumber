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
		"message":  sprintf("branch %q must be protected", [branch.name]),
		# No "job": a branch is not a job. branchName names what this finding is
		# about and is what the identity recipe selects (finding/identity).
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
