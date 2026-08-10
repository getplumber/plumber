# branch-non-compliant — flag protected branches whose rule settings
# do not meet the minimum bar set in .plumber.yaml.
#
# Only branches that fall under the same policy scope as ISSUE-501
# (namePatterns match or defaultMustBeProtected + default branch) are
# evaluated. Other protected branches are ignored so narrowing
# namePatterns does not leave stray ISSUE-505 on out-of-scope branches.
#
# Mirrors controlGitlabProtectionBranchProtectionNotCompliant.go:
#
#   - allowForcePush must be false (when configured)
#   - codeOwnerApprovalRequired must be true (when configured)
#   - minPushAccessLevel / minMergeAccessLevel: GitLab access levels are
#     numeric (0 = No one, 30 = Developer, 40 = Maintainer). 0 is the
#     STRICTEST setting — fewer roles can perform the action. The branch
#     is flagged when:
#       * GitLab reported a non-zero level for the branch, AND
#       * either policy is 0 (must be "No one"), or branch level < policy.
package branch_non_compliant

import rego.v1

deny contains finding if {
	some i
	branch := input.pipeline.branches[i]
	branch.protected == true
	# Skip branches whose protection-detail fetch failed (typically a
	# GitHub repo where the token lacks Administration:read). Without
	# this guard the rule would false-positive on every read-only
	# token because zero-valued AllowForcePush/CodeOwnerApprovalRequired
	# look identical to "force push allowed AND no code-owner
	# approval required". GitLab always sets this true; GitHub sets
	# it true only when /branches/{name}/protection succeeds.
	object.get(branch, "protectionDetailsKnown", false) == true
	_branch_in_protection_scope(branch.name)
	reasons := [r | r := _non_compliant_reasons[branch.name][_]]
	count(reasons) > 0
	finding := {
		"code":     "ISSUE-505",
		"severity": "high",
		"message":  sprintf("Branch '%s' has non-compliant protection settings", [branch.name]),
		# No "job": a branch is not a job. branchName names what this finding is
		# about and is what the identity recipe selects (finding/identity).
		"type":                          "non_compliant",
		"branchName":                    branch.name,
		"reasons":                       reasons,
		"allowForcePush":                object.get(branch, "allowForcePush", false),
		"allowForcePushDisplay":         object.get(branch, "allowForcePush", false),
		"minMergeAccessLevel":           object.get(branch, "minMergeAccessLevel", 0),
		"authorizedMinMergeAccessLevel": object.get(input.config.branchMustBeProtected, "minMergeAccessLevel", 0),
		"minPushAccessLevel":            object.get(branch, "minPushAccessLevel", 0),
		"authorizedMinPushAccessLevel":  object.get(input.config.branchMustBeProtected, "minPushAccessLevel", 0),
	}
}

# Same scope as package branch_unprotected: branches the user marked as
# subject to branch protection policy (not every protected branch in GitLab).
_branch_in_protection_scope(name) if {
	cfg := object.get(input.config, "branchMustBeProtected", {})
	object.get(cfg, "defaultMustBeProtected", false) == true
	name == input.pipeline.defaultBranch
}

_branch_in_protection_scope(name) if {
	cfg := object.get(input.config, "branchMustBeProtected", {})
	patterns := object.get(cfg, "namePatterns", [])
	some pattern in patterns
	glob.match(pattern, null, name)
}

# Set of human-readable detail lines (one ISSUE-505 groups them under a
# single headline in the CLI).
_non_compliant_reasons[branch.name] contains "Force push is allowed (should be disabled)" if {
	branch := input.pipeline.branches[_]
	input.config.branchMustBeProtected.allowForcePush == false
	branch.allowForcePush == true
}

_non_compliant_reasons[branch.name] contains "Code owner approval is not required" if {
	branch := input.pipeline.branches[_]
	input.config.branchMustBeProtected.codeOwnerApprovalRequired == true
	# IR JSON omits false booleans (omitempty); use object.get so missing reads as false.
	object.get(branch, "codeOwnerApprovalRequired", false) == false
}

# Merge access level: legacy guard — only check when GitLab reported a level
# (cur != 0). Trigger if policy is 0 (must be "No one") or branch < policy.
_non_compliant_reasons[branch.name] contains reason if {
	branch := input.pipeline.branches[_]
	cur := object.get(branch, "minMergeAccessLevel", 0)
	cur != 0
	min := object.get(input.config.branchMustBeProtected, "minMergeAccessLevel", 0)
	_access_level_violates(min, cur)
	reason := sprintf("Merge access level is too low (%d, minimum: %d)", [cur, min])
}

# Push access level: same shape, separate reason so one branch can produce both.
_non_compliant_reasons[branch.name] contains reason if {
	branch := input.pipeline.branches[_]
	cur := object.get(branch, "minPushAccessLevel", 0)
	cur != 0
	min := object.get(input.config.branchMustBeProtected, "minPushAccessLevel", 0)
	_access_level_violates(min, cur)
	reason := sprintf("Push access level is too low (%d, minimum: %d)", [cur, min])
}

# Policy = 0 ("No one allowed") is the strictest setting; any non-zero branch
# level is by definition more permissive.
_access_level_violates(min, _) if min == 0

_access_level_violates(min, cur) if {
	min > 0
	min > cur
}
