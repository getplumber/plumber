# branch-non-compliant — flag protected branches whose rule settings
# do not meet the minimum bar set in .plumber.yaml. The same four
# knobs the Go control compares are surfaced here:
#
#   - allowForcePush must be false (when
#     branchMustBeProtected.allowForcePush = false)
#   - codeOwnerApprovalRequired must be true (when configured)
#   - minPushAccessLevel must be >= threshold
#   - minMergeAccessLevel must be >= threshold
package branch_non_compliant

import rego.v1

deny contains finding if {
	some i
	branch := input.pipeline.branches[i]
	branch.protected == true
	reason := _non_compliant_reason(branch)
	finding := {
		"code":                          "ISSUE-505",
		"severity":                      "high",
		"message":                       sprintf("branch %q protection is non-compliant: %s", [branch.name, reason]),
		"job":                           branch.name,
		"type":                          "non_compliant",
		"branchName":                    branch.name,
		"allowForcePush":                object.get(branch, "allowForcePush", false),
		"allowForcePushDisplay":         object.get(branch, "allowForcePush", false),
		"minMergeAccessLevel":           object.get(branch, "minMergeAccessLevel", 0),
		"authorizedMinMergeAccessLevel": object.get(input.config.branchMustBeProtected, "minMergeAccessLevel", 0),
		"minPushAccessLevel":            object.get(branch, "minPushAccessLevel", 0),
		"authorizedMinPushAccessLevel":  object.get(input.config.branchMustBeProtected, "minPushAccessLevel", 0),
	}
}

_non_compliant_reason(branch) := "force push allowed" if {
	input.config.branchMustBeProtected.allowForcePush == false
	branch.allowForcePush == true
}

_non_compliant_reason(branch) := "code-owner approval not required" if {
	input.config.branchMustBeProtected.codeOwnerApprovalRequired == true
	branch.codeOwnerApprovalRequired == false
}

_non_compliant_reason(branch) := reason if {
	min := input.config.branchMustBeProtected.minPushAccessLevel
	min > 0
	branch.minPushAccessLevel < min
	reason := sprintf("min push access level %d below %d", [branch.minPushAccessLevel, min])
}

_non_compliant_reason(branch) := reason if {
	min := input.config.branchMustBeProtected.minMergeAccessLevel
	min > 0
	branch.minMergeAccessLevel < min
	reason := sprintf("min merge access level %d below %d", [branch.minMergeAccessLevel, min])
}
