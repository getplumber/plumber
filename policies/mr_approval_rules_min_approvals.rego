# mr-approval-rules-min-approvals — flag merge-request approval rules that
# require fewer approvals than the configured minimum. GitLab lets a rule
# covering all protected branches require zero (or too few) approvals, which
# quietly weakens the review gate on exactly the branches that ship to
# production. Only rules that cover ALL protected branches are checked: the
# explicit `applies_to_all_protected_branches` flag, or a rule scoped to no
# specific branch (GitLab treats that as covering every branch). A rule scoped
# to one feature branch is out of scope for this control, matching the legacy
# platform semantics.
#
# Three deliberate limitations, kept to match the legacy platform exactly — we
# are migrating it, not improving it (see
# jobs/control/controlGitlabProtectionMRApprovalRulesBelowMinApprovalRequired.go):
#   - Per rule, not aggregate: each covering rule below the minimum is flagged
#     on its own; a stricter covering rule does NOT suppress a weaker one. Two
#     covering rules requiring 1 and 2 both surface when the minimum is 2, even
#     though GitLab requires an MR to satisfy the stricter rule anyway.
#   - Coverage is decided by the flag or a zero branch scope, never by comparing
#     a named branch list against the project's protected branches. A rule that
#     enumerates every protected branch by name (protectedBranchCount > 0) is
#     treated as out of scope.
#   - Every approval rule type is checked (regular, any_approver, code_owner,
#     report_approver); the type is not projected onto the IR and not filtered.
#     A non-review rule — e.g. a scan-result-policy report_approver rule or the
#     built-in Coverage-Check — that covers all protected branches with a low bar
#     is flagged the same as a human-review rule.
#
# GitLab-only: reads input.pipeline.mrApprovalRules, projected from the
# protection collection (gitlab/gitlab_ir.go::buildApprovalRules).
# input.pipeline.mrApprovalRulesKnown is false when the approvals API could
# not be read (a 403/404 from a non-premium GitLab, or a token without scope);
# the rule abstains then, so the control reports not-evaluable, not a pass.
# Identity keys on the rule's stable ID (approvalRuleId), never the renameable
# name, per the #370 volatile-field discipline.
package mr_approval_rules_min_approvals

import rego.v1

deny contains finding if {
	input.pipeline.provider == "gitlab"
	input.pipeline.mrApprovalRulesKnown
	some rule in object.get(input.pipeline, "mrApprovalRules", [])
	_covers_all_protected_branches(rule)
	cfg := object.get(input.config, "mergeRequestApprovalRulesMustRequireMinimumApprovals", {})
	minimum := object.get(cfg, "minimumRequiredApprovals", 0)
	rule.approvalsRequired < minimum
	# A rule's name is optional (GitLab API-created / auto-created rules can carry
	# an empty name, dropped by json:",omitempty"); read it defensively so an
	# unnamed rule below the minimum is still flagged rather than silently
	# skipped when the whole finding object would otherwise be undefined.
	name := object.get(rule, "name", "")
	finding := {
		"code":                 "ISSUE-502",
		"severity":             "high",
		"message":              sprintf("merge request approval rule %q requires %d approval(s), below the configured minimum of %d — a protected branch can be merged with too little review", [name, rule.approvalsRequired, minimum]),
		"approvalRuleId":       rule.id,
		"ruleName":             name,
		"approvalsRequired":    rule.approvalsRequired,
		"minApprovalsRequired": minimum,
	}
}

# A rule covers all protected branches when GitLab's explicit flag is set, or
# when it is scoped to no specific protected branch (protectedBranchCount ==
# 0), which GitLab treats as applying to every branch. Mirrors the legacy
# control's `AppliesToAllProtectedBranches || len(ProtectedBranches) == 0`.
_covers_all_protected_branches(rule) if rule.appliesToAllProtectedBranches

_covers_all_protected_branches(rule) if rule.protectedBranchCount == 0
