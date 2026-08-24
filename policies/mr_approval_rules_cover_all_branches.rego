# mr-approval-rules-cover-all-branches — flag a project where no merge-request
# approval rule targets all protected branches. When every rule is scoped to
# specific branches, a protected branch can exist that no rule covers, so it
# can be merged with no required approval at all. GitLab-only singleton finding
# (one per project); the legacy platform's identity was empty, so the identity
# here is the code alone.
#
# A rule counts only when it carries GitLab's explicit
# `applies_to_all_protected_branches` flag, matching the legacy platform. A
# broader rule targeting "All branches" (no branch scope) is deliberately NOT
# counted here: this control is specifically about the "all protected branches"
# target, and blanket all-branches coverage is a separate concern. This is why
# the minimum-approvals sibling (ISSUE-502), which also accepts a zero-scope
# rule, uses a wider predicate than this one.
#
# The flag is also the ONLY signal used — the rule's scoped branch names are
# never unioned against the project's protected branches. So a project whose
# protected branches are each covered by branch-scoped rules (most commonly a
# single-protected-branch repo with a rule scoped to that one branch) still
# fires, because no rule carries the explicit flag. This is a deliberate
# legacy-faithful limitation, the same one ISSUE-502 carries for scoped rules
# (see mr_approval_rules_min_approvals.rego): the legacy control
# (controlGitlabProtectionMRApprovalRulesAllProtectedBranchesMissing.go) checked
# only the flag, and closing it would need the rule's branch names on the IR
# (only protectedBranchCount is projected today) to compare against
# input.pipeline.branches — a change away from the platform, not a bug fix.
#
# Reads input.pipeline.mrApprovalRules, projected from the protection
# collection. input.pipeline.mrApprovalRulesKnown is false when the approvals
# API could not be read (a 403/404 from a token without scope); the rule
# abstains then, so the control reports not-evaluable, not a pass. Merge
# request approval rules are a GitLab Premium/Ultimate feature; on GitLab Free
# the API returns an empty list (not an error), so a project there reads as
# zero rules and this control fires — enable it only where approval rules are
# available. A project with zero rules IS a finding: no rule covers all
# protected branches, so the gate is absent.
package mr_approval_rules_cover_all_branches

import rego.v1

deny contains finding if {
	input.pipeline.provider == "gitlab"
	input.pipeline.mrApprovalRulesKnown
	rules := object.get(input.pipeline, "mrApprovalRules", [])
	not _has_all_protected_branches_rule(rules)
	finding := {
		"code":       "ISSUE-504",
		"severity":   "high",
		"message":    sprintf("no merge request approval rule applies to all protected branches (%d rule(s) defined) — a protected branch can be merged with no required approval", [count(rules)]),
		"totalRules": count(rules),
	}
}

_has_all_protected_branches_rule(rules) if {
	some rule in rules
	rule.appliesToAllProtectedBranches
}
