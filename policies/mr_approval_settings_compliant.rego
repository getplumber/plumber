# mr-approval-settings-compliant — flag a project whose merge-request approval
# settings fall short of the configured expectations. GitLab lets approvals be
# weakened at the project level (authors approving their own MRs, committers
# approving code they wrote, per-MR rule overrides, no re-auth, approvals kept
# when new commits land), which quietly undermines every approval rule sitting
# on top. GitLab-only singleton finding (one per project); the legacy
# platform's identity was empty, so the identity here is the code alone — a
# deliberate consequence is that changing WHICH settings deviate does not
# re-key the finding.
#
# Every expectation is optional (unset = not checked). The four booleans check
# only when configured true, matching the legacy platform's conf semantics
# (controlGitlabProtectionMRApprovalSettings.go: `if p.PreventX && !actualX`),
# so an explicit `false` is the same as unset — there is no "expect the unsafe
# setting" mode. behaviorWhenCommitIsAdded is a minimum on the strictness
# ladder keep_approvals < remove_approvals_by_code_owners <
# remove_all_approvals, again the platform's ordinal comparison. A value
# outside the ladder is rejected at config load (plumberconfig validation),
# so an unknown string never silently disables the check here.
#
# Reads input.pipeline.mrApprovalSettings, projected in positive-security form
# from the protection collection (gitlab/gitlab_ir.go::buildApprovalSettings).
# The projection is nil — absent here — when the settings API could not be
# read (a 401/403 from a token without scope); the rule abstains then, so the
# control reports not-evaluable, not a pass. Merge-request approval settings
# require GitLab Premium or Ultimate; they do not exist on Free, where the API
# answers 200 with defaults instead of an error. That leaves no tier signal to
# branch on, so a Free project reads as unlocked-down and fires — which is why
# the control ships disabled and documents the tier requirement rather than
# guessing (the same call as #412 for the unmasked-variables control).
package mr_approval_settings_compliant

import rego.v1

_behavior_rank := {
	"keep_approvals": 1,
	"remove_approvals_by_code_owners": 2,
	"remove_all_approvals": 3,
}

# The four boolean expectations share one shape: configured true + actual
# false = deviation. Listed once so the deviation set and the finding message
# cannot drift apart.
_boolean_settings := [
	"preventApprovalByAuthor",
	"preventApprovalsByCommitters",
	"preventEditingApprovalRulesInMR",
	"requireReAuthToApprove",
]

deny contains finding if {
	input.pipeline.provider == "gitlab"
	settings := input.pipeline.mrApprovalSettings
	cfg := object.get(input.config, "mergeRequestApprovalSettingsMustBeCompliant", {})
	deviations := _deviations(settings, cfg)
	count(deviations) > 0
	clauses := [_deviation_clause(name, settings, cfg) | some name in deviations]
	finding := {
		"code": "ISSUE-503",
		"severity": "high",
		"message": sprintf(
			"merge request approval settings can be weakened at the project level, overriding any approval rule: %s",
			[concat("; ", clauses)],
		),
		"deviatingSettings": deviations,
		"behaviorWhenCommitIsAdded": settings.behaviorWhenCommitIsAdded,
	}
}

# _deviation_clause renders one deviation as a human-readable current-vs-expected
# clause, so the finding reads as "what is wrong and what was expected" rather
# than a bare list of config keys. The four booleans only ever reach here in
# their unsafe state (configured true, projected false), so each clause is
# fixed; behaviorWhenCommitIsAdded carries the project's actual rung and the
# configured minimum off the strictness ladder.
_deviation_clause("preventApprovalByAuthor", _, _) := "authors can approve their own merge requests (should be prevented)"

_deviation_clause("preventApprovalsByCommitters", _, _) := "users who added commits can approve (should be prevented)"

_deviation_clause("preventEditingApprovalRulesInMR", _, _) := "approval rules can be overridden per merge request (should be locked)"

_deviation_clause("requireReAuthToApprove", _, _) := "approving does not require re-authentication (should be required)"

_deviation_clause("behaviorWhenCommitIsAdded", settings, cfg) := sprintf(
	"approvals are %q when a commit is added (should be at least %q)",
	[settings.behaviorWhenCommitIsAdded, object.get(cfg, "behaviorWhenCommitIsAdded", "")],
)

# _deviations returns the sorted list of expectation names the project fails:
# the boolean expectations configured true whose projected setting is false,
# plus behaviorWhenCommitIsAdded when the project sits below the configured
# minimum on the strictness ladder.
_deviations(settings, cfg) := sort(array.concat(
	[name |
		some name in _boolean_settings
		object.get(cfg, name, false) == true
		object.get(settings, name, false) == false
	],
	[name |
		name := "behaviorWhenCommitIsAdded"
		expected := object.get(cfg, name, "")
		expected != ""
		_behavior_rank[expected] > _behavior_rank[settings.behaviorWhenCommitIsAdded]
	],
))
