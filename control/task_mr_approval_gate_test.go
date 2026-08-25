package control

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	glab "gitlab.com/gitlab-org/api/client-go"
)

func boolPtrT(b bool) *bool { return &b }

// mrApprovalRuleControlEnabled decides whether the GitLab protection collection
// runs for an approval-only configuration. If it wrongly returns false when an
// approval control is enabled, protectionData stays nil and both controls
// silently report not-evaluable — the feature quietly stops working. Mirrors
// TestShouldScanMutableExec / TestCicdVariableControlEnabled.
func TestMrApprovalRuleControlEnabled(t *testing.T) {
	minOn := &configuration.MRApprovalRulesMinApprovalsControlConfig{Enabled: boolPtrT(true)}
	minOff := &configuration.MRApprovalRulesMinApprovalsControlConfig{Enabled: boolPtrT(false)}
	coverOn := &configuration.EnabledOnlyControlConfig{Enabled: boolPtrT(true)}
	coverOff := &configuration.EnabledOnlyControlConfig{Enabled: boolPtrT(false)}

	cfgWith := func(min *configuration.MRApprovalRulesMinApprovalsControlConfig, cover *configuration.EnabledOnlyControlConfig) *configuration.Configuration {
		return &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{
			GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
				MergeRequestApprovalRulesMustRequireMinimumApprovals:   min,
				MergeRequestApprovalRulesMustCoverAllProtectedBranches: cover,
			}},
		}}
	}

	t.Run("nil PlumberConfig -> false", func(t *testing.T) {
		if mrApprovalRuleControlEnabled(&configuration.Configuration{}) {
			t.Fatal("expected false when PlumberConfig is nil")
		}
	})
	t.Run("both absent -> false", func(t *testing.T) {
		if mrApprovalRuleControlEnabled(cfgWith(nil, nil)) {
			t.Fatal("expected false when neither control is configured")
		}
	})
	t.Run("both disabled -> false", func(t *testing.T) {
		if mrApprovalRuleControlEnabled(cfgWith(minOff, coverOff)) {
			t.Fatal("expected false when both controls are disabled")
		}
	})
	t.Run("min-approvals only -> true", func(t *testing.T) {
		if !mrApprovalRuleControlEnabled(cfgWith(minOn, nil)) {
			t.Fatal("expected true when the min-approvals control is enabled")
		}
	})
	t.Run("cover-all only -> true", func(t *testing.T) {
		if !mrApprovalRuleControlEnabled(cfgWith(nil, coverOn)) {
			t.Fatal("expected true when the cover-all control is enabled")
		}
	})
	t.Run("--skip-controls excludes both -> false", func(t *testing.T) {
		conf := cfgWith(minOn, coverOn)
		conf.SkipControlsFilter = []string{controlMRApprovalRulesMinApprovals, controlMRApprovalRulesCoverAllBranches}
		if mrApprovalRuleControlEnabled(conf) {
			t.Fatal("expected false when both controls are in --skip-controls")
		}
	})
	t.Run("--controls omitting both -> false", func(t *testing.T) {
		conf := cfgWith(minOn, coverOn)
		conf.ControlsFilter = []string{"branchMustBeProtected"}
		if mrApprovalRuleControlEnabled(conf) {
			t.Fatal("expected false when --controls omits both approval controls")
		}
	})
}

// protectionDataNeeded is the crux of the PR: an approval-only run (with
// branchMustBeProtected disabled) must still fetch protection data.
func TestProtectionDataNeeded(t *testing.T) {
	branchOn := &configuration.BranchProtectionControlConfig{Enabled: boolPtrT(true)}
	approvalOn := &configuration.MRApprovalRulesMinApprovalsControlConfig{Enabled: boolPtrT(true)}

	base := func(branch *configuration.BranchProtectionControlConfig, min *configuration.MRApprovalRulesMinApprovalsControlConfig) *configuration.Configuration {
		return &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{
			GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
				BranchMustBeProtected:                                branch,
				MergeRequestApprovalRulesMustRequireMinimumApprovals: min,
			}},
		}}
	}

	t.Run("nothing enabled -> false", func(t *testing.T) {
		if protectionDataNeeded(base(nil, nil)) {
			t.Fatal("expected false when neither branch nor approval controls need protection")
		}
	})
	t.Run("branch protection enabled -> true", func(t *testing.T) {
		if !protectionDataNeeded(base(branchOn, nil)) {
			t.Fatal("expected true when branchMustBeProtected is enabled")
		}
	})
	t.Run("approval-only (branch disabled) still needs protection -> true", func(t *testing.T) {
		if !protectionDataNeeded(base(nil, approvalOn)) {
			t.Fatal("expected true when only an approval-rule control is enabled")
		}
	})
}

// approvalRulesTierCaveatApplies composes the enabled gate with the zero-rules
// signal. The enabled guard is the load-bearing half: a branch-protection-only
// run on a zero-rules project satisfies approvalRulesReturnedNone but must NOT
// surface the Premium/Ultimate caveat.
func TestApprovalRulesTierCaveatApplies(t *testing.T) {
	withApproval := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{
		GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			MergeRequestApprovalRulesMustRequireMinimumApprovals: &configuration.MRApprovalRulesMinApprovalsControlConfig{Enabled: boolPtrT(true)},
		}},
	}}
	branchOnly := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{
		GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			BranchMustBeProtected: &configuration.BranchProtectionControlConfig{Enabled: boolPtrT(true)},
		}},
	}}
	zeroRules := &gitlab.GitlabProtectionAnalysisData{MRApprovalRulesKnown: true}
	withRules := &gitlab.GitlabProtectionAnalysisData{MRApprovalRulesKnown: true, MRApprovalRules: []*glab.ProjectApprovalRule{{ID: 1}}}

	if approvalRulesTierCaveatApplies(branchOnly, zeroRules) {
		t.Fatal("caveat must NOT fire when the approval controls are disabled (branch-only run, zero rules)")
	}
	if !approvalRulesTierCaveatApplies(withApproval, zeroRules) {
		t.Fatal("caveat must fire when an approval control is enabled and zero rules were returned")
	}
	if approvalRulesTierCaveatApplies(withApproval, withRules) {
		t.Fatal("caveat must NOT fire when approval rules are present")
	}
}
