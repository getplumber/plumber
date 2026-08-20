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
	t.Run("approval-settings-only still needs protection -> true", func(t *testing.T) {
		conf := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{
			GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
				MergeRequestApprovalSettingsMustBeCompliant: &configuration.MRApprovalSettingsControlConfig{Enabled: boolPtrT(true)},
			}},
		}}
		if !protectionDataNeeded(conf) {
			t.Fatal("expected true when only the approval-settings control is enabled")
		}
	})
}

// mrApprovalSettingsControlEnabled gates the protection collection for a
// settings-only run the same way mrApprovalRuleControlEnabled does for the
// rule controls: wrongly false means protectionData stays nil and ISSUE-503
// silently reports not-evaluable on every run.
func TestMrApprovalSettingsControlEnabled(t *testing.T) {
	cfgWith := func(c *configuration.MRApprovalSettingsControlConfig) *configuration.Configuration {
		return &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{
			GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
				MergeRequestApprovalSettingsMustBeCompliant: c,
			}},
		}}
	}

	if mrApprovalSettingsControlEnabled(&configuration.Configuration{}) {
		t.Fatal("expected false when PlumberConfig is nil")
	}
	if mrApprovalSettingsControlEnabled(cfgWith(nil)) {
		t.Fatal("expected false when the control is not configured")
	}
	if mrApprovalSettingsControlEnabled(cfgWith(&configuration.MRApprovalSettingsControlConfig{Enabled: boolPtrT(false)})) {
		t.Fatal("expected false when the control is disabled")
	}
	if !mrApprovalSettingsControlEnabled(cfgWith(&configuration.MRApprovalSettingsControlConfig{Enabled: boolPtrT(true)})) {
		t.Fatal("expected true when the control is enabled")
	}
	skipped := cfgWith(&configuration.MRApprovalSettingsControlConfig{Enabled: boolPtrT(true)})
	skipped.SkipControlsFilter = []string{controlMRApprovalSettings}
	if mrApprovalSettingsControlEnabled(skipped) {
		t.Fatal("expected false when the control is in --skip-controls")
	}
	filtered := cfgWith(&configuration.MRApprovalSettingsControlConfig{Enabled: boolPtrT(true)})
	filtered.ControlsFilter = []string{"branchMustBeProtected"}
	if mrApprovalSettingsControlEnabled(filtered) {
		t.Fatal("expected false when --controls omits the control")
	}
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

// mrApprovalSettingsTierCaveatApplies composes the enabled gate with the
// all-settings-false signal. The enabled guard is load-bearing the same way it
// is for the rules caveat, and any single locked setting proves the project is
// on a paid tier and must suppress the caveat.
func TestMRApprovalSettingsTierCaveatApplies(t *testing.T) {
	withControl := func(enabled bool) *configuration.Configuration {
		return &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{
			GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
				MergeRequestApprovalSettingsMustBeCompliant: &configuration.MRApprovalSettingsControlConfig{Enabled: boolPtrT(enabled)},
			}},
		}}
	}
	// Fully unlocked (the GitLab-Free signature): authors CAN approve (the author
	// flag is inverted — true means no protection) and every other protection is
	// off. Equivalent to the r2devops/jobs read.
	unlocked := &gitlab.GitlabProtectionAnalysisData{MRApprovalSettings: &glab.ProjectApprovals{MergeRequestsAuthorApproval: true}}
	// Author approval PREVENTED (author flag false) is a protection in place, so
	// even a zero-value read is a configured paid tier, not the Free signature.
	authorLocked := &gitlab.GitlabProtectionAnalysisData{MRApprovalSettings: &glab.ProjectApprovals{}}
	// Any other single protection active likewise proves a paid tier.
	overrideLocked := &gitlab.GitlabProtectionAnalysisData{MRApprovalSettings: &glab.ProjectApprovals{MergeRequestsAuthorApproval: true, DisableOverridingApproversPerMergeRequest: true}}

	if mrApprovalSettingsTierCaveatApplies(withControl(false), unlocked) {
		t.Fatal("caveat must NOT fire when the settings control is disabled")
	}
	if !mrApprovalSettingsTierCaveatApplies(withControl(true), unlocked) {
		t.Fatal("caveat must fire when the control is enabled and the project has no protections")
	}
	if mrApprovalSettingsTierCaveatApplies(withControl(true), authorLocked) {
		t.Fatal("caveat must NOT fire when author approval is prevented (a protection proves a paid tier)")
	}
	if mrApprovalSettingsTierCaveatApplies(withControl(true), overrideLocked) {
		t.Fatal("caveat must NOT fire when a setting is locked (proves a paid tier)")
	}
	if mrApprovalSettingsTierCaveatApplies(withControl(true), &gitlab.GitlabProtectionAnalysisData{}) {
		t.Fatal("caveat must NOT fire when the settings were not read (nil settings)")
	}
}
