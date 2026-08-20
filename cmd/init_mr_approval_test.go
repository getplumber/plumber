package cmd

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
)

// applyAccessControls maps the three MR-approval wizard answers onto GitLab
// config. A field mix-up (wrong parse target, inverted Enabled, or one control
// writing the other's field) would silently emit a wrong .plumber.yaml from
// `plumber config init` with no drift guard, since both controls ship disabled.
// This pins the mapping.
func TestApplyAccessControls_MRApprovalMapping(t *testing.T) {
	t.Run("min-approvals: enabled with the parsed count", func(t *testing.T) {
		gl := &configuration.ProviderConfig{}
		(&initWizardState{MRApprovalMinEnabled: true, MRApprovalMinCount: "3"}).applyAccessControls(gl, nil)
		c := gl.Controls.MergeRequestApprovalRulesMustRequireMinimumApprovals
		if c == nil || !c.IsEnabled() {
			t.Fatal("min-approvals control should be enabled")
		}
		if c.MinimumRequiredApprovals == nil || *c.MinimumRequiredApprovals != 3 {
			t.Fatalf("MinimumRequiredApprovals = %v, want 3", c.MinimumRequiredApprovals)
		}
		if gl.Controls.MergeRequestApprovalRulesMustCoverAllProtectedBranches != nil {
			t.Fatal("cover-all must stay unset when only min-approvals was chosen (field mix-up)")
		}
	})
	t.Run("cover-all: enabled, min-approvals untouched", func(t *testing.T) {
		gl := &configuration.ProviderConfig{}
		(&initWizardState{MRApprovalCoverAllEnabled: true}).applyAccessControls(gl, nil)
		if c := gl.Controls.MergeRequestApprovalRulesMustCoverAllProtectedBranches; c == nil || !c.IsEnabled() {
			t.Fatal("cover-all control should be enabled")
		}
		if gl.Controls.MergeRequestApprovalRulesMustRequireMinimumApprovals != nil {
			t.Fatal("min-approvals must stay unset when only cover-all was chosen (field mix-up)")
		}
	})
	t.Run("neither approval control set when neither chosen", func(t *testing.T) {
		gl := &configuration.ProviderConfig{}
		(&initWizardState{}).applyAccessControls(gl, nil)
		if gl.Controls.MergeRequestApprovalRulesMustRequireMinimumApprovals != nil || gl.Controls.MergeRequestApprovalRulesMustCoverAllProtectedBranches != nil {
			t.Fatal("no approval controls should be set when neither was chosen")
		}
	})
	// The wizard defaults must come from the embedded shipped default (both ship
	// disabled), so the prompt defaults and the zero-config baseline cannot drift.
	t.Run("defaults sourced from the embedded shipped default", func(t *testing.T) {
		if defaultMRApprovalMinEnabled() {
			t.Error("defaultMRApprovalMinEnabled should be false (ships disabled)")
		}
		if defaultMRApprovalCoverAllEnabled() {
			t.Error("defaultMRApprovalCoverAllEnabled should be false (ships disabled)")
		}
		if got := defaultMRApprovalMinCount(); got < 1 {
			t.Errorf("defaultMRApprovalMinCount = %d, want >= 1 (the shipped minimum)", got)
		}
	})
}

// applyAccessControls maps the approval-settings wizard answers onto GitLab
// config: enabled emits the FULL surface (all five expectations, answered
// values included — a false boolean documents "not checked"), disabled leaves
// the control unset.
func TestApplyAccessControls_MRApprovalSettingsMapping(t *testing.T) {
	t.Run("enabled: full surface with the answered values", func(t *testing.T) {
		gl := &configuration.ProviderConfig{}
		(&initWizardState{
			MRApprovalSettingsEnabled:           true,
			MRApprovalSettingsPreventAuthor:     true,
			MRApprovalSettingsPreventCommitters: true,
			MRApprovalSettingsRequireReAuth:     false,
			MRApprovalSettingsBehavior:          "remove_all_approvals",
		}).applyAccessControls(gl, nil)
		c := gl.Controls.MergeRequestApprovalSettingsMustBeCompliant
		if c == nil || !c.IsEnabled() {
			t.Fatal("approval-settings control should be enabled")
		}
		if c.PreventApprovalByAuthor == nil || !*c.PreventApprovalByAuthor {
			t.Errorf("PreventApprovalByAuthor = %v, want true", c.PreventApprovalByAuthor)
		}
		if c.PreventApprovalsByCommitters == nil || !*c.PreventApprovalsByCommitters {
			t.Errorf("PreventApprovalsByCommitters = %v, want true", c.PreventApprovalsByCommitters)
		}
		if c.RequireReAuthToApprove == nil || *c.RequireReAuthToApprove {
			t.Errorf("RequireReAuthToApprove = %v, want an explicit false (documented surface)", c.RequireReAuthToApprove)
		}
		if c.BehaviorWhenCommitIsAdded == nil || *c.BehaviorWhenCommitIsAdded != "remove_all_approvals" {
			t.Errorf("BehaviorWhenCommitIsAdded = %v, want remove_all_approvals", c.BehaviorWhenCommitIsAdded)
		}
		// Whatever the wizard emits must pass the same validation the loaded
		// file goes through — a wizard writing an invalid file is the exact
		// drift the embedded-default sourcing exists to prevent.
		if err := (&configuration.PlumberConfig{Version: "2.0", GitLab: gl}).Validate(); err != nil {
			t.Errorf("wizard-emitted config failed validation: %v", err)
		}
	})
	t.Run("disabled: control stays unset", func(t *testing.T) {
		gl := &configuration.ProviderConfig{}
		(&initWizardState{}).applyAccessControls(gl, nil)
		if gl.Controls.MergeRequestApprovalSettingsMustBeCompliant != nil {
			t.Fatal("approval-settings control must stay unset when not chosen")
		}
	})
	t.Run("behavior options match what config validation accepts", func(t *testing.T) {
		for _, opt := range mrApprovalBehaviorOptions() {
			cfg := &configuration.PlumberConfig{Version: "2.0", GitLab: &configuration.ProviderConfig{
				Controls: configuration.ControlsConfig{
					MergeRequestApprovalSettingsMustBeCompliant: &configuration.MRApprovalSettingsControlConfig{
						BehaviorWhenCommitIsAdded: &opt,
					},
				},
			}}
			if err := cfg.Validate(); err != nil {
				t.Errorf("wizard option %q rejected by config validation: %v", opt, err)
			}
		}
	})
}
