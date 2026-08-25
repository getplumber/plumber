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
