package control

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/ir"
)

// TestMarkUnconfiguredControls pins #459 at the marker level: a RequiresConfig control enabled
// with no substantive field gets ReasonConfigRequired, StatusFor then reports it as error, and an
// existing mark (a more specific lane gap) is kept rather than overwritten.
func TestMarkUnconfiguredControls(t *testing.T) {
	on := true
	pc := &configuration.PlumberConfig{Version: "2.0", GitLab: &configuration.ProviderConfig{
		Controls: configuration.ControlsConfig{
			BranchMustBeProtected: &configuration.BranchProtectionControlConfig{Enabled: &on},
		},
	}}
	entries := []ControlEntry{{ControlName: controlBranchMustBeProtected}}

	t.Run("an unconfigured control is marked config_required and reports error", func(t *testing.T) {
		result := &AnalysisResult{}
		MarkUnconfiguredControls(result, entries, pc, configuration.ProviderGitLab)

		reason, marked := result.NotEvaluableReason(controlBranchMustBeProtected)
		if !marked || reason != ReasonConfigRequired {
			t.Fatalf("want config_required mark, got (%q, %v)", reason, marked)
		}
		if got := StatusFor(entries[0], result, 0); got != StatusError {
			t.Fatalf("want StatusError, got %q", got)
		}
	})

	t.Run("a first reason already recorded is kept", func(t *testing.T) {
		result := &AnalysisResult{}
		result.MarkNotEvaluable(controlBranchMustBeProtected, ReasonLaneNotServed)
		MarkUnconfiguredControls(result, entries, pc, configuration.ProviderGitLab)

		reason, marked := result.NotEvaluableReason(controlBranchMustBeProtected)
		if !marked || reason != ReasonLaneNotServed {
			t.Fatalf("the earlier, more specific reason must survive, got (%q, %v)", reason, marked)
		}
	})

	t.Run("a disabled control is skipped, not marked", func(t *testing.T) {
		off := false
		pcOff := &configuration.PlumberConfig{Version: "2.0", GitLab: &configuration.ProviderConfig{
			Controls: configuration.ControlsConfig{
				BranchMustBeProtected: &configuration.BranchProtectionControlConfig{Enabled: &off},
			},
		}}
		result := &AnalysisResult{}
		MarkUnconfiguredControls(result, []ControlEntry{{ControlName: controlBranchMustBeProtected, Skipped: true}}, pcOff, configuration.ProviderGitLab)
		if _, marked := result.NotEvaluableReason(controlBranchMustBeProtected); marked {
			t.Fatal("a skipped entry must never be marked")
		}
	})

	t.Run("a configured control is not marked", func(t *testing.T) {
		pcSet := &configuration.PlumberConfig{Version: "2.0", GitLab: &configuration.ProviderConfig{
			Controls: configuration.ControlsConfig{
				BranchMustBeProtected: &configuration.BranchProtectionControlConfig{Enabled: &on, NamePatterns: []string{"main"}},
			},
		}}
		result := &AnalysisResult{}
		MarkUnconfiguredControls(result, entries, pcSet, configuration.ProviderGitLab)
		if _, marked := result.NotEvaluableReason(controlBranchMustBeProtected); marked {
			t.Fatal("a control with a substantive field set asserts something and must not be marked")
		}
	})
}

// TestReEvaluateForConfigMarksUnconfiguredControls is the end-to-end half: two policies share the
// same run, one leaves branchMustBeProtected enabled bare, the other sets a substantive field.
// Only the bare policy's evaluation must come back marked config_required.
func TestReEvaluateForConfigMarksUnconfiguredControls(t *testing.T) {
	on := true
	local := &configuration.PlumberConfig{Version: "2.0"}
	conf := &configuration.Configuration{PlumberConfig: local}

	result := &AnalysisResult{
		CiValid:  true,
		Pipeline: &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, ProjectPath: "grp/app"},
	}

	barePolicy := &configuration.PlumberConfig{Version: "2.0", GitLab: &configuration.ProviderConfig{
		Controls: configuration.ControlsConfig{
			BranchMustBeProtected: &configuration.BranchProtectionControlConfig{Enabled: &on},
		},
	}}
	configuredPolicy := &configuration.PlumberConfig{Version: "2.0", GitLab: &configuration.ProviderConfig{
		Controls: configuration.ControlsConfig{
			BranchMustBeProtected: &configuration.BranchProtectionControlConfig{Enabled: &on, NamePatterns: []string{"main"}},
		},
	}}

	bareScoped, _, ok := ReEvaluateForConfig(result, conf, "gitlab", barePolicy)
	if !ok {
		t.Fatal("re-evaluation must succeed with a retained pipeline")
	}
	if _, marked := bareScoped.NotEvaluableReason(controlBranchMustBeProtected); !marked {
		t.Fatal("the bare policy leaves branchMustBeProtected unconfigured and must be marked")
	}

	configuredScoped, _, ok := ReEvaluateForConfig(result, conf, "gitlab", configuredPolicy)
	if !ok {
		t.Fatal("re-evaluation must succeed with a retained pipeline")
	}
	if _, marked := configuredScoped.NotEvaluableReason(controlBranchMustBeProtected); marked {
		t.Fatal("the configured policy set a substantive field and must not be marked")
	}
}
