package control

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
)

// cicdVariableControlEnabled decides whether the extra settings-variable API
// call runs, and therefore whether the two controls can produce findings at
// all. A false negative leaves variablesData nil and the controls report
// not-evaluable (never evaluate); a false positive makes an unnecessary API
// call every run. Mirrors TestShouldScanMutableExec for the sibling gate.
func TestCicdVariableControlEnabled(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }
	on := &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)}
	off := &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(false)}

	cfgWith := func(protected, masked *configuration.EnabledOnlyControlConfig) *configuration.Configuration {
		return &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{
			GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
				CicdVariablesMustBeProtected: protected,
				CicdVariablesMustBeMasked:    masked,
			}},
		}}
	}

	t.Run("nil PlumberConfig -> false", func(t *testing.T) {
		if cicdVariableControlEnabled(&configuration.Configuration{}) {
			t.Fatal("expected false when PlumberConfig is nil")
		}
	})
	t.Run("both absent -> false", func(t *testing.T) {
		if cicdVariableControlEnabled(cfgWith(nil, nil)) {
			t.Fatal("expected false when neither control is configured")
		}
	})
	t.Run("both disabled -> false", func(t *testing.T) {
		if cicdVariableControlEnabled(cfgWith(off, off)) {
			t.Fatal("expected false when both controls are disabled")
		}
	})
	t.Run("protected only -> true", func(t *testing.T) {
		if !cicdVariableControlEnabled(cfgWith(on, nil)) {
			t.Fatal("expected true when the protected control is enabled")
		}
	})
	t.Run("masked only -> true", func(t *testing.T) {
		if !cicdVariableControlEnabled(cfgWith(nil, on)) {
			t.Fatal("expected true when the masked control is enabled")
		}
	})
	t.Run("--skip-controls excludes both -> false", func(t *testing.T) {
		conf := cfgWith(on, on)
		conf.SkipControlsFilter = []string{controlCicdVariablesMustBeProtected, controlCicdVariablesMustBeMasked}
		if cicdVariableControlEnabled(conf) {
			t.Fatal("expected false when both controls are in --skip-controls")
		}
	})
	t.Run("--controls omitting both -> false", func(t *testing.T) {
		conf := cfgWith(on, on)
		conf.ControlsFilter = []string{"branchMustBeProtected"}
		if cicdVariableControlEnabled(conf) {
			t.Fatal("expected false when --controls omits both variable controls")
		}
	})
}

// TestStatusFor_VariablesDegradedCarveOut pins the fix for the "variables
// network failure flips every unrelated control to error" blocker: the
// variables degraded reason is carved out of StatusFor's degrade loop the same
// way branch protection is, so only the two variable controls report it.
func TestStatusFor_VariablesDegradedCarveOut(t *testing.T) {
	varsReason := degradedReasonVariablesPrefix + " (network or timeout)"
	result := &AnalysisResult{
		CiValid:         true,
		DegradedReasons: []string{varsReason},
		VariablesData:   &gitlab.GitlabVariablesAnalysisData{Known: false},
	}
	unrelated := ControlEntry{ControlName: "pipelineMustNotUseDockerInDocker"}
	if got := StatusFor(unrelated, result, 0); got != StatusPassed {
		t.Fatalf("a variables degrade must leave an unrelated CI-file control passed, got %q", got)
	}
	varsCtrl := ControlEntry{ControlName: "cicdVariablesMustBeProtected"}
	if got := StatusFor(varsCtrl, result, 0); got != StatusError {
		t.Fatalf("the variables control with Known=false must report error (not-evaluable), got %q", got)
	}
	// A non-carved-out degrade still flips unrelated controls to error.
	other := &AnalysisResult{CiValid: true, DegradedReasons: []string{"something unrelated failed"}}
	if got := StatusFor(unrelated, other, 0); got != StatusError {
		t.Fatalf("a non-carved degrade must still flip unrelated controls to error, got %q", got)
	}
}

// TestDegradedReasonIsVariables pins the classifier prefix contract.
func TestDegradedReasonIsVariables(t *testing.T) {
	if !degradedReasonIsVariables(degradedReasonVariablesPrefix + " (network or timeout)") {
		t.Fatal("classifier must match the variables degraded-reason prefix")
	}
	if degradedReasonIsVariables(degradedReasonBranchProtectionPrefix + " (network or timeout)") {
		t.Fatal("classifier must not match the branch-protection reason")
	}
}
