package control

import (
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/ir"
)

// TestReEvaluateForConfig_InvalidWorkflowFollowsThePolicysOwnControl is
// the #517 fix round 2: ReEvaluateForConfig evaluates each platform
// policy under that policy's own control tree, so the "control active"
// decision and the "could not be parsed" degraded reason must follow
// the policy, not the run that collected the pipeline.
func TestReEvaluateForConfig_InvalidWorkflowFollowsThePolicysOwnControl(t *testing.T) {
	pipeline := func() *ir.NormalizedPipeline {
		return &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			InvalidWorkflows: []ir.InvalidWorkflow{
				{Path: ".github/workflows/anchor-aliases.yml", Error: "yaml: unknown anchor 'checkout_with' referenced"},
			},
		}
	}
	hasParseReason := func(reasons []string) bool {
		for _, r := range reasons {
			if strings.Contains(r, "could not be parsed and were skipped") {
				return true
			}
		}
		return false
	}
	countCode := func(result *AnalysisResult, code string) int {
		n := 0
		for _, f := range result.Findings {
			if f.Code == code {
				n++
			}
		}
		return n
	}

	// Direction (a): the run's own config lacks the control (so the run
	// degraded and carries the parse reason), but this policy enables it.
	// The policy's verdict must have the finding, no parse reason, and
	// must not read as degraded on this account.
	t.Run("run without the control, policy with it", func(t *testing.T) {
		runConf := &configuration.Configuration{
			PlumberConfig: &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{}},
		}
		policy := &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			WorkflowsMustBeValid: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)},
		}}}
		result := &AnalysisResult{
			CiValid:                true,
			GitHubPipeline:         pipeline(),
			DataCollectionDegraded: true,
			DegradedReasons:        []string{"1 workflow file(s) could not be parsed and were skipped (enable workflowsMustBeValid to report them as findings)"},
		}

		scoped, _, ok := ReEvaluateForConfig(result, runConf, "github", policy)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if n := countCode(scoped, "ISSUE-423"); n != 1 {
			t.Fatalf("expected 1 ISSUE-423 finding, got %d", n)
		}
		if hasParseReason(scoped.DegradedReasons) {
			t.Fatalf("expected no parse-skip reason for a policy with the control active, got %v", scoped.DegradedReasons)
		}
		if scoped.DataCollectionDegraded {
			t.Fatalf("expected DataCollectionDegraded false, got reasons %v", scoped.DegradedReasons)
		}
	})

	// Direction (b): the run's own config has the control active (so the
	// run was clean, no parse reason), but this policy does not carry
	// the control at all. The policy's verdict must have no finding, the
	// parse reason, and read as degraded.
	t.Run("run with the control, policy without it", func(t *testing.T) {
		runConf := &configuration.Configuration{
			PlumberConfig: &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
				WorkflowsMustBeValid: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)},
			}}},
		}
		policy := &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{}}
		result := &AnalysisResult{
			CiValid:        true,
			GitHubPipeline: pipeline(),
		}

		scoped, _, ok := ReEvaluateForConfig(result, runConf, "github", policy)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if n := countCode(scoped, "ISSUE-423"); n != 0 {
			t.Fatalf("expected no ISSUE-423 finding for a policy without the control, got %d", n)
		}
		if !hasParseReason(scoped.DegradedReasons) {
			t.Fatalf("expected a parse-skip degraded reason, got %v", scoped.DegradedReasons)
		}
		if !scoped.DataCollectionDegraded {
			t.Fatal("expected DataCollectionDegraded true")
		}
	})

	// A policy that disables the control explicitly must behave exactly
	// like one that never declared it (direction b).
	t.Run("run with the control, policy explicitly disables it", func(t *testing.T) {
		runConf := &configuration.Configuration{
			PlumberConfig: &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
				WorkflowsMustBeValid: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)},
			}}},
		}
		policy := &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			WorkflowsMustBeValid: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(false)},
		}}}
		result := &AnalysisResult{
			CiValid:        true,
			GitHubPipeline: pipeline(),
		}

		scoped, _, ok := ReEvaluateForConfig(result, runConf, "github", policy)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if n := countCode(scoped, "ISSUE-423"); n != 0 {
			t.Fatalf("expected no ISSUE-423 finding for a policy that disables the control, got %d", n)
		}
		if !hasParseReason(scoped.DegradedReasons) {
			t.Fatalf("expected a parse-skip degraded reason, got %v", scoped.DegradedReasons)
		}
		if !scoped.DataCollectionDegraded {
			t.Fatal("expected DataCollectionDegraded true")
		}
	})

	// A policy with the control active drops only the parse reason: an
	// unrelated degraded reason the run carries (the branch-protection
	// fetch here) is copied as is, and the policy's verdict stays degraded
	// on its account.
	t.Run("policy with the control keeps an unrelated degraded reason", func(t *testing.T) {
		runConf := &configuration.Configuration{
			PlumberConfig: &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{}},
		}
		policy := &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			WorkflowsMustBeValid: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)},
		}}}
		branchReason := degradedReasonBranchProtectionPrefix + "; branch controls were not evaluated"
		result := &AnalysisResult{
			CiValid:                true,
			GitHubPipeline:         pipeline(),
			DataCollectionDegraded: true,
			DegradedReasons: []string{
				"1 workflow file(s) could not be parsed and were skipped (enable workflowsMustBeValid to report them as findings)",
				branchReason,
			},
		}

		scoped, _, ok := ReEvaluateForConfig(result, runConf, "github", policy)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if hasParseReason(scoped.DegradedReasons) {
			t.Fatalf("expected the parse-skip reason dropped, got %v", scoped.DegradedReasons)
		}
		if len(scoped.DegradedReasons) != 1 || scoped.DegradedReasons[0] != branchReason {
			t.Fatalf("expected only the branch-protection reason kept, got %v", scoped.DegradedReasons)
		}
		if !scoped.DataCollectionDegraded {
			t.Fatal("expected DataCollectionDegraded true on the unrelated reason")
		}
	})
}

// TestReEvaluateForConfig_EveryWorkflowInvalidMarksThePolicysCIControls
// is the policy-scoped mirror of the PR #560 all-invalid finding: a
// control the run's config left disabled, but this policy enables, has
// no parsed workflow to judge either, so it must not read as Passed.
func TestReEvaluateForConfig_EveryWorkflowInvalidMarksThePolicysCIControls(t *testing.T) {
	runConf := &configuration.Configuration{
		PlumberConfig: &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			WorkflowsMustBeValid: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)},
		}}},
	}
	policy := invalidOnlyControls()
	result := &AnalysisResult{
		CiValid: true,
		GitHubPipeline: &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			InvalidWorkflows: []ir.InvalidWorkflow{
				{Path: ".github/workflows/anchor-aliases.yml", Error: "yaml: unknown anchor 'checkout_with' referenced"},
			},
		},
	}

	scoped, _, ok := ReEvaluateForConfig(result, runConf, "github", policy)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if got := statusOf(t, scoped, policy, "workflowsMustDeclarePermissions"); got != StatusError {
		t.Errorf("workflowsMustDeclarePermissions: expected %s, got %s", StatusError, got)
	}
	if got := statusOf(t, scoped, policy, "workflowsMustBeValid"); got != StatusFailed {
		t.Errorf("workflowsMustBeValid: expected %s, got %s", StatusFailed, got)
	}
}
