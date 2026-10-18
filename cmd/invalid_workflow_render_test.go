package cmd

import (
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/provider"
)

// TestInvalidWorkflowFindingReachesTheTerminalReport is the full-wiring
// proof for ISSUE-423 (#517): a finding with no catalog.go entry is
// bucketed into no findingGroup and never reaches the printed report
// (control/catalog.go's GitHubControls is what both the terminal's
// Individual findings section and the per-control JSON key findings on).
// This feeds one ISSUE-423 finding through buildProviderControlSummariesAndGroups,
// exactly as outputTextWithProvider does, then renders it, to prove the
// control's catalog entry actually closes that gap rather than merely
// scoring the finding silently.
func TestInvalidWorkflowFindingReachesTheTerminalReport(t *testing.T) {
	useReportColor(colorOff)
	t.Cleanup(func() { useReportColor(colorBasic) })

	enabled := true
	pc := &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
		WorkflowsMustBeValid: &configuration.EnabledOnlyControlConfig{Enabled: &enabled},
	}}}
	message := `workflow file ".github/workflows/anchor-aliases.yml" could not be parsed as a workflow: yaml: unknown anchor 'checkout_with' referenced`
	result := &control.AnalysisResult{
		CiValid: true,
		Findings: []opaengine.Finding{{
			Code:    "ISSUE-423",
			File:    ".github/workflows/anchor-aliases.yml",
			Message: message,
		}},
		GitHubStats: &control.GitHubAnalysisStats{WorkflowsTotal: 110, WorkflowFilesInvalid: 1},
	}

	_, groups := buildProviderControlSummariesAndGroups(&provider.GitHubProvider{}, result, pc, false, nil, nil, true)

	var b strings.Builder
	renderIndividualFindings(&b, groups, -1, plainCaps)
	out := b.String()

	for _, want := range []string{
		"ISSUE-423",
		"Workflow file is not valid",
		`anchor-aliases.yml" could not be parsed as a workflow:`,
		"unknown anchor 'checkout_with' referenced",
		"Fix    fix the workflow file so GitHub can read it",
		"↳ docs: https://getplumber.io/docs/cli/issues/ISSUE-423",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("printed report does not contain %q:\n%s", want, out)
		}
	}
}
