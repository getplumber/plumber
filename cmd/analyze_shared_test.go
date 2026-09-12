package cmd

import (
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/provider"
)

// ---------------------------------------------------------------------------
// computeScoreResult / outputTextWithProvider, row 45: withhold the score
// when no control was evaluated, instead of reporting a perfect 100/A.
// ---------------------------------------------------------------------------

// TestComputeScoreResult_Row45WithholdsWhenNothingEvaluated pins the rule at
// its lowest level: a zero evaluated-control count withholds the score
// regardless of scoreMode, and scoreMode off withholds it regardless of the
// evaluated count (the existing --no-controls behaviour, unchanged).
func TestComputeScoreResult_Row45WithholdsWhenNothingEvaluated(t *testing.T) {
	result := &control.AnalysisResult{CiValid: true}

	if got := computeScoreResult(result, true, 0); got != nil {
		t.Fatalf("zero evaluated controls must withhold the score even with scoreMode on, got %+v", got)
	}
	if got := computeScoreResult(result, false, 3); got != nil {
		t.Fatalf("scoreMode off must withhold the score regardless of evaluatedCount, got %+v", got)
	}
	if got := computeScoreResult(result, true, 1); got == nil {
		t.Fatal("at least one evaluated control must still produce a score")
	}
}

// TestOutputText_Row45WithholdsScoreWhenNothingEvaluated exercises the full
// terminal render for a run whose only enabled control is config_required
// (#459): GitHub's own ComputeCompliance still counts it (unlike GitLab's,
// which excludes not_evaluable controls), so this is the shape that used to
// print a perfect 100/A grade on a run that checked nothing real. It must
// now print the withheld line and no graded letter badge.
func TestOutputText_Row45WithholdsScoreWhenNothingEvaluated(t *testing.T) {
	oPrint := printOutput
	defer func() { printOutput = oPrint }()
	printOutput = true
	newGateFlagsCmd(t)

	gh := &provider.GitHubProvider{}
	enabled := true
	conf := configuration.NewDefaultConfiguration()
	conf.PlumberConfig = &configuration.PlumberConfig{
		GitHub: &configuration.ProviderConfig{
			Controls: configuration.ControlsConfig{
				ActionsMustBePinnedByCommitSha: &configuration.ActionsPinnedByShaControlConfig{Enabled: &enabled},
			},
		},
	}
	result := &control.AnalysisResult{
		CiValid:     true,
		ProjectPath: "group/project",
		NotEvaluable: map[string]string{
			"actionsMustBePinnedByCommitSha": control.ReasonConfigRequired,
		},
	}

	s := buildComplianceSummary(gh, result, conf)
	out := captureStdout(t, func() {
		if err := outputTextWithProvider(gh, result, conf, s, nil, nil); err != nil {
			t.Fatalf("render: %v", err)
		}
	})

	if !strings.Contains(out, "Score withheld: no control was evaluated") {
		t.Fatalf("must print the withheld line, got:\n%s", out)
	}
	if strings.Contains(out, "/ 100 pts") {
		t.Fatalf("must not print the graded letter-score badge, got:\n%s", out)
	}
}
