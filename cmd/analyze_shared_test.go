package cmd

import (
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/gitlab"
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

// TestPrintSummaryScoreBanner_Row45DegradedTakesPrecedenceOverWithheldScore
// covers review finding 6c38fbc735473281 (row 45): a degraded run
// (DataCollectionDegraded, every content control StatusError) also has a nil
// score, since nothing it evaluated is trustworthy enough to count as
// evaluated. The degraded wording is the accurate one ("analysis ran on
// incomplete data, resolve the warnings above"); the generic
// "no control was evaluated" line would be wrong here (it reads as "there
// was nothing to check", not "collection failed"), so degraded must be
// checked first.
func TestPrintSummaryScoreBanner_Row45DegradedTakesPrecedenceOverWithheldScore(t *testing.T) {
	out := captureStdout(t, func() {
		printSummaryScoreBanner(nil, true, true)
	})

	if !strings.Contains(out, "Score withheld — analysis ran on incomplete data") {
		t.Fatalf("a degraded run with nothing evaluated must print the degraded wording, got:\n%s", out)
	}
	if strings.Contains(out, "no control was evaluated") {
		t.Fatalf("a degraded run must not print the generic withheld-score line, got:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// buildProviderControlSummariesAndGroups, row 62: on a run LINKED to the
// platform, bucket not-evaluated controls the same way the push does
// (control.StatusFor(...) == control.StatusError). A STANDALONE run keeps
// today's narrower bucket, keyed on result.NotEvaluable alone.
// ---------------------------------------------------------------------------

func TestBuildProviderControlSummariesAndGroups_Row62_BucketsLikeThePush(t *testing.T) {
	p := &provider.GitLabProvider{}

	t.Run("linked run, nil VariablesData buckets both variable controls not-evaluable", func(t *testing.T) {
		pc := &configuration.PlumberConfig{GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			CicdVariablesMustBeProtected: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)},
			CicdVariablesMustBeMasked:    &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)},
		}}}
		result := &control.AnalysisResult{CiValid: true, VariablesData: nil}

		_, groups := buildProviderControlSummariesAndGroups(p, result, pc, true, nil, nil)

		found := 0
		for _, g := range groups {
			if g.Title != "CI/CD variables must be protected" && g.Title != "CI/CD variables must be masked" {
				continue
			}
			found++
			if !g.NotEvaluable {
				t.Fatalf("%s: want NotEvaluable true on a linked run whose VariablesData is nil, got false", g.Title)
			}
			if g.NotEvaluableReason != "" {
				t.Fatalf("%s: VariablesData==nil names no single control in result.NotEvaluable, want an empty reason, got %q", g.Title, g.NotEvaluableReason)
			}
		}
		if found != 2 {
			t.Fatalf("want both variable controls present, found %d", found)
		}
		if n := countNotEvaluated(groups); n != 2 {
			t.Fatalf("countNotEvaluated: want 2, got %d", n)
		}
	})

	t.Run("standalone run, nil VariablesData keeps today's pass-with-caveat bucket", func(t *testing.T) {
		pc := &configuration.PlumberConfig{GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			CicdVariablesMustBeProtected: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)},
			CicdVariablesMustBeMasked:    &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)},
		}}}
		result := &control.AnalysisResult{CiValid: true, VariablesData: nil}

		_, groups := buildProviderControlSummariesAndGroups(p, result, pc, false, nil, nil)

		found := 0
		for _, g := range groups {
			if g.Title != "CI/CD variables must be protected" && g.Title != "CI/CD variables must be masked" {
				continue
			}
			found++
			if g.NotEvaluable {
				t.Fatalf("%s: standalone run must keep today's bucket (result.NotEvaluable only), got NotEvaluable true", g.Title)
			}
		}
		if found != 2 {
			t.Fatalf("want both variable controls present, found %d", found)
		}
		if n := countNotEvaluated(groups); n != 0 {
			t.Fatalf("countNotEvaluated: want 0 on the unchanged standalone bucket, got %d", n)
		}
	})

	t.Run("a control named in result.NotEvaluable keeps its reason, linked or not", func(t *testing.T) {
		pc := &configuration.PlumberConfig{GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			BranchMustBeProtected: &configuration.BranchProtectionControlConfig{Enabled: boolPtr(true)},
		}}}
		result := &control.AnalysisResult{
			CiValid:      true,
			NotEvaluable: map[string]string{"branchMustBeProtected": "include_attribution_unavailable"},
		}

		for _, linked := range []bool{true, false} {
			_, groups := buildProviderControlSummariesAndGroups(p, result, pc, linked, nil, nil)
			for _, g := range groups {
				if g.Title != "Branch must be protected" {
					continue
				}
				if !g.NotEvaluable {
					t.Fatalf("linked=%v: want NotEvaluable true, got false", linked)
				}
				if g.NotEvaluableReason != "include_attribution_unavailable" {
					t.Fatalf("linked=%v: want the reason from result.NotEvaluable, got %q", linked, g.NotEvaluableReason)
				}
			}
		}
	})

	t.Run("a skipped control stays skipped, not not-evaluable", func(t *testing.T) {
		pc := &configuration.PlumberConfig{GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			BranchMustBeProtected: &configuration.BranchProtectionControlConfig{Enabled: boolPtr(false)},
		}}}
		result := &control.AnalysisResult{CiValid: true}

		_, groups := buildProviderControlSummariesAndGroups(p, result, pc, true, nil, nil)
		for _, g := range groups {
			if g.Title != "Branch must be protected" {
				continue
			}
			if !g.Skipped {
				t.Fatalf("want Skipped true for a disabled control, got false")
			}
			if g.NotEvaluable {
				t.Fatalf("a disabled control must never also read as not-evaluable")
			}
		}
	})

	t.Run("a passing control on a healthy run is untouched", func(t *testing.T) {
		pc := &configuration.PlumberConfig{GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			CicdVariablesMustBeProtected: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)},
		}}}
		result := &control.AnalysisResult{
			CiValid:       true,
			VariablesData: &gitlab.GitlabVariablesAnalysisData{Known: true},
		}

		for _, linked := range []bool{true, false} {
			_, groups := buildProviderControlSummariesAndGroups(p, result, pc, linked, nil, nil)
			for _, g := range groups {
				if g.Title != "CI/CD variables must be protected" {
					continue
				}
				if g.NotEvaluable {
					t.Fatalf("linked=%v: a passing control with known data must not be bucketed not-evaluable", linked)
				}
			}
		}
	})
}
