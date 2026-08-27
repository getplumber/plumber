package cmd

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/provider"
	"github.com/spf13/cobra"
)

func scoreWithPoints(points float64) *control.PlumberScoreResult {
	// Mirrors the documented letter boundaries (docs/scoring.md).
	letter := "E"
	switch {
	case points >= 90:
		letter = "A"
	case points >= 71:
		letter = "B"
	case points >= 51:
		letter = "C"
	case points >= 31:
		letter = "D"
	}
	return &control.PlumberScoreResult{FinalPoints: points, Score: letter}
}

// ---------------------------------------------------------------------------
// gateErr / passed — score gate (the default)
// ---------------------------------------------------------------------------

func TestGate_DefaultPassesOnPerfectScore(t *testing.T) {
	s := complianceSummary{minPoints: 100, score: scoreWithPoints(100), controlCount: 1}
	if err := s.gateErr(); err != nil {
		t.Fatalf("100 pts with default gate must pass, got %v", err)
	}
	if !s.passed() {
		t.Fatal("passed() must be true")
	}
}

func TestGate_DefaultFailsOnAnyFinding(t *testing.T) {
	// Any finding costs points, so <100 pts must fail the default gate —
	// exact parity with the old default --threshold 100 behavior.
	s := complianceSummary{minPoints: 100, score: scoreWithPoints(97), controlCount: 1}
	err := s.gateErr()
	var gateErr *ScoreGateError
	if !errors.As(err, &gateErr) {
		t.Fatalf("97 pts with default gate must fail with ScoreGateError, got %v", err)
	}
	if !gateErr.PointsGate {
		t.Fatal("failure must be attributed to the points gate")
	}
}

func TestGate_MinPointsRelaxed(t *testing.T) {
	s := complianceSummary{minPoints: 80, minPointsSet: true, score: scoreWithPoints(85), controlCount: 1}
	if err := s.gateErr(); err != nil {
		t.Fatalf("85 pts >= 80 must pass, got %v", err)
	}
}

func TestGate_MinScoreOnlyDisablesPointsGate(t *testing.T) {
	// --min-score C without --min-points: 85 pts (B) passes even though the
	// default minPoints value (100) is still in the struct.
	s := complianceSummary{minPoints: 100, minScore: "C", score: scoreWithPoints(85), controlCount: 1}
	if err := s.gateErr(); err != nil {
		t.Fatalf("letter B >= C with points gate off must pass, got %v", err)
	}
}

func TestGate_MinScoreFails(t *testing.T) {
	s := complianceSummary{minPoints: 100, minScore: "B", score: scoreWithPoints(45), controlCount: 1} // D
	err := s.gateErr()
	var gateErr *ScoreGateError
	if !errors.As(err, &gateErr) {
		t.Fatalf("letter D < B must fail with ScoreGateError, got %v", err)
	}
	if gateErr.PointsGate {
		t.Fatal("failure must be attributed to the letter gate")
	}
	if gateErr.Letter != "D" || gateErr.MinLetter != "B" {
		t.Fatalf("letters = %q < %q, want D < B", gateErr.Letter, gateErr.MinLetter)
	}
}

func TestGate_MinScoreEqualLetterPasses(t *testing.T) {
	// --min-score B on a repo scoring exactly B: equality must pass ("require
	// at least a B" is the common configuration; the comparison is strict <).
	s := complianceSummary{minPoints: 100, minScore: "B", score: scoreWithPoints(85), controlCount: 1} // B
	if err := s.gateErr(); err != nil {
		t.Fatalf("letter B == min-score B must pass, got %v", err)
	}
}

func TestGate_BothGatesMustPass(t *testing.T) {
	// --min-score C --min-points 90: letter passes (B) but points fail.
	s := complianceSummary{minPoints: 90, minPointsSet: true, minScore: "C", score: scoreWithPoints(85), controlCount: 1}
	var gateErr *ScoreGateError
	if !errors.As(s.gateErr(), &gateErr) {
		t.Fatal("85 pts < 90 must fail even when the letter gate passes")
	}
	if !gateErr.PointsGate {
		t.Fatal("failure must be attributed to the points gate")
	}
}

// ---------------------------------------------------------------------------
// gateErr — nothing scoreable (zero controls evaluated)
// ---------------------------------------------------------------------------

func TestGate_NoControlsFailsDespitePerfectScore(t *testing.T) {
	// Zero controls evaluated (a .plumber.yaml that only configures the
	// other provider, all controls disabled, a skip-all filter, or a GitLab
	// project with no usable CI — GitLab compliance zeroes the count): zero
	// findings score 100 pts, but nothing was checked, so the gate must
	// fail. The old GitLab default failed this too (compliance 0 when no
	// control is considered).
	s := complianceSummary{minPoints: 100, score: scoreWithPoints(100), controlCount: 0}
	var gateErr *ScoreGateError
	if !errors.As(s.gateErr(), &gateErr) || !gateErr.NoControls {
		t.Fatalf("zero evaluated controls must fail the score gate, got %v", s.gateErr())
	}
	if !strings.Contains(s.gateLine(), "no controls evaluated") {
		t.Fatalf("gateLine %q must explain that no controls ran", s.gateLine())
	}
}

// TestGate_NoControlsFlagPasses is the counterpart of the test above: the
// zero-control fail-closed exists to catch a run that MEANT to check
// something and checked nothing. --no-controls means the user asked for
// nothing to be checked, so the same zero must pass. There is no score to
// gate on either, which is why the gate has nothing left to fail.
//
// This is what lets a PBOM-only pipeline exit 0 without pretending it was
// scored.
func TestGate_NoControlsFlagPasses(t *testing.T) {
	s := complianceSummary{minPoints: 100, controlCount: 0, noControls: true}
	if err := s.gateErr(); err != nil {
		t.Fatalf("--no-controls must not fail the gate, got %v", err)
	}
	if !s.passed() {
		t.Fatal("--no-controls must report passed")
	}
	if !strings.Contains(s.gateLine(), "no controls requested") {
		t.Fatalf("gateLine %q must say the run asked for no controls, not that scoring failed", s.gateLine())
	}
}

// TestGate_NoControlsFlagIgnoresScoreGates pins that the score gates are
// inert rather than fatal under --no-controls. A CI template that sets
// --min-points or --min-score globally must not turn a deliberate
// PBOM-only run into a failure: with nothing evaluated there is no score
// for those gates to read.
func TestGate_NoControlsFlagIgnoresScoreGates(t *testing.T) {
	s := complianceSummary{
		minPoints: 100, minPointsSet: true, minScore: "A",
		controlCount: 0, noControls: true,
	}
	if err := s.gateErr(); err != nil {
		t.Fatalf("score gates must be inert under --no-controls, got %v", err)
	}

	// The deprecated --threshold gate normally wins over everything, and it
	// reads the passing-controls percentage, which is 0 when nothing ran. It
	// must be inert too, or --no-controls would still fail for anyone whose
	// CI template still passes --threshold.
	withThreshold := complianceSummary{
		thresholdSet: true, threshold: 100, compliance: 0,
		controlCount: 0, noControls: true,
	}
	if err := withThreshold.gateErr(); err != nil {
		t.Fatalf("the deprecated --threshold gate must be inert under --no-controls, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// gateErr — deprecated --threshold gate
// ---------------------------------------------------------------------------

func TestGate_DeprecatedThresholdWins(t *testing.T) {
	// threshold set: the legacy passing-controls percentage gates, the score
	// is ignored (even a failing score passes when compliance meets it).
	s := complianceSummary{
		thresholdSet: true, threshold: 80, compliance: 90,
		minPoints: 100, score: scoreWithPoints(20), // letter E
	}
	if err := s.gateErr(); err != nil {
		t.Fatalf("compliance 90 >= threshold 80 must pass, got %v", err)
	}

	s.compliance = 75
	var complianceErr *ComplianceError
	if !errors.As(s.gateErr(), &complianceErr) {
		t.Fatal("compliance 75 < threshold 80 must fail with ComplianceError")
	}
}

// ---------------------------------------------------------------------------
// gateLine
// ---------------------------------------------------------------------------

func TestGateLine_ScoreGate(t *testing.T) {
	s := complianceSummary{minPoints: 100, score: scoreWithPoints(85), controlCount: 1}
	line := s.gateLine()
	for _, want := range []string{"score B", "85.0/100 pts", "≥ 100 pts"} {
		if !strings.Contains(line, want) {
			t.Fatalf("gateLine %q must contain %q", line, want)
		}
	}
}

func TestGateLine_MinScoreOnly(t *testing.T) {
	s := complianceSummary{minPoints: 100, minScore: "C", score: scoreWithPoints(85), controlCount: 1}
	line := s.gateLine()
	if strings.Contains(line, "pts, required ≥ 100 pts") {
		t.Fatalf("points requirement must not appear when only --min-score gates: %q", line)
	}
	if !strings.Contains(line, "≥ C") {
		t.Fatalf("gateLine %q must contain the letter requirement", line)
	}
}

func TestGateLine_DeprecatedThreshold(t *testing.T) {
	s := complianceSummary{thresholdSet: true, threshold: 80, compliance: 75}
	line := s.gateLine()
	if !strings.Contains(line, "75.0%") || !strings.Contains(line, "80%") {
		t.Fatalf("gateLine %q must carry compliance and threshold", line)
	}
	if !strings.Contains(line, "deprecated") {
		t.Fatalf("gateLine %q must flag the threshold gate as deprecated", line)
	}
}

// ---------------------------------------------------------------------------
// resolveGateFlags — gate selection and validation
// ---------------------------------------------------------------------------

// newGateFlagsCmd resets the gate globals (re-registering the flags rebinds
// them to their defaults), clears the set-markers and the component env vars,
// restores everything on cleanup, and returns a command resolveGateFlags can
// inspect — the same shape runAnalyze hands it.
func newGateFlagsCmd(t *testing.T) *cobra.Command {
	t.Helper()
	origThreshold, origThresholdSet := threshold, thresholdSet
	origMinPoints, origMinPointsSet := minPoints, minPointsSet
	origMinScore := minScore
	t.Cleanup(func() {
		threshold, thresholdSet = origThreshold, origThresholdSet
		minPoints, minPointsSet = origMinPoints, origMinPointsSet
		minScore = origMinScore
	})
	thresholdSet, minPointsSet = false, false
	t.Setenv(envKeys["threshold"], "")
	t.Setenv(envKeys["min-points"], "")
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Float64Var(&threshold, "threshold", 100, "")
	cmd.Flags().StringVar(&minScore, "min-score", "", "")
	cmd.Flags().Float64Var(&minPoints, "min-points", 100, "")
	return cmd
}

func TestResolveGateFlags_NothingSetIsDefaultScoreGate(t *testing.T) {
	cmd := newGateFlagsCmd(t)
	if err := resolveGateFlags(cmd); err != nil {
		t.Fatalf("no gate flags must resolve cleanly, got %v", err)
	}
	if thresholdSet || minPointsSet {
		t.Fatalf("nothing set: want both markers false, got thresholdSet=%v minPointsSet=%v", thresholdSet, minPointsSet)
	}
}

func TestResolveGateFlags_ThresholdExcludesScoreGate(t *testing.T) {
	t.Run("with min-points", func(t *testing.T) {
		cmd := newGateFlagsCmd(t)
		mustSetFlag(t, cmd, "threshold", "80")
		mustSetFlag(t, cmd, "min-points", "90")
		if err := resolveGateFlags(cmd); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
			t.Fatalf("threshold + min-points must error, got %v", err)
		}
	})
	t.Run("with min-score", func(t *testing.T) {
		cmd := newGateFlagsCmd(t)
		mustSetFlag(t, cmd, "threshold", "80")
		mustSetFlag(t, cmd, "min-score", "B")
		if err := resolveGateFlags(cmd); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
			t.Fatalf("threshold + min-score must error, got %v", err)
		}
	})
}

func TestResolveGateFlags_EnvThresholdActivatesLegacyGate(t *testing.T) {
	// The GitLab component path: PLUMBER_ANALYZE_THRESHOLD, never a CLI flag.
	cmd := newGateFlagsCmd(t)
	t.Setenv(envKeys["threshold"], "50")
	threshold = 50 // the env fallback copies the value in before resolveGateFlags runs
	if err := resolveGateFlags(cmd); err != nil {
		t.Fatalf("env threshold 50 must resolve cleanly, got %v", err)
	}
	if !thresholdSet {
		t.Fatal("PLUMBER_ANALYZE_THRESHOLD must switch the run to the deprecated gate")
	}
}

func TestResolveGateFlags_EnvMinPointsActivatesPointsGate(t *testing.T) {
	// The GitLab component delivers min_points only via env
	// (PLUMBER_ANALYZE_MIN_POINTS), never as a CLI flag. minPointsSet must
	// pick it up: with min-score also set, pointsGateActive() is
	// minPointsSet || minScore == "", so losing the env clause silently
	// disables the points gate for exactly that configuration.
	cmd := newGateFlagsCmd(t)
	t.Setenv(envKeys["min-points"], "80")
	minPoints = 80 // the env fallback copies the value in before resolveGateFlags runs
	minScore = "C"
	if err := resolveGateFlags(cmd); err != nil {
		t.Fatalf("env min-points 80 + min-score C must resolve cleanly, got %v", err)
	}
	if !minPointsSet {
		t.Fatal("PLUMBER_ANALYZE_MIN_POINTS must mark the points gate as set")
	}

	// Both gates active: 60 pts (letter C) meets ≥ C but not ≥ 80 pts.
	s := complianceSummary{minPoints: 80, minPointsSet: minPointsSet, minScore: minScore, score: scoreWithPoints(60), controlCount: 1}
	var gateErr *ScoreGateError
	if !errors.As(s.gateErr(), &gateErr) || !gateErr.PointsGate {
		t.Fatalf("60 pts < env min-points 80 must fail on the points gate, got %v", s.gateErr())
	}
}

func TestResolveGateFlags_MinScoreNormalized(t *testing.T) {
	cmd := newGateFlagsCmd(t)
	minScore = " b "
	if err := resolveGateFlags(cmd); err != nil {
		t.Fatalf("min-score ' b ' must normalize, got %v", err)
	}
	if minScore != "B" {
		t.Fatalf("min-score = %q, want normalized %q", minScore, "B")
	}
}

func TestResolveGateFlags_MinScoreInvalidErrors(t *testing.T) {
	// An unknown letter must error out (exit 2), never silently disable the
	// gate: a non-empty minScore turns off the default points gate, so letting
	// "F" through would pass every run unconditionally.
	for _, bad := range []string{"F", "AA", "1"} {
		cmd := newGateFlagsCmd(t)
		minScore = bad
		if err := resolveGateFlags(cmd); err == nil || !strings.Contains(err.Error(), "must be one of A, B, C, D, E") {
			t.Fatalf("min-score %q must error, got %v", bad, err)
		}
	}
}

func TestResolveGateFlags_RangeValidation(t *testing.T) {
	t.Run("min-points out of range", func(t *testing.T) {
		cmd := newGateFlagsCmd(t)
		mustSetFlag(t, cmd, "min-points", "150")
		if err := resolveGateFlags(cmd); err == nil || !strings.Contains(err.Error(), "between 0 and 100") {
			t.Fatalf("min-points 150 must error, got %v", err)
		}
	})
	t.Run("threshold out of range", func(t *testing.T) {
		cmd := newGateFlagsCmd(t)
		mustSetFlag(t, cmd, "threshold", "150")
		if err := resolveGateFlags(cmd); err == nil || !strings.Contains(err.Error(), "between 0 and 100") {
			t.Fatalf("threshold 150 must error, got %v", err)
		}
	})
	t.Run("NaN fails closed", func(t *testing.T) {
		// ParseFloat accepts "nan", and NaN answers false to every ordered
		// comparison — both in the range check and in gateErr's
		// `FinalPoints < minPoints` — so an accepted NaN would disable the
		// gate entirely. It must be rejected at validation instead.
		cmd := newGateFlagsCmd(t)
		mustSetFlag(t, cmd, "min-points", "nan")
		if err := resolveGateFlags(cmd); err == nil || !strings.Contains(err.Error(), "between 0 and 100") {
			t.Fatalf("min-points NaN must error, got %v", err)
		}

		cmd = newGateFlagsCmd(t)
		mustSetFlag(t, cmd, "threshold", "nan")
		if err := resolveGateFlags(cmd); err == nil || !strings.Contains(err.Error(), "between 0 and 100") {
			t.Fatalf("threshold NaN must error, got %v", err)
		}
	})
}

func mustSetFlag(t *testing.T, cmd *cobra.Command, name, value string) {
	t.Helper()
	if err := cmd.Flags().Set(name, value); err != nil {
		t.Fatalf("set --%s=%s: %v", name, value, err)
	}
}

// ---------------------------------------------------------------------------
// buildComplianceSummary — per-provider gate wiring from AnalysisResult
// ---------------------------------------------------------------------------

// confWithDebugTrace returns a Configuration whose PlumberConfig enables a
// single GitLab control, so compliance runs count at least one control.
func confWithDebugTrace() *configuration.Configuration {
	enabled := true
	pc := &configuration.PlumberConfig{
		Version: "2.0",
		GitLab: &configuration.ProviderConfig{
			Controls: configuration.ControlsConfig{
				PipelineMustNotEnableDebugTrace: &configuration.DebugTraceControlConfig{
					Enabled: &enabled,
				},
			},
		},
	}
	conf := configuration.NewDefaultConfiguration()
	conf.PlumberConfig = pc
	return conf
}

func TestBuildComplianceSummary_CiWiring(t *testing.T) {
	newGateFlagsCmd(t) // reset gate globals: default points gate (min-points 100)
	gl := &provider.GitLabProvider{}
	conf := confWithDebugTrace()

	t.Run("GitLab missing CI fails via zero controls", func(t *testing.T) {
		// GitLab compliance zeroes the control count on a missing CI, so a
		// CI-less GitLab project keeps failing (its historical verdict).
		s := buildComplianceSummary(gl, &control.AnalysisResult{CiMissing: true, CiValid: true}, conf)
		var gateErr *ScoreGateError
		if !errors.As(s.gateErr(), &gateErr) || !gateErr.NoControls {
			t.Fatalf("GitLab CiMissing must fail with ScoreGateError{NoControls}, got %v", s.gateErr())
		}
	})

	t.Run("GitLab invalid CI fails via zero controls", func(t *testing.T) {
		s := buildComplianceSummary(gl, &control.AnalysisResult{CiValid: false, CiMissing: false}, conf)
		var gateErr *ScoreGateError
		if !errors.As(s.gateErr(), &gateErr) || !gateErr.NoControls {
			t.Fatalf("GitLab invalid CI must fail with ScoreGateError{NoControls}, got %v", s.gateErr())
		}
	})

	t.Run("valid CI with no findings passes", func(t *testing.T) {
		s := buildComplianceSummary(gl, &control.AnalysisResult{CiValid: true}, conf)
		if !s.passed() {
			t.Fatalf("clean run on valid CI must pass, got %v", s.gateErr())
		}
	})

	t.Run("GitHub missing CI passes (pre-0.4.0 behavior restored)", func(t *testing.T) {
		// GitHub compliance counts enabled controls regardless of CiMissing,
		// so a repo with no workflows scores clean and passes the default
		// gate — restored on purpose (fleet scanners must not fail on
		// CI-less repositories). 0.4.0's unconditional CiMissing fail is
		// reverted.
		gh := &provider.GitHubProvider{}
		enabled := true
		ghConf := configuration.NewDefaultConfiguration()
		ghConf.PlumberConfig = &configuration.PlumberConfig{
			GitHub: &configuration.ProviderConfig{
				Controls: configuration.ControlsConfig{
					BranchMustBeProtected: &configuration.BranchProtectionControlConfig{Enabled: &enabled},
				},
			},
		}
		s := buildComplianceSummary(gh, &control.AnalysisResult{CiMissing: true}, ghConf)
		if !s.passed() {
			t.Fatalf("GitHub CI-less repo must pass the default gate again, got %v", s.gateErr())
		}
	})

	t.Run("GitHub with zero enabled controls still fails", func(t *testing.T) {
		gh := &provider.GitHubProvider{}
		emptyConf := configuration.NewDefaultConfiguration()
		emptyConf.PlumberConfig = &configuration.PlumberConfig{}
		s := buildComplianceSummary(gh, &control.AnalysisResult{CiMissing: true}, emptyConf)
		var gateErr *ScoreGateError
		if !errors.As(s.gateErr(), &gateErr) || !gateErr.NoControls {
			t.Fatalf("zero enabled controls must keep failing, got %v", s.gateErr())
		}
	})
}

// ---------------------------------------------------------------------------
// buildAnalysisJSONReport — the machine contract action.yml and the job
// summary parse: conditional minPoints/minScore/threshold keys + passed
// ---------------------------------------------------------------------------

func TestBuildAnalysisJSONReport_GateContract(t *testing.T) {
	result := &control.AnalysisResult{CiValid: true}
	pc := confWithDebugTrace().PlumberConfig
	params := jsonOutputParams{provider: "gitlab"}

	decode := func(t *testing.T, s complianceSummary) map[string]any {
		t.Helper()
		payload, err := buildAnalysisJSONReport(result, pc, s, params)
		if err != nil {
			t.Fatalf("buildAnalysisJSONReport: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(payload, &m); err != nil {
			t.Fatalf("report is not valid JSON: %v", err)
		}
		return m
	}
	assertAbsent := func(t *testing.T, m map[string]any, keys ...string) {
		t.Helper()
		for _, k := range keys {
			if v, ok := m[k]; ok {
				t.Errorf("key %q must be absent, got %v", k, v)
			}
		}
	}

	t.Run("default points gate", func(t *testing.T) {
		m := decode(t, complianceSummary{minPoints: 100, score: scoreWithPoints(100), scoreMode: true, controlCount: 1})
		if m["minPoints"] != 100.0 {
			t.Fatalf("minPoints = %v, want 100", m["minPoints"])
		}
		if m["passed"] != true {
			t.Fatalf("passed = %v, want true", m["passed"])
		}
		assertAbsent(t, m, "minScore", "threshold", "compliance")
	})

	t.Run("letter-only gate omits minPoints", func(t *testing.T) {
		m := decode(t, complianceSummary{minPoints: 100, minScore: "C", score: scoreWithPoints(85), scoreMode: true, controlCount: 1})
		if m["minScore"] != "C" {
			t.Fatalf("minScore = %v, want C", m["minScore"])
		}
		if m["passed"] != true {
			t.Fatalf("passed = %v, want true (85 pts, letter B >= C)", m["passed"])
		}
		// minPoints must NOT appear: only --min-score gates this run, and the
		// job summary renders exactly the keys present.
		assertAbsent(t, m, "minPoints", "threshold", "compliance")
	})

	t.Run("deprecated threshold gate", func(t *testing.T) {
		m := decode(t, complianceSummary{thresholdSet: true, threshold: 80, compliance: 75})
		if m["threshold"] != 80.0 {
			t.Fatalf("threshold = %v, want 80", m["threshold"])
		}
		if m["passed"] != false {
			t.Fatalf("passed = %v, want false (compliance 75 < 80)", m["passed"])
		}
		assertAbsent(t, m, "minPoints", "minScore", "compliance")
	})
}

// rawPointsUnclamped exists ONLY to be read out of the pushed report (the
// platform stores score history and wants the true signed deficit), so its
// presence in the serialized JSON is the contract — the struct field alone
// proves nothing if a projection or an omitempty tag ever drops it from the
// document. A negative fixture value also pins that the emitted number is the
// unclamped one, not a copy of the floored rawPoints sitting next to it.
func TestBuildAnalysisJSONReport_EmitsRawPointsUnclamped(t *testing.T) {
	score := &control.PlumberScoreResult{RawPoints: 0, RawPointsUnclamped: -37.5, Score: "E"}
	s := complianceSummary{minPoints: 100, score: score, scoreMode: true, controlCount: 1}

	payload, err := buildAnalysisJSONReport(&control.AnalysisResult{CiValid: true}, confWithDebugTrace().PlumberConfig, s, jsonOutputParams{provider: "gitlab"})
	if err != nil {
		t.Fatalf("buildAnalysisJSONReport: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}

	ps, ok := m["plumberScore"].(map[string]any)
	if !ok {
		t.Fatalf("plumberScore block missing from the report, got keys %v", m)
	}
	got, ok := ps["rawPointsUnclamped"]
	if !ok {
		t.Fatalf("rawPointsUnclamped missing from plumberScore: the platform's deficit-depth signal is gone, got %v", ps)
	}
	if got != -37.5 {
		t.Errorf("rawPointsUnclamped = %v, want -37.5 (the unclamped value, not the floored rawPoints)", got)
	}
	if ps["rawPoints"] != 0.0 {
		t.Errorf("rawPoints = %v, want 0: the clamped value next to it must stay floored", ps["rawPoints"])
	}
}

// ---------------------------------------------------------------------------
// finalizeRun — exit-code gate priority order
// ---------------------------------------------------------------------------

// TestFinalizeRun_OrderingPriority pins the priority order the platform push
// depends on: a degraded run fails regardless of anything else (#220); then
// --fail-warnings; then the score gate; and the platform token error is
// evaluated LAST, so a broken id-token grant can never mask (by pre-empting)
// a real degraded/warnings/gate failure the scan already found.
func TestFinalizeRun_OrderingPriority(t *testing.T) {
	platformErr := &PlatformTokenError{Reason: "no CI OIDC id-token available"}
	passingGate := complianceSummary{minPoints: 100, score: scoreWithPoints(100), controlCount: 1}
	failingGate := complianceSummary{minPoints: 100, score: scoreWithPoints(0), controlCount: 1}

	t.Run("degraded wins over everything, including a platform error", func(t *testing.T) {
		result := &control.AnalysisResult{DataCollectionDegraded: true, DegradedReasons: []string{"x"}}
		err := finalizeRun(result, passingGate, platformErr)
		var want *IncompleteDataError
		if !errors.As(err, &want) {
			t.Fatalf("finalizeRun = %v (%T), want *IncompleteDataError", err, err)
		}
	})

	t.Run("--fail-warnings wins over the gate and a platform error", func(t *testing.T) {
		defer func(v bool) { failWarnings = v }(failWarnings)
		failWarnings = true
		result := &control.AnalysisResult{Warnings: []string{"could not verify something"}}
		err := finalizeRun(result, passingGate, platformErr)
		var want *DegradedError
		if !errors.As(err, &want) {
			t.Fatalf("finalizeRun = %v (%T), want *DegradedError", err, err)
		}
	})

	t.Run("the score gate wins over a platform error", func(t *testing.T) {
		result := &control.AnalysisResult{}
		err := finalizeRun(result, failingGate, platformErr)
		var want *ScoreGateError
		if !errors.As(err, &want) {
			t.Fatalf("finalizeRun = %v (%T), want *ScoreGateError", err, err)
		}
	})

	t.Run("a platform error surfaces only once nothing else failed", func(t *testing.T) {
		result := &control.AnalysisResult{}
		if err := finalizeRun(result, passingGate, platformErr); err != platformErr {
			t.Fatalf("finalizeRun = %v, want the platform error itself", err)
		}
	})

	t.Run("a clean run with no platform error passes", func(t *testing.T) {
		result := &control.AnalysisResult{}
		if err := finalizeRun(result, passingGate, nil); err != nil {
			t.Fatalf("finalizeRun = %v, want nil", err)
		}
	})
}
