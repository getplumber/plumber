package control

import (
	"math"
	"testing"
)

func TestComputePlumberScore_noIssues(t *testing.T) {
	r := ComputePlumberScore(nil)
	if r.FinalPoints != 100 || r.RawPoints != 100 || r.Score != "A" {
		t.Fatalf("expected 100/A, got raw=%f final=%f score=%s", r.RawPoints, r.FinalPoints, r.Score)
	}
	if r.CriticalMalusApplied {
		t.Fatal("unexpected critical malus")
	}
	if r.ProfileID != PlumberScoreProfileID {
		t.Fatalf("expected profile %s, got %s", PlumberScoreProfileID, r.ProfileID)
	}
	if len(r.CodeLosses) != 0 || len(r.Losses) != 0 {
		t.Fatalf("expected no losses, got code=%d sev=%d", len(r.CodeLosses), len(r.Losses))
	}
}

// One Critical (ISSUE-203 = CodeDebugTraceEnabled): loss 25, raw 75, malus caps final at 30 → E.
func TestComputePlumberScore_oneCritical_malusToE(t *testing.T) {
	r := ComputePlumberScore(map[ErrorCode]int{CodeDebugTraceEnabled: 1})
	if math.Abs(r.RawPoints-75.0) > 1e-9 {
		t.Fatalf("expected raw 75, got %f", r.RawPoints)
	}
	if math.Abs(r.FinalPoints-30.0) > 1e-9 {
		t.Fatalf("expected final 30 after malus, got %f", r.FinalPoints)
	}
	if r.Score != "E" || !r.CriticalMalusApplied {
		t.Fatalf("expected score E and malus, got score=%s malus=%v", r.Score, r.CriticalMalusApplied)
	}
	if r.Counts.Critical != 1 {
		t.Fatalf("expected counts.critical=1, got %+v", r.Counts)
	}
}

// One High (CodeImageUnauthorizedSource): loss 15, raw 85 → letter B.
func TestComputePlumberScore_oneHigh(t *testing.T) {
	r := ComputePlumberScore(map[ErrorCode]int{CodeImageUnauthorizedSource: 1})
	if math.Abs(r.RawPoints-85.0) > 1e-9 {
		t.Fatalf("expected raw 85, got %f", r.RawPoints)
	}
	if r.FinalPoints != r.RawPoints {
		t.Fatalf("malus should not apply without critical")
	}
	if r.Score != "B" {
		t.Fatalf("expected score B, got %s", r.Score)
	}
}

// Repeats of the same code are dampened via 1 + 0.5·log2(n).
// High weight 15, n=2: loss = 15 × 1.5 = 22.5, raw = 77.5 → letter B.
func TestComputePlumberScore_repeatsDampened(t *testing.T) {
	r := ComputePlumberScore(map[ErrorCode]int{CodeImageUnauthorizedSource: 2})
	if math.Abs(r.RawPoints-77.5) > 1e-9 {
		t.Fatalf("expected raw 77.5 for one High code n=2, got %f", r.RawPoints)
	}
	if r.Score != "B" {
		t.Fatalf("expected score B, got %s", r.Score)
	}
}

// Per-code High cap is 60. With weight 15, the cap is reached at n ≥ 64 (15·(1+0.5·6) = 60).
// At n=512 (log2=9): uncapped = 15 × (1 + 0.5·9) = 82.5, capped to 60 → raw=40, letter D.
func TestComputePlumberScore_singleCodeCapped(t *testing.T) {
	r := ComputePlumberScore(map[ErrorCode]int{CodeImageUnauthorizedSource: 512})
	if math.Abs(r.RawPoints-40.0) > 1e-9 {
		t.Fatalf("expected raw 40 at single-High-code cap, got %f", r.RawPoints)
	}
	if r.Score != "D" {
		t.Fatalf("expected D, got %s", r.Score)
	}
	if len(r.CodeLosses) != 1 || math.Abs(r.CodeLosses[0].CappedLoss-60.0) > 1e-9 {
		t.Fatalf("expected single High code capped at 60, got %+v", r.CodeLosses)
	}
}

// scoring-v3 hallmark: two distinct High codes each at the per-code cap stack their losses.
// Two High codes at n=512 each → each capped at 60 → total loss 120 → raw clamped to 0 → letter E.
// In scoring-v2 this would have stayed at the single 60-point High cap (raw=40, D).
func TestComputePlumberScore_perCodeCapsStack(t *testing.T) {
	r := ComputePlumberScore(map[ErrorCode]int{
		CodeImageUnauthorizedSource: 512,
		CodeJobVariableOverridden:   512,
	})
	if r.RawPoints != 0 {
		t.Fatalf("expected raw 0 (two High codes both capped), got %f", r.RawPoints)
	}
	if r.Score != "E" {
		t.Fatalf("expected E with stacked High caps, got %s", r.Score)
	}
	if len(r.CodeLosses) != 2 {
		t.Fatalf("expected 2 code rows, got %d", len(r.CodeLosses))
	}
	for _, cl := range r.CodeLosses {
		if math.Abs(cl.CappedLoss-60.0) > 1e-9 {
			t.Fatalf("expected each High code capped at 60, got %+v", cl)
		}
	}
	// Severity rollup sums per-code losses for the same severity.
	if len(r.Losses) != 1 || r.Losses[0].Severity != SeverityHigh ||
		math.Abs(r.Losses[0].CappedLoss-120.0) > 1e-9 {
		t.Fatalf("expected single High rollup with cappedLoss=120, got %+v", r.Losses)
	}
}

// Sanity check: the Low per-code cap of 10 absorbs heavy repeats of one code.
// Low weight 3, n=1024: uncapped = 3 × (1 + 0.5·10) = 18, capped to 10 → raw 90, letter A.
func TestComputePlumberScore_lowCapped(t *testing.T) {
	r := ComputePlumberScore(map[ErrorCode]int{CodeIncludeOutdated: 1024})
	if math.Abs(r.RawPoints-90.0) > 1e-9 {
		t.Fatalf("expected raw 90 at Low cap, got %f", r.RawPoints)
	}
	if r.Score != "A" {
		t.Fatalf("expected A, got %s", r.Score)
	}
}

// Two distinct Medium codes: weight 6 each, n=1 each → 6 + 6 = 12 lost → raw 88, letter B.
// Demonstrates that distinct types at the same severity stack linearly until each hits its cap.
func TestComputePlumberScore_twoMediumCodes(t *testing.T) {
	r := ComputePlumberScore(map[ErrorCode]int{
		CodeJobHardcoded:            1,
		CodeUnsafeVariableExpansion: 1,
	})
	if math.Abs(r.RawPoints-88.0) > 1e-9 {
		t.Fatalf("expected raw 88 (6+6 Medium), got %f", r.RawPoints)
	}
	if r.Score != "B" {
		t.Fatalf("expected B, got %s", r.Score)
	}
	if r.Counts.Medium != 2 {
		t.Fatalf("expected counts.medium=2, got %+v", r.Counts)
	}
}

func TestScoreLetterFromPoints_boundaries(t *testing.T) {
	cases := []struct {
		final float64
		want  string
	}{
		{90, "A"},
		{71, "B"},
		{51, "C"},
		{31, "D"},
		{30.9, "E"},
	}
	for _, tc := range cases {
		if g := scoreLetterFromPoints(tc.final); g != tc.want {
			t.Fatalf("points %f: want letter %s, got %s", tc.final, tc.want, g)
		}
	}
}
