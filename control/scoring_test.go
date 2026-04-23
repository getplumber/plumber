package control

import (
	"math"
	"testing"
)

func TestComputePlumberScore_noIssues(t *testing.T) {
	r := ComputePlumberScore(SeverityCounts{})
	if r.FinalPoints != 100 || r.RawPoints != 100 || r.Score != "A" {
		t.Fatalf("expected 100/A, got raw=%f final=%f score=%s", r.RawPoints, r.FinalPoints, r.Score)
	}
	if r.CriticalMalusApplied {
		t.Fatal("unexpected critical malus")
	}
	if r.ProfileID != PlumberScoreProfileID {
		t.Fatalf("expected profile %s, got %s", PlumberScoreProfileID, r.ProfileID)
	}
}

// One Critical: loss 25, raw 75, Critical malus caps final at 30 -> E.
func TestComputePlumberScore_oneCritical_malusToE(t *testing.T) {
	r := ComputePlumberScore(SeverityCounts{Critical: 1})
	if math.Abs(r.RawPoints-75.0) > 1e-9 {
		t.Fatalf("expected raw 75, got %f", r.RawPoints)
	}
	if math.Abs(r.FinalPoints-30.0) > 1e-9 {
		t.Fatalf("expected final 30 after malus, got %f", r.FinalPoints)
	}
	if r.Score != "E" || !r.CriticalMalusApplied {
		t.Fatalf("expected score E and malus, got score=%s malus=%v", r.Score, r.CriticalMalusApplied)
	}
}

// One High: loss 20, raw 80 -> letter B.
func TestComputePlumberScore_oneHigh(t *testing.T) {
	r := ComputePlumberScore(SeverityCounts{High: 1})
	if math.Abs(r.RawPoints-80.0) > 1e-9 {
		t.Fatalf("expected raw 80, got %f", r.RawPoints)
	}
	if r.FinalPoints != r.RawPoints {
		t.Fatalf("malus should not apply without critical")
	}
	if r.Score != "B" {
		t.Fatalf("expected score B, got %s", r.Score)
	}
}

// Repeats are dampened via 1 + 0.5·log2(n).
// High with n=2: loss = 20 × 1.5 = 30, raw = 70, letter C.
func TestComputePlumberScore_repeatsDampened(t *testing.T) {
	r := ComputePlumberScore(SeverityCounts{High: 2})
	if math.Abs(r.RawPoints-70.0) > 1e-9 {
		t.Fatalf("expected raw 70 for High=2, got %f", r.RawPoints)
	}
	if r.Score != "C" {
		t.Fatalf("expected score C, got %s", r.Score)
	}
}

// High cap is 60. High=32 would otherwise lose 70 points;
// cap clamps it to 60 -> raw 40 -> letter D.
func TestComputePlumberScore_highCapped(t *testing.T) {
	r := ComputePlumberScore(SeverityCounts{High: 32})
	if math.Abs(r.RawPoints-40.0) > 1e-9 {
		t.Fatalf("expected raw 40 at High cap, got %f", r.RawPoints)
	}
	if r.Score != "D" {
		t.Fatalf("expected D, got %s", r.Score)
	}
	if len(r.Losses) != 1 || math.Abs(r.Losses[0].CappedLoss-60.0) > 1e-9 {
		t.Fatalf("expected High bucket capped at 60, got losses=%+v", r.Losses)
	}
}

// Sanity check: the Low bucket cap of 10 is reached at enough repeats.
// Low n=16: loss = 3 × (1 + 0.5·4) = 9, still below cap. n=1024: 3×6 = 18, capped to 10.
func TestComputePlumberScore_lowCapped(t *testing.T) {
	r := ComputePlumberScore(SeverityCounts{Low: 1024})
	if math.Abs(r.RawPoints-90.0) > 1e-9 {
		t.Fatalf("expected raw 90 at Low cap, got %f", r.RawPoints)
	}
	if r.Score != "A" {
		t.Fatalf("expected A, got %s", r.Score)
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
