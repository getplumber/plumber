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
}

func TestComputePlumberScore_oneCritical_malusToE(t *testing.T) {
	r := ComputePlumberScore(SeverityCounts{Critical: 1})
	if math.Abs(r.RawPoints-70.0) > 1e-9 {
		t.Fatalf("expected raw 70, got %f", r.RawPoints)
	}
	if math.Abs(r.FinalPoints-30.0) > 1e-9 {
		t.Fatalf("expected final 30 after malus, got %f", r.FinalPoints)
	}
	if r.Score != "E" || !r.CriticalMalusApplied {
		t.Fatalf("expected score E and malus, got score=%s malus=%v", r.Score, r.CriticalMalusApplied)
	}
}

func TestComputePlumberScore_oneHigh(t *testing.T) {
	r := ComputePlumberScore(SeverityCounts{High: 1})
	if math.Abs(r.RawPoints-70.0) > 1e-9 {
		t.Fatalf("expected raw 70, got %f", r.RawPoints)
	}
	if r.FinalPoints != r.RawPoints {
		t.Fatalf("malus should not apply without critical")
	}
	if r.Score != "C" {
		t.Fatalf("expected score C, got %s", r.Score)
	}
}

func TestComputePlumberScore_highCapped(t *testing.T) {
	r := ComputePlumberScore(SeverityCounts{High: 8})
	// uncapped loss would exceed 100; capped at 100 -> 0 points
	if math.Abs(r.FinalPoints) > 1e-9 {
		t.Fatalf("expected 0 final points, got %f", r.FinalPoints)
	}
	if r.Score != "E" {
		t.Fatalf("expected E, got %s", r.Score)
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
