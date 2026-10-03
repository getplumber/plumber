package cmd

import "testing"

func TestScoreProfileFlagDefaultsToV3(t *testing.T) {
	f := analyzeCmd.Flags().Lookup("score-profile")
	if f == nil {
		t.Fatal("no --score-profile flag")
	}
	if f.DefValue != "v3" {
		t.Fatalf("default = %q, want v3 until the flip", f.DefValue)
	}
	if envKeys["score-profile"] != "PLUMBER_ANALYZE_SCORE_PROFILE" {
		t.Fatalf("env key = %q", envKeys["score-profile"])
	}
}

func TestValidateScoreProfile(t *testing.T) {
	for _, ok := range []string{"v3", "v4", "V4", " v3 "} {
		if err := validateScoreProfile(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	if err := validateScoreProfile("v5"); err == nil {
		t.Error("v5 must be refused")
	}
}
