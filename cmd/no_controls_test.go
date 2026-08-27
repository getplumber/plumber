package cmd

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/provider"
)

// TestBuildComplianceSummary_NoControlsWithholdsScore pins the honest
// outcome of a --no-controls run: no score, anywhere. Zero findings would
// otherwise compute a perfect 100/100, and stamping that on the terminal
// banner, the JSON report, the PBOM and the CycloneDX output would present
// "we checked nothing" as "we checked everything and it was clean".
//
// scoreMode=false is the existing withhold-the-score path (every consumer
// already guards on a nil score), so this reuses it rather than adding a
// second way to say the same thing.
func TestBuildComplianceSummary_NoControlsWithholdsScore(t *testing.T) {
	result := &control.AnalysisResult{CiValid: true}

	for _, p := range []provider.Provider{&provider.GitLabProvider{}, &provider.GitHubProvider{}} {
		t.Run(p.Name(), func(t *testing.T) {
			conf := &configuration.Configuration{NoControls: true}
			s := buildComplianceSummary(p, result, conf)
			if s.score != nil {
				t.Fatalf("--no-controls must withhold the score, got %+v", s.score)
			}
			if s.scoreMode {
				t.Fatal("--no-controls must turn score mode off so every output withholds it")
			}
			if s.controlCount != 0 {
				t.Fatalf("controlCount: got %d, want 0", s.controlCount)
			}
			if !s.noControls {
				t.Fatal("the summary must carry the flag so the gate and the renderer can tell it apart from a misconfiguration")
			}
		})
	}
}

// A run WITHOUT the flag keeps computing a score: the default behaviour is
// untouched by this feature.
func TestBuildComplianceSummary_ScoreStillComputedByDefault(t *testing.T) {
	result := &control.AnalysisResult{CiValid: true}
	conf := &configuration.Configuration{}
	s := buildComplianceSummary(&provider.GitLabProvider{}, result, conf)
	if s.score == nil || !s.scoreMode {
		t.Fatal("without --no-controls the score must still be computed")
	}
	if s.noControls {
		t.Fatal("noControls must be false without the flag")
	}
}

// TestInertFlagsUnderNoControls names every flag that reads or publishes a
// score, so a --no-controls run tells the user once what it ignored instead
// of quietly doing less than they asked. These are warned about rather than
// rejected: CI templates set them globally, and erroring would make
// --no-controls unusable in exactly the templated pipeline that wants it.
func TestInertFlagsUnderNoControls(t *testing.T) {
	oMinPointsSet, oMinScore, oThresholdSet := minPointsSet, minScore, thresholdSet
	oShowScore, oShowScorePoint, oBadge := showScore, showScorePoint, badge
	oPushScore, oMRComment, oPlatformURL := pushScore, mrComment, platformURL
	defer func() {
		minPointsSet, minScore, thresholdSet = oMinPointsSet, oMinScore, oThresholdSet
		showScore, showScorePoint, badge = oShowScore, oShowScorePoint, oBadge
		pushScore, mrComment, platformURL = oPushScore, oMRComment, oPlatformURL
	}()

	minPointsSet, minScore, thresholdSet = false, "", false
	showScore, showScorePoint, badge, pushScore, mrComment, platformURL = false, false, false, false, false, ""
	if got := inertFlagsUnderNoControls(); len(got) != 0 {
		t.Fatalf("nothing set: expected no notice, got %v", got)
	}

	minPointsSet, badge, platformURL = true, true, "https://platform.example"
	got := inertFlagsUnderNoControls()
	want := []string{"--min-points", "--badge", "--platform"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
