package control

import (
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

const pinnedSHA = "0123456789abcdef0123456789abcdef01234567"

// An unprotected branch is Critical on the default branch, High on any
// other; an action from an unauthorized owner is Medium pinned by a full
// commit SHA, High otherwise.
func TestIndividualSeverityFollowsTheBranchAndThePin(t *testing.T) {
	branch := func(name string) opaengine.Finding {
		return opaengine.Finding{Code: string(CodeBranchUnprotected), Data: map[string]any{"branchName": name}}
	}
	cases := []struct {
		name          string
		f             opaengine.Finding
		defaultBranch string
		want          IssueSeverity
	}{
		{"default branch", branch("main"), "main", SeverityCritical},
		{"another branch", branch("release/1.x"), "main", SeverityHigh},
		{"default branch unknown", branch("release/1.x"), "", SeverityCritical},
		{"pinned action", opaengine.Finding{Code: string(CodeActionUnauthorizedSource), Data: map[string]any{"uses": "o/a@" + pinnedSHA}}, "main", SeverityMedium},
		{"pinned action subject", opaengine.Finding{Code: string(CodeActionUnauthorizedSource), Subject: "o/a@" + pinnedSHA}, "main", SeverityMedium},
		{"action on a tag", opaengine.Finding{Code: string(CodeActionUnauthorizedSource), Data: map[string]any{"uses": "o/a@v1"}}, "main", SeverityHigh},
		{"another code", opaengine.Finding{Code: "ISSUE-701"}, "main", SeverityForCode("ISSUE-701")},
	}
	for _, c := range cases {
		if got := IndividualSeverity(c.f, c.defaultBranch); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
		if got := ContextualSeverity(c.f, nil, c.defaultBranch); got != c.want {
			t.Errorf("%s: contextual %s, want %s", c.name, got, c.want)
		}
	}
}

// The score prices an individual finding at that severity, and counts it
// there.
func TestTheScorePricesAnIndividualFindingAtItsOwnSeverity(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: string(CodeBranchUnprotected), Data: map[string]any{"branchName": "release/1.x"}},
		{Code: string(CodeActionUnauthorizedSource), Job: "ci/build", Data: map[string]any{"uses": "o/a@" + pinnedSHA}},
	}
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: findings, DefaultBranch: "main"})
	if s.OtherFindings == nil || s.OtherFindings.Counts.High != 1 || s.OtherFindings.Counts.Medium != 1 || s.OtherFindings.UncappedLoss != 15 {
		t.Errorf("want one High and one Medium individual finding, 15 points, got %+v", s.OtherFindings)
	}
	if s.Counts.High != 1 || s.Counts.Medium != 1 || s.Counts.Critical != 0 {
		t.Errorf("counts = %+v", s.Counts)
	}
}

// A pinned action from an unauthorized owner anchors nothing on its own.
func TestAPinnedUnauthorizedActionAnchorsNothing(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"ci/build": {}}}
	f := opaengine.Finding{Code: string(CodeActionUnauthorizedSource), Job: "ci/build", Data: map[string]any{"uses": "o/a@" + pinnedSHA}}
	if paths := assemblePaths([]opaengine.Finding{f}, sit); len(paths) != 0 {
		t.Errorf("want no path, got %+v", paths)
	}
}
