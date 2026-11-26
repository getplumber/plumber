package control

import (
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

const pinnedSHA = "0123456789abcdef0123456789abcdef01234567"

// An unprotected branch is Critical on the default branch, High on any
// other; an action, a component or a function from an unauthorized source
// is High however its reference is pinned (a full commit SHA, an image
// digest): the pinning finding judges the pin, and nobody vetted the owner.
func TestIndividualSeverityFollowsTheBranchNotThePin(t *testing.T) {
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
		{"pinned action", opaengine.Finding{Code: string(CodeActionUnauthorizedSource), Data: map[string]any{"uses": "o/a@" + pinnedSHA}}, "main", SeverityHigh},
		{"pinned action subject", opaengine.Finding{Code: string(CodeActionUnauthorizedSource), Subject: "o/a@" + pinnedSHA}, "main", SeverityHigh},
		{"action on a tag", opaengine.Finding{Code: string(CodeActionUnauthorizedSource), Data: map[string]any{"uses": "o/a@v1"}}, "main", SeverityHigh},
		{"pinned component", opaengine.Finding{Code: string(CodeComponentUnauthorizedSource), Subject: "gitlab.example.com/g/c/x@" + pinnedSHA, Data: map[string]any{"componentPath": "gitlab.example.com/g/c/x"}}, "main", SeverityHigh},
		{"pinned component path", opaengine.Finding{Code: string(CodeComponentUnauthorizedSource), Data: map[string]any{"componentPath": "gitlab.example.com/g/c/x@" + pinnedSHA}}, "main", SeverityHigh},
		{"component on a version", opaengine.Finding{Code: string(CodeComponentUnauthorizedSource), Subject: "gitlab.example.com/g/c/x@1.0.0", Data: map[string]any{"componentPath": "gitlab.example.com/g/c/x"}}, "main", SeverityHigh},
		{"component without a ref", opaengine.Finding{Code: string(CodeComponentUnauthorizedSource), Data: map[string]any{"componentPath": "gitlab.example.com/g/c/x"}}, "main", SeverityHigh},
		{"function by digest", opaengine.Finding{Code: string(CodeFunctionUnauthorizedSource), Data: map[string]any{"link": "registry.example.com/g/fn@sha256:" + strings.Repeat("a", 64)}}, "main", SeverityHigh},
		{"function on a tag", opaengine.Finding{Code: string(CodeFunctionUnauthorizedSource), Data: map[string]any{"link": "registry.example.com/g/fn:1.0"}}, "main", SeverityHigh},
		{"function on a short digest", opaengine.Finding{Code: string(CodeFunctionUnauthorizedSource), Data: map[string]any{"link": "registry.example.com/g/fn@sha256:" + strings.Repeat("a", 40)}}, "main", SeverityHigh},
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
// there: the branch other than the default one at High, not the code's
// Critical, and the pinned action at its registered High.
func TestTheScorePricesAnIndividualFindingAtItsOwnSeverity(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: string(CodeBranchUnprotected), Data: map[string]any{"branchName": "release/1.x"}},
		{Code: string(CodeActionUnauthorizedSource), Job: "ci/build", Data: map[string]any{"uses": "o/a@" + pinnedSHA}},
	}
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: findings, DefaultBranch: "main"})
	if s.OtherFindings == nil || s.OtherFindings.Counts.High != 2 || s.OtherFindings.Counts.Medium != 0 || s.OtherFindings.UncappedLoss != 20 {
		t.Errorf("want two High individual findings, 20 points, got %+v", s.OtherFindings)
	}
	if s.Counts.High != 2 || s.Counts.Medium != 0 || s.Counts.Critical != 0 {
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
