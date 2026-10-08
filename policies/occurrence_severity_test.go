package policies_test

import (
	"context"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// TestOccurrenceSeverityOfBranchAndSourceFindings pins the severity a
// single occurrence deserves, carried on the finding next to the code's
// registered severity (which stays the code's own): an unprotected
// branch (ISSUE-501) is critical on the default branch and high on any
// other branch; an action from an unauthorized owner (ISSUE-713) is high
// on a movable ref and medium when pinned by a full commit SHA, a
// reusable workflow call included.
func TestOccurrenceSeverityOfBranchAndSourceFindings(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	const sha = "0123456789abcdef0123456789abcdef01234567"
	cfg := map[string]any{
		"branchMustBeProtected": map[string]any{"defaultMustBeProtected": true, "namePatterns": []any{"release/*"}},
		"githubActionMustComeFromAuthorizedSources": map[string]any{
			"trustGithubOfficialActions": true, "trustSameOrgActions": true, "minimumStars": 0,
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitHub,
		ProjectPath:   "o/r",
		DefaultBranch: "main",
		Branches:      []ir.Branch{{Name: "main", Protected: false}, {Name: "release/1", Protected: false}},
		Jobs: []ir.Job{
			{Name: "ci/a", Uses: []ir.Action{{Uses: "other/tag@v1", Line: 1}, {Uses: "other/pinned@" + sha, Line: 2}, {Uses: "other/short@0123456", Line: 3}}},
			{Name: "ci/call", ReusableWorkflowUses: "other/wf/.github/workflows/x.yml@" + sha},
		},
	}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range findings {
		switch f.Code {
		case "ISSUE-501":
			if f.Severity != "critical" {
				t.Errorf("ISSUE-501 keeps its registered severity, got %q", f.Severity)
			}
			got[f.Data["branchName"].(string)], _ = f.Data["occurrenceSeverity"].(string)
		case "ISSUE-713":
			if f.Severity != "high" {
				t.Errorf("ISSUE-713 keeps its registered severity, got %q", f.Severity)
			}
			got[f.Data["uses"].(string)], _ = f.Data["occurrenceSeverity"].(string)
		}
	}
	want := map[string]string{
		"main":                "critical",
		"release/1":           "high",
		"other/tag@v1":        "high",
		"other/pinned@" + sha: "medium",
		"other/short@0123456": "high",
		"other/wf/.github/workflows/x.yml@" + sha: "medium",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: occurrenceSeverity = %q, want %q (all: %v)", k, got[k], w, got)
		}
	}
}

// With the default branch unknown, any unprotected branch may be it: its
// occurrence is critical, as the score prices a branch it cannot place.
func TestOccurrenceSeverityOfABranchWithTheDefaultUnknown(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{"branchMustBeProtected": map[string]any{"defaultMustBeProtected": true, "namePatterns": []any{"release/*"}}}
	pipeline := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "o/r",
		Branches: []ir.Branch{{Name: "release/1", Protected: false}}}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, f := range findings {
		if f.Code == "ISSUE-501" {
			seen = true
			if got, _ := f.Data["occurrenceSeverity"].(string); got != "critical" {
				t.Errorf("occurrenceSeverity = %q, want critical", got)
			}
		}
	}
	if !seen {
		t.Fatal("no ISSUE-501 finding")
	}
}
