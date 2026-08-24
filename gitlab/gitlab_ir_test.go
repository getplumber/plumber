package gitlab

import (
	"testing"

	"github.com/getplumber/plumber/internal/ir"
	glab "gitlab.com/gitlab-org/api/client-go"
)

// TestBuildApprovalRules covers the approval-rules projection: an unreadable
// listing stays known=false (so ISSUE-502/504 report not-evaluable), and a
// known listing projects the stable ID (stringified), the renameable name,
// the approvals count, and protected-branch coverage.
func TestBuildApprovalRules(t *testing.T) {
	// nil protection -> not known, no rules.
	if got, known := buildApprovalRules(nil); got != nil || known {
		t.Fatalf("nil protection: got %v known %v, want nil/false", got, known)
	}

	// An unreadable listing (a 403 the collector recorded) stays known=false
	// even if rules are somehow present.
	if _, known := buildApprovalRules(&GitlabProtectionAnalysisData{MRApprovalRulesKnown: false}); known {
		t.Fatal("unreadable approval-rules listing must report known=false")
	}

	data := &GitlabProtectionAnalysisData{
		MRApprovalRulesKnown: true,
		MRApprovalRules: []*glab.ProjectApprovalRule{
			{ID: 42, Name: "Security", ApprovalsRequired: 1, AppliesToAllProtectedBranches: true},
			{ID: 7, Name: "Scoped", ApprovalsRequired: 2, ProtectedBranches: []*glab.ProtectedBranch{{Name: "main"}}},
			nil,
		},
	}
	got, known := buildApprovalRules(data)
	if !known {
		t.Fatal("known listing must report known=true")
	}
	if len(got) != 2 {
		t.Fatalf("want 2 projected rules (nil entry skipped), got %d", len(got))
	}
	if r := got[0]; r.ID != "42" || r.Name != "Security" || r.ApprovalsRequired != 1 || !r.AppliesToAllProtectedBranches || r.ProtectedBranchCount != 0 {
		t.Fatalf("rule 0 projection mismatch: %+v", r)
	}
	if r := got[1]; r.ID != "7" || r.ApprovalsRequired != 2 || r.AppliesToAllProtectedBranches || r.ProtectedBranchCount != 1 {
		t.Fatalf("rule 1 projection mismatch: %+v", r)
	}
}

func TestToNormalizedPipeline_Empty(t *testing.T) {
	pipeline := ToNormalizedPipeline("group/project", "main", "", nil, nil, nil)
	if pipeline.Provider != ir.ProviderGitLab {
		t.Fatalf("expected provider gitlab, got %q", pipeline.Provider)
	}
	if pipeline.ProjectPath != "group/project" {
		t.Fatalf("expected project path propagated, got %q", pipeline.ProjectPath)
	}
	if pipeline.DefaultBranch != "main" {
		t.Fatalf("expected default branch propagated, got %q", pipeline.DefaultBranch)
	}
	if len(pipeline.Jobs) != 0 {
		t.Fatalf("expected no jobs, got %d", len(pipeline.Jobs))
	}
}

func TestToNormalizedPipeline_JobsAndImages(t *testing.T) {
	origin := &GitlabPipelineOriginData{
		JobMap: map[string]*GitlabPipelineJobData{
			"build":  {Name: "build"},
			"deploy": {Name: "deploy"},
			"lint":   {Name: "lint"},
		},
	}
	images := &GitlabPipelineImageData{
		Images: []GitlabPipelineImageInfo{
			{Job: "build", Link: "docker.io/alpine:3.20", Name: "alpine", Tag: "3.20"},
			{Job: "deploy", Link: "registry.example.com/deployer@sha256:abcdef", Name: "deployer"},
		},
	}

	pipeline := ToNormalizedPipeline("grp/proj", "main", "", origin, images, nil)

	if got := len(pipeline.Jobs); got != 3 {
		t.Fatalf("expected 3 jobs, got %d", got)
	}

	// Sorted alphabetically: build, deploy, lint
	names := []string{pipeline.Jobs[0].Name, pipeline.Jobs[1].Name, pipeline.Jobs[2].Name}
	expected := []string{"build", "deploy", "lint"}
	for i := range names {
		if names[i] != expected[i] {
			t.Fatalf("jobs[%d]: expected %q, got %q", i, expected[i], names[i])
		}
	}

	if pipeline.Jobs[0].Image == nil || pipeline.Jobs[0].Image.Tag != "3.20" {
		t.Fatalf("build job image: expected tag 3.20, got %+v", pipeline.Jobs[0].Image)
	}
	if pipeline.Jobs[1].Image == nil || pipeline.Jobs[1].Image.Digest != "sha256:abcdef" {
		t.Fatalf("deploy job image: expected digest sha256:abcdef, got %+v", pipeline.Jobs[1].Image)
	}
	if pipeline.Jobs[2].Image != nil {
		t.Fatalf("lint job: expected no image, got %+v", pipeline.Jobs[2].Image)
	}
}

func TestToNormalizedPipeline_NilJobInMap(t *testing.T) {
	origin := &GitlabPipelineOriginData{
		JobMap: map[string]*GitlabPipelineJobData{
			"valid":     {Name: "valid"},
			"corrupted": nil,
		},
	}

	pipeline := ToNormalizedPipeline("grp/proj", "main", "", origin, nil, nil)
	if got := len(pipeline.Jobs); got != 1 {
		t.Fatalf("expected 1 job (nil entry skipped), got %d", got)
	}
	if pipeline.Jobs[0].Name != "valid" {
		t.Fatalf("expected valid job kept, got %q", pipeline.Jobs[0].Name)
	}
}
