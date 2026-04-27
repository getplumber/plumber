package collector

import (
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

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
