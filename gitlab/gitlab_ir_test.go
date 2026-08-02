package gitlab

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

func TestClassifyFunctionRef(t *testing.T) {
	cases := []struct {
		name           string
		ref            string
		expectedKind   string
		expectedDeprec bool
	}{
		{"oci_registry_tag", "registry.gitlab.com/gitlab-org/ci-cd/runner-tools/example/echo:1", "oci", false},
		{"oci_digest", "registry.gitlab.com/gitlab-org/example/echo@sha256:abcd1234", "oci", false},
		{"oci_no_slash", "echo:1", "oci", false},
		{"local_relative", "./path/to/my-function", "local", false},
		{"local_relative_parent", "../shared/my-function", "local", false},
		{"local_absolute", "/opt/gitlab-functions/my-function", "local", false},
		{"git_deprecated", "gitlab.com/funcs/my-git-repo@v1.0.0", "git", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, deprecated := classifyFunctionRef(tc.ref)
			if kind != tc.expectedKind || deprecated != tc.expectedDeprec {
				t.Fatalf("classifyFunctionRef(%q) = (%q, %v), want (%q, %v)", tc.ref, kind, deprecated, tc.expectedKind, tc.expectedDeprec)
			}
		})
	}
}

func TestExtractGitLabRunSteps(t *testing.T) {
	steps := []any{
		map[any]any{
			"name": "say_hi",
			"func": "registry.gitlab.com/gitlab-org/ci-cd/runner-tools/example/echo:1",
		},
		map[any]any{
			"name": "legacy",
			"step": "registry.gitlab.com/gitlab-org/example/legacy:1",
		},
	}
	fns := extractGitLabRunSteps(steps)
	if len(fns) != 2 {
		t.Fatalf("expected 2 functions, got %d (%+v)", len(fns), fns)
	}
	if fns[0].Name != "say_hi" || fns[0].Kind != "oci" || fns[0].Deprecated {
		t.Fatalf("unexpected func: entry: %+v", fns[0])
	}
	if fns[1].Name != "legacy" || fns[1].Ref != "registry.gitlab.com/gitlab-org/example/legacy:1" || !fns[1].Deprecated {
		t.Fatalf("unexpected step: entry: %+v", fns[1])
	}
}
