package control

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/getplumber/plumber/configuration"
)

func TestRunGitHubAnalysis_EndToEnd(t *testing.T) {
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	workflow := `name: CI
on: push
jobs:
  lint:
    runs-on: ubuntu-latest
    container: alpine:latest
  test:
    runs-on: ubuntu-latest
    container:
      image: node:20.10.0
`
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}

	enabled := true
	conf := &configuration.Configuration{
		ProjectPath: "owner/repo",
		Branch:      "main",
		GitRepoRoot: tmp,
		PlumberConfig: &configuration.PlumberConfig{
			Version: "1.0",
			GitHub: &configuration.ProviderConfig{
				Controls: configuration.ControlsConfig{
					ContainerImageMustNotUseForbiddenTags: &configuration.ImageForbiddenTagsControlConfig{
						Enabled: &enabled,
						Tags:    []string{"latest"},
					},
				},
			},
		},
	}

	result, err := RunGitHubAnalysis(conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if !result.CiValid {
		t.Error("expected CiValid=true (jobs discovered)")
	}
	if result.CiMissing {
		t.Error("expected CiMissing=false")
	}

	hits := map[string]int{}
	for _, f := range result.Findings {
		hits[f.Code+":"+f.Job]++
	}
	// alpine:latest on ci/lint must flag; node:20.10.0 on ci/test must not.
	if hits["ISSUE-102:ci/lint"] != 1 {
		t.Errorf("expected 1 ISSUE-102 on ci/lint, got %+v", hits)
	}
	if hits["ISSUE-102:ci/test"] != 0 {
		t.Errorf("unexpected finding on ci/test, got %+v", hits)
	}
	// Test asserts on ISSUE-102 only — unrelated defaults-on rules
	// (ISSUE-304 undocumented permissions, ISSUE-602 no concurrency,
	// …) also fire on this intentionally-minimal fixture and are
	// tracked in their own suites.
	if hits["ISSUE-102:ci/lint"]+hits["ISSUE-102:ci/test"] != 1 {
		t.Errorf("expected exactly 1 ISSUE-102 finding, got %+v", hits)
	}
}

func TestRunGitHubAnalysis_NoWorkflows(t *testing.T) {
	tmp := t.TempDir()
	conf := &configuration.Configuration{
		ProjectPath:   "owner/repo",
		GitRepoRoot:   tmp,
		PlumberConfig: &configuration.PlumberConfig{},
	}

	result, err := RunGitHubAnalysis(conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CiValid {
		t.Error("expected CiValid=false when no workflows")
	}
	if !result.CiMissing {
		t.Error("expected CiMissing=true when no workflows")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(result.Findings))
	}
}
