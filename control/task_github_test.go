package control

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/getplumber/plumber/configuration"
	githubpkg "github.com/getplumber/plumber/github"
	"github.com/getplumber/plumber/internal/ir"
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
		return
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
	// (ISSUE-801 undocumented permissions, ISSUE-418 no concurrency,
	// …) also fire on this intentionally-minimal fixture and are
	// tracked in their own suites.
	if hits["ISSUE-102:ci/lint"]+hits["ISSUE-102:ci/test"] != 1 {
		t.Errorf("expected exactly 1 ISSUE-102 finding, got %+v", hits)
	}
}

// writeMinimalWorkflow lays down a one-job workflow so the scan finds CI.
func writeMinimalWorkflow(t *testing.T) string {
	t.Helper()
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
`
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}
	return tmp
}

// swapDefaultBranchFetch replaces the package seam for the repo-metadata
// default-branch lookup. Restores via t.Cleanup.
func swapDefaultBranchFetch(t *testing.T, fn func(host, owner, repo string) (string, error)) {
	t.Helper()
	orig := fetchGitHubDefaultBranch
	fetchGitHubDefaultBranch = fn
	t.Cleanup(func() { fetchGitHubDefaultBranch = orig })
}

// Regression for the "public score badge stays unknown" bug: the report's
// defaultBranch must be resolved from the forge even when the
// branchMustBeProtected control is disabled (the only place that used to
// fetch it), otherwise the score service cannot attribute a default-branch
// push and never updates the public badge.
func TestRunGitHubAnalysis_ResolvesDefaultBranch_WithoutBranchProtectionControl(t *testing.T) {
	var gotOwner, gotRepo string
	swapDefaultBranchFetch(t, func(host, owner, repo string) (string, error) {
		gotOwner, gotRepo = owner, repo
		return "master", nil
	})

	conf := &configuration.Configuration{
		ProjectPath:   "toptal/chewy",
		GitRepoRoot:   writeMinimalWorkflow(t),
		PlumberConfig: &configuration.PlumberConfig{},
	}

	result, err := RunGitHubAnalysis(conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOwner != "toptal" || gotRepo != "chewy" {
		t.Errorf("expected fetch for toptal/chewy, got %q/%q", gotOwner, gotRepo)
	}
	if result.DefaultBranch != "master" {
		t.Errorf("expected DefaultBranch %q, got %q", "master", result.DefaultBranch)
	}
}

// The forge-resolved default branch is authoritative: --branch selects the
// branch to ANALYZE and must not masquerade as the repo default when the
// real one is known.
func TestRunGitHubAnalysis_ForgeDefaultBranchWinsOverAnalyzeBranch(t *testing.T) {
	swapDefaultBranchFetch(t, func(host, owner, repo string) (string, error) {
		return "main", nil
	})

	conf := &configuration.Configuration{
		ProjectPath:   "owner/repo",
		Branch:        "feature-x",
		GitRepoRoot:   writeMinimalWorkflow(t),
		PlumberConfig: &configuration.PlumberConfig{},
	}

	result, err := RunGitHubAnalysis(conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.DefaultBranch != "main" {
		t.Errorf("expected DefaultBranch %q, got %q", "main", result.DefaultBranch)
	}
	if result.AnalyzeBranch != "feature-x" {
		t.Errorf("expected AnalyzeBranch %q, got %q", "feature-x", result.AnalyzeBranch)
	}
}

// When the lookup degrades (no auth, API down) the analyze branch remains
// the best available stand-in, matching the pre-existing behavior.
func TestRunGitHubAnalysis_DefaultBranchFallsBackToAnalyzeBranch(t *testing.T) {
	swapDefaultBranchFetch(t, func(host, owner, repo string) (string, error) {
		return "", errors.New("api unreachable")
	})

	conf := &configuration.Configuration{
		ProjectPath:   "owner/repo",
		Branch:        "main",
		GitRepoRoot:   writeMinimalWorkflow(t),
		PlumberConfig: &configuration.PlumberConfig{},
	}

	result, err := RunGitHubAnalysis(conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.DefaultBranch != "main" {
		t.Errorf("expected DefaultBranch fallback %q, got %q", "main", result.DefaultBranch)
	}
}

// swapRemoteScan replaces the package seam for the remote workflow fetch so
// RunGitHubAnalysisRemote tests never need network or auth. Restores via
// t.Cleanup.
func swapRemoteScan(t *testing.T, fn func(host, owner, repo, ref string, enrich, scanMutableExec bool, progressFn githubpkg.ProgressFunc) (*ir.NormalizedPipeline, []error, error)) {
	t.Helper()
	orig := scanGitHubWorkflowsRemote
	scanGitHubWorkflowsRemote = fn
	t.Cleanup(func() { scanGitHubWorkflowsRemote = orig })
}

// remoteScanStub mirrors the production remote scan's seeding contract:
// pipeline.DefaultBranch starts as the fetched ref.
func remoteScanStub(host, owner, repo, ref string, enrich, scanMutableExec bool, progressFn githubpkg.ProgressFunc) (*ir.NormalizedPipeline, []error, error) {
	return &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitHub,
		ProjectPath:   owner + "/" + repo,
		DefaultBranch: ref,
	}, nil, nil
}

// Remote-path mirror of the forge-wins test: the analyzed ref must not
// masquerade as the repo default when the real one is known.
func TestRunGitHubAnalysisRemote_ForgeDefaultBranchWinsOverRef(t *testing.T) {
	swapRemoteScan(t, remoteScanStub)
	swapDefaultBranchFetch(t, func(host, owner, repo string) (string, error) {
		return "main", nil
	})

	conf := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{}}
	result, err := RunGitHubAnalysisRemote(conf, "owner", "repo", "feature-x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.DefaultBranch != "main" {
		t.Errorf("expected DefaultBranch %q, got %q", "main", result.DefaultBranch)
	}
	if result.AnalyzeBranch != "feature-x" {
		t.Errorf("expected AnalyzeBranch %q, got %q", "feature-x", result.AnalyzeBranch)
	}
}

// Remote-path mirror of the degraded-lookup fallbacks: the fetched ref stays
// the stand-in on both the error and the empty-answer shapes.
func TestRunGitHubAnalysisRemote_DefaultBranchFallsBackToRef(t *testing.T) {
	for name, fetch := range map[string]func(host, owner, repo string) (string, error){
		"error":        func(string, string, string) (string, error) { return "", errors.New("api unreachable") },
		"empty answer": func(string, string, string) (string, error) { return "", nil },
	} {
		t.Run(name, func(t *testing.T) {
			swapRemoteScan(t, remoteScanStub)
			swapDefaultBranchFetch(t, fetch)

			conf := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{}}
			result, err := RunGitHubAnalysisRemote(conf, "owner", "repo", "feature-x")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.DefaultBranch != "feature-x" {
				t.Errorf("expected DefaultBranch fallback %q, got %q", "feature-x", result.DefaultBranch)
			}
		})
	}
}

// The degraded lookup can also answer ("", nil) — 401/404 from the API, or
// the PLUMBER_DISABLE_GITHUB_API guard. Same fallback as the error path.
func TestRunGitHubAnalysis_DefaultBranchFallsBackOnEmptyAnswer(t *testing.T) {
	swapDefaultBranchFetch(t, func(host, owner, repo string) (string, error) {
		return "", nil
	})

	conf := &configuration.Configuration{
		ProjectPath:   "owner/repo",
		Branch:        "main",
		GitRepoRoot:   writeMinimalWorkflow(t),
		PlumberConfig: &configuration.PlumberConfig{},
	}

	result, err := RunGitHubAnalysis(conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.DefaultBranch != "main" {
		t.Errorf("expected DefaultBranch fallback %q, got %q", "main", result.DefaultBranch)
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

// TestRunGitHubAnalysis_MarksUnconfiguredControlNotEvaluable pins
// MarkUnconfiguredControls' wiring into RunGitHubAnalysis (#459): a
// RequiresConfig control enabled with no substantive field must surface
// as config_required, not a silent pass, at the real entry point rather
// than only in the unit-level configuration package tests.
func TestRunGitHubAnalysis_MarksUnconfiguredControlNotEvaluable(t *testing.T) {
	enabled := true
	conf := &configuration.Configuration{
		ProjectPath: "owner/repo",
		GitRepoRoot: writeMinimalWorkflow(t),
		PlumberConfig: &configuration.PlumberConfig{
			GitHub: &configuration.ProviderConfig{
				Controls: configuration.ControlsConfig{
					WorkflowMustIncludeRequiredActions: &configuration.RequiredActionsControlConfig{
						Enabled: &enabled,
					},
				},
			},
		},
	}

	result, err := RunGitHubAnalysis(conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	reason, ok := result.NotEvaluableReason("workflowMustIncludeRequiredActions")
	if !ok || reason != ReasonConfigRequired {
		t.Fatalf("expected workflowMustIncludeRequiredActions to be config_required, got reason=%q ok=%v", reason, ok)
	}

	entry := findControlEntry(t, GitHubControls(conf.PlumberConfig), "workflowMustIncludeRequiredActions")
	findingCount := len(FindingsByControl(result.Findings)["workflowMustIncludeRequiredActions"])
	if got := StatusFor(entry, result, findingCount); got != StatusError {
		t.Errorf("expected StatusFor %q, got %q", StatusError, got)
	}
}

// TestRunGitHubAnalysisRemote_MarksUnconfiguredControlNotEvaluable is the
// remote-fetch mirror of the above: MarkUnconfiguredControls is called
// separately in RunGitHubAnalysisRemote (control/task_github.go), so the
// local-path test alone leaves this call site free to be deleted with the
// suite still green.
func TestRunGitHubAnalysisRemote_MarksUnconfiguredControlNotEvaluable(t *testing.T) {
	swapRemoteScan(t, remoteScanStub)

	enabled := true
	conf := &configuration.Configuration{
		PlumberConfig: &configuration.PlumberConfig{
			GitHub: &configuration.ProviderConfig{
				Controls: configuration.ControlsConfig{
					WorkflowMustIncludeRequiredActions: &configuration.RequiredActionsControlConfig{
						Enabled: &enabled,
					},
				},
			},
		},
	}

	result, err := RunGitHubAnalysisRemote(conf, "owner", "repo", "main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	reason, ok := result.NotEvaluableReason("workflowMustIncludeRequiredActions")
	if !ok || reason != ReasonConfigRequired {
		t.Fatalf("expected workflowMustIncludeRequiredActions to be config_required, got reason=%q ok=%v", reason, ok)
	}

	entry := findControlEntry(t, GitHubControls(conf.PlumberConfig), "workflowMustIncludeRequiredActions")
	findingCount := len(FindingsByControl(result.Findings)["workflowMustIncludeRequiredActions"])
	if got := StatusFor(entry, result, findingCount); got != StatusError {
		t.Errorf("expected StatusFor %q, got %q", StatusError, got)
	}
}

// findControlEntry returns the ControlEntry named name out of entries, or
// fails the test. Small helper shared by the two tests above.
func findControlEntry(t *testing.T, entries []ControlEntry, name string) ControlEntry {
	t.Helper()
	for _, e := range entries {
		if e.ControlName == name {
			return e
		}
	}
	t.Fatalf("no control entry named %s", name)
	return ControlEntry{}
}
