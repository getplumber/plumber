package control

import (
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// TestGitHubAnalysisSetsPipelineVisibility checks that
// applyGitHubVisibility threads the collector's answer straight onto
// the pipeline when the project path is owner/repo shaped.
func TestGitHubAnalysisSetsPipelineVisibility(t *testing.T) {
	orig := fetchGitHubVisibility
	fetchGitHubVisibility = func(host, owner, repo string) (string, string) { return ir.VisibilityPrivate, "" }
	t.Cleanup(func() { fetchGitHubVisibility = orig })

	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "acme/widget"}
	applyGitHubVisibility(p, "", "acme/widget")
	if p.Visibility != ir.VisibilityPrivate {
		t.Fatalf("Visibility = %q", p.Visibility)
	}
}

// TestGitHubAnalysisVisibilityUnknownWithoutProjectPath checks that
// applyGitHubVisibility never calls the collector when there is no
// owner/repo to ask about, and leaves the pipeline unknown.
func TestGitHubAnalysisVisibilityUnknownWithoutProjectPath(t *testing.T) {
	orig := fetchGitHubVisibility
	fetchGitHubVisibility = func(host, owner, repo string) (string, string) {
		t.Fatal("must not be called")
		return "", ""
	}
	t.Cleanup(func() { fetchGitHubVisibility = orig })
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub}
	applyGitHubVisibility(p, "", "")
	if p.Visibility != ir.VisibilityUnknown {
		t.Fatalf("Visibility = %q", p.Visibility)
	}
}

// TestGitHubAnalysisRecordsCanonicalProjectPath checks that the pipeline
// the policies read carries the owner/repo GitHub answers for the
// repository (the API follows renames: facebook/react is react/react),
// so a reference to the repository under its current name is known as
// its own, and that a lookup with no answer keeps the given path.
func TestGitHubAnalysisRecordsCanonicalProjectPath(t *testing.T) {
	orig := fetchGitHubVisibility
	t.Cleanup(func() { fetchGitHubVisibility = orig })

	fetchGitHubVisibility = func(host, owner, repo string) (string, string) { return ir.VisibilityPublic, "react/react" }
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "facebook/react"}
	applyGitHubVisibility(p, "", "facebook/react")
	if p.ProjectPath != "react/react" {
		t.Fatalf("ProjectPath = %q, want the canonical react/react", p.ProjectPath)
	}

	fetchGitHubVisibility = func(host, owner, repo string) (string, string) { return ir.VisibilityUnknown, "" }
	p = &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "facebook/react"}
	applyGitHubVisibility(p, "", "facebook/react")
	if p.ProjectPath != "facebook/react" {
		t.Fatalf("ProjectPath = %q, want the given path kept when the lookup fails", p.ProjectPath)
	}
}
