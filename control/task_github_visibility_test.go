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
	fetchGitHubVisibility = func(host, owner, repo string) string { return ir.VisibilityPrivate }
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
	fetchGitHubVisibility = func(host, owner, repo string) string { t.Fatal("must not be called"); return "" }
	t.Cleanup(func() { fetchGitHubVisibility = orig })
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub}
	applyGitHubVisibility(p, "", "")
	if p.Visibility != ir.VisibilityUnknown {
		t.Fatalf("Visibility = %q", p.Visibility)
	}
}
