package control

import (
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// githubAnalyzedCIConfig projects the scanned GitHub workflow files onto the
// JSON report's analyzedCiConfig block (#443). It is the retention path that
// carries the workflow bytes from the IR (a json:"-" field, never sent to
// OPA) into the artifact, so a regression here would silently drop the
// analyzed CI file from GitHub reports.
func TestGithubAnalyzedCIConfig(t *testing.T) {
	t.Run("maps each retained workflow file into the report block", func(t *testing.T) {
		pipeline := &ir.NormalizedPipeline{
			AnalyzedWorkflows: []ir.AnalyzedWorkflow{
				{Path: ".github/workflows/ci.yml", Content: "name: ci"},
				{Path: ".github/workflows/release.yml", Content: "name: release"},
			},
		}
		got := githubAnalyzedCIConfig(pipeline)
		if got == nil {
			t.Fatal("analyzedCiConfig = nil, want the scanned workflow files")
		}
		if len(got.Workflows) != 2 {
			t.Fatalf("workflows = %d, want 2 retained files", len(got.Workflows))
		}
		if got.Workflows[0].Path != ".github/workflows/ci.yml" || got.Workflows[0].Content != "name: ci" {
			t.Fatalf("first workflow = %+v, want path and content preserved", got.Workflows[0])
		}
		if got.Workflows[1].Path != ".github/workflows/release.yml" || got.Workflows[1].Content != "name: release" {
			t.Fatalf("second workflow = %+v, want path and content preserved", got.Workflows[1])
		}
	})

	t.Run("nil when no workflow files were retained", func(t *testing.T) {
		if got := githubAnalyzedCIConfig(&ir.NormalizedPipeline{}); got != nil {
			t.Fatalf("analyzedCiConfig = %+v, want nil so the block is omitted", got)
		}
		if got := githubAnalyzedCIConfig(nil); got != nil {
			t.Fatalf("analyzedCiConfig = %+v, want nil for a nil pipeline", got)
		}
	})
}

// gitlabAnalyzedCIConfig records the resolved GitLab merged pipeline as the
// report's analyzedCiConfig block (#443), symmetric with the GitHub side. It
// is the RunAnalysis branch that carries the merged YAML into the report.
func TestGitlabAnalyzedCIConfig(t *testing.T) {
	t.Run("records the merged pipeline under its ci_config_path", func(t *testing.T) {
		got := gitlabAnalyzedCIConfig(".gitlab-ci.yml", "stages:\n  - test")
		if got == nil {
			t.Fatal("analyzedCiConfig = nil, want the merged pipeline")
		}
		if got.Path != ".gitlab-ci.yml" {
			t.Fatalf("path = %q, want the ci_config_path", got.Path)
		}
		if got.Content != "stages:\n  - test" {
			t.Fatalf("content = %q, want the merged YAML", got.Content)
		}
		if !got.Merged {
			t.Fatal("merged = false, want true for a GitLab merged pipeline")
		}
	})

	t.Run("nil when no merged yaml resolved", func(t *testing.T) {
		if got := gitlabAnalyzedCIConfig(".gitlab-ci.yml", ""); got != nil {
			t.Fatalf("analyzedCiConfig = %+v, want nil so the block is omitted", got)
		}
	})
}
