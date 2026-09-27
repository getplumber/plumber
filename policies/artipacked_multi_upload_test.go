package policies_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/getplumber/plumber/github"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// scanWorkflow runs one workflow through the real GitHub workflow scanner:
// the rule reads the upload steps' `with.path` inputs and their line numbers,
// which only the production parser carries. Metadata enrichment stays off.
func scanWorkflow(t *testing.T, workflow string) *ir.NormalizedPipeline {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "repro.yml"), []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}
	pipeline, _, err := github.ScanGitHubWorkflowsWithProgress("acme/repro", "main", root, "", false, false, nil)
	if err != nil {
		t.Fatalf("scan workflows: %v", err)
	}
	return pipeline
}

func loadPolicies(t *testing.T) *opaengine.Engine {
	t.Helper()
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	return engine
}

// TestArtipacked_SeveralPackingUploadsInOneJob is the #489 policy
// regression: two upload-artifact steps in one job that both pack the
// workspace made _git_packing_upload produce two outputs for one input
// (eval_conflict_error), which took every finding of the run with it. The
// rule must evaluate and report one ISSUE-310 per packing upload.
func TestArtipacked_SeveralPackingUploadsInOneJob(t *testing.T) {
	const workflow = `name: repro
on: push
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v5
      - uses: actions/upload-artifact@v4
        with:
          name: everything
          path: ${{ github.workspace }}
      - uses: actions/upload-artifact@v4
        with:
          name: everything-again
          path: .
`
	findings, err := evaluateStrict(loadPolicies(t), context.Background(), scanWorkflow(t, workflow), nil)
	if err != nil {
		t.Fatalf("evaluate must not fail on several packing uploads in one job: %v", err)
	}
	if got := countCode(findings, "ISSUE-310"); got != 2 {
		t.Fatalf("want one ISSUE-310 per packing upload (2), got %d: %+v", got, findings)
	}
	if got := countCode(findings, "ISSUE-307"); got != 0 {
		t.Fatalf("ISSUE-307 (nothing packs .git) must not fire when uploads pack .git, got %d", got)
	}
}

// TestArtipacked_UploadsUnderTheWorkspaceAreNotALeak is the issue's exact
// workflow: two uploads of paths UNDER the workspace (a report directory
// and a file inside it). Neither packs `.git`, so the run evaluates, reports
// the latent ISSUE-307 for the persisted credential, and no ISSUE-310.
func TestArtipacked_UploadsUnderTheWorkspaceAreNotALeak(t *testing.T) {
	const workflow = `name: repro
on: push
jobs:
  build:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v5
      - run: mkdir -p reports/clients && echo hi > reports/clients/index.html
      - name: Publish all reports
        uses: actions/upload-artifact@v4
        with:
          name: full report
          path: ${{github.workspace}}/reports
      - name: Publish report client
        uses: actions/upload-artifact@v4
        with:
          name: client
          path: ${{github.workspace}}/reports/clients/index.html
`
	findings, err := evaluateStrict(loadPolicies(t), context.Background(), scanWorkflow(t, workflow), nil)
	if err != nil {
		t.Fatalf("evaluate must not fail on the issue's workflow: %v", err)
	}
	if got := countCode(findings, "ISSUE-310"); got != 0 {
		t.Fatalf("uploads under the workspace do not pack .git; want no ISSUE-310, got %d: %+v", got, findings)
	}
	if got := countCode(findings, "ISSUE-307"); got != 1 {
		t.Fatalf("the persisted credential is still the latent ISSUE-307, want 1, got %d", got)
	}
}
