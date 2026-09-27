package policies_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/getplumber/plumber/github"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/policies"
)

// TestArtipacked_SeveralUploadStepsInOneJob is the #489 policy regression:
// a job with two upload-artifact steps that both pack a workspace-rooted
// path made _git_packing_upload produce two outputs for one input
// (eval_conflict_error), which took every finding of the run with it. The
// rule must evaluate and report one ISSUE-310 per packing upload.
func TestArtipacked_SeveralUploadStepsInOneJob(t *testing.T) {
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
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	// The real workflow scanner, not the fixture parser: the rule reads the
	// upload steps' `with.path` inputs and their line numbers, which only the
	// production parser carries. Metadata enrichment stays off (no network).
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
	findings, err := engine.Evaluate(context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate must not fail on several upload steps in one job: %v", err)
	}
	if got := countCode(findings, "ISSUE-310"); got != 2 {
		t.Fatalf("want one ISSUE-310 per packing upload (2), got %d: %+v", got, findings)
	}
	if got := countCode(findings, "ISSUE-307"); got != 0 {
		t.Fatalf("ISSUE-307 (latent, nothing packs .git) must not fire when uploads pack .git, got %d", got)
	}
}
