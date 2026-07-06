package github

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScanGitHubWorkflowsSkipsSymlink verifies that a committed symlinked
// workflow file is not followed out of the repository, while a real in-repo
// workflow is still scanned.
func TestScanGitHubWorkflowsSkipsSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	wfDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}

	mustWriteFile(t, filepath.Join(wfDir, "ci.yml"),
		"name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")

	secret := filepath.Join(outside, "secret.yml")
	mustWriteFile(t, secret,
		"name: leaked\non: push\njobs:\n  SHOULDNOTAPPEAR:\n    runs-on: x\n    steps:\n      - run: echo x\n")
	if err := os.Symlink(secret, filepath.Join(wfDir, "evil.yml")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	pipeline, _, err := ScanGitHubWorkflows("o/r", "main", root, "github.com", false)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	foundLegit := false
	for _, j := range pipeline.Jobs {
		if strings.Contains(j.Name, "SHOULDNOTAPPEAR") || strings.Contains(j.Name, "evil") {
			t.Fatalf("symlinked workflow was scanned: %q", j.Name)
		}
		if strings.Contains(j.Name, "build") {
			foundLegit = true
		}
	}
	if !foundLegit {
		t.Fatalf("legit in-repo workflow not scanned; jobs=%+v", pipeline.Jobs)
	}
}

// TestScanGitHubWorkflowsCapsSize verifies an oversized workflow file is not
// read into the pipeline (bounded read).
func TestScanGitHubWorkflowsCapsSize(t *testing.T) {
	root := t.TempDir()
	wfDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	big := make([]byte, maxWorkflowFileBytes+1)
	if err := os.WriteFile(filepath.Join(wfDir, "big.yml"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	pipeline, partial, err := ScanGitHubWorkflows("o/r", "main", root, "github.com", false)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(pipeline.Jobs) != 0 {
		t.Fatalf("oversized workflow should yield no jobs, got %d", len(pipeline.Jobs))
	}
	if len(partial) == 0 {
		t.Fatal("expected a partial error for the oversized workflow")
	}
}
