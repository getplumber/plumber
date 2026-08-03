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

	pipeline, _, err := ScanGitHubWorkflowsWithProgress("o/r", "main", root, "github.com", false, true, nil)
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

// TestScanGitHubWorkflowsSymlinkedDirStillScansArtifacts verifies that a
// workflows directory symlinked outside the repository is ignored without
// aborting the rest of the scan: repository-level artifacts (dependabot
// config, security policy, ...) are still collected.
func TestScanGitHubWorkflowsSymlinkedDirStillScansArtifacts(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	ghDir := filepath.Join(root, ".github")
	if err := os.MkdirAll(ghDir, 0o755); err != nil {
		t.Fatal(err)
	}

	outsideWfDir := filepath.Join(outside, "workflows")
	if err := os.MkdirAll(outsideWfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, filepath.Join(outsideWfDir, "evil.yml"),
		"name: leaked\non: push\njobs:\n  SHOULDNOTAPPEAR:\n    runs-on: x\n    steps:\n      - run: echo x\n")
	if err := os.Symlink(outsideWfDir, filepath.Join(ghDir, "workflows")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	mustWriteFile(t, filepath.Join(ghDir, "dependabot.yml"),
		"updates:\n  - package-ecosystem: npm\n    insecure-external-code-execution: allow\n")
	mustWriteFile(t, filepath.Join(root, "SECURITY.md"), "# security\n")

	pipeline, _, err := ScanGitHubWorkflowsWithProgress("o/r", "main", root, "github.com", false, true, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(pipeline.Jobs) != 0 {
		t.Fatalf("symlinked workflows dir should yield no jobs, got %+v", pipeline.Jobs)
	}
	if pipeline.Dependabot == nil {
		t.Fatal("dependabot config should still be scanned when the workflows dir is rejected")
	}
	if pipeline.SecurityPolicyPath == "" {
		t.Fatal("security policy should still be scanned when the workflows dir is rejected")
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
	pipeline, partial, err := ScanGitHubWorkflowsWithProgress("o/r", "main", root, "github.com", false, true, nil)
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
