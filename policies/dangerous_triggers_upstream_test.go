package policies_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	githubpkg "github.com/getplumber/plumber/github"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/policies"
)

// TestIssue802_WorkflowRunNeedsAnUntrustedUpstream pins that a
// workflow_run job checking out the triggering run's head is a dangerous
// trigger only when an upstream workflow it names (`workflows:`) can run
// on a pull request (pull_request or pull_request_target). When every
// upstream is in the scan and none runs on one, the head is a commit of
// the repository's own branches, not fork code, and nothing fires. An
// upstream the scan does not hold keeps the finding: Plumber cannot know
// what triggers it.
func TestIssue802_WorkflowRunNeedsAnUntrustedUpstream(t *testing.T) {
	cases := []struct {
		dir          string
		expectedHits []string
	}{
		{"workflow_run_upstream_push", nil},
		{"workflow_run_upstream_pr", []string{"post/post"}},
		{"workflow_run_upstream_unnamed", []string{"after/after"}},
	}
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			tmp := t.TempDir()
			wfDir := filepath.Join(tmp, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join("testdata", "ISSUE-802", "github", tc.dir)
			entries, err := os.ReadDir(src)
			if err != nil {
				t.Fatalf("read fixtures: %v", err)
			}
			for _, e := range entries {
				data, err := os.ReadFile(filepath.Join(src, e.Name()))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(wfDir, e.Name()), data, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			pipeline, _, err := githubpkg.ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			findings, err := evaluateStrict(engine, context.Background(), pipeline, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			hits := []string{}
			for _, f := range findings {
				if f.Code == "ISSUE-802" {
					hits = append(hits, f.Job)
				}
			}
			sort.Strings(hits)
			want := append([]string{}, tc.expectedHits...)
			if !stringSlicesEqual(hits, want) {
				t.Fatalf("%s: expected %v, got %v", tc.dir, want, hits)
			}
		})
	}
}
