package github

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const lockfileTestWorkflow = `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5.0.1
`

const lockfileTestContent = `version: v0.0.2
workflows:
    '.github/workflows/ci.yml':
        - 'actions/checkout@v5.0.1'
dependencies:
    'actions/checkout@v5.0.1':
        ref: 'v5.0.1'
        commit: 'sha1-93cb6efe18208431cddfb8368fd83d5badbf9bfd'
        owner_id: 44036562
        repo_id: 197814629
`

// writeLockfileRepo lays out a checkout with one workflow and lets setup
// place (or not) whatever sits at .github/workflows/actions.lock.
func writeLockfileRepo(t *testing.T, setup func(dir string)) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ci.yml"), []byte(lockfileTestWorkflow), 0o644); err != nil {
		t.Fatal(err)
	}
	if setup != nil {
		setup(dir)
	}
	return root
}

func TestScanGitHubWorkflows_WorkflowLockfile(t *testing.T) {
	cases := []struct {
		name  string
		setup func(dir string)
		want  string
	}{
		{name: "absent", want: ""},
		{
			name: "regular file",
			setup: func(dir string) {
				if err := os.WriteFile(filepath.Join(dir, "actions.lock"), []byte(lockfileTestContent), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: ".github/workflows/actions.lock",
		},
		{
			name: "directory",
			setup: func(dir string) {
				if err := os.Mkdir(filepath.Join(dir, "actions.lock"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			want: "",
		},
		{
			name: "symlink",
			setup: func(dir string) {
				target := filepath.Join(dir, "real.lock")
				if err := os.WriteFile(target, []byte(lockfileTestContent), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(dir, "actions.lock")); err != nil {
					t.Skipf("symlink unsupported: %v", err)
				}
			},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeLockfileRepo(t, tc.setup)
			pipeline, _, err := ScanGitHubWorkflowsWithProgress("owner/repo", "main", root, "", false, false, nil)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if pipeline.WorkflowLockfilePath != tc.want {
				t.Errorf("WorkflowLockfilePath = %q, want %q", pipeline.WorkflowLockfilePath, tc.want)
			}
			if len(pipeline.Jobs) != 1 {
				t.Errorf("jobs = %d, want 1 (the lockfile must not be read as a workflow)", len(pipeline.Jobs))
			}
		})
	}
}

func TestScanGitHubWorkflowsRemote_WorkflowLockfile(t *testing.T) {
	cases := []struct {
		name    string
		listing []map[string]any
		want    string
	}{
		{name: "absent", want: ""},
		{
			name:    "file",
			listing: []map[string]any{{"name": "actions.lock", "path": ".github/workflows/actions.lock", "type": "file"}},
			want:    ".github/workflows/actions.lock",
		},
		{
			name:    "directory",
			listing: []map[string]any{{"name": "actions.lock", "path": ".github/workflows/actions.lock", "type": "dir"}},
			want:    "",
		},
		{
			name:    "symlink",
			listing: []map[string]any{{"name": "actions.lock", "path": ".github/workflows/actions.lock", "type": "symlink"}},
			want:    "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotRef string
			mux := http.NewServeMux()
			mux.HandleFunc("/repos/owner/repo/contents/.github/workflows", func(w http.ResponseWriter, r *http.Request) {
				gotRef = r.URL.Query().Get("ref")
				entries := append([]map[string]any{{"name": "ci.yml", "path": ".github/workflows/ci.yml", "type": "file"}}, tc.listing...)
				_ = json.NewEncoder(w).Encode(entries)
			})
			mux.HandleFunc("/repos/owner/repo/contents/.github/workflows/ci.yml", func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"content": b64(lockfileTestWorkflow), "encoding": "base64"})
			})
			mux.HandleFunc("/repos/owner/repo/contents/.github/workflows/actions.lock", func(_ http.ResponseWriter, _ *http.Request) {
				t.Errorf("the lockfile must not be fetched as a workflow")
			})
			server := httptest.NewServer(mux)
			defer server.Close()
			swapRESTClient(t, server)

			pipeline, partial, err := ScanGitHubWorkflowsRemote("", "owner", "repo", "feature/x", false, false, nil)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if len(partial) != 0 {
				t.Errorf("partial errors: %v", partial)
			}
			if gotRef != "feature/x" {
				t.Errorf("listing ref = %q, want the analyzed branch", gotRef)
			}
			if pipeline.WorkflowLockfilePath != tc.want {
				t.Errorf("WorkflowLockfilePath = %q, want %q", pipeline.WorkflowLockfilePath, tc.want)
			}
			if pipeline.WorkflowFileCount != 1 {
				t.Errorf("WorkflowFileCount = %d, want 1", pipeline.WorkflowFileCount)
			}
		})
	}
}
