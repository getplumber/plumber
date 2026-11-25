package github

import (
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
		name  string
		files map[string]fakeFile
		want  string
	}{
		{name: "absent", want: ""},
		{
			name:  "file",
			files: map[string]fakeFile{".github/workflows/actions.lock": {text: "lock"}},
			want:  ".github/workflows/actions.lock",
		},
		{
			name:  "directory",
			files: map[string]fakeFile{".github/workflows/actions.lock/x": {text: "lock"}},
			want:  "",
		},
		{
			name:  "symlink",
			files: map[string]fakeFile{".github/workflows/actions.lock": {text: "../lock", mode: 0o120000}},
			want:  "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]fakeFile{".github/workflows/ci.yml": {text: lockfileTestWorkflow}}
			for p, f := range tc.files {
				files[p] = f
			}
			queries := swapGitRepo(t, gitRepo{refs: []string{"refs/heads/feature/x"}, files: files})
			restRecorder(t, nil)

			pipeline, partial, err := ScanGitHubWorkflowsRemote("", "owner", "repo", "feature/x", false, false, nil)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if len(partial) != 0 {
				t.Errorf("partial errors: %v", partial)
			}
			if got := (*queries)[0].Variables["t0"]; got != "refs/heads/feature/x:.github/workflows" {
				t.Errorf("tree expression = %v, want the analyzed branch", got)
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
