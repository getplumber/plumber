package github

import (
	"os"
	"path/filepath"
	"testing"
)

// TestScanGitHubWorkflows_StepIfConditions pins the step-level `if:`
// capture that the cache-poisoning per-trigger resolution relies on
// (issue #497): an action step's condition lands on Action.If, run
// steps' conditions land on Job.ScriptIfs aligned with Job.Scripts
// ("" for an unconditional step), and a job whose run steps are all
// unconditional leaves ScriptIfs absent.
func TestScanGitHubWorkflows_StepIfConditions(t *testing.T) {
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}

	wf := `name: release
on:
  workflow_dispatch:
  pull_request:
jobs:
  build:
    if: github.event_name != 'release'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: cached setup
        if: github.event_name != 'workflow_dispatch'
        uses: actions/setup-java@v4
        with:
          cache: maven
      - run: mvn -B package
      - name: publish
        if: github.event_name == 'workflow_dispatch'
        run: npm publish
  plain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make test
`
	if err := os.WriteFile(filepath.Join(wfDir, "release.yml"), []byte(wf), 0o644); err != nil {
		t.Fatal(err)
	}

	pipeline, _, err := ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	jobs := map[string]int{}
	for i, j := range pipeline.Jobs {
		jobs[j.Name] = i
	}
	build, ok := jobs["release/build"]
	if !ok {
		t.Fatalf("job release/build not found in %v", jobs)
	}
	b := pipeline.Jobs[build]
	if b.If != "github.event_name != 'release'" {
		t.Errorf("job-level If = %q, want the raw condition", b.If)
	}
	if len(b.Uses) != 2 {
		t.Fatalf("release/build: expected 2 actions, got %d", len(b.Uses))
	}
	if b.Uses[0].If != "" {
		t.Errorf("checkout step: If = %q, want empty", b.Uses[0].If)
	}
	if b.Uses[1].If != "github.event_name != 'workflow_dispatch'" {
		t.Errorf("cached setup step: If = %q, want the raw condition", b.Uses[1].If)
	}
	if len(b.Scripts) != 2 {
		t.Fatalf("release/build: expected 2 scripts, got %d", len(b.Scripts))
	}
	wantIfs := []string{"", "github.event_name == 'workflow_dispatch'"}
	if len(b.ScriptIfs) != len(wantIfs) {
		t.Fatalf("release/build: ScriptIfs = %v, want %v (aligned with Scripts)", b.ScriptIfs, wantIfs)
	}
	for i := range wantIfs {
		if b.ScriptIfs[i] != wantIfs[i] {
			t.Errorf("release/build: ScriptIfs[%d] = %q, want %q", i, b.ScriptIfs[i], wantIfs[i])
		}
	}

	plain, ok := jobs["release/plain"]
	if !ok {
		t.Fatalf("job release/plain not found in %v", jobs)
	}
	p := pipeline.Jobs[plain]
	if p.ScriptIfs != nil {
		t.Errorf("release/plain: ScriptIfs = %v, want absent when no run step is conditional", p.ScriptIfs)
	}
	if p.If != "" {
		t.Errorf("release/plain: job-level If = %q, want empty for an unconditional job", p.If)
	}
}
