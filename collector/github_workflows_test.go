package collector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

func TestScanGitHubWorkflows_Missing(t *testing.T) {
	tmp := t.TempDir()

	pipeline, partial, err := ScanGitHubWorkflows("owner/repo", "main", tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(partial) != 0 {
		t.Fatalf("expected no partial errors, got %v", partial)
	}
	if pipeline.Provider != ir.ProviderGitHub {
		t.Errorf("expected provider github, got %q", pipeline.Provider)
	}
	if len(pipeline.Jobs) != 0 {
		t.Errorf("expected no jobs, got %d", len(pipeline.Jobs))
	}
}

func TestScanGitHubWorkflows_FindsAndNamespacesJobs(t *testing.T) {
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}

	ci := `name: CI
on: push
jobs:
  lint:
    runs-on: ubuntu-latest
    container: alpine:latest
  test:
    runs-on: ubuntu-latest
    container:
      image: node:20-alpha
`
	release := `name: Release
on:
  push:
    tags: [v*]
jobs:
  lint:  # same name as CI's job, must not collide
    runs-on: ubuntu-latest
    container:
      image: debian:bookworm
`
	notWorkflow := `this is not yaml workflow`

	for name, content := range map[string]string{
		"ci.yml":           ci,
		"release.yaml":     release,
		"not-a-workflow.md": notWorkflow,
	} {
		if err := os.WriteFile(filepath.Join(wfDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	pipeline, partial, err := ScanGitHubWorkflows("owner/repo", "main", tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(partial) != 0 {
		t.Fatalf("unexpected partial errors: %v", partial)
	}

	got := map[string]string{}
	for _, j := range pipeline.Jobs {
		tag := ""
		if j.Image != nil {
			tag = j.Image.Tag
		}
		got[j.Name] = tag
	}

	expected := map[string]string{
		"ci/lint":      "latest",
		"ci/test":      "20-alpha",
		"release/lint": "bookworm",
	}
	if len(got) != len(expected) {
		t.Fatalf("expected %d jobs, got %d: %v", len(expected), len(got), got)
	}
	for name, tag := range expected {
		if got[name] != tag {
			t.Errorf("job %q: expected tag %q, got %q", name, tag, got[name])
		}
	}
}

func TestScanGitHubWorkflows_TriggersPropagation(t *testing.T) {
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// YAML 1.1 booleanism trap: `on` is coerced to `true` unless we use a
	// typed struct. This fixture intentionally uses all three forms.
	fixtures := map[string]string{
		"string-form.yml": `name: str
on: push
jobs:
  job1: { runs-on: ubuntu-latest }
`,
		"list-form.yml": `name: list
on: [push, pull_request]
jobs:
  job2: { runs-on: ubuntu-latest }
`,
		"map-form.yml": `name: map
on:
  pull_request_target:
    types: [opened]
  workflow_run:
    workflows: [CI]
jobs:
  job3: { runs-on: ubuntu-latest }
`,
	}
	for name, content := range fixtures {
		if err := os.WriteFile(filepath.Join(wfDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	pipeline, partial, err := ScanGitHubWorkflows("owner/repo", "main", tmp)
	if err != nil || len(partial) != 0 {
		t.Fatalf("unexpected: err=%v partial=%v", err, partial)
	}

	got := map[string][]string{}
	for _, j := range pipeline.Jobs {
		got[j.Name] = j.Triggers
	}

	expected := map[string][]string{
		"string-form/job1": {"push"},
		"list-form/job2":   {"pull_request", "push"}, // sorted
		"map-form/job3":    {"pull_request_target", "workflow_run"},
	}
	for name, want := range expected {
		if !stringSliceEqual(got[name], want) {
			t.Errorf("%s: expected triggers %v, got %v", name, want, got[name])
		}
	}
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestScanGitHubWorkflows_PermissionsPropagation(t *testing.T) {
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	workflow := `name: perms
on: push
permissions: write-all  # workflow-level
jobs:
  inherit:
    runs-on: ubuntu-latest
  override-string:
    runs-on: ubuntu-latest
    permissions: read-all
  override-map:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
`
	if err := os.WriteFile(filepath.Join(wfDir, "perms.yml"), []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}

	pipeline, partial, err := ScanGitHubWorkflows("owner/repo", "main", tmp)
	if err != nil || len(partial) != 0 {
		t.Fatalf("unexpected: err=%v partial=%v", err, partial)
	}

	got := map[string]any{}
	for _, j := range pipeline.Jobs {
		got[j.Name] = j.Permissions
	}

	if got["perms/inherit"] != "write-all" {
		t.Errorf("inherit: expected workflow-level write-all, got %#v", got["perms/inherit"])
	}
	if got["perms/override-string"] != "read-all" {
		t.Errorf("override-string: expected read-all, got %#v", got["perms/override-string"])
	}
	mapPerms, ok := got["perms/override-map"].(map[string]string)
	if !ok {
		t.Fatalf("override-map: expected map, got %#v", got["perms/override-map"])
	}
	if mapPerms["contents"] != "read" || mapPerms["packages"] != "write" {
		t.Errorf("override-map: unexpected values: %v", mapPerms)
	}
}

func TestScanGitHubWorkflows_StepScriptsPropagation(t *testing.T) {
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}

	workflow := `name: scripts
on: push
jobs:
  one-inline:
    runs-on: ubuntu-latest
    steps:
      - run: echo single
  mixed:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: build
        run: |
          echo build
          make all
      - run: echo "${PWD}"
  only-uses:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
`
	if err := os.WriteFile(filepath.Join(wfDir, "scripts.yml"), []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}

	pipeline, partial, err := ScanGitHubWorkflows("owner/repo", "main", tmp)
	if err != nil || len(partial) != 0 {
		t.Fatalf("unexpected: err=%v partial=%v", err, partial)
	}

	byName := map[string][]string{}
	for _, j := range pipeline.Jobs {
		byName[j.Name] = j.Scripts
	}

	if got := byName["scripts/one-inline"]; len(got) != 1 || got[0] != "echo single" {
		t.Errorf("one-inline: expected [\"echo single\"], got %v", got)
	}
	if got := byName["scripts/mixed"]; len(got) != 2 {
		t.Errorf("mixed: expected 2 run scripts, got %v", got)
	}
	if got := byName["scripts/only-uses"]; len(got) != 0 {
		t.Errorf("only-uses: expected no scripts, got %v", got)
	}
}

func TestScanGitHubWorkflows_ParseErrorReportedAsPartial(t *testing.T) {
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	broken := "this: is: : not valid yaml\n - [1,\n"
	if err := os.WriteFile(filepath.Join(wfDir, "broken.yml"), []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}

	_, partial, err := ScanGitHubWorkflows("owner/repo", "main", tmp)
	if err != nil {
		t.Fatalf("expected no fatal error, got %v", err)
	}
	if len(partial) != 1 {
		t.Fatalf("expected 1 partial error, got %d: %v", len(partial), partial)
	}
}
