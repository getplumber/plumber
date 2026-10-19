package github

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/policies"
)

// Reproduces monorepo issue #517: a workflow file GitHub itself refuses to
// run (an undefined YAML anchor) must not withhold the grade for every
// other workflow in the repository. The file is recorded as an invalid
// workflow, separate from a fetch or read failure.
func TestScanGitHubWorkflows_InvalidWorkflowReportedSeparately(t *testing.T) {
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	valid := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{ run: echo hi }]
`
	invalid := `name: Anchor Aliases
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: *checkout_with
`
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "anchor-aliases.yml"), []byte(invalid), 0o644); err != nil {
		t.Fatal(err)
	}

	pipeline, partial, err := ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(partial) != 0 {
		t.Fatalf("expected no partial errors, got %v", partial)
	}
	if len(pipeline.Jobs) != 1 {
		t.Fatalf("expected 1 job from the valid file only, got %d", len(pipeline.Jobs))
	}
	if len(pipeline.InvalidWorkflows) != 1 {
		t.Fatalf("expected 1 invalid workflow, got %d: %+v", len(pipeline.InvalidWorkflows), pipeline.InvalidWorkflows)
	}
	inv := pipeline.InvalidWorkflows[0]
	if inv.Path != ".github/workflows/anchor-aliases.yml" {
		t.Errorf("path = %q, want %q", inv.Path, ".github/workflows/anchor-aliases.yml")
	}
	if !strings.HasPrefix(inv.Error, "yaml: unknown anchor 'checkout_with'") {
		t.Errorf("error = %q, want it to contain %q", inv.Error, "unknown anchor 'checkout_with'")
	}
}

// A file the collector cannot read at all (not a parse failure) still
// degrades as a partial error, unchanged by the split above. A file over
// the read-size limit exercises the same readErr branch as a permission
// failure would, without depending on root bypassing file permissions.
func TestScanGitHubWorkflows_UnreadableFileStillPartial(t *testing.T) {
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	oversized := strings.Repeat("a", int(maxWorkflowFileBytes)+1)
	if err := os.WriteFile(filepath.Join(wfDir, "huge.yml"), []byte(oversized), 0o644); err != nil {
		t.Fatal(err)
	}

	pipeline, partial, err := ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(partial) != 1 {
		t.Fatalf("expected 1 partial error for the unreadable file, got %d: %v", len(partial), partial)
	}
	if len(pipeline.InvalidWorkflows) != 0 {
		t.Fatalf("expected no invalid workflows, got %+v", pipeline.InvalidWorkflows)
	}
}

// TestParseGitHubWorkflowJobsErrorHasOnePrefix pins the message a user
// reads for an invalid workflow file: exactly one leading "yaml: ",
// whether the failure comes from the yaml library itself (an undefined
// anchor, a tab-indented block, a syntax error) or from the duplicate-key
// pre-check.
func TestParseGitHubWorkflowJobsErrorHasOnePrefix(t *testing.T) {
	cases := map[string]string{
		"undefined anchor": "on: push\njobs:\n  a:\n    runs-on: *missing\n",
		"tab indent":       "on: push\njobs:\n\ta:\n\t\truns-on: ubuntu-latest\n",
		"syntax error":     "on: [push\njobs: {}\n",
		"duplicate key":    "on: push\njobs:\n  a:\n    runs-on: x\n    runs-on: y\n",
	}
	for name, src := range cases {
		_, err := parseGitHubWorkflowJobs([]byte(src), "wf", "wf.yml")
		if err == nil {
			t.Errorf("%s: expected a parse error", name)
			continue
		}
		msg := err.Error()
		if !strings.HasPrefix(msg, "yaml: ") || strings.HasPrefix(msg, "yaml: yaml: ") {
			t.Errorf("%s: want exactly one \"yaml: \" prefix, got %q", name, msg)
		}
	}
}

// The three tests below are PR #560's thread 2 fixtures: the catalog
// text, the docs section and the config comments each name three
// constructs (an undefined anchor, a duplicate key, a tab-indented
// block), but before this round only the anchor went through the real
// parser in tests.

// TestScanGitHubWorkflows_DuplicateTopLevelKeyIsInvalid is PR #560's
// thread 2, case 1: a workflow with `on:` declared twice at the top
// level. GitHub's own YAML 1.1 parser refuses a document with a
// duplicate mapping key outright; the typed decode into ghWorkflowHeader
// does not (gopkg.in/yaml.v2 silently keeps the last value), which would
// be a false pass on a file GitHub refuses and the docs promise is
// caught: the decision taken here is to fix the parser rather than
// weaken the docs.
func TestScanGitHubWorkflows_DuplicateTopLevelKeyIsInvalid(t *testing.T) {
	const duplicateTopLevel = `name: Duplicate Top-Level Key
on: push
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{ run: echo hi }]
`
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "dup-top.yml"), []byte(duplicateTopLevel), 0o644); err != nil {
		t.Fatal(err)
	}

	pipeline, partial, err := ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(partial) != 0 {
		t.Fatalf("expected no partial errors, got %v", partial)
	}
	if len(pipeline.InvalidWorkflows) != 1 {
		t.Fatalf("expected 1 invalid workflow for the duplicate top-level key, got %d: %+v", len(pipeline.InvalidWorkflows), pipeline.InvalidWorkflows)
	}
	if len(pipeline.Jobs) != 0 {
		t.Fatalf("expected no jobs out of a file that does not parse, got %d", len(pipeline.Jobs))
	}

	// End to end: the invalid workflow must be exactly one ISSUE-423
	// finding once the pipeline reaches the Rego engine, the same chain
	// a real analyze run drives.
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	findings, failed, err := engine.EvaluateModules(context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(failed) > 0 {
		t.Fatalf("module failed: %+v", failed)
	}
	n := 0
	for _, f := range findings {
		if f.Code == "ISSUE-423" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 ISSUE-423 finding, got %d: %+v", n, findings)
	}
}

// TestScanGitHubWorkflows_DuplicateNestedKeyIsInvalid is PR #560's
// thread 2, case 2: a duplicate key nested inside one job (`runs-on:` twice). Same
// false-pass risk and the same fix as the top-level case.
func TestScanGitHubWorkflows_DuplicateNestedKeyIsInvalid(t *testing.T) {
	const duplicateNested = `name: Duplicate Nested Key
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    runs-on: windows-latest
    steps: [{ run: echo hi }]
`
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "dup-nested.yml"), []byte(duplicateNested), 0o644); err != nil {
		t.Fatal(err)
	}

	pipeline, partial, err := ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(partial) != 0 {
		t.Fatalf("expected no partial errors, got %v", partial)
	}
	if len(pipeline.InvalidWorkflows) != 1 {
		t.Fatalf("expected 1 invalid workflow for the duplicate nested key, got %d: %+v", len(pipeline.InvalidWorkflows), pipeline.InvalidWorkflows)
	}
}

// TestScanGitHubWorkflows_TabIndentedBlockIsInvalid is PR #560's thread
// 2, case 3: a tab-indented job block. YAML forbids tabs for indentation,
// so gopkg.in/yaml.v2 already refuses this one on its own; the fixture
// pins that it stays refused rather than silently starting to parse on
// a future library bump.
func TestScanGitHubWorkflows_TabIndentedBlockIsInvalid(t *testing.T) {
	tabIndented := "name: Tab Indented\non: push\njobs:\n\tbuild:\n\t\truns-on: ubuntu-latest\n"
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "tab-indented.yml"), []byte(tabIndented), 0o644); err != nil {
		t.Fatal(err)
	}

	pipeline, partial, err := ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(partial) != 0 {
		t.Fatalf("expected no partial errors, got %v", partial)
	}
	if len(pipeline.InvalidWorkflows) != 1 {
		t.Fatalf("expected 1 invalid workflow for the tab-indented block, got %d: %+v", len(pipeline.InvalidWorkflows), pipeline.InvalidWorkflows)
	}
}

// TestDuplicateKeyWalkReachesStepsAndSurvivesComplexKeys pins two edges
// of the duplicate-key pre-check: a duplicate inside one element of a
// job's steps list (a mapping nested in a sequence) is refused, and a
// document whose mapping key is itself a sequence, legal YAML that no
// workflow uses, is walked without a panic and without a false duplicate.
func TestDuplicateKeyWalkReachesStepsAndSurvivesComplexKeys(t *testing.T) {
	dupInStep := []byte("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo one\n        run: echo two\n")
	if err := firstDuplicateYAMLKey(dupInStep); err == nil {
		t.Fatal("a duplicate key inside a step must be refused")
	} else if !strings.Contains(err.Error(), "run") {
		t.Fatalf("the error must name the key, got %v", err)
	}
	complexKey := []byte("? [a, b]\n: value\n? [a, b]\n: other\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	err := firstDuplicateYAMLKey(complexKey)
	if err == nil {
		t.Fatal("the same sequence key twice is a duplicate too")
	}
	distinct := []byte("1: a\n\"1\": b\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	if err := firstDuplicateYAMLKey(distinct); err != nil {
		t.Fatalf("1 and \"1\" are distinct keys, got %v", err)
	}
}
