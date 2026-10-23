package github

import (
	"reflect"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// locationsWorkflow's line numbers are what the assertions below expect:
// keep every edit to it in step with them.
const locationsWorkflow = `name: ci
on: pull_request
permissions: write-all
env:
  WF: one
  SHARED: workflow
jobs:
  build:
    runs-on: ubuntu-latest
    continue-on-error: true
    container:
      image: node:latest
    env:
      SHARED: job
    steps:
      - name: literal
        run: |
          echo one
          echo "${{ github.event.pull_request.title }}"
      - uses: actions/checkout@v5
      - name: plain
        run: echo plain
        env:
          SHARED: step
      - name: folded
        run: >
          echo folded
          more
  short:
    runs-on: ubuntu-latest
    container: alpine:3
    permissions:
      contents: read
    steps:
      - run: echo short
  call:
    uses: owner/repo/.github/workflows/x.yml@main
    secrets: inherit
`

func TestBuildJobLocations(t *testing.T) {
	jobs, err := parseGitHubWorkflowJobs([]byte(locationsWorkflow), "ci", ".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]ir.Job{}
	for _, j := range jobs {
		byName[j.Name] = j
	}

	build := byName["ci/build"]
	if build.Image == nil || build.Image.Line != 12 {
		t.Errorf("build image = %+v, want line 12", build.Image)
	}
	wantScripts := [][]int{{18, 19, 20}, {22}, {27, 27}}
	if !reflect.DeepEqual(build.ScriptLines, wantScripts) {
		t.Errorf("build ScriptLines = %v, want %v", build.ScriptLines, wantScripts)
	}
	wantVars := map[string]int{"WF": 5, "SHARED": 24}
	if !reflect.DeepEqual(build.VariableLines, wantVars) {
		t.Errorf("build VariableLines = %v, want %v", build.VariableLines, wantVars)
	}
	if got := build.KeyLines["continue-on-error"]; got != 10 {
		t.Errorf("build continue-on-error line = %d, want 10", got)
	}
	if got := build.KeyLines["permissions"]; got != 3 {
		t.Errorf("build inherited permissions line = %d, want 3 (the workflow's)", got)
	}

	short := byName["ci/short"]
	if short.Image == nil || short.Image.Line != 31 {
		t.Errorf("short image = %+v, want line 31", short.Image)
	}
	if got := short.KeyLines["permissions"]; got != 32 {
		t.Errorf("short permissions line = %d, want 32 (its own)", got)
	}
	if !reflect.DeepEqual(short.ScriptLines, [][]int{{35}}) {
		t.Errorf("short ScriptLines = %v", short.ScriptLines)
	}

	call := byName["ci/call"]
	if call.KeyLines["uses"] != 37 || call.KeyLines["secrets"] != 38 {
		t.Errorf("call KeyLines = %v, want uses 37, secrets 38", call.KeyLines)
	}
}

// TestBuildJobLocations_MisalignedScriptsGetNone pins the alignment
// guard: a run: the YAML 1.1 decoder reads as a boolean is no script for
// Scripts but is a string node for the line scan, so the two lists no
// longer pair index for index and no script line is claimed.
func TestBuildJobLocations_MisalignedScriptsGetNone(t *testing.T) {
	wf := `on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: yes
      - run: echo real
`
	jobs, err := parseGitHubWorkflowJobs([]byte(wf), "ci", "ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || len(jobs[0].Scripts) != 1 {
		t.Fatalf("jobs = %+v, want one job with one script", jobs)
	}
	if jobs[0].ScriptLines != nil {
		t.Errorf("ScriptLines = %v, want nil when the lists do not align", jobs[0].ScriptLines)
	}
}

// TestResolveNested_CalleeKeepsNoLocations pins that a called workflow's
// jobs carry none of their own script, image, variable or key lines:
// those are lines of the callee, and its findings land on the calling
// job (R9).
func TestResolveNested_CalleeKeepsNoLocations(t *testing.T) {
	callee := "on:\n  workflow_call:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    container: node:latest\n    env:\n      A: b\n    steps:\n      - run: echo hi\n"
	stub := newStub(map[string]string{"acme/shared@v1:.github/workflows/build.yml": callee})
	caller := ir.Job{
		Name: "ci/call", OriginFile: ".github/workflows/ci.yml", OriginLine: 9,
		ReusableWorkflowUses: "acme/shared/.github/workflows/build.yml@v1",
	}
	p := resolveWith(t, stub, nestedScope{}, caller)
	for _, j := range p.Jobs {
		if j.Name != "ci/call/build" {
			continue
		}
		if j.ScriptLines != nil || j.VariableLines != nil || j.KeyLines != nil || j.Image == nil || j.Image.Line != 0 {
			t.Fatalf("callee kept callee lines: scripts %v vars %v keys %v image %+v", j.ScriptLines, j.VariableLines, j.KeyLines, j.Image)
		}
		return
	}
	t.Fatalf("callee not appended: %v", jobNames(p.Jobs))
}
