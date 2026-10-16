package github

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/getplumber/plumber/internal/ir"
)

func TestScanGitHubWorkflows_Missing(t *testing.T) {
	tmp := t.TempDir()

	pipeline, partial, err := ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
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
		"ci.yml":            ci,
		"release.yaml":      release,
		"not-a-workflow.md": notWorkflow,
	} {
		if err := os.WriteFile(filepath.Join(wfDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	pipeline, partial, err := ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
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

	// The scan wires the retained workflow files onto the pipeline for the JSON
	// report's analyzed-CI-config block (#443): the two YAML files with their
	// content, under their repo-relative paths; the .md is not a workflow.
	wf := map[string]string{}
	for _, w := range pipeline.AnalyzedWorkflows {
		wf[w.Path] = w.Content
	}
	if len(wf) != 2 {
		t.Fatalf("retained %d workflow files, want 2: %+v", len(wf), pipeline.AnalyzedWorkflows)
	}
	if wf[".github/workflows/ci.yml"] != ci {
		t.Errorf("ci.yml content = %q, want it retained verbatim", wf[".github/workflows/ci.yml"])
	}
	if wf[".github/workflows/release.yaml"] != release {
		t.Errorf("release.yaml content = %q, want it retained verbatim", wf[".github/workflows/release.yaml"])
	}
	if _, present := wf[".github/workflows/not-a-workflow.md"]; present {
		t.Error("not-a-workflow.md retained as a workflow; it must be excluded")
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

	pipeline, partial, err := ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
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

	pipeline, partial, err := ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
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

	pipeline, partial, err := ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
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

// TestScanGitHubWorkflows_ContinueOnErrorMapsToAllowFailure is the
// regression for the security_jobs_weakened blind spot: GitHub's
// `continue-on-error: true` at the job level is the equivalent of
// GitLab's `allow_failure: true`. The IR field is shared, so the
// rego rule fires uniformly across providers when the parser maps
// the field correctly.
//
// `${{ … }}` template values must NOT trip the mapping: we cannot
// statically decide whether a runtime expression evaluates to true,
// so staying quiet is the right call (mirrors plumber's high-
// precision philosophy elsewhere).
func TestScanGitHubWorkflows_ContinueOnErrorMapsToAllowFailure(t *testing.T) {
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}

	wf := `name: CI
on: push
jobs:
  flaky:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - run: ./flaky-test.sh
  strict:
    runs-on: ubuntu-latest
    steps:
      - run: ./real-test.sh
  experimental:
    runs-on: ubuntu-latest
    continue-on-error: ${{ matrix.experimental }}
    steps:
      - run: ./matrix-test.sh
`
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(wf), 0o644); err != nil {
		t.Fatal(err)
	}

	pipeline, partial, err := ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(partial) != 0 {
		t.Fatalf("unexpected partial errors: %v", partial)
	}

	byName := map[string]bool{}
	for _, j := range pipeline.Jobs {
		byName[j.Name] = j.AllowFailure
	}

	if !byName["ci/flaky"] {
		t.Error("ci/flaky: expected AllowFailure=true (continue-on-error: true)")
	}
	if byName["ci/strict"] {
		t.Error("ci/strict: expected AllowFailure=false (no continue-on-error)")
	}
	if byName["ci/experimental"] {
		t.Error("ci/experimental: expected AllowFailure=false (template expression — cannot statically resolve)")
	}
}

// TestScanGitHubWorkflows_EnvPropagation locks in the merge order
// for `env:` blocks at workflow, job, and step scope. The IR folds
// all three into a single Job.Variables map; later writes overwrite
// earlier ones (step > job > workflow), mirroring GitHub's runtime
// precedence. Rules that scan workflow content (ISSUE-203 debug
// trace, ISSUE-207 template injection, …) read Job.Variables, so
// every level needs to land there or the rule sees nothing.
func TestScanGitHubWorkflows_EnvPropagation(t *testing.T) {
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	workflow := `name: env-merge
on: push
env:
  WORKFLOW_ONLY: wf-value
  OVERRIDE_ME: from-workflow
jobs:
  only-workflow-env:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
  job-overrides-workflow:
    runs-on: ubuntu-latest
    env:
      JOB_ONLY: job-value
      OVERRIDE_ME: from-job
    steps:
      - run: echo hi
  step-overrides-job-and-workflow:
    runs-on: ubuntu-latest
    env:
      OVERRIDE_ME: from-job
    steps:
      - run: echo hi
        env:
          STEP_ONLY: step-value
          OVERRIDE_ME: from-step
`
	if err := os.WriteFile(filepath.Join(wfDir, "env.yml"), []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}

	pipeline, partial, err := ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
	if err != nil || len(partial) != 0 {
		t.Fatalf("unexpected: err=%v partial=%v", err, partial)
	}

	got := map[string]map[string]string{}
	for _, j := range pipeline.Jobs {
		got[j.Name] = j.Variables
	}

	// Workflow-only env reaches a job that declares no env:. This was
	// the false-negative gap behind ISSUE-203 missing workflow-level
	// ACTIONS_STEP_DEBUG / ACTIONS_RUNNER_DEBUG toggles.
	if v := got["env/only-workflow-env"]["WORKFLOW_ONLY"]; v != "wf-value" {
		t.Errorf("only-workflow-env: expected WORKFLOW_ONLY=wf-value, got %q (got=%v)", v, got["env/only-workflow-env"])
	}

	// Job env extends workflow env and overrides on key collision.
	jobEnv := got["env/job-overrides-workflow"]
	if jobEnv["WORKFLOW_ONLY"] != "wf-value" || jobEnv["JOB_ONLY"] != "job-value" || jobEnv["OVERRIDE_ME"] != "from-job" {
		t.Errorf("job-overrides-workflow: bad merge: %v", jobEnv)
	}

	// Step env wins over both job and workflow.
	stepEnv := got["env/step-overrides-job-and-workflow"]
	if stepEnv["WORKFLOW_ONLY"] != "wf-value" || stepEnv["STEP_ONLY"] != "step-value" || stepEnv["OVERRIDE_ME"] != "from-step" {
		t.Errorf("step-overrides-job-and-workflow: bad merge: %v", stepEnv)
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

	_, partial, err := ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
	if err != nil {
		t.Fatalf("expected no fatal error, got %v", err)
	}
	if len(partial) != 1 {
		t.Fatalf("expected 1 partial error, got %d: %v", len(partial), partial)
	}
}

// TestSplitImageRef_FoldsHubAliases pins the Docker Hub registry-host
// alias fold in the container-image parser used by the workflow
// collector (parseGitHubContainer -> splitImageRef): aliases like
// registry.hub.docker.com and index.docker.io are canonicalized to
// docker.io so trustedUrls patterns match regardless of Hub hostname.
func TestSplitImageRef_FoldsHubAliases(t *testing.T) {
	cases := []struct {
		ref      string
		wantName string
		wantTag  string
	}{
		{"registry.hub.docker.com/library/node:alpine", "docker.io/library/node", "alpine"},
		{"index.docker.io/python:3.12", "docker.io/python", "3.12"},
		{"ghcr.io/astral-sh/uv:latest", "ghcr.io/astral-sh/uv", "latest"},
		{"alpine:3.20", "alpine", "3.20"},
	}
	for _, tc := range cases {
		got := splitImageRef(tc.ref)
		if got.Name != tc.wantName || got.Tag != tc.wantTag {
			t.Errorf("splitImageRef(%q) = {name:%q tag:%q}, want {name:%q tag:%q}",
				tc.ref, got.Name, got.Tag, tc.wantName, tc.wantTag)
		}
	}
}

// Test_enrichActionsWithClient_carriesTagObjectMetadata locks the
// collector-to-IR handoff for ISSUE-401. Every field the rego rules read
// crosses from GitHubMetadata into ir.ActionMetadata inside the
// enrichment loop, and that copy is the single bridge between the
// collector fix and the policy fix. Dropping RefCommitSha there would
// re-flag a tag-object pin as an impostor commit (ISSUE-707, critical),
// as a version mismatch (ISSUE-708) and as stale (ISSUE-709) in a real
// scan, while the collector tests (which assert on the source) and the
// rego tests (which hand-build the destination) both stayed green.
func Test_enrichActionsWithClient_carriesTagObjectMetadata(t *testing.T) {
	const (
		owner        = "pnpm"
		repo         = "action-setup"
		tagObjectSHA = "7088e561eb65bb68695d245aa206f005ef30921d"
		commitSHA    = "a7487c7e89a18df4991f7f222e4898a00d66ddda"
		absentSHA    = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	)
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		p := r.URL.Path
		body, status := `{}`, http.StatusNotFound
		switch {
		case strings.Count(p, "/") == 3 && strings.HasPrefix(p, "/repos/"):
			body, status = `{"archived":false,"stargazers_count":900}`, http.StatusOK
		case strings.Contains(p, "/releases"):
			body, status = `[]`, http.StatusOK
		case strings.HasPrefix(p, "/advisories"):
			body, status = `[]`, http.StatusOK
		case strings.HasSuffix(p, "/git/tags/"+tagObjectSHA):
			body, status = `{"sha":"`+tagObjectSHA+`","tag":"v4.1.0","object":{"sha":"`+commitSHA+`","type":"commit"}}`, http.StatusOK
		case strings.HasSuffix(p, "/commits/"+commitSHA):
			body, status = `{"sha":"`+commitSHA+`"}`, http.StatusOK
		case strings.Contains(p, "/commits/"):
			body, status = `{"message":"No commit found for SHA"}`, http.StatusUnprocessableEntity
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})
	client := NewGitHubMetadataClientForHost("")
	// TestMain disables the API package-wide; re-enable this instance so
	// the enrichment loop actually runs against the stub.
	client.disabled = false
	rest, err := api.NewRESTClient(api.ClientOptions{AuthToken: "x", Transport: rt})
	if err != nil {
		t.Fatalf("new rest client: %v", err)
	}
	client.rest = rest

	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name: "build",
			Uses: []ir.Action{
				{Uses: owner + "/" + repo + "@" + tagObjectSHA},
				{Uses: "actions/checkout@" + absentSHA},
			},
		}},
	}
	// scanMutableExec off: this test is about the metadata copy, not the
	// per-action source fetch.
	enrichActionsWithClient(pipeline, client, false, nil)

	pin := pipeline.Jobs[0].Uses[0]
	if pin.Metadata == nil {
		t.Fatal("enrichment dropped the metadata for a tag-object pin")
	}
	if pin.Metadata.RefCommitSha != commitSHA {
		t.Fatalf("Metadata.RefCommitSha = %q, want %q: the dereferenced commit did not cross into the IR, so ISSUE-708 and ISSUE-709 would fire on a correct pin", pin.Metadata.RefCommitSha, commitSHA)
	}
	if !pin.Metadata.RefExists || pin.Metadata.RefKind != "commit" {
		t.Fatalf("Metadata = {RefExists:%v RefKind:%q}, want {true \"commit\"}", pin.Metadata.RefExists, pin.Metadata.RefKind)
	}
	if pin.Metadata.RefKnownAbsent {
		t.Fatal("Metadata.RefKnownAbsent is true for a resolvable tag object: ISSUE-707 would fire critical on a valid pin")
	}

	// The control SHA must still cross over as a confirmed absence, so a
	// broken copy cannot pass by blanking every field.
	absent := pipeline.Jobs[0].Uses[1]
	if absent.Metadata == nil || !absent.Metadata.RefKnownAbsent {
		t.Fatal("a fabricated SHA must reach the IR with RefKnownAbsent set, or ISSUE-707 is silently disabled")
	}
	if absent.Metadata.RefCommitSha != "" {
		t.Fatalf("Metadata.RefCommitSha = %q for an absent SHA, want empty", absent.Metadata.RefCommitSha)
	}
}

// TestSecretFirstLineRecordsWhereEachSecretIsFirstReferenced pins the
// fixture the step-order reach check depends on: secrets.A at line 12,
// secrets.github_token at line 14 (never recorded, any case, it is the
// job token), an untrusted uses: step at line 20 referencing nothing, and
// secrets.B at line 30. The collector must record only A and B, each at
// its own first line.
func TestSecretFirstLineRecordsWhereEachSecretIsFirstReferenced(t *testing.T) {
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}

	ci := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: pad1
        run: echo pad1
      - name: pad2
        run: echo pad2
      - name: use-a
        run: echo "${{ secrets.A }}"
      - name: use-token
        run: echo "${{ secrets.github_token }}"
      - name: pad3
        run: echo pad3
      - name: pad4
        run: echo pad4
      - name: untrusted
        uses: some/untrusted-action@v1
      - name: pad5
        run: echo pad5
      - name: pad6
        run: echo pad6
      - name: pad7
        run: echo pad7
      - name: pad8
        run: echo pad8
      - name: use-b
        run: echo "${{ secrets.B }}"
`
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(ci), 0o644); err != nil {
		t.Fatal(err)
	}

	// Fixture-line sanity: the test fixture above has to actually carry
	// each reference at the line number the assertion below expects, or
	// the test would pass for the wrong reason.
	lines := strings.Split(ci, "\n")
	if got := lines[11]; !strings.Contains(got, "secrets.A") {
		t.Fatalf("fixture drifted: line 12 is %q, want it to carry secrets.A", got)
	}
	if got := lines[13]; !strings.Contains(got, "secrets.github_token") {
		t.Fatalf("fixture drifted: line 14 is %q, want it to carry secrets.github_token", got)
	}
	if got := lines[19]; !strings.Contains(got, "uses: some/untrusted-action") {
		t.Fatalf("fixture drifted: line 20 is %q, want the untrusted uses: step", got)
	}
	if got := lines[29]; !strings.Contains(got, "secrets.B") {
		t.Fatalf("fixture drifted: line 30 is %q, want it to carry secrets.B", got)
	}

	pipeline, partial, err := ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(partial) != 0 {
		t.Fatalf("unexpected partial errors: %v", partial)
	}
	if len(pipeline.Jobs) != 1 {
		t.Fatalf("want one job, got %d", len(pipeline.Jobs))
	}
	job := pipeline.Jobs[0]
	want := map[string]int{"A": 12, "B": 30}
	if !reflect.DeepEqual(job.SecretFirstLine, want) {
		t.Fatalf("SecretFirstLine = %v, want %v (github_token never recorded)", job.SecretFirstLine, want)
	}
}

// scanOneWorkflowJob writes ci as the sole workflow file of a fresh repo,
// scans it, and returns its one job's SecretFirstLine. Shared by the
// job-level-env and comment/string-literal cases below.
func scanOneWorkflowJob(t *testing.T, ci string) map[string]int {
	t.Helper()
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(ci), 0o644); err != nil {
		t.Fatal(err)
	}
	pipeline, partial, err := ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(partial) != 0 {
		t.Fatalf("unexpected partial errors: %v", partial)
	}
	if len(pipeline.Jobs) != 1 {
		t.Fatalf("want one job, got %d", len(pipeline.Jobs))
	}
	return pipeline.Jobs[0].SecretFirstLine
}

// TestSecretFirstLineJobLevelEnvIsLineZero pins that a secret referenced
// in the job's own env: (outside steps:) is recorded at line 0, not its
// textual line: it is set up before any step runs, so it is visible to
// every step regardless of where in the job's YAML block it sits,
// exactly like a workflow-level env: reference.
func TestSecretFirstLineJobLevelEnvIsLineZero(t *testing.T) {
	ci := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.ENVSECRET }}
    steps:
      - name: untrusted
        uses: some/untrusted-action@v1
      - name: later
        run: echo done
`
	got := scanOneWorkflowJob(t, ci)
	want := map[string]int{"ENVSECRET": 0}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SecretFirstLine = %v, want %v: a job-level env: reference reaches every step", got, want)
	}
}

// TestSecretFirstLineContainerAndServicesEnvAreLineZero extends the
// job-level-env rule to a job's container: and services: blocks, which
// are set up the same way, before any step runs.
func TestSecretFirstLineContainerAndServicesEnvAreLineZero(t *testing.T) {
	t.Run("container env", func(t *testing.T) {
		ci := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: node:20
      env:
        CTOKEN: ${{ secrets.CONTAINERSECRET }}
    steps:
      - name: untrusted
        uses: some/untrusted-action@v1
`
		got := scanOneWorkflowJob(t, ci)
		want := map[string]int{"CONTAINERSECRET": 0}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("SecretFirstLine = %v, want %v", got, want)
		}
	})
	t.Run("services env", func(t *testing.T) {
		ci := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    services:
      redis:
        image: redis
        env:
          STOKEN: ${{ secrets.SERVICESECRET }}
    steps:
      - name: untrusted
        uses: some/untrusted-action@v1
`
		got := scanOneWorkflowJob(t, ci)
		want := map[string]int{"SERVICESECRET": 0}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("SecretFirstLine = %v, want %v", got, want)
		}
	})
}

// TestSecretFirstLineOnlyCountsLiveExpressions pins that a bash comment
// mentioning secrets.X, or a quoted string literal that merely contains
// the text "secrets.X", never counts: only a real ${{ ... }} expression
// does, the same restriction situation.rego's github_expressions applies
// before its own secret_member_pattern ever runs.
func TestSecretFirstLineOnlyCountsLiveExpressions(t *testing.T) {
	ci := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: comment-step
        run: |
          # rotate secrets.NPM_TOKEN
          echo "secrets.X"
      - name: untrusted
        uses: some/untrusted-action@v1
      - name: real-use
        run: echo "${{ secrets.NPM_TOKEN }}"
`
	got := scanOneWorkflowJob(t, ci)
	want := map[string]int{"NPM_TOKEN": 14}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SecretFirstLine = %v, want %v: the comment at line 9 and the quoted literal at line 10 must not count, and X must never appear at all", got, want)
	}
}
