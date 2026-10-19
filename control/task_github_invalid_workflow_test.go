package control

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	githubpkg "github.com/getplumber/plumber/github"
	"github.com/getplumber/plumber/internal/ir"
)

// remoteInvalidWorkflowStub mirrors remoteScanStub's seeding contract
// (task_github_test.go) but also carries one invalid workflow, and,
// when withJob is true, one valid job, for the PR #560 thread 1
// remote-path tests below: RunGitHubAnalysisRemote
// carries the same CiValid/CiMissing and inactive-control degraded
// logic as the local entry point, but only the local one was tested.
func remoteInvalidWorkflowStub(withJob bool) func(host, owner, repo, ref string, enrich, scanMutableExec bool, progressFn githubpkg.ProgressFunc) (*ir.NormalizedPipeline, []error, error) {
	return func(host, owner, repo, ref string, enrich, scanMutableExec bool, progressFn githubpkg.ProgressFunc) (*ir.NormalizedPipeline, []error, error) {
		p := &ir.NormalizedPipeline{
			Provider:      ir.ProviderGitHub,
			ProjectPath:   owner + "/" + repo,
			DefaultBranch: ref,
			InvalidWorkflows: []ir.InvalidWorkflow{
				{Path: ".github/workflows/anchor-aliases.yml", Error: "yaml: unknown anchor 'checkout_with' referenced"},
			},
		}
		if withJob {
			p.Jobs = []ir.Job{{Name: "ci/build", OriginFile: ".github/workflows/ci.yml"}}
		}
		return p, nil, nil
	}
}

// writeInvalidAndValidWorkflows writes one parseable workflow and one
// GitHub itself refuses to run (an undefined YAML anchor) under
// root/.github/workflows, for the #517 fix round 1, Important 1 tests
// below: an invalid file must be either a finding or a degraded cause,
// never neither.
func writeInvalidAndValidWorkflows(t *testing.T, root string) {
	t.Helper()
	wfDir := filepath.Join(root, ".github", "workflows")
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
}

func hasDegradedReasonContaining(result *AnalysisResult, substr string) bool {
	for _, r := range result.DegradedReasons {
		if strings.Contains(r, substr) {
			return true
		}
	}
	return false
}

func countFindingsOfCode(result *AnalysisResult, code string) int {
	n := 0
	for _, f := range result.Findings {
		if f.Code == code {
			n++
		}
	}
	return n
}

// TestRunGitHubAnalysis_InvalidWorkflowControlInactiveDegrades: with
// workflowsMustBeValid not active, an invalid workflow file must degrade
// the run (never a silent drop), both when the config carries no block
// at all (every existing user config before this control shipped) and
// when it is explicitly disabled.
func TestRunGitHubAnalysis_InvalidWorkflowControlInactiveDegrades(t *testing.T) {
	cases := []struct {
		name string
		pc   *configuration.PlumberConfig
	}{
		{"control absent from config", &configuration.PlumberConfig{}},
		{"control explicitly disabled", &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			WorkflowsMustBeValid: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(false)},
		}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			writeInvalidAndValidWorkflows(t, tmp)
			conf := &configuration.Configuration{
				ProjectPath:   "owner/repo",
				GitRepoRoot:   tmp,
				PlumberConfig: tc.pc,
			}

			result, err := RunGitHubAnalysis(conf)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !result.DataCollectionDegraded {
				t.Fatal("expected DataCollectionDegraded true when the control is inactive")
			}
			if !hasDegradedReasonContaining(result, "could not be parsed and were skipped") {
				t.Fatalf("expected a parse-skip degraded reason, got %v", result.DegradedReasons)
			}
			if n := countFindingsOfCode(result, "ISSUE-423"); n != 0 {
				t.Fatalf("expected no ISSUE-423 finding when the control is inactive, got %d", n)
			}
		})
	}
}

// TestRunGitHubAnalysis_InvalidWorkflowSkippedByFilterDegrades: a control
// enabled in config but excluded by --skip-controls is inactive too.
func TestRunGitHubAnalysis_InvalidWorkflowSkippedByFilterDegrades(t *testing.T) {
	tmp := t.TempDir()
	writeInvalidAndValidWorkflows(t, tmp)
	conf := &configuration.Configuration{
		ProjectPath: "owner/repo",
		GitRepoRoot: tmp,
		PlumberConfig: &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			WorkflowsMustBeValid: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)},
		}}},
		SkipControlsFilter: []string{"workflowsMustBeValid"},
	}

	result, err := RunGitHubAnalysis(conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.DataCollectionDegraded {
		t.Fatal("expected DataCollectionDegraded true when skipped by --skip-controls")
	}
	if !hasDegradedReasonContaining(result, "could not be parsed and were skipped") {
		t.Fatalf("expected a parse-skip degraded reason, got %v", result.DegradedReasons)
	}
}

// TestRunGitHubAnalysis_InvalidWorkflowControlActiveReportsFinding is the
// control case: active, so nothing degrades and the file is a finding.
func TestRunGitHubAnalysis_InvalidWorkflowControlActiveReportsFinding(t *testing.T) {
	tmp := t.TempDir()
	writeInvalidAndValidWorkflows(t, tmp)
	conf := &configuration.Configuration{
		ProjectPath: "owner/repo",
		GitRepoRoot: tmp,
		PlumberConfig: &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			WorkflowsMustBeValid: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)},
		}}},
	}

	result, err := RunGitHubAnalysis(conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.DataCollectionDegraded {
		t.Fatalf("expected DataCollectionDegraded false when active, got reasons %v", result.DegradedReasons)
	}
	if n := countFindingsOfCode(result, "ISSUE-423"); n != 1 {
		t.Fatalf("expected 1 ISSUE-423 finding, got %d", n)
	}
}

// TestRunGitHubAnalysis_EveryWorkflowInvalid is Minor 1: a repo whose
// only workflow file is invalid is neither "no CI" nor a collection
// failure on its own merits; CiMissing is about there being no CI file
// at all, not about whether it parsed.
func TestRunGitHubAnalysis_EveryWorkflowInvalid(t *testing.T) {
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	invalid := `name: Anchor Aliases
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: *checkout_with
`
	if err := os.WriteFile(filepath.Join(wfDir, "anchor-aliases.yml"), []byte(invalid), 0o644); err != nil {
		t.Fatal(err)
	}
	conf := &configuration.Configuration{
		ProjectPath: "owner/repo",
		GitRepoRoot: tmp,
		PlumberConfig: &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			WorkflowsMustBeValid: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)},
		}}},
	}

	result, err := RunGitHubAnalysis(conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CiMissing {
		t.Error("expected CiMissing false: a file is here, GitHub just refuses to run it")
	}
	if !result.CiValid {
		t.Error("expected CiValid true: the configuration was read, its files are the findings")
	}
	if n := countFindingsOfCode(result, "ISSUE-423"); n != 1 {
		t.Fatalf("expected 1 ISSUE-423 finding, got %d", n)
	}
}

// TestRunGitHubAnalysisRemote_InvalidWorkflowControlActiveReportsFinding
// is the remote-path mirror of TestRunGitHubAnalysis_InvalidWorkflowControlActiveReportsFinding
// (PR #560, thread 1): control enabled, one valid job and one invalid
// workflow, nothing degraded, one ISSUE-423 finding.
func TestRunGitHubAnalysisRemote_InvalidWorkflowControlActiveReportsFinding(t *testing.T) {
	swapRemoteScan(t, remoteInvalidWorkflowStub(true))

	conf := &configuration.Configuration{
		PlumberConfig: &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			WorkflowsMustBeValid: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)},
		}}},
	}

	result, err := RunGitHubAnalysisRemote(conf, "owner", "repo", "main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.DataCollectionDegraded {
		t.Fatalf("expected DataCollectionDegraded false, got reasons %v", result.DegradedReasons)
	}
	if n := countFindingsOfCode(result, "ISSUE-423"); n != 1 {
		t.Fatalf("expected 1 ISSUE-423 finding, got %d", n)
	}
	if !result.CiValid {
		t.Error("expected CiValid true")
	}
}

// TestRunGitHubAnalysisRemote_InvalidWorkflowControlInactiveDegrades is
// the remote-path mirror of TestRunGitHubAnalysis_InvalidWorkflowControlInactiveDegrades
// (PR #560, thread 1): control absent from config, same files, the run
// degrades instead of silently dropping the file.
func TestRunGitHubAnalysisRemote_InvalidWorkflowControlInactiveDegrades(t *testing.T) {
	swapRemoteScan(t, remoteInvalidWorkflowStub(true))

	conf := &configuration.Configuration{
		PlumberConfig: &configuration.PlumberConfig{},
	}

	result, err := RunGitHubAnalysisRemote(conf, "owner", "repo", "main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.DataCollectionDegraded {
		t.Fatal("expected DataCollectionDegraded true when the control is inactive")
	}
	if !hasDegradedReasonContaining(result, "could not be parsed and were skipped") {
		t.Fatalf("expected a parse-skip degraded reason, got %v", result.DegradedReasons)
	}
	if n := countFindingsOfCode(result, "ISSUE-423"); n != 0 {
		t.Fatalf("expected no ISSUE-423 finding when the control is inactive, got %d", n)
	}
}

// TestRunGitHubAnalysisRemote_EveryWorkflowInvalid is the remote-path
// mirror of TestRunGitHubAnalysis_EveryWorkflowInvalid (PR #560, thread
// 1): a repo whose only workflow is invalid is neither "no CI" nor a
// collection failure on its own merits.
func TestRunGitHubAnalysisRemote_EveryWorkflowInvalid(t *testing.T) {
	swapRemoteScan(t, remoteInvalidWorkflowStub(false))

	conf := &configuration.Configuration{
		PlumberConfig: &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			WorkflowsMustBeValid: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)},
		}}},
	}

	result, err := RunGitHubAnalysisRemote(conf, "owner", "repo", "main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CiMissing {
		t.Error("expected CiMissing false: a file is here, GitHub just refuses to run it")
	}
	if !result.CiValid {
		t.Error("expected CiValid true: the configuration was read, its files are the findings")
	}
	if n := countFindingsOfCode(result, "ISSUE-423"); n != 1 {
		t.Fatalf("expected 1 ISSUE-423 finding, got %d", n)
	}
}

// invalidOnlyControls enables workflowsMustBeValid next to one control
// that reads the workflows, for the PR #560 all-invalid status tests
// below.
func invalidOnlyControls() *configuration.PlumberConfig {
	return &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
		WorkflowsMustBeValid:            &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)},
		WorkflowsMustDeclarePermissions: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)},
	}}}
}

// statusOf returns StatusFor for one GitHub control of result, counting
// that control's findings the way the renderers do.
func statusOf(t *testing.T, result *AnalysisResult, pc *configuration.PlumberConfig, name string) string {
	t.Helper()
	for _, e := range GitHubControls(pc) {
		if e.ControlName == name {
			return StatusFor(e, result, len(FindingsByControl(result.Findings)[name]))
		}
	}
	t.Fatalf("control %s not in the GitHub catalog", name)
	return ""
}

// assertNoWorkflowParsed is the PR #560 review finding: when every
// workflow file is invalid no workflow was examined, so a control that
// reads them must not read as Passed, while ISSUE-423 still fails and
// the run is not degraded (an invalid file is a user-fixable finding).
func assertNoWorkflowParsed(t *testing.T, result *AnalysisResult, pc *configuration.PlumberConfig) {
	t.Helper()
	if got := statusOf(t, result, pc, "workflowsMustBeValid"); got != StatusFailed {
		t.Errorf("workflowsMustBeValid: expected %s, got %s", StatusFailed, got)
	}
	if got := statusOf(t, result, pc, "workflowsMustDeclarePermissions"); got != StatusError {
		t.Errorf("workflowsMustDeclarePermissions: expected %s, got %s", StatusError, got)
	}
	if reason, ok := result.NotEvaluableReason("workflowsMustDeclarePermissions"); !ok || reason != ReasonResolutionUnavailable {
		t.Errorf("workflowsMustDeclarePermissions: expected not evaluable for %s, got %q (%v)", ReasonResolutionUnavailable, reason, ok)
	}
	if _, ok := result.NotEvaluableReason("workflowsMustBeValid"); ok {
		t.Error("workflowsMustBeValid reports the invalid files: it must not be marked")
	}
	if result.DataCollectionDegraded {
		t.Errorf("expected DataCollectionDegraded false, got reasons %v", result.DegradedReasons)
	}
}

func TestRunGitHubAnalysis_EveryWorkflowInvalidLeavesCIControlsNotEvaluated(t *testing.T) {
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	invalid := "name: Dup\non: push\non: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: [{ run: echo hi }]\n"
	if err := os.WriteFile(filepath.Join(wfDir, "dup.yml"), []byte(invalid), 0o644); err != nil {
		t.Fatal(err)
	}
	pc := invalidOnlyControls()
	result, err := RunGitHubAnalysis(&configuration.Configuration{ProjectPath: "owner/repo", GitRepoRoot: tmp, PlumberConfig: pc})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertNoWorkflowParsed(t, result, pc)
}

func TestRunGitHubAnalysisRemote_EveryWorkflowInvalidLeavesCIControlsNotEvaluated(t *testing.T) {
	swapRemoteScan(t, remoteInvalidWorkflowStub(false))
	pc := invalidOnlyControls()
	result, err := RunGitHubAnalysisRemote(&configuration.Configuration{PlumberConfig: pc}, "owner", "repo", "main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertNoWorkflowParsed(t, result, pc)
}

// TestRunGitHubAnalysis_MixedWorkflowsKeepCIControlsEvaluated: one valid
// file is enough for the workflow controls to have something to judge.
func TestRunGitHubAnalysis_MixedWorkflowsKeepCIControlsEvaluated(t *testing.T) {
	tmp := t.TempDir()
	writeInvalidAndValidWorkflows(t, tmp)
	pc := invalidOnlyControls()
	result, err := RunGitHubAnalysis(&configuration.Configuration{ProjectPath: "owner/repo", GitRepoRoot: tmp, PlumberConfig: pc})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reason, ok := result.NotEvaluableReason("workflowsMustDeclarePermissions"); ok {
		t.Errorf("expected workflowsMustDeclarePermissions evaluated with a valid file present, got not evaluable (%s)", reason)
	}
}
