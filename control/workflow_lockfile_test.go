package control

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	githubpkg "github.com/getplumber/plumber/github"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

const lockfileTaskWorkflow = `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: codecov/codecov-action@v5
  shared:
    uses: octo/shared/.github/workflows/ci.yml@v1.2.0
`

const lockfilePath = ".github/workflows/actions.lock"

func pinnedShaConfig() *configuration.PlumberConfig {
	return &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
		ActionsMustBePinnedByCommitSha: &configuration.ActionsPinnedByShaControlConfig{Enabled: boolPtr(true)},
	}}}
}

// lockfilePipeline mixes the shapes #542 separates: the repository's own
// steps (locked by its lockfile), a same-repo local action (exempt as
// local, never listed as locked), a reusable-workflow call (never locked)
// and a job appended from another repository's reusable workflow (its
// steps are governed by that repository's lockfile, not read yet).
func lockfilePipeline(lockfile string) *ir.NormalizedPipeline {
	via := []string{"octo/shared/.github/workflows/ci.yml@v1.2.0"}
	return &ir.NormalizedPipeline{
		ProjectPath:          "me/repo",
		WorkflowLockfilePath: lockfile,
		Jobs: []ir.Job{
			{Name: "ci/build", Uses: []ir.Action{
				{Uses: "docker/setup-qemu-action@v3.6.0", Line: 11},
				{Uses: "codecov/codecov-action@v5", Line: 12},
				{Uses: "docker/build-push-action@0123456789abcdef0123456789abcdef01234567", Line: 13},
			}},
			{Name: "ci/shared", ReusableWorkflowUses: "octo/shared/.github/workflows/ci.yml@v1.2.0"},
			{Name: "ci/shared/test", Nested: true, Via: via, Uses: []ir.Action{
				{Uses: "docker/setup-buildx-action@v3.11.1", Nested: true, Via: via},
			}},
		},
	}
}

func TestAggregate_WorkflowLockfileCoversOwnStepsOnly(t *testing.T) {
	pc := &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{}}

	stats := AggregateGitHubStats(lockfilePipeline(lockfilePath), pc)
	if stats.WorkflowLockfilePath != lockfilePath {
		t.Errorf("WorkflowLockfilePath = %q", stats.WorkflowLockfilePath)
	}
	want := []PinnedRef{
		{Job: "ci/build", Uses: "docker/setup-qemu-action@v3.6.0", Line: 11, PinnedVia: PinnedViaWorkflowLockfile},
		{Job: "ci/build", Uses: "codecov/codecov-action@v5", Line: 12, PinnedVia: PinnedViaWorkflowLockfile},
	}
	if !slices.Equal(stats.ActionRefsWorkflowLockfile, want) {
		t.Errorf("ActionRefsWorkflowLockfile = %+v, want %+v", stats.ActionRefsWorkflowLockfile, want)
	}
	if stats.ActionRefsUnpinned != 2 {
		t.Errorf("ActionRefsUnpinned = %d, want 2 (the reusable call and the nested step)", stats.ActionRefsUnpinned)
	}

	without := AggregateGitHubStats(lockfilePipeline(""), pc)
	if len(without.ActionRefsWorkflowLockfile) != 0 || without.ActionRefsUnpinned != 4 {
		t.Errorf("without a lockfile: locked %v, unpinned %d, want none and 4", without.ActionRefsWorkflowLockfile, without.ActionRefsUnpinned)
	}

	// A same-repo `$/` action (the form gh actions-lock writes) is never
	// listed as locked.
	local := lockfilePipeline(lockfilePath)
	local.Jobs[0].Uses = append(local.Jobs[0].Uses, ir.Action{Uses: "$/.github/actions/setup"})
	for _, r := range AggregateGitHubStats(local, pc).ActionRefsWorkflowLockfile {
		if strings.HasPrefix(r.Uses, "$/") {
			t.Errorf("local ref listed as locked: %+v", r)
		}
	}
}

// TestWorkflowLockfileRegoAndGoAgree keeps the unpinned counter equal to
// the ISSUE-701 findings, with and without the lockfile.
func TestWorkflowLockfileRegoAndGoAgree(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	pc := pinnedShaConfig()
	for _, lockfile := range []string{"", lockfilePath} {
		pipeline := lockfilePipeline(lockfile)
		findings, err := evaluateStrict(engine, context.Background(), pipeline, buildEngineConfig(pc.ControlsFor("github"), ""))
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		flagged := 0
		for _, f := range findings {
			if f.Code == string(CodeActionUnpinned) {
				flagged++
			}
		}
		if got := AggregateGitHubStats(pipeline, pc).ActionRefsUnpinned; got != flagged {
			t.Fatalf("lockfile %q: ActionRefsUnpinned = %d, ISSUE-701 findings = %d: the Go mirror drifted from the rule", lockfile, got, flagged)
		}
	}
}

func writeLockfileTaskRepo(t *testing.T, withLockfile bool) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ci.yml"), []byte(lockfileTaskWorkflow), 0o644); err != nil {
		t.Fatal(err)
	}
	if withLockfile {
		if err := os.WriteFile(filepath.Join(dir, "actions.lock"), []byte("version: v0.0.3\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func issue701Uses(result *AnalysisResult) []string {
	var out []string
	for _, f := range result.Findings {
		if f.Code == string(CodeActionUnpinned) {
			uses, _ := f.Data["uses"].(string)
			out = append(out, uses)
		}
	}
	slices.Sort(out)
	return out
}

// TestRunGitHubAnalysis_WorkflowLockfile runs the whole local path on a
// checkout: with the lockfile only the reusable call keeps its ISSUE-701,
// the control stays evaluated (failed, never skipped), and the locked step
// is counted.
func TestRunGitHubAnalysis_WorkflowLockfile(t *testing.T) {
	cases := []struct {
		lockfile bool
		want     []string
	}{
		{false, []string{"codecov/codecov-action@v5", "octo/shared/.github/workflows/ci.yml@v1.2.0"}},
		{true, []string{"octo/shared/.github/workflows/ci.yml@v1.2.0"}},
	}
	for _, tc := range cases {
		conf := &configuration.Configuration{ProjectPath: "owner/repo", GitRepoRoot: writeLockfileTaskRepo(t, tc.lockfile), PlumberConfig: pinnedShaConfig()}
		result, err := RunGitHubAnalysis(conf)
		if err != nil {
			t.Fatalf("lockfile=%v: %v", tc.lockfile, err)
		}
		if got := issue701Uses(result); !slices.Equal(got, tc.want) {
			t.Errorf("lockfile=%v: ISSUE-701 on %v, want %v", tc.lockfile, got, tc.want)
		}
		if n := len(result.GitHubStats.ActionRefsWorkflowLockfile); (n == 1) != tc.lockfile {
			t.Errorf("lockfile=%v: %d ref(s) counted as locked", tc.lockfile, n)
		}
		for _, e := range GitHubControls(conf.PlumberConfig) {
			if e.ControlName == "actionsMustBePinnedByCommitSha" {
				if got := StatusFor(e, result, len(tc.want)); got != StatusFailed {
					t.Errorf("lockfile=%v: status = %q, want %q", tc.lockfile, got, StatusFailed)
				}
			}
		}
	}
}

func TestRunGitHubAnalysisRemote_WorkflowLockfile(t *testing.T) {
	swapRemoteScan(t, func(host, owner, repo, ref string, enrich, scanMutableExec bool, progressFn githubpkg.ProgressFunc) (*ir.NormalizedPipeline, []error, error) {
		p, errs, err := remoteScanStub(host, owner, repo, ref, enrich, scanMutableExec, progressFn)
		p.Jobs = []ir.Job{
			{Name: "ci/build", Uses: []ir.Action{{Uses: "codecov/codecov-action@v5"}}},
			{Name: "ci/shared", ReusableWorkflowUses: "octo/shared/.github/workflows/ci.yml@v1.2.0"},
		}
		p.WorkflowLockfilePath = lockfilePath
		return p, errs, err
	})
	swapDefaultBranchFetch(t, func(host, owner, repo string) (string, error) { return "main", nil })

	result, err := RunGitHubAnalysisRemote(&configuration.Configuration{PlumberConfig: pinnedShaConfig()}, "owner", "repo", "feature-x")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := issue701Uses(result), []string{"octo/shared/.github/workflows/ci.yml@v1.2.0"}; !slices.Equal(got, want) {
		t.Errorf("ISSUE-701 on %v, want %v", got, want)
	}
	if result.GitHubStats.WorkflowLockfilePath != lockfilePath {
		t.Errorf("stats lockfile path = %q", result.GitHubStats.WorkflowLockfilePath)
	}
}
