package control

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/getplumber/plumber/configuration"
)

// writeMinimalGitHubWorkflowRow62 writes a workflow with no `uses:` steps,
// so a scan needs no network: enrichActionMetadata finds zero unique action
// refs and no-ops, and the mutable-remote-code scan reads only the local
// checkout (ScanLocalSelfAction). Returns the checkout root.
func writeMinimalGitHubWorkflowRow62(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	workflow := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}
	return tmp
}

// TestRunGitHubAnalysis_Row62_CollectsForThePolicyUnion is the LOCAL mirror
// of TestRunGitHubAnalysisRemote_Row62_CollectsForThePolicyUnion
// (control/task_github_test.go) and the GitHub counterpart of
// TestRunAnalysis_Row62_CollectsForThePolicyUnion
// (control/task_gitlab_row62_test.go).
//
// RunGitHubAnalysis computes scanMutableExec and branchScope from the union
// of the collecting configurations (row 62), the same as its remote sibling,
// but nothing exercised RunGitHubAnalysis itself: every existing local test
// leaves conf.CollectionConfigs empty, so the union path
// (control/task_github.go ~219, ~241, ~257, ~283) was only ever reached
// through the remote entry point.
func TestRunGitHubAnalysis_Row62_CollectsForThePolicyUnion(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }
	githubConfig := func(controls configuration.ControlsConfig) *configuration.PlumberConfig {
		return &configuration.PlumberConfig{
			Version: "2.0",
			GitHub:  &configuration.ProviderConfig{Controls: controls},
		}
	}
	mutableExec := func(enabled bool) configuration.ControlsConfig {
		return configuration.ControlsConfig{
			ActionsMustNotExecuteMutableRemoteCode: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(enabled)},
		}
	}
	branchProtection := func(enabled bool) configuration.ControlsConfig {
		return configuration.ControlsConfig{
			BranchMustBeProtected: &configuration.BranchProtectionControlConfig{
				Enabled:      boolPtr(enabled),
				NamePatterns: []string{"main"},
			},
		}
	}

	t.Run("the action-source scan is asked for by a policy the local config disables", func(t *testing.T) {
		conf := &configuration.Configuration{
			ProjectPath:       "owner/repo",
			Branch:            "main",
			GitRepoRoot:       writeMinimalGitHubWorkflowRow62(t),
			PlumberConfig:     githubConfig(mutableExec(false)),
			CollectionConfigs: []*configuration.PlumberConfig{githubConfig(mutableExec(true))},
		}

		result, err := RunGitHubAnalysis(conf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.CollectedLanes[laneGitHubActionSource] {
			t.Fatalf("the action-source lane must be recorded as collected, got %v", result.CollectedLanes)
		}
		if result.CollectedLanes[laneGitHubBranches] {
			t.Fatalf("no configuration enables branchMustBeProtected: the branch lane must stay unrecorded, got %v", result.CollectedLanes)
		}
	})

	t.Run("the branch-protection fetch runs for a policy the local config disables", func(t *testing.T) {
		conf := &configuration.Configuration{
			ProjectPath: "owner/repo",
			Branch:      "main",
			GitRepoRoot: writeMinimalGitHubWorkflowRow62(t),
			// A closed port: the fetch fails immediately without reaching any
			// service, and the failure is itself the evidence that the scope
			// handed to the collector came from the union. Had the run's own
			// configuration been passed, the control is disabled there and no
			// fetch would have been attempted at all (mirrors the remote
			// test's closed-loopback approach).
			GithubAPIHost: "127.0.0.1:1",
			PlumberConfig: githubConfig(branchProtection(false)),
			CollectionConfigs: []*configuration.PlumberConfig{
				githubConfig(branchProtection(true)),
				githubConfig(branchProtection(false)),
			},
		}

		result, err := RunGitHubAnalysis(conf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.CollectedLanes[laneGitHubBranches] {
			t.Fatalf("the branch-protection lane must be recorded as collected, got %v", result.CollectedLanes)
		}
		if !result.DataCollectionDegraded {
			t.Fatal("the branch-protection fetch was attempted and failed, so the run is degraded: " +
				"a run that never attempted it would not be, which is what proves the union scope reached the collector")
		}
	})

	t.Run("with no collecting configurations the run's own configuration still gates", func(t *testing.T) {
		conf := &configuration.Configuration{
			ProjectPath: "owner/repo",
			Branch:      "main",
			GitRepoRoot: writeMinimalGitHubWorkflowRow62(t),
			PlumberConfig: &configuration.PlumberConfig{
				Version: "2.0",
				GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
					ActionsMustNotExecuteMutableRemoteCode: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(false)},
					BranchMustBeProtected: &configuration.BranchProtectionControlConfig{
						Enabled:      boolPtr(false),
						NamePatterns: []string{"main"},
					},
				}},
			},
			// Deliberately empty: collectionConfigs() then falls back to
			// conf.PlumberConfig alone (control/collection_scope.go), so a
			// standalone run with no resolved policy must gate on its own
			// configuration exactly as before row 62.
			CollectionConfigs: nil,
		}

		result, err := RunGitHubAnalysis(conf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.CollectedLanes[laneGitHubActionSource] {
			t.Fatalf("both controls are disabled and no collecting configuration was resolved: the action-source lane must stay unrecorded, got %v", result.CollectedLanes)
		}
		if result.CollectedLanes[laneGitHubBranches] {
			t.Fatalf("both controls are disabled and no collecting configuration was resolved: the branch lane must stay unrecorded, got %v", result.CollectedLanes)
		}
	})
}
