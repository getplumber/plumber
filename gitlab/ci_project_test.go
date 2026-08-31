package gitlab

import "testing"

// The re-raised #431 review threads: ProjectFromCIEnvironment substitutes
// the two project-lookup API calls in platform mode, and its refusal guard
// is what keeps `plumber analyze --project other/repo` from filing a whole
// report about the runner's own repository. These tests pin the identity
// mapping and every refusal branch.

func ciJobEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CI", "true")
	t.Setenv("CI_PROJECT_PATH", "grp/proj")
	t.Setenv("CI_PROJECT_ID", "42")
	t.Setenv("CI_PROJECT_NAME", "proj")
	t.Setenv("CI_DEFAULT_BRANCH", "main")
	t.Setenv("CI_COMMIT_SHA", "abc123def")
	t.Setenv("CI_CONFIG_PATH", "ci/pipeline.yml")
}

func TestProjectFromCIEnvironment_MapsThePredefinedVariables(t *testing.T) {
	ciJobEnv(t)
	p, ok := ProjectFromCIEnvironment("grp/proj", "")
	if !ok {
		t.Fatal("a complete CI environment for the analyzed project must be accepted")
	}
	if p.IdOnPlatform != 42 || p.Path != "grp/proj" || p.Name != "proj" ||
		p.DefaultBranch != "main" || p.LatestHeadCommitSha != "abc123def" {
		t.Fatalf("identity mapping mismatch: %+v", p)
	}
	// $CI_COMMIT_SHA is the analyzed commit, NOT the default branch's head
	// (the API's answer): pinned via LatestHeadCommitSha above.
	if p.CiConfPath != "ci/pipeline.yml" {
		t.Fatalf("CiConfPath = %q, want the job's $CI_CONFIG_PATH", p.CiConfPath)
	}
}

// The wrong-repository guard: analyzing a DIFFERENT project from inside a CI
// job must refuse the environment, or branch protections, variables and the
// CI config of the runner's project would be filed under the other
// project's name with nothing downstream able to notice.
func TestProjectFromCIEnvironment_RefusesADifferentAnalyzedProject(t *testing.T) {
	ciJobEnv(t)
	if _, ok := ProjectFromCIEnvironment("other/repo", ""); ok {
		t.Fatal("the environment describes grp/proj; it must not be accepted for other/repo")
	}
}

func TestProjectFromCIEnvironment_RefusalBranches(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T)
	}{
		{"outside CI", func(t *testing.T) {
			ciJobEnv(t)
			t.Setenv("CI", "")
		}},
		{"missing project path", func(t *testing.T) {
			ciJobEnv(t)
			t.Setenv("CI_PROJECT_PATH", "")
		}},
		{"missing commit sha", func(t *testing.T) {
			ciJobEnv(t)
			t.Setenv("CI_COMMIT_SHA", "")
		}},
		{"non-numeric project id", func(t *testing.T) {
			ciJobEnv(t)
			t.Setenv("CI_PROJECT_ID", "not-a-number")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(t)
			if _, ok := ProjectFromCIEnvironment("grp/proj", ""); ok {
				t.Fatal("an environment that cannot answer completely must be refused, never a partial identity")
			}
		})
	}
}

// resolveCIConfigPath precedence: the platform snapshot's value wins (the
// anchor digest was computed against it), then the job's $CI_CONFIG_PATH,
// then GitLab's default.
func TestResolveCIConfigPath_Precedence(t *testing.T) {
	ciJobEnv(t)
	if got := resolveCIConfigPath("custom/from-snapshot.yml"); got != "custom/from-snapshot.yml" {
		t.Fatalf("snapshot value must win, got %q", got)
	}
	if got := resolveCIConfigPath(""); got != "ci/pipeline.yml" {
		t.Fatalf("without a snapshot value the job's $CI_CONFIG_PATH must win, got %q", got)
	}
	t.Setenv("CI_CONFIG_PATH", "")
	if got := resolveCIConfigPath(""); got != ".gitlab-ci.yml" {
		t.Fatalf("with neither, the GitLab default must apply, got %q", got)
	}
}
