package cmd

import (
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

func TestLocationLinker_LocalRunUsesAbsolutePath(t *testing.T) {
	// Local run against the local clone, no CI env: we keep the bare
	// `<absolute-path>:<line>` form so editors and iTerm-style
	// terminals can detect the source reference and jump to it.
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("GITHUB_SHA", "")
	t.Setenv("GITHUB_REF_NAME", "")
	t.Setenv("GITHUB_SERVER_URL", "")

	conf := configuration.NewDefaultConfiguration()
	conf.ProjectPath = "owner/repo"
	conf.IsLocalProject = true
	res := &control.AnalysisResult{ProjectPath: "owner/repo", DefaultBranch: "main"}

	got := newLocationLinker(conf, res, "github").BuildURL("/abs/path/repro.yml", 25)
	if got != "/abs/path/repro.yml:25" {
		t.Errorf("local link = %q, want %q", got, "/abs/path/repro.yml:25")
	}
}

func TestLocationLinker_RemoteProjectUsesBlobURL(t *testing.T) {
	// Local CLI run but not against the local clone (e.g. user runs
	// `plumber analyze --project owner/repo` without a checkout):
	// the local file doesn't exist on disk, so we emit the remote
	// blob URL even though we're not in CI.
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("GITHUB_SHA", "")
	t.Setenv("GITHUB_REF_NAME", "")
	t.Setenv("GITHUB_SERVER_URL", "")

	conf := configuration.NewDefaultConfiguration()
	conf.ProjectPath = "owner/repo"
	conf.IsLocalProject = false
	res := &control.AnalysisResult{
		ProjectPath:   "owner/repo",
		DefaultBranch: "main",
		AnalyzeBranch: "feature",
	}

	got := newLocationLinker(conf, res, "github").BuildURL(".github/workflows/ci.yml", 12)
	want := "https://github.com/owner/repo/blob/feature/.github/workflows/ci.yml#L12"
	if got != want {
		t.Errorf("remote-project link = %q, want %q", got, want)
	}
}

func TestLocationLinker_GitHubActionsUsesEnvVars(t *testing.T) {
	// In GitHub Actions the env vars are authoritative — we follow
	// them even if the AnalysisResult has different values, because
	// they describe the exact commit GitHub knows about.
	t.Setenv("CI", "true")
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_SERVER_URL", "https://github.example.com")
	t.Setenv("GITHUB_REPOSITORY", "acme/api")
	t.Setenv("GITHUB_SHA", "abc123def456")
	t.Setenv("GITHUB_REF_NAME", "main")
	t.Setenv("GITLAB_CI", "")

	conf := configuration.NewDefaultConfiguration()
	conf.ProjectPath = "stale/value"
	conf.IsLocalProject = true
	res := &control.AnalysisResult{
		ProjectPath:   "stale/value",
		DefaultBranch: "trunk",
	}

	got := newLocationLinker(conf, res, "github").BuildURL(".github/workflows/deploy.yml", 7)
	want := "https://github.example.com/acme/api/blob/abc123def456/.github/workflows/deploy.yml#L7"
	if got != want {
		t.Errorf("github actions link = %q, want %q", got, want)
	}
}

func TestLocationLinker_GitLabCIUsesEnvVars(t *testing.T) {
	t.Setenv("CI", "true")
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_SERVER_URL", "https://gitlab.example.com")
	t.Setenv("CI_PROJECT_PATH", "group/sub/proj")
	t.Setenv("CI_COMMIT_SHA", "deadbeefcafe")
	t.Setenv("CI_COMMIT_REF_NAME", "main")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITHUB_SERVER_URL", "")

	conf := configuration.NewDefaultConfiguration()
	conf.ProjectPath = "group/sub/proj"
	res := &control.AnalysisResult{ProjectPath: "group/sub/proj", DefaultBranch: "main"}

	got := newLocationLinker(conf, res, "gitlab").BuildURL(".gitlab-ci.yml", 56)
	want := "https://gitlab.example.com/group/sub/proj/-/blob/deadbeefcafe/.gitlab-ci.yml#L56"
	if got != want {
		t.Errorf("gitlab CI link = %q, want %q", got, want)
	}
}

func TestLocationLinker_BranchRefWithSlashKeepsSlash(t *testing.T) {
	// Branch names like "feature/foo" must keep their literal slash —
	// encoding to %2F breaks GitHub's tree-walking ref resolver. Same
	// guarantee applies to file paths and GitLab subgroup paths.
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	t.Setenv("GITHUB_SERVER_URL", "")
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("GITHUB_SHA", "")
	t.Setenv("GITHUB_REF_NAME", "")

	conf := configuration.NewDefaultConfiguration()
	conf.ProjectPath = "owner/repo"
	conf.IsLocalProject = false
	res := &control.AnalysisResult{
		ProjectPath:   "owner/repo",
		AnalyzeBranch: "feature/foo",
	}

	got := newLocationLinker(conf, res, "github").BuildURL(".github/workflows/ci.yml", 12)
	want := "https://github.com/owner/repo/blob/feature/foo/.github/workflows/ci.yml#L12"
	if got != want {
		t.Errorf("slashed-branch link = %q, want %q", got, want)
	}

	// Verify the same for GitLab subgroups (a known case where %2F
	// encoding would have broken paths like group/sub/proj/-/blob/…).
	confGL := configuration.NewDefaultConfiguration()
	confGL.ProjectPath = "group/sub/proj"
	confGL.IsLocalProject = false
	resGL := &control.AnalysisResult{
		ProjectPath:   "group/sub/proj",
		AnalyzeBranch: "release/v1",
	}
	gotGL := newLocationLinker(confGL, resGL, "gitlab").BuildURL(".gitlab-ci.yml", 1)
	wantGL := "https://gitlab.com/group/sub/proj/-/blob/release/v1/.gitlab-ci.yml#L1"
	if gotGL != wantGL {
		t.Errorf("subgroup link = %q, want %q", gotGL, wantGL)
	}
}

func TestLocationLinker_PrefersSHAOverBranch(t *testing.T) {
	// When both a SHA and a branch name are available the SHA wins:
	// it's stable, so a link in a downloaded artifact still points
	// at the exact code reviewed even after the branch moves.
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("GITHUB_SHA", "")
	t.Setenv("GITHUB_REF_NAME", "")
	t.Setenv("GITHUB_SERVER_URL", "")

	conf := configuration.NewDefaultConfiguration()
	conf.ProjectPath = "owner/repo"
	conf.IsLocalProject = false
	res := &control.AnalysisResult{
		ProjectPath:   "owner/repo",
		HeadCommitSha: "feedface1234",
		AnalyzeBranch: "main",
	}

	got := newLocationLinker(conf, res, "github").BuildURL(".github/workflows/ci.yml", 1)
	if !strings.Contains(got, "/blob/feedface1234/") {
		t.Errorf("expected SHA in link, got %q", got)
	}
	if strings.Contains(got, "/blob/main/") {
		t.Errorf("expected SHA to win over branch, got %q", got)
	}
}

func TestLocationLinker_MissingFileReturnsEmpty(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")

	conf := configuration.NewDefaultConfiguration()
	res := &control.AnalysisResult{ProjectPath: "owner/repo"}
	if got := newLocationLinker(conf, res, "github").BuildURL("", 1); got != "" {
		t.Errorf("expected empty link for missing file, got %q", got)
	}
}

func TestLocationLinker_Annotate(t *testing.T) {
	t.Setenv("CI", "true")
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")
	t.Setenv("GITHUB_SHA", "abc123")
	t.Setenv("GITLAB_CI", "")

	conf := configuration.NewDefaultConfiguration()
	conf.ProjectPath = "owner/repo"
	res := &control.AnalysisResult{ProjectPath: "owner/repo"}

	findings := []opaengine.Finding{
		{Code: "ISSUE-411", File: ".github/workflows/ci.yml", Line: 25},
		{Code: "ISSUE-203", File: ".github/workflows/ci.yml", Line: 0},
		{Code: "ISSUE-501", File: ""}, // repo-level, no file
	}
	newLocationLinker(conf, res, "github").Annotate(findings)

	if findings[0].URL != "https://github.com/owner/repo/blob/abc123/.github/workflows/ci.yml#L25" {
		t.Errorf("finding[0].URL = %q", findings[0].URL)
	}
	if findings[1].URL != "https://github.com/owner/repo/blob/abc123/.github/workflows/ci.yml" {
		t.Errorf("finding[1].URL (no line) = %q", findings[1].URL)
	}
	if findings[2].URL != "" {
		t.Errorf("repo-level finding should have empty URL, got %q", findings[2].URL)
	}
}

func TestGitHubWebURL_DerivesFromAPIHost(t *testing.T) {
	t.Setenv("GITHUB_SERVER_URL", "")

	cases := map[string]string{
		"":                               "https://github.com",
		"github.com":                     "https://github.com",
		"ghes.example.com":               "https://ghes.example.com",
		"ghes.example.com/api/v3":        "https://ghes.example.com",
		"https://ghes.example.com/api/v3": "https://ghes.example.com",
	}
	for in, want := range cases {
		if got := githubWebURL(in); got != want {
			t.Errorf("githubWebURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGitHubWebURL_HonoursGITHUBSERVERURL(t *testing.T) {
	t.Setenv("GITHUB_SERVER_URL", "https://github.acme.com")
	if got := githubWebURL("ghes.example.com"); got != "https://github.acme.com" {
		t.Errorf("GITHUB_SERVER_URL override not honoured: %q", got)
	}
}
