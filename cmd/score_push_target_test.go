package cmd

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	providerPkg "github.com/getplumber/plumber/provider"
)

// TestHandleScorePublishing_SkipsForeignProject locks in the fix for the
// "remote scan wrong score target" case: when --project (conf.ProjectPath)
// points the scan at a repo other than the CI pipeline's own, the push is
// skipped rather than keyed to the CI repo's badge with foreign content.
func TestHandleScorePublishing_SkipsForeignProject(t *testing.T) {
	p, ok := providerPkg.Get("github")
	if !ok {
		t.Skip("github provider not registered")
	}

	var posts atomic.Int32
	score := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer score.Close()

	defer func(pp bool, e string) { pushScore, scoreEndpoint = pp, e }(pushScore, scoreEndpoint)
	pushScore, scoreEndpoint = true, score.URL
	scorePublishOnce = sync.Once{}

	// In CI for owner/ci-repo, but the scan was retargeted at owner/other-repo.
	t.Setenv("CI", "true")
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "owner/ci-repo")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", score.URL+"/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "req-token")

	conf := &configuration.Configuration{
		ProjectPath:   "owner/other-repo",
		PlumberConfig: &configuration.PlumberConfig{},
	}
	result := &control.AnalysisResult{ProjectPath: "owner/other-repo", DefaultBranch: "main"}

	handleScorePublishing(p, conf, result, complianceSummary{})

	if got := posts.Load(); got != 0 {
		t.Fatalf("foreign-project scan POSTed %d time(s); want 0 (push must be skipped)", got)
	}
}

// TestCIScoreTargetMismatch covers the decision table directly.
func TestCIScoreTargetMismatch(t *testing.T) {
	p, ok := providerPkg.Get("github")
	if !ok {
		t.Skip("github provider not registered")
	}
	tests := []struct {
		name     string
		ciRepo   string // GITHUB_REPOSITORY ("" = not in CI)
		scanned  string // conf.ProjectPath
		mismatch bool
	}{
		{"match publishes", "owner/repo", "owner/repo", false},
		{"case-insensitive match", "Owner/Repo", "owner/repo", false},
		{"foreign project skips", "owner/ci-repo", "owner/other", true},
		{"no CI identity (local) never blocks", "", "owner/other", false},
		{"no scanned path never blocks", "owner/repo", "", false},
		{"trailing slashes normalized", "owner/repo/", "/owner/repo", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GITHUB_REPOSITORY", tc.ciRepo)
			conf := &configuration.Configuration{ProjectPath: tc.scanned}
			if _, _, got := ciScoreTargetMismatch(p, conf); got != tc.mismatch {
				t.Errorf("mismatch = %v, want %v", got, tc.mismatch)
			}
		})
	}
}
