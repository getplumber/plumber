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

// TestHandleScorePublishing_DisabledNeverSends proves the privacy guarantee:
// with score-push OFF (the default), NOTHING is sent to the score service —
// even inside a full CI context with a valid OIDC token present. Only an
// explicit opt-in (pushScore=true, i.e. --score-push / PLUMBER_ANALYZE_SCORE_PUSH)
// may POST.
func TestHandleScorePublishing_DisabledNeverSends(t *testing.T) {
	p, ok := providerPkg.Get("gitlab")
	if !ok {
		t.Skip("gitlab provider not registered")
	}

	var posts atomic.Int32
	score := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer score.Close()

	defer func(pp bool, e string) { pushScore, scoreEndpoint = pp, e }(pushScore, scoreEndpoint)
	// Endpoint is configured, token is present, we're "in CI" — the ONLY thing
	// off is the explicit opt-in.
	pushScore, scoreEndpoint = false, score.URL
	scorePublishOnce = sync.Once{}

	t.Setenv("CI", "true")
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_COMMIT_BRANCH", "main")
	t.Setenv("CI_PROJECT_PATH", "group/repo")
	t.Setenv("CI_SERVER_URL", "https://gitlab.com")
	t.Setenv(gitlabScoreTokenEnv, "a-valid-token")

	// The endpoint is set via the flag (scoreEndpoint above); publishing is
	// still gated solely by the opt-in, which is off here.
	conf := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{}}
	result := &control.AnalysisResult{ProjectPath: "group/repo", DefaultBranch: "main"}

	handleScorePublishing(p, conf, result, complianceSummary{})

	if got := posts.Load(); got != 0 {
		t.Fatalf("score-push disabled but the service was contacted %d time(s); want 0", got)
	}
}
