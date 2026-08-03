package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	providerPkg "github.com/getplumber/plumber/provider"
)

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"https://gitlab.com":        "gitlab.com",
		"gitlab.example.com":        "gitlab.example.com",
		"https://github.com/":       "github.com",
		"https://ghes.example.com/": "ghes.example.com",
		"":                          "",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEffectiveScorePush(t *testing.T) {
	defer func(p bool, e string) { pushScore, scoreEndpoint = p, e }(pushScore, scoreEndpoint)
	tests := []struct {
		name     string
		flagPush bool
		flagEnd  string
		wantPush bool
		wantEnd  string
	}{
		{"default off", false, "", false, "https://score.getplumber.io"},
		{"flag push on", true, "", true, "https://score.getplumber.io"},
		{"flag endpoint used", false, "https://score.example.com", false, "https://score.example.com"},
		{"flag endpoint trims slash", false, "https://score.example.com/", false, "https://score.example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pushScore, scoreEndpoint = tc.flagPush, tc.flagEnd
			gotPush, gotEnd := effectiveScorePush()
			if gotPush != tc.wantPush || gotEnd != tc.wantEnd {
				t.Errorf("got (%v, %q), want (%v, %q)", gotPush, gotEnd, tc.wantPush, tc.wantEnd)
			}
		})
	}
}

func TestFetchGitHubActionsIDToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer req-tok" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		if got := r.URL.Query().Get("audience"); got != "https://score.getplumber.io" {
			http.Error(w, "bad audience: "+got, http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "id-token-123"})
	}))
	defer srv.Close()

	tok, err := fetchGitHubActionsIDToken(srv.URL+"?x=1", "req-tok", "https://score.getplumber.io")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "id-token-123" {
		t.Fatalf("token = %q, want id-token-123", tok)
	}
}

func TestPostScoreReport(t *testing.T) {
	var gotAuth, gotCT, gotPath string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		if r.URL.Path == "/forbidden" {
			http.Error(w, "nope", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	if err := postScoreReport(srv.URL+"/github.com/o/r", "tok", []byte(`{"a":1}`)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "Bearer tok" || gotCT != "application/json" || gotPath != "/github.com/o/r" || string(gotBody) != `{"a":1}` {
		t.Fatalf("auth=%q ct=%q path=%q body=%q", gotAuth, gotCT, gotPath, gotBody)
	}

	if err := postScoreReport(srv.URL+"/forbidden", "tok", []byte("{}")); err == nil {
		t.Fatal("expected a non-2xx error")
	}
}

func TestResolveScoreTarget_FromCIEnv(t *testing.T) {
	p, ok := providerPkg.Get("github")
	if !ok {
		t.Skip("github provider not registered")
	}
	t.Setenv("GITHUB_REPOSITORY", "octo/Hello-World")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")

	platform, projectPath, gotOK := resolveScoreTarget(p, &configuration.Configuration{})
	if !gotOK || platform != "github.com" || projectPath != "octo/Hello-World" {
		t.Fatalf("got (%q, %q, %v), want (github.com, octo/Hello-World, true)", platform, projectPath, gotOK)
	}
}

func TestBuildPlumberConfigBlock(t *testing.T) {
	// Explicit config file: shipped parsed (a JSON object), not as a raw
	// string, with the source path and a sha256 content hash.
	b := buildPlumberConfigBlock(&configuration.PlumberConfig{
		Raw:    "version: \"2.0\"\ngitlab:\n  controls:\n    secretsMustNotBeLeaked:\n      enabled: false\n",
		Source: ".plumber.yaml",
	})
	if _, shippedRaw := b["raw"]; shippedRaw {
		t.Fatalf("must not ship the verbatim file as `raw`: %+v", b)
	}
	if b["source"] != ".plumber.yaml" {
		t.Fatalf("source = %v, want .plumber.yaml", b["source"])
	}
	policy, ok := b["effectivePolicy"].(map[string]any)
	if !ok {
		t.Fatalf("effectivePolicy must be an object, got %T", b["effectivePolicy"])
	}
	if policy["version"] != "2.0" {
		t.Fatalf("parsed policy missing version: %+v", policy)
	}
	// Nested maps must be string-keyed so the report stays JSON-encodable.
	if _, err := json.Marshal(policy); err != nil {
		t.Fatalf("parsed policy is not JSON-encodable: %v", err)
	}
	if gl, ok := policy["gitlab"].(map[string]any); !ok {
		t.Fatalf("gitlab section not an object: %T", policy["gitlab"])
	} else if _, ok := gl["controls"].(map[string]any); !ok {
		t.Fatalf("gitlab.controls not an object: %T", gl["controls"])
	}
	hash, _ := b["hash"].(string)
	if !strings.HasPrefix(hash, "sha256:") || len(hash) != len("sha256:")+64 {
		t.Fatalf("hash is not a sha256 hex digest: %q", hash)
	}

	// Same policy, different comments/whitespace -> identical hash (the digest
	// is over the parsed content, not the file text).
	b2 := buildPlumberConfigBlock(&configuration.PlumberConfig{
		Raw:    "# a header comment\nversion: \"2.0\"\n\ngitlab:\n  controls:\n    secretsMustNotBeLeaked:\n      enabled: false  # inline note\n",
		Source: ".plumber.yaml",
	})
	if b2["hash"] != b["hash"] {
		t.Fatalf("hash should ignore comments/whitespace: %v vs %v", b2["hash"], b["hash"])
	}

	// No raw -> falls back to the embedded default, source "default".
	d := buildPlumberConfigBlock(&configuration.PlumberConfig{})
	if d["source"] != "default" {
		t.Fatalf("default source = %v, want default", d["source"])
	}
	if _, ok := d["effectivePolicy"].(map[string]any); !ok {
		t.Fatalf("default effectivePolicy must be an object, got %T", d["effectivePolicy"])
	}
	if h, _ := d["hash"].(string); !strings.HasPrefix(h, "sha256:") {
		t.Fatalf("default hash = %q, want sha256: prefix", h)
	}
}

// TestAnalysisJSONKeyOrder_PlumberConfigLast pins plumberConfig to the very end
// of the report, after the per-control *Result blocks and everything else.
func TestAnalysisJSONKeyOrder_PlumberConfigLast(t *testing.T) {
	out := map[string]any{
		"projectPath":                  "g/r",
		"compliance":                   100,
		"plumberScore":                 map[string]any{"score": "A"},
		"secretsMustNotBeLeakedResult": map[string]any{},
		"imageForbiddenTagsResult":     map[string]any{},
		"partialControls":              []any{}, // a non-head, non-*Result key
		"plumberConfig":                map[string]any{"source": "default"},
	}
	order := legacyAnalysisJSONKeyOrder(out)
	t.Logf("key order: %v", order)
	if len(order) != len(out) {
		t.Fatalf("order has %d keys, want %d: %v", len(order), len(out), order)
	}
	if order[0] != "projectPath" {
		t.Fatalf("head key projectPath must come first; got %v", order)
	}
	if order[len(order)-1] != "plumberConfig" {
		t.Fatalf("plumberConfig must be emitted last; got %v", order)
	}
}

// TestMaybePushScore_FullFlow proves the end-to-end publish path on the GitHub
// (OIDC-mint) side: fetch the id-token from the Actions runtime endpoint, then
// POST the report to {endpoint}/{platform}/{project} with that token.
func TestMaybePushScore_FullFlow(t *testing.T) {
	p, ok := providerPkg.Get("github")
	if !ok {
		t.Skip("github provider not registered")
	}

	oidc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "id-tok"})
	}))
	defer oidc.Close()

	var gotPath, gotAuth string
	var gotBody []byte
	score := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer score.Close()

	defer func(pp bool, e string) { pushScore, scoreEndpoint = pp, e }(pushScore, scoreEndpoint)
	pushScore, scoreEndpoint = true, score.URL
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "octo/repo")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", oidc.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "req")

	conf := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{}}
	maybePushScore(p, conf, []byte(`{"plumberScore":{"score":"A"}}`), "main")

	if gotPath != "/github.com/octo/repo" || gotAuth != "Bearer id-tok" || string(gotBody) != `{"plumberScore":{"score":"A"}}` {
		t.Fatalf("push not received as expected: path=%q auth=%q body=%q", gotPath, gotAuth, gotBody)
	}
}

// TestMaybePushScore_NonDefaultBranchNote proves the success line carries a
// note when the run's branch is not the repo default: the score service stores
// such a push per-branch only, so the PUBLIC badge does not change and a bare
// "published" would be misleading. On the default branch (or when either side
// is unknown) the line stays bare.
func TestMaybePushScore_NonDefaultBranchNote(t *testing.T) {
	p, ok := providerPkg.Get("github")
	if !ok {
		t.Skip("github provider not registered")
	}

	oidc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "id-tok"})
	}))
	defer oidc.Close()
	score := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer score.Close()

	defer func(pp bool, e string) { pushScore, scoreEndpoint = pp, e }(pushScore, scoreEndpoint)
	pushScore, scoreEndpoint = true, score.URL
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "octo/repo")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", oidc.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "req")

	conf := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{}}
	payload := []byte(`{"plumberScore":{"score":"A"}}`)

	push := func(t *testing.T, refType, refName, defaultBranch string) string {
		t.Helper()
		t.Setenv("GITHUB_REF_TYPE", refType)
		t.Setenv("GITHUB_REF_NAME", refName)
		return captureStderr(t, func() {
			maybePushScore(p, conf, payload, defaultBranch)
		})
	}

	t.Run("non-default branch gets the note", func(t *testing.T) {
		out := push(t, "branch", "feature-x", "main")
		if !strings.Contains(out, "Plumber Score published") {
			t.Fatalf("expected the success line, got: %q", out)
		}
		if !strings.Contains(out, "not displayed") || !strings.Contains(out, "feature-x") {
			t.Fatalf("expected a non-default-branch note naming the branch, got: %q", out)
		}
	})

	t.Run("default branch stays bare", func(t *testing.T) {
		out := push(t, "branch", "main", "main")
		if !strings.Contains(out, "Plumber Score published") {
			t.Fatalf("expected the success line, got: %q", out)
		}
		if strings.Contains(out, "not displayed") {
			t.Fatalf("unexpected note on a default-branch run: %q", out)
		}
	})

	t.Run("unknown run branch stays bare", func(t *testing.T) {
		out := push(t, "", "", "main")
		if strings.Contains(out, "not displayed") {
			t.Fatalf("unexpected note when the run branch is unknown: %q", out)
		}
	})

	t.Run("unknown default branch stays bare", func(t *testing.T) {
		out := push(t, "branch", "feature-x", "")
		if strings.Contains(out, "not displayed") {
			t.Fatalf("unexpected note when the default branch is unknown: %q", out)
		}
	})
}

// TestMaybePushScore_NonDefaultBranchNote_GitLab drives the GitLab side of
// ciRunBranch (CI_COMMIT_BRANCH): a branch pipeline off the default branch
// gets the note, the default branch stays bare, and an MR pipeline (empty
// CI_COMMIT_BRANCH) stays bare because the run branch is unknown.
func TestMaybePushScore_NonDefaultBranchNote_GitLab(t *testing.T) {
	p, ok := providerPkg.Get("gitlab")
	if !ok {
		t.Skip("gitlab provider not registered")
	}

	score := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer score.Close()

	defer func(pp bool, e string) { pushScore, scoreEndpoint = pp, e }(pushScore, scoreEndpoint)
	pushScore, scoreEndpoint = true, score.URL
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_PROJECT_PATH", "group/repo")
	t.Setenv("CI_SERVER_URL", "https://gitlab.com")
	t.Setenv(gitlabScoreTokenEnv, "tok")

	conf := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{}}
	payload := []byte(`{"plumberScore":{"score":"A"}}`)

	push := func(t *testing.T, commitBranch, defaultBranch string) string {
		t.Helper()
		t.Setenv("CI_COMMIT_BRANCH", commitBranch)
		return captureStderr(t, func() {
			maybePushScore(p, conf, payload, defaultBranch)
		})
	}

	t.Run("non-default branch gets the note", func(t *testing.T) {
		out := push(t, "feature-x", "main")
		if !strings.Contains(out, "Plumber Score published") {
			t.Fatalf("expected the success line, got: %q", out)
		}
		if !strings.Contains(out, "not displayed") || !strings.Contains(out, "feature-x") {
			t.Fatalf("expected a non-default-branch note naming the branch, got: %q", out)
		}
	})

	t.Run("default branch stays bare", func(t *testing.T) {
		out := push(t, "main", "main")
		if !strings.Contains(out, "Plumber Score published") {
			t.Fatalf("expected the success line, got: %q", out)
		}
		if strings.Contains(out, "not displayed") {
			t.Fatalf("unexpected note on a default-branch run: %q", out)
		}
	})

	t.Run("MR pipeline stays bare", func(t *testing.T) {
		out := push(t, "", "main")
		if strings.Contains(out, "not displayed") {
			t.Fatalf("unexpected note when CI_COMMIT_BRANCH is empty: %q", out)
		}
	})
}

// captureStderr redirects os.Stderr for the duration of fn and returns whatever
// was written. maybePushScore prints its notes straight to stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	_ = w.Close()
	os.Stderr = old
	return <-done
}

// TestMaybePushScore_LocalNote proves an explicit --score-push outside a
// token-granting CI prints a note (not silence), so a requested push is never
// silently ignored.
func TestMaybePushScore_LocalNote(t *testing.T) {
	p, ok := providerPkg.Get("github")
	if !ok {
		t.Skip("github provider not registered")
	}
	// A local run: no CI flags, no OIDC request endpoint, but a resolvable repo.
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("GITHUB_REPOSITORY", "octo/repo")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	payload := []byte(`{"plumberScore":{"score":"A"}}`)

	defer func(pp bool, e string) { pushScore, scoreEndpoint = pp, e }(pushScore, scoreEndpoint)

	t.Run("explicit --score-push gets a note", func(t *testing.T) {
		pushScore, scoreEndpoint = true, ""
		out := captureStderr(t, func() {
			maybePushScore(p, &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{}}, payload, "main")
		})
		if !strings.Contains(out, "--score-push") || !strings.Contains(out, "CI") {
			t.Fatalf("expected a local-skip note mentioning --score-push and CI, got: %q", out)
		}
	})
}

// TestHandleScorePublishing_NonDefaultBranchStillPublishes proves the branch
// gate is gone: a GitLab MR pipeline (empty CI_COMMIT_BRANCH, subgroup path)
// still POSTs exactly once. The score service, not the CLI, filters by branch
// using the verified OIDC token claim.
func TestHandleScorePublishing_NonDefaultBranchStillPublishes(t *testing.T) {
	p, ok := providerPkg.Get("gitlab")
	if !ok {
		t.Skip("gitlab provider not registered")
	}

	var posts atomic.Int32
	var gotPath, gotAuth string
	score := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
	}))
	defer score.Close()

	defer func(pp bool, e string) { pushScore, scoreEndpoint = pp, e }(pushScore, scoreEndpoint)
	pushScore, scoreEndpoint = true, score.URL
	scorePublishOnce = sync.Once{}

	// GitLab MR pipeline: CI_COMMIT_BRANCH is empty (the old gate would have
	// skipped), the project lives in a subgroup, and the component minted the
	// OIDC token into PLUMBER_ANALYZE_SCORE_TOKEN.
	t.Setenv("CI", "true")
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_COMMIT_BRANCH", "")
	t.Setenv("CI_MERGE_REQUEST_IID", "42")
	t.Setenv("CI_PROJECT_PATH", "group/subgroup/repo")
	t.Setenv("CI_SERVER_URL", "https://gitlab.com")
	t.Setenv(gitlabScoreTokenEnv, "mr-token")

	conf := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{}}
	result := &control.AnalysisResult{ProjectPath: "group/subgroup/repo", DefaultBranch: "main"}

	handleScorePublishing(p, conf, result, complianceSummary{})

	if got := posts.Load(); got != 1 {
		t.Fatalf("MR-pipeline run POSTed %d times, want exactly 1", got)
	}
	if gotPath != "/gitlab.com/group/subgroup/repo" {
		t.Fatalf("path = %q, want /gitlab.com/group/subgroup/repo", gotPath)
	}
	if gotAuth != "Bearer mr-token" {
		t.Fatalf("auth = %q, want Bearer mr-token", gotAuth)
	}
}

// TestHandleScorePublishing_SkipsDegraded keeps the orthogonal guard from #220:
// a degraded (incomplete / rate-limited) run must not overwrite the last good
// score, so it does not POST.
func TestHandleScorePublishing_SkipsDegraded(t *testing.T) {
	p, ok := providerPkg.Get("gitlab")
	if !ok {
		t.Skip("gitlab provider not registered")
	}

	var posts atomic.Int32
	score := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer score.Close()

	defer func(pp bool, e string) { pushScore, scoreEndpoint = pp, e }(pushScore, scoreEndpoint)
	pushScore, scoreEndpoint = true, score.URL
	scorePublishOnce = sync.Once{}

	t.Setenv("CI", "true")
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_PROJECT_PATH", "group/repo")
	t.Setenv("CI_SERVER_URL", "https://gitlab.com")
	t.Setenv(gitlabScoreTokenEnv, "tok")

	conf := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{}}
	result := &control.AnalysisResult{ProjectPath: "group/repo", DefaultBranch: "main", DataCollectionDegraded: true}

	handleScorePublishing(p, conf, result, complianceSummary{})

	if got := posts.Load(); got != 0 {
		t.Fatalf("degraded run POSTed %d times, want 0", got)
	}
}

// TestHandleScorePublishing_PublishesOnce locks in the double-push guard: even
// if both provider entry points call handleScorePublishing in one run, the
// badge is POSTed only once.
func TestHandleScorePublishing_PublishesOnce(t *testing.T) {
	p, ok := providerPkg.Get("github")
	if !ok {
		t.Skip("github provider not registered")
	}

	oidc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "id-tok"})
	}))
	defer oidc.Close()

	var posts atomic.Int32
	score := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer score.Close()

	defer func(pp bool, e string) { pushScore, scoreEndpoint = pp, e }(pushScore, scoreEndpoint)
	pushScore, scoreEndpoint = true, score.URL
	scorePublishOnce = sync.Once{} // fresh guard for this run

	t.Setenv("CI", "true")
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REF_TYPE", "branch")
	t.Setenv("GITHUB_REF_NAME", "main")
	t.Setenv("GITHUB_REPOSITORY", "octo/repo")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", oidc.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "req")

	conf := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{}}
	result := &control.AnalysisResult{ProjectPath: "octo/repo", DefaultBranch: "main"}

	handleScorePublishing(p, conf, result, complianceSummary{})
	handleScorePublishing(p, conf, result, complianceSummary{})

	if got := posts.Load(); got != 1 {
		t.Fatalf("score POSTed %d times, want exactly 1", got)
	}
}
