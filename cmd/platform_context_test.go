package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
)

// withPlatformContextTestEnv extends withPlatformTestEnv with CI_PROJECT_PATH
// (GitLab's RepoPath env, read by resolveScoreTarget) and a pinned configFile,
// so the derived policy name is deterministic ("default") and a /context call
// has a project path to fetch for. Returns a restore func.
func withPlatformContextTestEnv(t *testing.T, url, token, projectPath string) func() {
	t.Helper()
	restorePlatform := withPlatformTestEnv(t, url, token)
	t.Setenv("CI_PROJECT_PATH", projectPath)
	origConfigFile := configFile
	configFile = ".plumber.yaml"
	return func() {
		configFile = origConfigFile
		restorePlatform()
	}
}

// platformTestServer serves both the push (POST /api/v1/pushes) and the
// context (GET .../context) routes from one httptest.Server, matching the
// single-server, two-endpoint shape a real platform push exercises in one
// run. contextHandler may be nil to leave /context unhandled (a caller that
// closes the server or wants a transport error typically does that instead).
func platformTestServer(t *testing.T, contextHandler func(w http.ResponseWriter, r *http.Request), pushBody *[]byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.EscapedPath(), "/context") {
			if contextHandler != nil {
				contextHandler(w, r)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		*pushBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
}

// The happy path: /context returns a policy whose name matches the locally
// derived name ("default", from the pinned .plumber.yaml), so the push body
// carries results[].policy_id alongside the existing name-only policy string.
func TestMaybePushPlatform_StampsPolicyIDOnExactNameMatch(t *testing.T) {
	var gotPushBody []byte
	var gotContextPath string
	srv := platformTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotContextPath = r.URL.EscapedPath()
		if auth := r.Header.Get("Authorization"); auth != "Bearer tok-123" {
			t.Errorf("context request Authorization = %q, want the same bearer token as the push", auth)
		}
		_, _ = w.Write([]byte(`{"policies":[{"id":"11111111-2222-3333-4444-555555555555","name":"default","enforcement":"block"}],"snapshot":{}}`))
	}, &gotPushBody)
	defer srv.Close()

	restore := withPlatformContextTestEnv(t, srv.URL, "tok-123", "org/repo")
	defer restore()

	conf := &configuration.Configuration{ConfigFilePath: ".plumber.yaml", PlumberConfig: testDefaultPlumberConfig(t)}
	score := &control.PlumberScoreResult{Score: "B", RawPointsUnclamped: 82.5}
	if err := maybePushPlatform(testProvider(t), conf, &control.AnalysisResult{}, score); err != nil {
		t.Fatalf("maybePushPlatform: %v", err)
	}
	if !strings.HasSuffix(gotContextPath, "/api/v1/projects/org%2Frepo/context") {
		t.Errorf("context request path = %q, want the project path percent-escaped as a single segment", gotContextPath)
	}

	var push platformPush
	if err := json.Unmarshal(gotPushBody, &push); err != nil {
		t.Fatalf("push body does not decode as a platformPush: %v", err)
	}
	if len(push.Results) != 1 {
		t.Fatalf("results = %d, want exactly 1: %s", len(push.Results), gotPushBody)
	}
	entry := push.Results[0]
	if entry.PolicyID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("policy_id = %q, want the /context uuid", entry.PolicyID)
	}
	if entry.Policy != "default" {
		t.Errorf("policy = %q, want %q (unchanged by stamping)", entry.Policy, "default")
	}

	// The raw wire body must actually carry the key: a struct-level assertion
	// alone would not catch a broken json tag.
	if !strings.Contains(string(gotPushBody), `"policy_id":"11111111-2222-3333-4444-555555555555"`) {
		t.Errorf("raw push body does not contain the policy_id key: %s", gotPushBody)
	}
}

// No /context entry names the local policy ("default"): the key is omitted
// from the wire entirely, not sent empty or zero.
func TestMaybePushPlatform_NoMatchOmitsPolicyIDKey(t *testing.T) {
	var gotPushBody []byte
	srv := platformTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"policies":[{"id":"11111111-2222-3333-4444-555555555555","name":"strict","enforcement":"report"}]}`))
	}, &gotPushBody)
	defer srv.Close()

	conf := &configuration.Configuration{ConfigFilePath: ".plumber.yaml", PlumberConfig: testDefaultPlumberConfig(t)}
	score := &control.PlumberScoreResult{Score: "B", RawPointsUnclamped: 82.5}

	out := captureStderr(t, func() {
		restore := withPlatformContextTestEnv(t, srv.URL, "tok-123", "org/repo")
		defer restore()

		if err := maybePushPlatform(testProvider(t), conf, &control.AnalysisResult{}, score); err != nil {
			t.Fatalf("maybePushPlatform: %v", err)
		}
	})

	if strings.Contains(string(gotPushBody), "policy_id") {
		t.Errorf("push body contains policy_id with no /context match: %s", gotPushBody)
	}
	var push platformPush
	if err := json.Unmarshal(gotPushBody, &push); err != nil {
		t.Fatalf("push body does not decode as a platformPush: %v", err)
	}
	if push.Results[0].Policy != "default" {
		t.Errorf("policy = %q, want %q: a no-match push stays name-only, never dropped", push.Results[0].Policy, "default")
	}
	if !strings.Contains(out, "default") {
		t.Errorf("stderr = %q, want an informative line naming the unmatched policy", out)
	}
}

// Ambiguous /context response (two entries with the same name): also no id,
// same as zero matches - the platform's tolerance covers the name-only push,
// guessing at ambiguity is worse than omitting.
func TestMaybePushPlatform_AmbiguousMatchOmitsPolicyIDKey(t *testing.T) {
	var gotPushBody []byte
	srv := platformTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"policies":[
			{"id":"11111111-2222-3333-4444-555555555555","name":"default","enforcement":"block"},
			{"id":"66666666-7777-8888-9999-000000000000","name":"default","enforcement":"report"}
		]}`))
	}, &gotPushBody)
	defer srv.Close()

	restore := withPlatformContextTestEnv(t, srv.URL, "tok-123", "org/repo")
	defer restore()

	conf := &configuration.Configuration{ConfigFilePath: ".plumber.yaml", PlumberConfig: testDefaultPlumberConfig(t)}
	score := &control.PlumberScoreResult{Score: "B", RawPointsUnclamped: 82.5}
	if err := maybePushPlatform(testProvider(t), conf, &control.AnalysisResult{}, score); err != nil {
		t.Fatalf("maybePushPlatform: %v", err)
	}
	if strings.Contains(string(gotPushBody), "policy_id") {
		t.Errorf("push body contains policy_id for an ambiguous /context match: %s", gotPushBody)
	}
}

// Every failure mode of the /context call itself (5xx, transport/timeout,
// 403, unparseable body) must never affect the run or the push: no id, one
// warning, the push still succeeds name-only.
func TestMaybePushPlatform_ContextFetchFailureFallsBackToNameOnly(t *testing.T) {
	conf := &configuration.Configuration{ConfigFilePath: ".plumber.yaml", PlumberConfig: testDefaultPlumberConfig(t)}
	score := &control.PlumberScoreResult{Score: "B", RawPointsUnclamped: 82.5}

	t.Run("500", func(t *testing.T) {
		var gotPushBody []byte
		srv := platformTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}, &gotPushBody)
		defer srv.Close()

		var err error
		out := captureStderr(t, func() {
			restore := withPlatformContextTestEnv(t, srv.URL, "tok-123", "org/repo")
			defer restore()
			err = maybePushPlatform(testProvider(t), conf, &control.AnalysisResult{}, score)
		})
		if err != nil {
			t.Fatalf("maybePushPlatform: %v, want nil: a /context 500 must never fail the run", err)
		}
		if strings.Contains(string(gotPushBody), "policy_id") {
			t.Errorf("push body contains policy_id despite a /context 500: %s", gotPushBody)
		}
		if len(gotPushBody) == 0 {
			t.Error("push body is empty: the push must still proceed name-only after a /context failure")
		}
		if !strings.Contains(out, "⚠️") {
			t.Errorf("stderr = %q, want a scoreWarn-style warning line", out)
		}
	})

	t.Run("403", func(t *testing.T) {
		var gotPushBody []byte
		srv := platformTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}, &gotPushBody)
		defer srv.Close()

		var err error
		out := captureStderr(t, func() {
			restore := withPlatformContextTestEnv(t, srv.URL, "tok-123", "org/repo")
			defer restore()
			err = maybePushPlatform(testProvider(t), conf, &control.AnalysisResult{}, score)
		})
		if err != nil {
			t.Fatalf("maybePushPlatform: %v, want nil: a /context 403 must never fail the run", err)
		}
		if strings.Contains(string(gotPushBody), "policy_id") {
			t.Errorf("push body contains policy_id despite a /context 403: %s", gotPushBody)
		}
		if len(gotPushBody) == 0 {
			t.Error("push body is empty: the push must still proceed name-only after a /context 403")
		}
		if !strings.Contains(out, "⚠️") {
			t.Errorf("stderr = %q, want a scoreWarn-style warning line", out)
		}
	})

	t.Run("unreachable (transport error)", func(t *testing.T) {
		// Start a server, learn its URL, then close it: nothing is listening,
		// so any request (context GET or push POST) is a transport error.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		url := srv.URL
		srv.Close()

		var err error
		out := captureStderr(t, func() {
			restore := withPlatformContextTestEnv(t, url, "tok-123", "org/repo")
			defer restore()
			err = maybePushPlatform(testProvider(t), conf, &control.AnalysisResult{}, score)
		})
		if err != nil {
			t.Fatalf("maybePushPlatform: %v, want nil: an unreachable /context must never fail the run", err)
		}
		if !strings.Contains(out, "⚠️") {
			t.Errorf("stderr = %q, want a scoreWarn-style warning line", out)
		}
	})

	t.Run("unparseable body", func(t *testing.T) {
		var gotPushBody []byte
		srv := platformTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}, &gotPushBody)
		defer srv.Close()

		var err error
		out := captureStderr(t, func() {
			restore := withPlatformContextTestEnv(t, srv.URL, "tok-123", "org/repo")
			defer restore()
			err = maybePushPlatform(testProvider(t), conf, &control.AnalysisResult{}, score)
		})
		if err != nil {
			t.Fatalf("maybePushPlatform: %v, want nil: an unparseable /context body must never fail the run", err)
		}
		if strings.Contains(string(gotPushBody), "policy_id") {
			t.Errorf("push body contains policy_id despite an unparseable /context body: %s", gotPushBody)
		}
		if !strings.Contains(out, "⚠️") {
			t.Errorf("stderr = %q, want a scoreWarn-style warning line", out)
		}
	})
}

// The zero-uuid rule, pinned directly at the wire-shape level: a
// platformPolicyResult with no resolved id must never serialize the literal
// all-zero uuid, and must omit the key rather than emit it empty. This is
// what makes "no match" and "no id resolved" structurally the same thing as
// "policy_id was never set" - there is no code path that can fall back to a
// zero-value uuid string.
func TestPlatformPolicyResult_ZeroPolicyIDNeverEmitsAllZeroUUID(t *testing.T) {
	body, err := json.Marshal(platformPolicyResult{Policy: "default"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(body), "00000000") {
		t.Errorf("zero-value policy result carries an all-zero uuid on the wire: %s", body)
	}
	if strings.Contains(string(body), "policy_id") {
		t.Errorf("zero-value policy result carries the policy_id key at all, want it omitted: %s", body)
	}
}

// matchPlatformContextPolicyID is the matching primitive on its own, isolated
// from the HTTP/env plumbing above.
func TestMatchPlatformContextPolicyID(t *testing.T) {
	policies := []platformContextPolicy{
		{ID: "aaa", Name: "default"},
		{ID: "bbb", Name: "strict"},
	}
	if id, ok := matchPlatformContextPolicyID("default", policies); !ok || id != "aaa" {
		t.Errorf("exact match: id=%q ok=%v, want aaa/true", id, ok)
	}
	if _, ok := matchPlatformContextPolicyID("nonexistent", policies); ok {
		t.Error("zero matches: ok=true, want false")
	}
	dup := []platformContextPolicy{{ID: "aaa", Name: "default"}, {ID: "bbb", Name: "default"}}
	if _, ok := matchPlatformContextPolicyID("default", dup); ok {
		t.Error("duplicate names: ok=true, want false (ambiguous)")
	}
	if _, ok := matchPlatformContextPolicyID("Default", policies); ok {
		t.Error("case-insensitive match: ok=true, want false (exact match only)")
	}
}
