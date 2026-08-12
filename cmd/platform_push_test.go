package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	providerPkg "github.com/getplumber/plumber/provider"
)

// --platform implies the push; there is no separate switch.
func TestEffectivePlatformPush_SetImpliesPush(t *testing.T) {
	orig := platformURL
	defer func() { platformURL = orig }()

	platformURL = "  https://app.example.com/  "
	push, endpoint := effectivePlatformPush()
	if !push {
		t.Error("push = false, want true: setting --platform implies pushing")
	}
	if endpoint != "https://app.example.com" {
		t.Errorf("endpoint = %q, want the trimmed URL without a trailing slash", endpoint)
	}
}

func TestEffectivePlatformPush_UnsetDoesNotPush(t *testing.T) {
	orig := platformURL
	defer func() { platformURL = orig }()

	platformURL = ""
	if push, _ := effectivePlatformPush(); push {
		t.Error("push = true with no --platform, want false")
	}
}

// The GitLab component defaults its `platform` input to platformSentinelURL
// because id_tokens requires a non-empty audience. That default reaches the
// CLI as PLUMBER_ANALYZE_PLATFORM on every run, so seeing it alone must not
// enable a push — only an operator-supplied, non-sentinel URL does.
func TestEffectivePlatformPush_SentinelDoesNotPush(t *testing.T) {
	orig := platformURL
	defer func() { platformURL = orig }()

	for _, v := range []string{
		platformSentinelURL,
		platformSentinelURL + "/",
		"  " + platformSentinelURL + "  ",
	} {
		platformURL = v
		if push, endpoint := effectivePlatformPush(); push || endpoint != "" {
			t.Errorf("platformURL = %q: push = %v, endpoint = %q, want false, \"\" for the template's sentinel default", v, push, endpoint)
		}
	}

	platformURL = "https://platform.example.com"
	if push, endpoint := effectivePlatformPush(); !push || endpoint != "https://platform.example.com" {
		t.Errorf("an ordinary URL: push = %v, endpoint = %q, want true, %q", push, endpoint, "https://platform.example.com")
	}
}

// The badge push yields, so a run never publishes to both. Silence would make a
// dropped push a mystery, which is the failure mode this feature exists to fix.
func TestEffectiveScorePush_YieldsToPlatform(t *testing.T) {
	origP, origS := platformURL, pushScore
	defer func() { platformURL, pushScore = origP, origS }()

	platformURL, pushScore = "https://app.example.com", true
	if push, _ := effectiveScorePush(); push {
		t.Error("badge push = true while --platform is set, want false")
	}

	platformURL = ""
	if push, _ := effectiveScorePush(); !push {
		t.Error("badge push = false with --platform unset, want true")
	}
}

// buildPublishPayload is the single gate deciding whether a payload exists for
// BOTH publish paths — every maybePushPlatform/handleScorePublishing test
// injects a payload directly, so only this test would catch a narrowed gate
// (e.g. dropping the platformPush term): a --platform-only run would then get
// nil and maybePushPlatform would silently do nothing, with the suite green.
// Also pins that the bytes ARE buildAnalysisJSONReport's output, the
// no-divergence promise in the doc comment.
func TestBuildPublishPayload_GateAndBytes(t *testing.T) {
	origP, origS := platformURL, pushScore
	defer func() { platformURL, pushScore = origP, origS }()

	prov := &providerPkg.GitLabProvider{}
	result := &control.AnalysisResult{CiValid: true}
	conf := configuration.NewDefaultConfiguration()
	conf.PlumberConfig = &configuration.PlumberConfig{}
	summary := complianceSummary{minPoints: 100, score: scoreWithPoints(100), scoreMode: true, controlCount: 1}

	t.Run("platform-only run gets the exact report bytes", func(t *testing.T) {
		platformURL, pushScore = "https://app.example.com", false
		payload := buildPublishPayload(prov, conf, result, summary)
		if payload == nil {
			t.Fatal("payload = nil for a --platform-only run: the platform push would silently never happen")
		}
		want, err := buildAnalysisJSONReport(result, conf.PlumberConfig, summary, jsonOutputParams{
			provider: prov.Name(), includeOnly: conf.ControlsFilter, skip: conf.SkipControlsFilter,
		})
		if err != nil {
			t.Fatalf("buildAnalysisJSONReport: %v", err)
		}
		if !bytes.Equal(payload, want) {
			t.Errorf("payload diverges from buildAnalysisJSONReport:\ngot:  %s\nwant: %s", payload, want)
		}
	})

	t.Run("badge-only run gets a payload", func(t *testing.T) {
		platformURL, pushScore = "", true
		if buildPublishPayload(prov, conf, result, summary) == nil {
			t.Fatal("payload = nil for a --score-push-only run: the badge push would silently never happen")
		}
	})

	t.Run("neither push configured skips the marshal", func(t *testing.T) {
		platformURL, pushScore = "", false
		if payload := buildPublishPayload(prov, conf, result, summary); payload != nil {
			t.Errorf("payload = %d bytes with no push configured, want nil (a plain run must not pay the marshal cost)", len(payload))
		}
	})

	t.Run("the component's sentinel default does not opt in", func(t *testing.T) {
		platformURL, pushScore = platformSentinelURL, false
		if payload := buildPublishPayload(prov, conf, result, summary); payload != nil {
			t.Errorf("payload = %d bytes for the sentinel platform URL, want nil: the GitLab component sets it on every run", len(payload))
		}
	})
}

// The report is embedded with the same DATA the file on disk gets: one
// builder (buildAnalysisJSONReport) feeds both, so the two cannot drift.
// json.Marshal on the envelope re-serializes report compactly (it is nested
// inside a larger document) and would HTML-escape '<', '>', '&' — that is
// accepted and intentional (see buildPlatformEnvelope's doc comment), so this
// deliberately asserts semantic equality, not byte equality. The fixture is
// indented, multi-line, and carries a unicode character so a naive compact-ASCII
// fixture couldn't have masked a real mutation.
func TestBuildPlatformEnvelope_EmbedsTheReportUnchanged(t *testing.T) {
	report := []byte(`{
  "projectPath": "org/repo",
  "plumberScore": {
    "score": "B"
  },
  "note": "café — pipeline ok"
}`)

	body, err := buildPlatformEnvelope(report, ".plumber.yaml", false, nil)
	if err != nil {
		t.Fatalf("buildPlatformEnvelope: %v", err)
	}
	var env platformEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("envelope does not round-trip: %v", err)
	}
	if env.SchemaVersion != 1 {
		t.Errorf("schemaVersion = %d, want 1", env.SchemaVersion)
	}
	if len(env.Results) != 1 {
		t.Fatalf("results = %d, want exactly 1 while policy resolution is local", len(env.Results))
	}

	var want, got any
	if err := json.Unmarshal(report, &want); err != nil {
		t.Fatalf("fixture does not parse as JSON: %v", err)
	}
	if err := json.Unmarshal(env.Results[0].Report, &got); err != nil {
		t.Fatalf("embedded report does not parse as JSON: %v", err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("embedded report is not semantically equal to the input:\n got %#v\nwant %#v", got, want)
	}
}

// The descriptor is per entry, not envelope-level, so #368 grows the array
// without changing the shape.
func TestBuildPlatformEnvelope_CarriesThePolicyDescriptor(t *testing.T) {
	body, err := buildPlatformEnvelope([]byte(`{}`), "config/.plumber.strict.yaml", false, nil)
	if err != nil {
		t.Fatalf("buildPlatformEnvelope: %v", err)
	}
	var env platformEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	p := env.Results[0].Policy
	if p.Source != "local" {
		t.Errorf("policy.source = %q, want %q while the policy is a local file", p.Source, "local")
	}
	if p.Ref != "config/.plumber.strict.yaml" {
		t.Errorf("policy.ref = %q, want the config path as given", p.Ref)
	}
	if p.Name != "strict" {
		t.Errorf("policy.name = %q, want %q", p.Name, "strict")
	}
}

// The bug this guards: a zero-config run never reads a .plumber.yaml file —
// it loads the config embedded in the binary (loadEmbeddedDefaultConfig) —
// but the --config flag still carries its own default (".plumber.yaml"),
// which names no file that was actually read and may not even exist on
// disk. builtinDefaultConfigSource is what conf.ConfigFilePath holds in that
// case; the descriptor must not claim "local" for it. An empty configPath
// (no resolved path known at all) gets the same treatment: safer to say
// "not a local file" than to guess ".plumber.yaml".
func TestBuildPlatformEnvelope_EmbeddedDefaultDoesNotClaimALocalFile(t *testing.T) {
	for _, configPath := range []string{builtinDefaultConfigSource, "", "   "} {
		body, err := buildPlatformEnvelope([]byte(`{}`), configPath, false, nil)
		if err != nil {
			t.Fatalf("buildPlatformEnvelope(%q): %v", configPath, err)
		}
		var env platformEnvelope
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatal(err)
		}
		p := env.Results[0].Policy
		if p.Source != platformPolicySourceEmbedded {
			t.Errorf("configPath=%q: policy.source = %q, want %q", configPath, p.Source, platformPolicySourceEmbedded)
		}
		if p.Ref != "" {
			t.Errorf("configPath=%q: policy.ref = %q, want empty — no local file was read", configPath, p.Ref)
		}
		if p.Name != "default" {
			t.Errorf("configPath=%q: policy.name = %q, want %q", configPath, p.Name, "default")
		}
	}
}

// maybePushPlatform must describe the config that was ACTUALLY loaded —
// conf.ConfigFilePath, resolved once at load time (cmd/analyze_gitlab.go,
// cmd/analyze_github.go) — not the raw --config flag value: the flag
// defaults to ".plumber.yaml" whether or not that file exists, so using it
// directly (the pre-fix behavior) claimed a local file even on a zero-config
// run that read the embedded default instead.
func TestMaybePushPlatform_DescriptorUsesResolvedConfigPathFromConf(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	// The --config flag still carries its unrelated default; conf.ConfigFilePath
	// is what the run actually resolved, and must win.
	origConfigFile := configFile
	configFile = ".plumber.yaml"
	defer func() { configFile = origConfigFile }()

	conf := &configuration.Configuration{ConfigFilePath: builtinDefaultConfigSource}
	if err := maybePushPlatform(testProvider(t), conf, &control.AnalysisResult{}, []byte(`{}`)); err != nil {
		t.Fatalf("maybePushPlatform: %v", err)
	}
	var env platformEnvelope
	if err := json.Unmarshal(gotBody, &env); err != nil {
		t.Fatal(err)
	}
	p := env.Results[0].Policy
	if p.Source != platformPolicySourceEmbedded || p.Ref != "" {
		t.Errorf("policy = %+v, want the embedded-default descriptor (source=%q, ref=\"\") even though --config defaults to %q", p, platformPolicySourceEmbedded, configFile)
	}
}

// When conf carries no resolved path (nil conf, or an empty
// ConfigFilePath, as in tests that build the payload directly), the
// --config flag is still consulted as a fallback so the descriptor is never
// simply blank for a run that DID read a real file.
func TestMaybePushPlatform_FallsBackToConfigFlagWhenConfHasNoPath(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	origConfigFile := configFile
	configFile = "config/.plumber.strict.yaml"
	defer func() { configFile = origConfigFile }()

	if err := maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, []byte(`{}`)); err != nil {
		t.Fatalf("maybePushPlatform: %v", err)
	}
	var env platformEnvelope
	if err := json.Unmarshal(gotBody, &env); err != nil {
		t.Fatal(err)
	}
	p := env.Results[0].Policy
	if p.Source != platformPolicySourceLocal || p.Ref != "config/.plumber.strict.yaml" {
		t.Errorf("policy = %+v, want source=%q ref=%q from the --config flag fallback", p, platformPolicySourceLocal, "config/.plumber.strict.yaml")
	}
}

// The analysis document has no degradation signal at all, so without these the
// platform would render a partial scan as complete.
func TestBuildPlatformEnvelope_MarksADegradedRun(t *testing.T) {
	reasons := []string{"branch protection could not be fetched (network or timeout)"}
	body, err := buildPlatformEnvelope([]byte(`{}`), ".plumber.yaml", true, reasons)
	if err != nil {
		t.Fatalf("buildPlatformEnvelope: %v", err)
	}
	var env platformEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	if !env.Results[0].Degraded {
		t.Error("degraded = false, want true")
	}
	if len(env.Results[0].DegradedReasons) != 1 || env.Results[0].DegradedReasons[0] != reasons[0] {
		t.Errorf("degradedReasons = %v, want %v", env.Results[0].DegradedReasons, reasons)
	}
}

func TestPolicyNameFor(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{".plumber.yaml", "default"},
		{"/abs/path/.plumber.yaml", "default"},
		{".plumber.strict.yaml", "strict"},
		{"config/team.plumber.yml", "team"},
		{"", "default"},
	} {
		if got := policyNameFor(tc.path); got != tc.want {
			t.Errorf("policyNameFor(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// The happy path: the push is a POST to {platform}/api/v1/results carrying the
// bearer token and the envelope.
func TestMaybePushPlatform_PostsTheEnvelope(t *testing.T) {
	var gotPath, gotAuth, gotType string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotType = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	err := maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, []byte(`{"projectPath":"org/repo"}`))
	if err != nil {
		t.Fatalf("maybePushPlatform returned %v, want nil on a 202", err)
	}
	if gotPath != "/api/v1/results" {
		t.Errorf("path = %q, want /api/v1/results", gotPath)
	}
	if gotAuth != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want the bearer id-token", gotAuth)
	}
	if gotType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotType)
	}
	var env platformEnvelope
	if err := json.Unmarshal(gotBody, &env); err != nil {
		t.Fatalf("body is not an envelope: %v", err)
	}
	if len(env.Results) != 1 || len(env.Results[0].Report) == 0 {
		t.Errorf("body did not carry exactly one complete result: %s", gotBody)
	}
}

// Every remote condition warns and leaves the exit code alone: the platform
// being unhappy must never gate somebody's pipeline.
func TestMaybePushPlatform_RemoteFailuresOnlyWarn(t *testing.T) {
	for _, status := range []int{
		http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
		http.StatusNotFound, http.StatusRequestEntityTooLarge, http.StatusInternalServerError,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			defer srv.Close()
			restore := withPlatformTestEnv(t, srv.URL, "tok-123")
			defer restore()

			if err := maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, []byte(`{}`)); err != nil {
				t.Errorf("status %d returned %v, want nil: a remote condition must not fail the run", status, err)
			}
		})
	}
}

func TestMaybePushPlatform_UnreachableOnlyWarns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening now

	restore := withPlatformTestEnv(t, url, "tok-123")
	defer restore()

	if err := maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, []byte(`{}`)); err != nil {
		t.Errorf("unreachable platform returned %v, want nil", err)
	}
}

// The one failing case: no id-token. It is a pipeline defect the user must fix
// and would otherwise never notice.
func TestMaybePushPlatform_MissingTokenFailsWithActionableMessage(t *testing.T) {
	restore := withPlatformTestEnv(t, "https://app.example.com", "")
	defer restore()

	err := maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, []byte(`{}`))
	if err == nil {
		t.Fatal("missing id-token returned nil, want an error: a silently skipped push is the failure mode this prevents")
	}
	if !strings.Contains(err.Error(), "id-token") {
		t.Errorf("error %q does not name the missing grant", err)
	}
}

// The GitHub side of the one failing case: a workflow that never granted
// `permissions: id-token: write` has no ACTIONS_ID_TOKEN_REQUEST_URL /
// ACTIONS_ID_TOKEN_REQUEST_TOKEN at all, so scoreOIDCToken returns ("", nil)
// (not a token-granting context) rather than an error — maybePushPlatform
// must still fail the run and name the exact permission to add, mirroring the
// GitLab id_tokens: case above. Only the GitLab token branch was covered
// before this test; the GitHub branch is the same run-failing path and needs
// the same guarantee.
func TestMaybePushPlatform_GitHubMissingGrantFailsWithActionableMessage(t *testing.T) {
	p, ok := providerPkg.Get("github")
	if !ok {
		t.Skip("github provider not registered")
	}

	orig := platformURL
	defer func() { platformURL = orig }()
	platformURL = "https://app.example.com"

	// Absent, not merely empty: a workflow without `permissions: id-token:
	// write` never has these set in the runner environment at all.
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	err := maybePushPlatform(p, nil, &control.AnalysisResult{}, []byte(`{}`))
	if err == nil {
		t.Fatal("missing GitHub id-token grant returned nil, want an error: a silently skipped push is the failure mode this prevents")
	}
	var tokenErr *PlatformTokenError
	if !errors.As(err, &tokenErr) {
		t.Fatalf("error %v is not a *PlatformTokenError", err)
	}
	if !strings.Contains(err.Error(), "permissions: id-token: write") {
		t.Errorf("error %q does not name the missing grant (`permissions: id-token: write`)", err)
	}
}

// A 500 from the token-MINTING endpoint (the GitHub Actions runtime that
// issues the id-token, not the platform the report is pushed to) means the
// run never obtained a token to push with. That is still the one failing
// condition — a *PlatformTokenError, not a remote-push warning — and is
// distinct from the missing-grant case above, where the request is never
// attempted at all.
func TestMaybePushPlatform_GitHubTokenMintFailureReturnsPlatformTokenError(t *testing.T) {
	p, ok := providerPkg.Get("github")
	if !ok {
		t.Skip("github provider not registered")
	}

	mint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mint.Close()

	orig := platformURL
	defer func() { platformURL = orig }()
	platformURL = "https://app.example.com"

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", mint.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "req-token")

	err := maybePushPlatform(p, nil, &control.AnalysisResult{}, []byte(`{}`))
	if err == nil {
		t.Fatal("a failed token mint returned nil, want a *PlatformTokenError: the run must not proceed as if the push were merely skipped")
	}
	var tokenErr *PlatformTokenError
	if !errors.As(err, &tokenErr) {
		t.Fatalf("error %v is not a *PlatformTokenError", err)
	}
}

// The degraded markers must reach the wire, since that is what makes pushing a
// degraded run safe rather than misleading.
func TestMaybePushPlatform_SendsDegradedMarkers(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	result := &control.AnalysisResult{
		DataCollectionDegraded: true,
		DegradedReasons:        []string{"pipeline configuration could not be fetched (network or timeout)"},
	}
	if err := maybePushPlatform(testProvider(t), nil, result, []byte(`{}`)); err != nil {
		t.Fatalf("maybePushPlatform: %v", err)
	}
	var env platformEnvelope
	if err := json.Unmarshal(gotBody, &env); err != nil {
		t.Fatal(err)
	}
	if !env.Results[0].Degraded || len(env.Results[0].DegradedReasons) != 1 {
		t.Errorf("degraded markers did not reach the wire: %s", gotBody)
	}
}

// testProvider returns the GitLab provider, whose scoreOIDCToken path reads
// the id-token env var directly (no HTTP round trip to mint), which is what
// makes these tests exercisable with httptest alone.
func testProvider(t *testing.T) providerPkg.Provider {
	t.Helper()
	p, ok := providerPkg.Get("gitlab")
	if !ok {
		t.Skip("gitlab provider not registered")
	}
	return p
}

// withPlatformTestEnv points the CLI at a stand-in platform and supplies (or
// withholds) the GitLab-style id-token, which is the path that needs no HTTP
// round trip to mint. Returns a restore func.
func withPlatformTestEnv(t *testing.T, url, token string) func() {
	t.Helper()
	origURL, origTok := platformURL, os.Getenv(gitlabPlatformTokenEnv)
	platformURL = url
	if token == "" {
		_ = os.Unsetenv(gitlabPlatformTokenEnv)
	} else {
		t.Setenv(gitlabPlatformTokenEnv, token)
	}
	return func() {
		platformURL = origURL
		if origTok != "" {
			_ = os.Setenv(gitlabPlatformTokenEnv, origTok)
		}
	}
}

// A token failure must announce itself on stderr, not only through the
// returned error. finalizeRun evaluates the platform error LAST so it cannot
// mask a security finding, which means a run that also fails its gate discards
// it. Found in real use: a GitLab scan scoring C pushed nothing and said
// nothing, because the gate error won and the token error vanished with it.
func TestMaybePushPlatform_TokenFailureIsAnnouncedNotOnlyReturned(t *testing.T) {
	restore := withPlatformTestEnv(t, "https://app.example.com", "")
	defer restore()

	var err error
	out := captureStderr(t, func() {
		err = maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, []byte(`{}`))
	})

	if err == nil {
		t.Fatal("no error returned for a missing id-token")
	}
	if !strings.Contains(out, "id_tokens") && !strings.Contains(out, "id-token") {
		t.Errorf("stderr = %q, want the actionable diagnosis printed at the point of failure; "+
			"without it a run that also fails its gate reports nothing at all", out)
	}
}
