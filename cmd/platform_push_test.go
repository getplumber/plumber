package cmd

import (
	"bytes"
	"encoding/json"

	"errors"
	"gopkg.in/yaml.v2"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
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

// The GitLab CI component wires PLUMBER_ANALYZE_PLATFORM to the sentinel
// (https://platform.invalid) on EVERY run — it cannot default to empty because
// an empty id_tokens audience is a template error. So a user who wants only the
// badge push runs with pushScore=true AND platformURL=platformSentinelURL. The
// sentinel is treated as "not configured", so it must NOT preempt the badge:
// effectiveScorePush() has to still return true. This is the real every-run
// GitLab-component configuration, and a regression that stopped special-casing
// the sentinel would silently disable the badge for every such user.
func TestEffectiveScorePush_SentinelDoesNotPreemptBadge(t *testing.T) {
	origP, origS := platformURL, pushScore
	defer func() { platformURL, pushScore = origP, origS }()

	platformURL, pushScore = platformSentinelURL, true
	if push, _ := effectiveScorePush(); !push {
		t.Errorf("badge push = false with pushScore=true and platformURL=%q (the sentinel), want true: the sentinel must not preempt the badge", platformSentinelURL)
	}
	// And the sentinel must not itself enable a platform push.
	if push, _ := effectivePlatformPush(); push {
		t.Errorf("platform push = true for the sentinel %q, want false", platformSentinelURL)
	}
}

// buildPublishPayload gates on scorePush alone: maybePushPlatform builds its
// own structured push directly from result/conf/score (see buildPlatformPush)
// and never reads this payload, so a --platform-only run must NOT pay the
// marshal cost, while a --score-push run must still get the exact bytes the
// badge always got. Also pins that those bytes ARE buildAnalysisJSONReport's
// output, the no-divergence promise in the doc comment.
func TestBuildPublishPayload_GateAndBytes(t *testing.T) {
	origP, origS := platformURL, pushScore
	defer func() { platformURL, pushScore = origP, origS }()

	prov := &providerPkg.GitLabProvider{}
	result := &control.AnalysisResult{CiValid: true}
	conf := configuration.NewDefaultConfiguration()
	conf.PlumberConfig = &configuration.PlumberConfig{}
	summary := complianceSummary{minPoints: 100, score: scoreWithPoints(100), scoreMode: true, controlCount: 1}

	t.Run("badge-only run gets the exact report bytes", func(t *testing.T) {
		platformURL, pushScore = "", true
		payload := buildPublishPayload(prov, conf, result, summary)
		if payload == nil {
			t.Fatal("payload = nil for a --score-push-only run: the badge push would silently never happen")
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

	t.Run("platform-only run does not pay the marshal cost", func(t *testing.T) {
		platformURL, pushScore = "https://app.example.com", false
		if payload := buildPublishPayload(prov, conf, result, summary); payload != nil {
			t.Errorf("payload = %d bytes for a --platform-only run, want nil: maybePushPlatform builds its own push and never reads this payload", len(payload))
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

// The platform parses schema_version and a plain-string results[].policy; a
// prior version of this file sent schemaVersion (silently reads as the zero
// value, 422s) and results[].policy as a {name,source,ref} object
// (json.Unmarshal into ingestion.PolicyResult.Policy, a string, fails
// outright). Decoding into platformPush would not catch either regression on
// its own — a reverted json tag or field type still decodes cleanly into its
// own (reverted) Go type — so this asserts the raw wire bytes instead, the
// only way these failure modes, being silent or type-safe-in-isolation, are
// actually caught.
func TestBuildPlatformPush_KeysAreSnakeCaseAndPolicyIsAString(t *testing.T) {
	body, err := buildPlatformPush(testProvider(t), nil, nil, nil, ".plumber.yaml")
	if err != nil {
		t.Fatalf("buildPlatformPush: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("push does not parse as JSON: %v", err)
	}
	if v, ok := raw["schema_version"]; !ok || v != float64(1) {
		t.Errorf("schema_version = %v (present=%v), want 1", v, ok)
	}
	if _, ok := raw["schemaVersion"]; ok {
		t.Error("schemaVersion is present on the wire: the platform reads schema_version only, and this silently 422s")
	}

	results, _ := raw["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("results = %v, want exactly 1 entry", raw["results"])
	}
	entry, _ := results[0].(map[string]any)
	policy, ok := entry["policy"]
	if !ok {
		t.Fatal("policy is missing on the entry")
	}
	if _, isString := policy.(string); !isString {
		t.Errorf("policy = %#v (type %T), want a plain string: the contract's PolicyResult.Policy is `json:\"policy\"` string, not an object", policy, policy)
	}
	if findingsVal, ok := entry["findings"]; !ok || findingsVal == nil {
		t.Errorf("findings = %v, want an empty array (not null/absent) when no PlumberConfig is available to enumerate controls", findingsVal)
	}
	if _, ok := entry["effective_config"]; !ok {
		t.Error("effective_config is missing: buildPlumberConfigBlock falls back to the embedded default even with a nil PlumberConfig")
	}
	for _, obj := range []string{"project", "ref", "pipeline", "cli", "collection"} {
		if _, ok := raw[obj]; !ok {
			t.Errorf("%s is missing on the push (the contract has no omitempty on struct-typed top-level fields)", obj)
		}
	}
}

// score.points is PlumberScoreResult.RawPointsUnclamped rounded to the
// nearest int (math.Round rounds half away from zero) — the contract's
// Score.Points is a signed int with no clamp (ADR-0020), unlike the
// gate/badge's floored-at-zero RawPoints.
func TestBuildPlatformPush_ScorePointsRoundToSignedInt(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  float64
		want int
	}{
		{"positive half rounds away from zero", 82.5, 83},
		{"negative unclamped deficit survives, rounded", -99.5, -100},
		{"whole number is untouched", -42, -42},
	} {
		t.Run(tc.name, func(t *testing.T) {
			score := &control.PlumberScoreResult{Score: "E", RawPointsUnclamped: tc.raw}
			body, err := buildPlatformPush(testProvider(t), nil, &control.AnalysisResult{}, score, ".plumber.yaml")
			if err != nil {
				t.Fatalf("buildPlatformPush: %v", err)
			}
			var push platformPush
			if err := json.Unmarshal(body, &push); err != nil {
				t.Fatal(err)
			}
			got := push.Results[0].Score
			if got.Letter != "E" || got.Points != tc.want {
				t.Errorf("score = %+v, want letter=E points=%d", got, tc.want)
			}
		})
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

// maybePushPlatform must name the policy from the config that was ACTUALLY
// loaded — conf.ConfigFilePath, resolved once at load time — not the raw
// --config flag value: the flag defaults to ".plumber.yaml" whether or not
// that file exists, so using it directly would misname a zero-config run
// that actually read the embedded default.
func TestMaybePushPlatform_PolicyNameUsesResolvedConfigPathFromConf(t *testing.T) {
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
	if err := maybePushPlatform(testProvider(t), conf, &control.AnalysisResult{}, nil); err != nil {
		t.Fatalf("maybePushPlatform: %v", err)
	}
	var push platformPush
	if err := json.Unmarshal(gotBody, &push); err != nil {
		t.Fatal(err)
	}
	if got := push.Results[0].Policy; got != "default" {
		t.Errorf("policy = %q, want %q (the embedded default), even though --config defaults to %q", got, "default", configFile)
	}
}

// When conf carries no resolved path (nil conf, or an empty ConfigFilePath),
// the --config flag is still consulted as a fallback so the policy name is
// never simply "default" for a run that DID read a real file.
func TestMaybePushPlatform_PolicyNameFallsBackToConfigFlagWhenConfHasNoPath(t *testing.T) {
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

	if err := maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, nil); err != nil {
		t.Fatalf("maybePushPlatform: %v", err)
	}
	var push platformPush
	if err := json.Unmarshal(gotBody, &push); err != nil {
		t.Fatal(err)
	}
	if got := push.Results[0].Policy; got != "strict" {
		t.Errorf("policy = %q, want %q from the --config flag fallback", got, "strict")
	}
}

// The happy path: the push is a POST to {platform}/api/v1/pushes carrying the
// bearer token and the full contract shape — schema_version, a string
// policy, findings, effective_config and score all present on the one
// entry. Uses a real default PlumberConfig so findings enumerates the real
// control catalog instead of coming back trivially empty.
func TestMaybePushPlatform_PostsThePush(t *testing.T) {
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

	conf := &configuration.Configuration{ConfigFilePath: ".plumber.yaml", PlumberConfig: testDefaultPlumberConfig(t)}
	result := &control.AnalysisResult{
		CiValid:  true,
		Findings: []opaengine.Finding{{Code: "ISSUE-101", Severity: "high", Message: "untrusted registry"}},
	}
	score := &control.PlumberScoreResult{Score: "B", RawPointsUnclamped: 82.5}
	err := maybePushPlatform(testProvider(t), conf, result, score)
	if err != nil {
		t.Fatalf("maybePushPlatform returned %v, want nil on a 202", err)
	}
	if gotPath != "/api/v1/pushes" {
		t.Errorf("path = %q, want /api/v1/pushes", gotPath)
	}
	if gotAuth != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want the bearer id-token", gotAuth)
	}
	if gotType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotType)
	}
	var push platformPush
	if err := json.Unmarshal(gotBody, &push); err != nil {
		t.Fatalf("body does not decode as a platformPush: %v", err)
	}
	if push.SchemaVersion != 1 {
		t.Errorf("schema_version = %d, want 1", push.SchemaVersion)
	}
	if len(push.Results) != 1 {
		t.Fatalf("results = %d, want exactly 1: %s", len(push.Results), gotBody)
	}
	entry := push.Results[0]
	if entry.Policy != "default" {
		t.Errorf("policy = %q, want %q (a plain string, not an object)", entry.Policy, "default")
	}
	if len(entry.Findings) == 0 {
		t.Error("findings = 0, want at least the enumerated controls for this run")
	}
	if len(entry.EffectiveConfig) == 0 {
		t.Error("effective_config = empty, want the (possibly default) policy block")
	}
	if entry.Score.Letter != "B" || entry.Score.Points != 83 {
		t.Errorf("score = %+v, want letter=B points=83 (82.5 rounded)", entry.Score)
	}
}

// The explicit-results model: one findings entry per applicable control.
// A failing control contributes one entry per underlying finding (with
// Data); a passing control contributes one bare {control,status:"pass"}
// entry; a control that could not really be evaluated contributes one bare
// {control,status:"not_evaluable"} entry — reusing control.StatusFor, the
// same verdict the --output JSON/CSV/OCSF renderers already compute, not a
// second notion of "did this control pass" invented here.
func TestMaybePushPlatform_FindingsCoverPassFailAndNotEvaluable(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	conf := &configuration.Configuration{ConfigFilePath: ".plumber.yaml", PlumberConfig: testDefaultPlumberConfig(t)}
	result := &control.AnalysisResult{
		CiValid: true, // most controls read "passed" with zero findings
		Findings: []opaengine.Finding{
			{Code: "ISSUE-101", Severity: "high", Message: "untrusted registry", Job: "build", File: ".gitlab-ci.yml", Line: 4},
		},
		// ProtectionData stays nil on purpose: branchMustBeProtected never
		// truly evaluated on this fixture (control/status.go StatusFor),
		// giving a real not_evaluable case alongside the pass/fail ones.
	}
	if err := maybePushPlatform(testProvider(t), conf, result, &control.PlumberScoreResult{Score: "C"}); err != nil {
		t.Fatalf("maybePushPlatform: %v", err)
	}

	var push platformPush
	if err := json.Unmarshal(gotBody, &push); err != nil {
		t.Fatalf("body does not decode as a platformPush: %v", err)
	}
	byControl := map[string]platformFinding{}
	for _, f := range push.Results[0].Findings {
		byControl[f.Control] = f
	}

	fail, ok := byControl["containerImageMustComeFromAuthorizedSources"]
	if !ok || fail.Status != platformStatusFail {
		t.Fatalf("containerImageMustComeFromAuthorizedSources = %+v (present=%v), want status=fail", fail, ok)
	}
	var data map[string]any
	if err := json.Unmarshal(fail.Data, &data); err != nil {
		t.Fatalf("fail finding data does not parse: %v", err)
	}
	if data["code"] != "ISSUE-101" || data["message"] != "untrusted registry" {
		t.Errorf("fail finding data = %v, want the flat Finding.MarshalJSON shape", data)
	}

	notEval, ok := byControl["branchMustBeProtected"]
	if !ok || notEval.Status != platformStatusNotEvaluable || len(notEval.Data) != 0 {
		t.Errorf("branchMustBeProtected = %+v (present=%v), want status=not_evaluable with no data", notEval, ok)
	}

	pass, ok := byControl["pipelineMustNotEnableDebugTrace"]
	if !ok || pass.Status != platformStatusPass || len(pass.Data) != 0 {
		t.Errorf("pipelineMustNotEnableDebugTrace = %+v (present=%v), want status=pass with no data", pass, ok)
	}
}

// A control excluded via --skip-controls (the same e.Skipped flag a control
// disabled in .plumber.yaml sets) is OMITTED from findings entirely: it is
// still visible in effective_config, but "not evaluated by choice" is a
// different fact than "could not be evaluated" (not_evaluable), and folding
// them together would hide operator intent from the platform.
func TestMaybePushPlatform_SkippedControlIsOmittedFromFindings(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	conf := &configuration.Configuration{
		ConfigFilePath:     ".plumber.yaml",
		PlumberConfig:      testDefaultPlumberConfig(t),
		SkipControlsFilter: []string{"pipelineMustNotEnableDebugTrace"},
	}
	result := &control.AnalysisResult{CiValid: true}
	if err := maybePushPlatform(testProvider(t), conf, result, nil); err != nil {
		t.Fatalf("maybePushPlatform: %v", err)
	}
	var push platformPush
	if err := json.Unmarshal(gotBody, &push); err != nil {
		t.Fatal(err)
	}
	for _, f := range push.Results[0].Findings {
		if f.Control == "pipelineMustNotEnableDebugTrace" {
			t.Errorf("a --skip-controls control appeared in findings: %+v, want it omitted entirely", f)
		}
	}
	if len(push.Results[0].EffectiveConfig) == 0 {
		t.Error("effective_config = empty, want the loaded policy block regardless of --skip-controls (a run-time filter, not a policy edit)")
	}
}

// score.points is RawPointsUnclamped rounded to a signed int: a badly
// failing project's true deficit goes negative even though the gate/badge's
// RawPoints floors at zero (see platformScore's doc comment). The score is
// threaded through from complianceSummary.score rather than recomputed
// inside maybePushPlatform, so constructing the score directly is the
// correct way to fixture a negative case: no need to synthesize enough
// critical findings to drive ComputePlumberScore below zero.
func TestMaybePushPlatform_NegativeScorePointsReachTheWire(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	// Measured on a 14-finding fixture in the design doc: real losses totaled
	// 199.5, so the true value was -99.5 where the clamped RawPoints read 0.
	// math.Round rounds half away from zero, so -99.5 -> -100.
	score := &control.PlumberScoreResult{Score: "E", RawPointsUnclamped: -99.5}
	if err := maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, score); err != nil {
		t.Fatalf("maybePushPlatform: %v", err)
	}
	var push platformPush
	if err := json.Unmarshal(gotBody, &push); err != nil {
		t.Fatal(err)
	}
	got := push.Results[0].Score
	if got.Letter != "E" || got.Points != -100 {
		t.Errorf("score = %+v, want letter=E points=-100 (signed, not floored at zero)", got)
	}
}

// No production caller passes a nil score (scoreMode is always on in
// buildComplianceSummary), but a best-effort push crashing the run over a nil
// pointer would be strictly worse than sending the zero value.
func TestMaybePushPlatform_NilScoreDoesNotPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	if err := maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, nil); err != nil {
		t.Fatalf("maybePushPlatform: %v", err)
	}
}

// effective_config is conf.PlumberConfig run through buildPlumberConfigBlock
// — the SAME builder the JSON report's plumberConfig block uses — reached via
// conf rather than a separate parameter, so the config actually loaded for
// this run (not just some default fallback) is what reaches the platform.
func TestMaybePushPlatform_EffectiveConfigReflectsTheLoadedConfig(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	loaded := "version: \"2.0\"\ngitlab:\n  controls:\n    branchMustBeProtected:\n      enabled: true\n      minMergeAccessLevel: 40\n"
	conf := &configuration.Configuration{
		ConfigFilePath: ".plumber.yaml",
		PlumberConfig:  &configuration.PlumberConfig{Source: ".plumber.yaml", Raw: loaded},
	}
	if err := maybePushPlatform(testProvider(t), conf, &control.AnalysisResult{}, nil); err != nil {
		t.Fatalf("maybePushPlatform: %v", err)
	}
	var push platformPush
	if err := json.Unmarshal(gotBody, &push); err != nil {
		t.Fatal(err)
	}
	raw := push.Results[0].EffectiveConfig
	if len(raw) == 0 {
		t.Fatal("effective_config = empty, want the loaded config's flat controls map")
	}
	// The J12-F5 flat shape: control names at top level, values from the
	// LOADED config (minMergeAccessLevel 40 does not exist in the embedded
	// default fallback, so its presence proves the loaded Raw was read).
	var got map[string]map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("effective_config does not parse as the flat controls map: %v", err)
	}
	bp := got["branchMustBeProtected"]
	if bp == nil || bp["minMergeAccessLevel"] != float64(40) {
		t.Errorf("effective_config[branchMustBeProtected] = %v, want the loaded config's values", got)
	}
}

// Every remote condition warns and leaves the exit code alone: the platform
// being unhappy must never gate somebody's pipeline. Both halves matter —
// asserting only err == nil would stay green if a refactor dropped the
// warning call and turned the skipped push silent, the exact failure mode
// this feature exists to prevent. Since the gate block landed, the warning
// is one of the two class-distinguished sentences (see
// cmd/platform_gate_test.go for the full class matrix) rather than the
// single generic "platform push failed" line this test used to check.
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

			var err error
			out := captureStderr(t, func() {
				err = maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, nil)
			})
			if err != nil {
				t.Errorf("status %d returned %v, want nil: a remote condition must not fail the run", status, err)
			}
			if !strings.Contains(out, "gate unavailable, letting through") && !strings.Contains(out, "gate NOT RUN: authentication/configuration failed") {
				t.Errorf("status %d: stderr = %q, want one of the two class-distinguished fail-open sentences", status, out)
			}
			if !strings.Contains(out, http.StatusText(status)) {
				t.Errorf("status %d: stderr = %q, want the server's status in the warning so the operator can diagnose it", status, out)
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

	var err error
	out := captureStderr(t, func() {
		err = maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, nil)
	})
	if err != nil {
		t.Errorf("unreachable platform returned %v, want nil", err)
	}
	if !strings.Contains(out, "gate unavailable, letting through") {
		t.Errorf("stderr = %q, want the transport-failure class sentence", out)
	}
}

// The one failing case: no id-token. It is a pipeline defect the user must fix
// and would otherwise never notice.
func TestMaybePushPlatform_MissingTokenFailsWithActionableMessage(t *testing.T) {
	restore := withPlatformTestEnv(t, "https://app.example.com", "")
	defer restore()

	err := maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, nil)
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

	err := maybePushPlatform(p, nil, &control.AnalysisResult{}, nil)
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

	err := maybePushPlatform(p, nil, &control.AnalysisResult{}, nil)
	if err == nil {
		t.Fatal("a failed token mint returned nil, want a *PlatformTokenError: the run must not proceed as if the push were merely skipped")
	}
	var tokenErr *PlatformTokenError
	if !errors.As(err, &tokenErr) {
		t.Fatalf("error %v is not a *PlatformTokenError", err)
	}
}

// collection.degraded is the only degradation signal on the wire now (the
// contract has no per-result degraded/degraded_reasons — see
// platformCollectionMeta's doc comment for why DegradedReasons prose is not
// forced into missing_fields). Without it the platform would render a
// partial scan as complete.
func TestMaybePushPlatform_SendsCollectionDegradedMarker(t *testing.T) {
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
	if err := maybePushPlatform(testProvider(t), nil, result, nil); err != nil {
		t.Fatalf("maybePushPlatform: %v", err)
	}
	var push platformPush
	if err := json.Unmarshal(gotBody, &push); err != nil {
		t.Fatal(err)
	}
	if !push.Collection.Degraded {
		t.Errorf("collection.degraded = false, want true: %s", gotBody)
	}
	if len(push.Collection.MissingFields) != 0 {
		t.Errorf("collection.missing_fields = %v, want omitted/empty: DegradedReasons is prose, not a field-name list", push.Collection.MissingFields)
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

// testDefaultPlumberConfig loads the shipped default config the same way
// production does (defaultconfig.Get()), giving tests a real, fully
// populated *configuration.PlumberConfig so p.Controls(pc) enumerates the
// real catalog instead of coming back empty.
func testDefaultPlumberConfig(t *testing.T) *configuration.PlumberConfig {
	t.Helper()
	pc, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "test-default")
	if err != nil {
		t.Fatalf("LoadPlumberConfigFromBytes: %v", err)
	}
	return pc
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
		err = maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, nil)
	})

	if err == nil {
		t.Fatal("no error returned for a missing id-token")
	}
	if !strings.Contains(out, "id_tokens") && !strings.Contains(out, "id-token") {
		t.Errorf("stderr = %q, want the actionable diagnosis printed at the point of failure; "+
			"without it a run that also fails its gate reports nothing at all", out)
	}
}

// The "a token failure fails the run" guarantee is not maybePushPlatform's
// alone: it holds only because the callers capture platformErr and thread it
// into finalizeRun. The unit tests above pin each half in isolation; this one
// drives presentResultWithProvider — a real production caller — end to end, so
// a refactor that passes finalizeRun a nil (or drops the assignment) fails
// here instead of shipping a run that warns but exits 0. runWithProvider
// shares the identical wiring but starts with p.Run (a live analysis), so the
// caller that is exercisable hermetically stands in for both.
func TestPresentResultWithProvider_ThreadsPlatformErrIntoTheExitCode(t *testing.T) {
	origPrint := printOutput
	printOutput = false // the terminal report is not under test
	defer func() { printOutput = origPrint }()
	newGateFlagsCmd(t) // reset gate globals: default points gate (min-points 100)

	// A clean result with one enabled control scores 100 and passes the gate,
	// so the ONLY thing deciding the returned error is the platform push.
	conf := confWithDebugTrace()

	t.Run("missing id-token fails the run", func(t *testing.T) {
		restore := withPlatformTestEnv(t, "https://app.example.com", "")
		defer restore()

		var err error
		_ = captureStderr(t, func() {
			err = presentResultWithProvider(testProvider(t), nil, &control.AnalysisResult{CiValid: true}, conf)
		})

		var tokenErr *PlatformTokenError
		if !errors.As(err, &tokenErr) {
			t.Fatalf("err = %v, want a *PlatformTokenError: the caller must thread maybePushPlatform's error into finalizeRun, or a missing grant warns but stops failing the run", err)
		}
	})

	t.Run("healthy push passes and actually POSTs", func(t *testing.T) {
		pushed := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { pushed = true }))
		defer srv.Close()
		restore := withPlatformTestEnv(t, srv.URL, "tok-123")
		defer restore()

		var err error
		_ = captureStderr(t, func() {
			err = presentResultWithProvider(testProvider(t), nil, &control.AnalysisResult{CiValid: true}, conf)
		})

		if err != nil {
			t.Fatalf("err = %v, want nil: a passing gate with a healthy push must not fail the run", err)
		}
		if !pushed {
			t.Fatal("the platform endpoint was never POSTed: the payload/push wiring is broken in the production caller path")
		}
	})
}

// The CI-identity fields (ref, pipeline, project.id) are read from CI env vars
// and must reach the wire with the RIGHT value: the presence-only assertions in
// TestBuildPlatformPush_* would still pass if the mapping were swapped (e.g.
// GITHUB_JOB read into pipeline.id). These two tests pin each env var to a
// distinct sentinel and assert it lands in the correct field, per provider —
// so a dropped or crossed mapping fails loudly instead of shipping silent.
func TestBuildPlatformPush_GitLabCIIdentityValuesReachTheWire(t *testing.T) {
	p, ok := providerPkg.Get("gitlab")
	if !ok {
		t.Skip("gitlab provider not registered")
	}
	t.Setenv("CI_COMMIT_SHA", "sha-gl-111")
	t.Setenv("CI_COMMIT_BRANCH", "branch-gl-222")
	t.Setenv("CI_PIPELINE_ID", "pipe-gl-333")
	t.Setenv("CI_JOB_ID", "job-gl-444")
	t.Setenv("CI_PROJECT_ID", "proj-gl-555")

	body, err := buildPlatformPush(p, nil, &control.AnalysisResult{}, nil, ".plumber.yaml")
	if err != nil {
		t.Fatalf("buildPlatformPush: %v", err)
	}
	var got struct {
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
		Ref struct {
			Branch string `json:"branch"`
			SHA    string `json:"sha"`
		} `json:"ref"`
		Pipeline struct {
			ID    string `json:"id"`
			JobID string `json:"job_id"`
		} `json:"pipeline"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal push: %v", err)
	}
	for _, c := range []struct{ field, want, have string }{
		{"ref.sha", "sha-gl-111", got.Ref.SHA},
		{"ref.branch", "branch-gl-222", got.Ref.Branch},
		{"pipeline.id", "pipe-gl-333", got.Pipeline.ID},
		{"pipeline.job_id", "job-gl-444", got.Pipeline.JobID},
		{"project.id", "proj-gl-555", got.Project.ID},
	} {
		if c.have != c.want {
			t.Errorf("%s = %q, want %q (env-var mapping dropped or crossed)", c.field, c.have, c.want)
		}
	}
}

func TestBuildPlatformPush_GitHubCIIdentityValuesReachTheWire(t *testing.T) {
	p, ok := providerPkg.Get("github")
	if !ok {
		t.Skip("github provider not registered")
	}
	t.Setenv("GITHUB_SHA", "sha-gh-111")
	t.Setenv("GITHUB_REF_TYPE", "branch")
	t.Setenv("GITHUB_REF_NAME", "branch-gh-222")
	t.Setenv("GITHUB_RUN_ID", "run-gh-333")
	t.Setenv("GITHUB_JOB", "job-gh-444")

	body, err := buildPlatformPush(p, nil, &control.AnalysisResult{}, nil, ".plumber.yaml")
	if err != nil {
		t.Fatalf("buildPlatformPush: %v", err)
	}
	var got struct {
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
		Ref struct {
			Branch string `json:"branch"`
			SHA    string `json:"sha"`
		} `json:"ref"`
		Pipeline struct {
			ID    string `json:"id"`
			JobID string `json:"job_id"`
		} `json:"pipeline"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal push: %v", err)
	}
	if got.Ref.SHA != "sha-gh-111" {
		t.Errorf("ref.sha = %q, want %q", got.Ref.SHA, "sha-gh-111")
	}
	if got.Ref.Branch != "branch-gh-222" {
		t.Errorf("ref.branch = %q, want %q", got.Ref.Branch, "branch-gh-222")
	}
	if got.Pipeline.ID != "run-gh-333" {
		t.Errorf("pipeline.id = %q, want GITHUB_RUN_ID %q (not GITHUB_JOB)", got.Pipeline.ID, "run-gh-333")
	}
	if got.Pipeline.JobID != "job-gh-444" {
		t.Errorf("pipeline.job_id = %q, want GITHUB_JOB %q", got.Pipeline.JobID, "job-gh-444")
	}
	// GitHub has no cheap numeric project id at this call site: it must stay empty.
	if got.Project.ID != "" {
		t.Errorf("project.id = %q, want empty for GitHub", got.Project.ID)
	}
}

// TestPlatformEffectiveConfigIsTheFlatControlsMap pins the J12-F5 ruling
// (2026-08-31): a push's effective_config is the FLAT per-provider controls
// map, keys are control names, exactly what the platform's
// issueident.ParamsFor unmarshals into configuration.ControlsConfig. The
// previous nested report shape ({"effectivePolicy": {"gitlab": ...}})
// decoded to a zero ControlsConfig on the platform, so every issue stored
// empty params and See & fix could never run.
func TestPlatformEffectiveConfigIsTheFlatControlsMap(t *testing.T) {
	raw := `version: "2.0"
gitlab:
  controls:
    mergeRequestApprovalRulesMustRequireMinimumApprovals:
      enabled: true
      minimumRequiredApprovals: 3
    branchMustBeProtected:
      enabled: true
`
	var pc configuration.PlumberConfig
	if err := yaml.Unmarshal([]byte(raw), &pc); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	pc.Raw = raw

	out := platformEffectiveConfigRaw(&pc, "gitlab")
	if len(out) == 0 {
		t.Fatal("expected a non-empty effective_config")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(out, &top); err != nil {
		t.Fatalf("effective_config is not a JSON object: %v", err)
	}
	for _, forbidden := range []string{"effectivePolicy", "gitlab", "github", "version", "controls"} {
		if _, ok := top[forbidden]; ok {
			t.Errorf("effective_config must be the flat controls map; found nesting key %q", forbidden)
		}
	}
	if _, ok := top["mergeRequestApprovalRulesMustRequireMinimumApprovals"]; !ok {
		t.Fatalf("control name missing at top level; keys: %v", keysOf(top))
	}

	// The platform-reader contract, verified against the EXACT shared type
	// the platform unmarshals into (it imports this module's
	// configuration.ControlsConfig).
	var controls configuration.ControlsConfig
	if err := json.Unmarshal(out, &controls); err != nil {
		t.Fatalf("the platform's reader could not decode this effective_config: %v", err)
	}
	cfg := controls.MergeRequestApprovalRulesMustRequireMinimumApprovals
	if cfg == nil || cfg.MinimumRequiredApprovals == nil || *cfg.MinimumRequiredApprovals != 3 {
		t.Fatalf("the platform reader would extract empty params from this shape: %+v", cfg)
	}
	if controls.BranchMustBeProtected == nil || !controls.BranchMustBeProtected.IsEnabled() {
		t.Fatalf("branchMustBeProtected did not survive the platform-reader decode")
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
