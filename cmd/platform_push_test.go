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
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
	"github.com/getplumber/plumber/finding/identity"
	"github.com/getplumber/plumber/gitlab"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/internal/platform"
	"github.com/getplumber/plumber/pbom"
	providerPkg "github.com/getplumber/plumber/provider"
	"github.com/getplumber/plumber/utils"
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
		}, nil, nil)
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
	body, err := buildPlatformPush(testProvider(t), nil, nil, nil, ".plumber.yaml", nil)
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
			body, err := buildPlatformPush(testProvider(t), nil, &control.AnalysisResult{}, score, ".plumber.yaml", nil)
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

// End to end: score.final_points must survive the full build -> marshal ->
// unmarshal round trip, and a zero final_points (the Critical malus floor)
// must be present on the wire as "final_points": 0, not omitted, since a
// present-but-zero and a genuinely-absent field mean different things to a
// platform doing a recompute cross-check.
func TestBuildPlatformPush_ScoreFinalPointsOnWire(t *testing.T) {
	for _, tc := range []struct {
		name  string
		score *control.PlumberScoreResult
		want  int
	}{
		{"nonzero final_points", &control.PlumberScoreResult{Score: "C", RawPointsUnclamped: 55, FinalPoints: 55}, 55},
		{"zero final_points (malus floor)", &control.PlumberScoreResult{Score: "E", RawPointsUnclamped: -5, FinalPoints: 0}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := buildPlatformPush(testProvider(t), nil, &control.AnalysisResult{}, tc.score, ".plumber.yaml", nil)
			if err != nil {
				t.Fatalf("buildPlatformPush: %v", err)
			}

			var raw map[string]json.RawMessage
			if err := json.Unmarshal(body, &raw); err != nil {
				t.Fatal(err)
			}
			var rawResults []map[string]json.RawMessage
			if err := json.Unmarshal(raw["results"], &rawResults); err != nil {
				t.Fatal(err)
			}
			var rawScore map[string]json.RawMessage
			if err := json.Unmarshal(rawResults[0]["score"], &rawScore); err != nil {
				t.Fatal(err)
			}
			finalRaw, present := rawScore["final_points"]
			if !present {
				t.Fatalf("final_points key is absent from the wire body, want it present (even when the value is 0): %s", rawResults[0]["score"])
			}
			if string(finalRaw) != strconv.Itoa(tc.want) {
				t.Errorf("wire final_points = %s, want %d", finalRaw, tc.want)
			}

			var push platformPush
			if err := json.Unmarshal(body, &push); err != nil {
				t.Fatal(err)
			}
			got := push.Results[0].Score.FinalPoints
			if got == nil || *got != tc.want {
				t.Errorf("push.Results[0].Score.FinalPoints = %v, want %d", got, tc.want)
			}
		})
	}
}

// Row 40 (platform): the push carries final_points beside the existing signed
// points, so the platform can cross-check its own recompute against the
// CLI's exact formula (malus included).
func TestPlatformScoreFrom_CarriesFinalPoints(t *testing.T) {
	s := &control.PlumberScoreResult{Score: "E", RawPointsUnclamped: 75, FinalPoints: 30}
	got := platformScoreFrom(s)
	if got.Letter != "E" || got.Points != 75 || got.FinalPoints == nil || *got.FinalPoints != 30 {
		t.Fatalf("want E, points 75 (raw), final_points 30, got %+v", got)
	}
}

// The Critical malus floors FinalPoints at zero even when the raw deficit is
// negative (RawPointsUnclamped survives unclamped, per its own doc comment);
// FinalPoints must still be a present, non-nil zero, not treated as absent.
func TestPlatformScoreFrom_FinalPointsFloorAtZero(t *testing.T) {
	s := &control.PlumberScoreResult{Score: "E", RawPointsUnclamped: -5, FinalPoints: 0}
	got := platformScoreFrom(s)
	if got.FinalPoints == nil || *got.FinalPoints != 0 {
		t.Fatalf("final_points = %v, want a non-nil 0 (the malus floor, not an absent field)", got.FinalPoints)
	}
	if got.Points != -5 {
		t.Fatalf("points = %d, want -5 (RawPointsUnclamped stays signed and unclamped)", got.Points)
	}
}

// FinalPoints rounds half away from zero (math.Round), matching Points'
// rounding rule.
func TestPlatformScoreFrom_FinalPointsRounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		final float64
		want  int
	}{
		{"half rounds up away from zero", 30.5, 31},
		{"below half rounds down", 29.4, 29},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &control.PlumberScoreResult{Score: "C", RawPointsUnclamped: tc.final, FinalPoints: tc.final}
			got := platformScoreFrom(s)
			if got.FinalPoints == nil || *got.FinalPoints != tc.want {
				t.Fatalf("final_points = %v, want %d", got.FinalPoints, tc.want)
			}
		})
	}
}

// A nil score must not panic and must leave FinalPoints nil (genuinely
// absent), alongside the existing zero-value Letter/Points behaviour.
func TestPlatformScoreFrom_NilScore(t *testing.T) {
	got := platformScoreFrom(nil)
	if got.FinalPoints != nil {
		t.Fatalf("final_points = %v, want nil for a nil score", got.FinalPoints)
	}
	if got.Letter != "" || got.Points != 0 {
		t.Fatalf("want zero-value Letter/Points for a nil score, got %+v", got)
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
	if _, err := maybePushPlatform(testProvider(t), conf, &control.AnalysisResult{}, nil, nil); err != nil {
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

	if _, err := maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, nil, nil); err != nil {
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
	_, err := maybePushPlatform(testProvider(t), conf, result, score, nil)
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
	if _, err := maybePushPlatform(testProvider(t), conf, result, &control.PlumberScoreResult{Score: "C"}, nil); err != nil {
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

	// Every branch carries the display metadata (#440), asserted on the
	// DECODED BODY so the real platformFindingsFor wiring is what is
	// pinned, not the helper in isolation. The fail branch matters most:
	// it resolves its control name through LookupCode(f.Code) rather than
	// e.ControlName, so its metadata lookup goes through a distinct path.
	for name, f := range map[string]platformFinding{
		"containerImageMustComeFromAuthorizedSources": fail,
		"branchMustBeProtected":                       notEval,
		"pipelineMustNotEnableDebugTrace":             pass,
	} {
		meta, ok := configuration.ControlMetaFor(name)
		if !ok {
			t.Fatalf("%s: no exported catalog row", name)
		}
		if f.Name != meta.DisplayName || f.Category != meta.Category {
			t.Errorf("%s: pushed (name=%q, category=%q), want (%q, %q) from the exported catalog",
				name, f.Name, f.Category, meta.DisplayName, meta.Category)
		}
	}
}

// TestPlatformFindingsFor_DismissedMarkerFollowsTheFinding pins #447 part 2
// on the build side: platformFindingsFor's fail branch must carry each
// finding's own Dismissed bit onto the pushed entry, not the same value for
// every finding of a control. Two findings under the same failing control,
// one dismissed and one not, must come out tagged independently.
func TestPlatformFindingsFor_DismissedMarkerFollowsTheFinding(t *testing.T) {
	pc := testDefaultPlumberConfig(t)
	result := &control.AnalysisResult{
		CiValid: true,
		Findings: []opaengine.Finding{
			{Code: "ISSUE-101", Severity: "high", Message: "live", Job: "build", File: ".gitlab-ci.yml", Line: 1},
			{Code: "ISSUE-101", Severity: "high", Message: "dismissed one", Job: "deploy", File: ".gitlab-ci.yml", Line: 2, Dismissed: true},
		},
	}
	findings := platformFindingsFor(testProvider(t), result, pc, nil, nil)

	var live, dismissed *platformFinding
	for i := range findings {
		if findings[i].Control != "containerImageMustComeFromAuthorizedSources" {
			continue
		}
		var data map[string]any
		if err := json.Unmarshal(findings[i].Data, &data); err != nil {
			t.Fatalf("finding data does not parse: %v", err)
		}
		switch data["message"] {
		case "live":
			live = &findings[i]
		case "dismissed one":
			dismissed = &findings[i]
		}
	}
	if live == nil || dismissed == nil {
		t.Fatalf("expected both the live and the dismissed finding among %+v", findings)
	}
	if live.Status != platformStatusFail || live.Dismissed {
		t.Errorf("live finding = %+v, want status=fail, dismissed=false", live)
	}
	if dismissed.Status != platformStatusFail || !dismissed.Dismissed {
		t.Errorf("dismissed finding = %+v, want status=fail, dismissed=true", dismissed)
	}
}

// TestMaybePushPlatform_DismissedFindingWireShape checks the marker on the
// raw wire bytes, the same way the rest of this file distrusts decoding
// into platformFinding alone (see docs/platform-push-testing.md): a
// dismissed finding's pushed entry must carry `"dismissed":true`, and an
// ordinary finding's entry must carry no `dismissed` key at all
// (omitempty), not a `false`.
func TestMaybePushPlatform_DismissedFindingWireShape(t *testing.T) {
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
		CiValid: true,
		Findings: []opaengine.Finding{
			{Code: "ISSUE-101", Severity: "high", Message: "untrusted registry", Job: "build", File: ".gitlab-ci.yml", Line: 4, Dismissed: true},
		},
	}
	if _, err := maybePushPlatform(testProvider(t), conf, result, &control.PlumberScoreResult{Score: "C"}, nil); err != nil {
		t.Fatalf("maybePushPlatform: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(gotBody, &raw); err != nil {
		t.Fatalf("body does not decode as JSON: %v", err)
	}
	results, _ := raw["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("results = %v, want exactly 1 entry", results)
	}
	entry, _ := results[0].(map[string]any)
	rawFindings, _ := entry["findings"].([]any)

	var sawDismissedTrue, sawEntryWithNoDismissedKey bool
	for _, rf := range rawFindings {
		f, _ := rf.(map[string]any)
		controlName, _ := f["control"].(string)
		val, hasKey := f["dismissed"]
		if controlName == "containerImageMustComeFromAuthorizedSources" {
			b, ok := val.(bool)
			if !hasKey || !ok || !b {
				t.Errorf("dismissed finding's wire entry = %v, want \"dismissed\":true", f)
			}
			sawDismissedTrue = true
			continue
		}
		if hasKey {
			t.Errorf("control %q must carry no \"dismissed\" key at all (omitempty): %v", controlName, f)
		} else {
			sawEntryWithNoDismissedKey = true
		}
	}
	if !sawDismissedTrue {
		t.Fatal("the dismissed finding's control must appear in the pushed findings with dismissed:true")
	}
	if !sawEntryWithNoDismissedKey {
		t.Fatal("fixture must include at least one non-dismissed control to prove the key is truly absent elsewhere")
	}
}

// stubRunProvider is the real GitLab provider with Run replaced by a canned result, so a test can
// drive runWithProvider - the GitLab entry point, and the only path where platform mode actually
// operates - without a live collection. Every other method is the real provider's, so the catalog,
// the compliance computation and the CI mapping behave exactly as they do in production.
type stubRunProvider struct {
	providerPkg.Provider
	result *control.AnalysisResult
}

func (s stubRunProvider) Run(*configuration.Configuration) (*control.AnalysisResult, error) {
	return s.result, nil
}

// dismissalPolicy is the resolved policy this test's runs are evaluated under: one real policy
// declaring containerImageMustComeFromAuthorizedSources with a trusted list the fixture image
// does not match, so the control produces exactly one live ISSUE-101.
//
// A resolved policy is required, not decoration: in platform mode a run that resolves NONE
// evaluates nothing and never reaches the push (runPlatformMode), so a context carrying only a
// dismissed list would assert against a push that was never sent.
func dismissalPolicy() platform.Policy {
	return policyWithTree("Images", "containerImageMustComeFromAuthorizedSources",
		`{"enabled":true,"trustedUrls":["registry.example.com/*"],"includePlumberDefaults":false}`)
}

// imageResult is a collected GitLab run whose RETAINED IR carries one job pulling from the given
// registry. Re-evaluated under dismissalPolicy it produces one ISSUE-101 for an untrusted
// registry and none for the trusted one, which is what makes the dismissal's effect on the score
// observable.
func imageResult(registry string) *control.AnalysisResult {
	return &control.AnalysisResult{
		CiValid:     true,
		ProjectPath: "grp/app",
		Pipeline: &ir.NormalizedPipeline{
			Provider:      ir.ProviderGitLab,
			ProjectPath:   "grp/app",
			DefaultBranch: "main",
			Jobs: []ir.Job{{
				Name:       "build",
				OriginFile: ".gitlab-ci.yml",
				Image:      &ir.Image{Registry: registry, Name: "app", Tag: "1"},
			}},
		},
	}
}

// TestSharedPipeline_ServedDismissalMarksThePushAndLeavesTheScore pins the run-level half of #447,
// which the wire-shape test above does not reach: on the shared pipeline a served dismissal must
// reach the pushed entry as "dismissed":true and cost the score nothing. Drop the marking on
// either path and a run pushes a served dismissal as a live finding and scores it, with every
// unit test still green.
//
// Both production entry points are driven, because platform mode is not symmetric between them:
// presentResultWithProvider serves the GitHub paths, while runWithProvider is GitLab's and is the
// one path where platform mode actually operates. They share finalizeFindings and the
// platform-mode tail it hands to (continueRun), and this test is what says so - a copy of the
// sequence in either of them, minus a step, fails here.
//
// The served entry is built the way the platform builds it: the identity hash of the finding as it
// exists AFTER fingerprint stamping, under the current recipe version, keyed by the finding's
// control. It is derived by a probe evaluation through the very helpers production uses
// (policyConfigFromTree + control.ReEvaluateForConfig) rather than hand-written, so the fixture
// cannot drift away from the identity the run actually computes. Both halves of the claim are
// asserted on the SAME run: the captured push body carries "dismissed":true on that entry, and the
// score the run computed is the score of a run with no such finding at all.
func TestSharedPipeline_ServedDismissalMarksThePushAndLeavesTheScore(t *testing.T) {
	origPrint := printOutput
	printOutput = false // the terminal report is not under test
	defer func() { printOutput = origPrint }()
	newGateFlagsCmd(t) // reset gate globals: default points gate (min-points 100)

	// The probe: evaluate the fixture under the policy exactly as the run will, and read the
	// identity of the finding it produces. That is the identity the platform would have hashed.
	probeCfg, err := policyConfigFromTree("gitlab", dismissalPolicy())
	if err != nil {
		t.Fatalf("assembling the policy config: %v", err)
	}
	probe, _, ok := control.ReEvaluateForConfig(imageResult("evil.registry.io"), confWithPolicies(t, dismissalPolicy()), "gitlab", probeCfg)
	if !ok {
		t.Fatal("the fixture has no retained IR: nothing could be re-evaluated per policy")
	}
	if len(probe.Findings) != 1 || probe.Findings[0].Code != "ISSUE-101" {
		t.Fatalf("want exactly one ISSUE-101 from the untrusted image, got %+v", probe.Findings)
	}
	hash, _, ok := identity.PlatformHash(probe.Findings[0].IdentityInput())
	if !ok {
		t.Fatal("the fixture finding has no platform identity, so no served dismissal could ever match it")
	}
	served := platform.DismissedIssue{
		IdentityHash:  hash,
		RecipeVersion: identity.RecipeVersion,
		ControlType:   control.ControlKeyFor(probe.Findings[0].Code),
	}

	// dismissedKeyFor reads the marker off the raw wire bytes rather than through platformFinding,
	// for the reason docs/platform-push-testing.md gives: decoding into the struct cannot tell an
	// absent key from a false.
	dismissedKeyFor := func(t *testing.T, body []byte, controlName string) (val any, present, found bool) {
		t.Helper()
		var raw map[string]any
		if err := json.Unmarshal(body, &raw); err != nil {
			t.Fatalf("body does not decode as JSON: %v", err)
		}
		results, _ := raw["results"].([]any)
		if len(results) == 0 {
			t.Fatal("results = empty")
		}
		entry, _ := results[0].(map[string]any)
		rawFindings, _ := entry["findings"].([]any)
		for _, rf := range rawFindings {
			f, _ := rf.(map[string]any)
			if name, _ := f["control"].(string); name != controlName {
				continue
			}
			v, has := f["dismissed"]
			return v, has, true
		}
		return nil, false, false
	}

	const dismissedControl = "containerImageMustComeFromAuthorizedSources"

	entries := []struct {
		name  string
		drive func(t *testing.T, p providerPkg.Provider, conf *configuration.Configuration, result *control.AnalysisResult)
	}{
		{
			// The GitHub paths: the result is already in hand.
			name: "presentResultWithProvider",
			drive: func(t *testing.T, p providerPkg.Provider, conf *configuration.Configuration, result *control.AnalysisResult) {
				t.Helper()
				_ = presentResultWithProvider(p, nil, result, conf)
			},
		},
		{
			// The GitLab entry point (cmd/analyze_gitlab.go), with p.Run stubbed out: everything
			// after collection is the production path, spinner and publish included.
			name: "runWithProvider",
			drive: func(t *testing.T, p providerPkg.Provider, conf *configuration.Configuration, result *control.AnalysisResult) {
				t.Helper()
				_ = runWithProvider(stubRunProvider{Provider: p, result: result}, nil, conf, nil, nil)
			},
		},
	}

	for _, entry := range entries {
		t.Run(entry.name, func(t *testing.T) {
			// run drives the production pipeline once and returns the raw pushed body plus the
			// score that same run computed. A context with no policies pushes the single
			// locally-named entry, so the assertions read one result rather than one per policy;
			// the served dismissed list is the only variable.
			run := func(t *testing.T, registry string, dismissed []platform.DismissedIssue) ([]byte, int) {
				t.Helper()
				var gotBody []byte
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					gotBody, _ = io.ReadAll(r.Body)
					w.WriteHeader(http.StatusAccepted)
				}))
				defer srv.Close()
				restore := withPlatformTestEnv(t, srv.URL, "tok-123")
				defer restore()

				conf := configuration.NewDefaultConfiguration()
				conf.ConfigFilePath = ".plumber.yaml"
				conf.PlumberConfig = testDefaultPlumberConfig(t)
				// runContextWith supplies the resolved-and-valid config resolution the
				// probe used. It is load bearing: with no resolution the lane-gap rule
				// marks every pipeline control not_evaluable and drops its findings, so
				// the fixture violation would vanish and the test would compare two
				// perfect scores (it did, before this line).
				conf.PlatformRun = runContextWith(dismissalPolicy())
				conf.PlatformRun.Endpoint = srv.URL
				conf.PlatformRun.Context.DismissedIssues = dismissed

				// The returned error is the gate verdict, which is not what this test reads: the
				// difference the dismissal makes is asserted on the pushed score below, which is
				// the score itself rather than a proxy for it.
				_ = captureStderr(t, func() {
					entry.drive(t, testProvider(t), conf, imageResult(registry))
				})

				if len(gotBody) == 0 {
					t.Fatal("nothing was POSTed: the run-level pipeline never reached the platform push")
				}
				var push platformPush
				if err := json.Unmarshal(gotBody, &push); err != nil {
					t.Fatalf("pushed body does not decode: %v", err)
				}
				if len(push.Results) != 1 {
					t.Fatalf("results = %d, want exactly 1 entry", len(push.Results))
				}
				return gotBody, push.Results[0].Score.Points
			}

			// The clean run swaps the registry for the one the policy trusts, so the control
			// produces no finding at all: the same policy, the same pipeline shape, and the
			// only difference is whether the finding exists.
			servedBody, servedPoints := run(t, "evil.registry.io", []platform.DismissedIssue{served})
			liveBody, livePoints := run(t, "evil.registry.io", nil)
			_, cleanPoints := run(t, "registry.example.com", nil)

			val, present, found := dismissedKeyFor(t, servedBody, dismissedControl)
			if !found {
				t.Fatalf("control %q is absent from the pushed findings: the served dismissal must be pushed, not withheld", dismissedControl)
			}
			if b, ok := val.(bool); !present || !ok || !b {
				t.Errorf("dismissed = %v (present=%v), want \"dismissed\":true: the served dismissal must be marked on this entry point's pipeline", val, present)
			}

			if _, present, found := dismissedKeyFor(t, liveBody, dismissedControl); !found || present {
				t.Errorf("without a served entry, control %q carried dismissed=%v: the marker must come from the served list alone", dismissedControl, present)
			}

			if servedPoints <= livePoints {
				t.Errorf("score points = %d dismissed vs %d live, want the dismissed finding to cost nothing (#447: out of the score like not_evaluable)", servedPoints, livePoints)
			}
			if servedPoints != cleanPoints {
				t.Errorf("score points = %d with the finding dismissed, %d with no such finding at all: the two must agree, or the exclusion is partial", servedPoints, cleanPoints)
			}
		})
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
	if _, err := maybePushPlatform(testProvider(t), conf, result, nil, nil); err != nil {
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
	if _, err := maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, score, nil); err != nil {
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

// A nil score reaches maybePushPlatform for real now (row 45:
// buildComplianceSummary withholds it whenever nothing was evaluated), and a
// best-effort push crashing the run over a nil pointer would be strictly
// worse than sending no score at all.
func TestMaybePushPlatform_NilScoreDoesNotPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	if _, err := maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, nil, nil); err != nil {
		t.Fatalf("maybePushPlatform: %v", err)
	}
}

// TestMaybePushPlatform_Row45OmitsScoreWhenNil is the standalone-push
// counterpart of TestBuildPolicyResults_Row45OmitsScoreWhenNothingEvaluated:
// a nil score must reach the wire as an absent "score" key, never as
// platformScoreFrom's zero-value fallback ({"points":0}), which would read
// as a real, if empty, score rather than as none at all.
func TestMaybePushPlatform_Row45OmitsScoreWhenNil(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok-123")
	defer restore()

	if _, err := maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, nil, nil); err != nil {
		t.Fatalf("maybePushPlatform: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(gotBody, &raw); err != nil {
		t.Fatal(err)
	}
	results, ok := raw["results"].([]any)
	if !ok || len(results) != 1 {
		t.Fatalf("results: %#v", raw["results"])
	}
	entry, _ := results[0].(map[string]any)
	if _, present := entry["score"]; present {
		t.Errorf("a nil score must be omitted from the push, not sent as a zero-value object, got %#v", entry["score"])
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
	if _, err := maybePushPlatform(testProvider(t), conf, &control.AnalysisResult{}, nil, nil); err != nil {
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
				_, err = maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, nil, nil)
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
		_, err = maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, nil, nil)
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

	_, err := maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, nil, nil)
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

	_, err := maybePushPlatform(p, nil, &control.AnalysisResult{}, nil, nil)
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

	_, err := maybePushPlatform(p, nil, &control.AnalysisResult{}, nil, nil)
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
	if _, err := maybePushPlatform(testProvider(t), nil, result, nil, nil); err != nil {
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
		_, err = maybePushPlatform(testProvider(t), nil, &control.AnalysisResult{}, nil, nil)
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

	// Platform mode makes every local gate inert, so the ONLY thing deciding
	// the returned error is the platform push. The context carries one
	// resolved policy against a result with retained IR, because a run that
	// resolves NO policy evaluates nothing and never reaches the push
	// (runPlatformMode) - the token guarantee is about a run that had
	// something to send.
	conf := confWithPolicies(t, policyWithTree("A", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig))

	t.Run("missing id-token fails the run", func(t *testing.T) {
		restore := withPlatformTestEnv(t, "https://app.example.com", "")
		defer restore()

		var err error
		_ = captureStderr(t, func() {
			err = presentResultWithProvider(testProvider(t), nil, debugTraceResult(), conf)
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
			err = presentResultWithProvider(testProvider(t), nil, debugTraceResult(), conf)
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

	body, err := buildPlatformPush(p, nil, &control.AnalysisResult{}, nil, ".plumber.yaml", nil)
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

	body, err := buildPlatformPush(p, nil, &control.AnalysisResult{}, nil, ".plumber.yaml", nil)
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

// notEvaluableReasonData carries the machine-readable reason onto the
// pushed finding; dropping it would leave the platform unable to tell "the
// resolution was unavailable" from "this lane is not switched over" without
// parsing prose (re-raised #431 review thread).
func TestNotEvaluableReasonData(t *testing.T) {
	r := &control.AnalysisResult{}
	r.MarkNotEvaluable("includesMustBeUpToDate", "resolution_unavailable")

	raw := notEvaluableReasonData(r, "includesMustBeUpToDate")
	var got map[string]string
	if err := json.Unmarshal(raw, &got); err != nil || got["reason"] != "resolution_unavailable" {
		t.Fatalf("want {reason: resolution_unavailable}, got %s (err %v)", raw, err)
	}
	if data := notEvaluableReasonData(r, "someOtherControl"); data != nil {
		t.Fatalf("an unmarked control must carry no reason data, got %s", data)
	}
	if data := notEvaluableReasonData(nil, "includesMustBeUpToDate"); data != nil {
		t.Fatalf("a nil result must yield nil, got %s", data)
	}
}

// Platform mode runs tokenless by design: the OIDC id-token replaces the
// personal token, so resolveGitLabToken must permit an empty GITLAB_TOKEN
// when --platform is configured and still refuse it otherwise (re-raised
// #431 review thread; the core of #368's tokenless CI).
func TestResolveGitLabToken_PlatformModeBypass(t *testing.T) {
	orig := platformURL
	defer func() { platformURL = orig }()
	t.Setenv("GITLAB_TOKEN", "")

	platformURL = "https://app.example.com"
	token, err := resolveGitLabToken(analyzeFlags{})
	if err != nil || token != "" {
		t.Fatalf("platform mode must continue tokenless: got (%q, %v)", token, err)
	}

	platformURL = ""
	if _, err := resolveGitLabToken(analyzeFlags{}); err == nil {
		t.Fatal("without --platform a missing GITLAB_TOKEN must stay an informative error")
	}

	platformURL = "https://app.example.com"
	t.Setenv("GITLAB_TOKEN", "glpat-real")
	token, err = resolveGitLabToken(analyzeFlags{})
	if err != nil || token != "glpat-real" {
		t.Fatalf("a supplied token must always win: got (%q, %v)", token, err)
	}
}

// The report's control blocks and issue rows carry display metadata next
// to their technical ids (#440): name + category per control, title per
// issue code, all sourced from the exported tables so no consumer keeps a
// hand map.
func TestReportCarriesDisplayMetadata(t *testing.T) {
	entry := control.ControlEntry{ControlName: "branchMustBeProtected"}
	block := _withControlMeta(map[string]any{}, entry, &control.AnalysisResult{CiValid: true}, 0)
	m := block.(map[string]any)
	if m["controlName"] != "branchMustBeProtected" {
		t.Fatalf("technical id must stay: %v", m)
	}
	if m["name"] != "Branch must be protected" {
		t.Errorf("display name missing or wrong: %v", m["name"])
	}
	if m["category"] != configuration.CategoryAccessAndAuthorization {
		t.Errorf("category missing or wrong: %v", m["category"])
	}

	issue := projectFinding(opaengine.Finding{Code: "ISSUE-501", Message: "x"}, "job")
	if issue["code"] != "ISSUE-501" {
		t.Fatalf("technical code must stay: %v", issue)
	}
	title, _ := issue["title"].(string)
	if title == "" {
		t.Errorf("issue title missing: %v", issue)
	}
}

// The push findings carry the same display metadata additively (#440): the
// platform and any consumer of the raw artifact see the docs wording next
// to the stable technical control name.
func TestPlatformFindingsCarryDisplayMetadata(t *testing.T) {
	f := decoratedPlatformFinding("branchMustBeProtected", platformStatusPass, nil)
	if f.Control != "branchMustBeProtected" || f.Name != "Branch must be protected" ||
		f.Category != configuration.CategoryAccessAndAuthorization {
		t.Fatalf("decorated finding mismatch: %+v", f)
	}
	unknown := decoratedPlatformFinding("noSuchControl", platformStatusPass, nil)
	if unknown.Name != "" || unknown.Category != "" {
		t.Fatalf("an unknown control must not invent metadata: %+v", unknown)
	}
}

// row63Fixture is one shape of a LINKED run, as the nothing-evaluated marker
// (platform decision row 63) has to classify it: either the run reported a
// policy verdict, or it evaluated nothing and says so.
type row63Fixture struct {
	name       string
	conf       *configuration.Configuration
	result     *control.AnalysisResult
	wantMarker bool
	wantReason string
}

// unreadableControlConfig is a control config the CLI cannot read at all
// (truncated JSON). A policy declaring only this has a tree that FAILS TO
// APPLY: policyConfigFromTree reports that none of its controls could be
// read, so the policy is evaluated against nothing and its run is not
// applied. That is the "policies_not_applicable" fact itself, rather than
// the weaker "there was no pipeline to re-evaluate".
const unreadableControlConfig = `{"enabled":`

// confWithUnreachablePlatform is a LINKED run whose /context fetch failed:
// the RunContext exists (platform mode was set up) but carries no Context,
// which is what RunContext.Engaged answers false for. Such a run resolved no
// policy because the platform said nothing, not because it assigned nothing.
func confWithUnreachablePlatform(t *testing.T) *configuration.Configuration {
	t.Helper()
	conf := confWithPolicies(t)
	conf.PlatformRun = &platform.RunContext{
		Endpoint:    "https://platform.example.com",
		ProjectPath: "g/p",
		ContextErr:  errors.New("dial tcp: connection refused"),
	}
	return conf
}

// row63Fixtures builds the four shapes side by side, so the marker and the
// results array are always asserted against the same set of runs.
//
// The second is the "not applicable" shape: two policies that DO declare a
// tree, over a real retained pipeline, whose trees cannot be applied at all
// (they group into one run, since they fail for the same reason), so nothing
// is applied and nothing may be pushed as a verdict.
//
// The fourth is the one that is NOT a nothing-evaluated run: a platform that
// never answered. It resolves no policy either, and it must still take the
// standalone branch.
func row63Fixtures(t *testing.T) []row63Fixture {
	t.Helper()
	baseline := policyWithTree("Baseline", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig)
	unreadableA := policyWithTree("Unreadable A", "pipelineMustNotEnableDebugTrace", unreadableControlConfig)
	unreadableB := policyWithTree("Unreadable B", "pipelineMustNotUseDockerInDocker", unreadableControlConfig)
	return []row63Fixture{
		{
			name:       "no policy resolved",
			conf:       confWithPolicies(t),
			result:     &control.AnalysisResult{},
			wantMarker: true,
			wantReason: "no_policy",
		},
		{
			name:       "policies resolved, no tree applied",
			conf:       confWithPolicies(t, unreadableA, unreadableB),
			result:     debugTraceResult(),
			wantMarker: true,
			wantReason: "policies_not_applicable",
		},
		{
			name:       "one applied run",
			conf:       confWithPolicies(t, baseline),
			result:     debugTraceResult(),
			wantMarker: false,
		},
		{
			name:       "the platform never answered",
			conf:       confWithUnreachablePlatform(t),
			result:     debugTraceResult(),
			wantMarker: false,
		},
	}
}

// row63PushBody builds the push for one fixture and decodes the RAW wire
// bytes, the way TestBuildPlatformPush_KeysAreSnakeCaseAndPolicyIsAString
// does: the marker is a wire contract, and a decode back into this package's
// own types would pass on a renamed or re-typed json tag.
func row63PushBody(t *testing.T, f row63Fixture) (map[string]any, []byte) {
	t.Helper()
	runs := evaluatePlatformPolicies(testProvider(t), f.conf, f.result)
	body, err := buildPlatformPush(testProvider(t), f.conf, f.result, nil, "team.plumber.yaml", runs)
	if err != nil {
		t.Fatalf("buildPlatformPush: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("push does not parse as JSON: %v", err)
	}
	return raw, body
}

// A linked run that resolved NO policy pushes the marker and no result at
// all (row 63). Pushing the local configuration's verdict here would report
// a verdict no policy asked for, and pushing a bare empty results array is
// what the platform refuses outright (422).
func TestBuildPlatformPush_Row63_NoPolicyResolvedSendsTheMarkerAndNoResults(t *testing.T) {
	restore := withPlatformTestEnv(t, "https://platform.example.com", "")
	defer restore()

	f := row63Fixtures(t)[0]
	raw, body := row63PushBody(t, f)

	results, ok := raw["results"].([]any)
	if !ok {
		t.Fatalf("results = %#v, want an EMPTY array: the key is present and non-null on every push", raw["results"])
	}
	if len(results) != 0 {
		t.Fatalf("results = %v, want no entry at all for a run that evaluated nothing", results)
	}
	if strings.Contains(string(body), `"policy"`) {
		t.Errorf("a policy entry reached the wire on a run that evaluated nothing:\n%s", body)
	}
	evaluation, ok := raw["evaluation"].(map[string]any)
	if !ok {
		t.Fatalf("evaluation = %#v, want the nothing-evaluated marker (row 63)", raw["evaluation"])
	}
	if evaluation["nothing_evaluated"] != true {
		t.Errorf("evaluation.nothing_evaluated = %v, want true", evaluation["nothing_evaluated"])
	}
	if evaluation["reason"] != f.wantReason {
		t.Errorf("evaluation.reason = %v, want %q: the platform resolved no policy for this project", evaluation["reason"], f.wantReason)
	}
}

// Policies WERE resolved and not one of their trees could be applied here:
// the same empty push, a different reason. The two must not be collapsed -
// the platform echoes the reason back through the gate, and "no policy
// assigned" and "your policies did not apply" are different operator
// problems.
func TestBuildPlatformPush_Row63_AllTreesUnappliableSendsPoliciesNotApplicable(t *testing.T) {
	restore := withPlatformTestEnv(t, "https://platform.example.com", "")
	defer restore()

	f := row63Fixtures(t)[1]
	raw, _ := row63PushBody(t, f)

	results, ok := raw["results"].([]any)
	if !ok || len(results) != 0 {
		t.Fatalf("results = %#v, want an empty array: a policy the CLI could not evaluate is absent from the push", raw["results"])
	}
	evaluation, ok := raw["evaluation"].(map[string]any)
	if !ok {
		t.Fatalf("evaluation = %#v, want the nothing-evaluated marker (row 63)", raw["evaluation"])
	}
	if evaluation["reason"] != f.wantReason {
		t.Errorf("evaluation.reason = %v, want %q", evaluation["reason"], f.wantReason)
	}
}

// An unreachable platform is NOT a nothing-evaluated run. The /context fetch
// failed, so no policy was ASSIGNED - none was ANSWERED, and reporting
// no_policy for it would blame the project's configuration for a third party
// being down. Such a run keeps the existing degradation: the standalone
// branch, the single locally-named entry, no marker.
//
// This is what pins the RunContext.Engaged term in buildPlatformPush.
// Keying the marker on "a platform URL is set and a RunContext exists"
// instead passes every other test in this file, and turns every unreachable
// platform into a marked, resultless push.
func TestBuildPlatformPush_Row63_UnreachablePlatformIsNotAMarkedRun(t *testing.T) {
	restore := withPlatformTestEnv(t, "https://platform.example.com", "")
	defer restore()

	f := row63Fixtures(t)[3]
	if platformRunOf(f.conf).Engaged() {
		t.Fatal("the fixture must be a run whose context fetch FAILED (Engaged false)")
	}
	raw, _ := row63PushBody(t, f)

	if v, present := raw["evaluation"]; present {
		t.Errorf("evaluation = %#v on a run the platform never answered, want the key ABSENT: it evaluated nothing because nothing answered, which is the existing degradation and not a nothing-evaluated run", v)
	}
	results, _ := raw["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("results = %#v, want the single locally-named entry the standalone branch builds", raw["results"])
	}
	entry, _ := results[0].(map[string]any)
	if entry["policy"] != "team" {
		t.Errorf("policy = %v, want the local config's name: the unreachable run keeps today's name-only push", entry["policy"])
	}
}

// The golden shape of every push that came before the field existed: one
// applied run reports its verdict and carries NO evaluation key. Absent is
// what means "this push evaluated something", so an always-present marker
// object would re-interpret every ordinary push.
func TestBuildPlatformPush_Row63_AnOrdinaryPushCarriesNoEvaluationKey(t *testing.T) {
	restore := withPlatformTestEnv(t, "https://platform.example.com", "")
	defer restore()

	raw, _ := row63PushBody(t, row63Fixtures(t)[2])

	results, _ := raw["results"].([]any)
	if len(results) == 0 {
		t.Fatalf("results = %#v, want the applied run's entry", raw["results"])
	}
	if v, present := raw["evaluation"]; present {
		t.Errorf("evaluation = %#v is present on a push that evaluated something, want the key ABSENT", v)
	}
}

// The invariant the platform enforces from both sides (row 63): an empty
// results array is legitimate ONLY with the marker (422 without it), and the
// marker is refused outright when it rides a non-empty results array (422,
// reason evaluation_marker_with_results). The two are derived from one
// another here so they can never contradict each other on the wire.
func TestBuildPlatformPush_Row63_MarkerAndResultsAreMutuallyExclusive(t *testing.T) {
	restore := withPlatformTestEnv(t, "https://platform.example.com", "")
	defer restore()

	for _, f := range row63Fixtures(t) {
		t.Run(f.name, func(t *testing.T) {
			raw, _ := row63PushBody(t, f)
			results, _ := raw["results"].([]any)
			_, marked := raw["evaluation"]
			if (len(results) == 0) != marked {
				t.Fatalf("results = %d entries, marker present = %v: the platform 422s both halves of this disagreement", len(results), marked)
			}
			if marked != f.wantMarker {
				t.Fatalf("marker present = %v, want %v", marked, f.wantMarker)
			}
		})
	}
}

// bomFixture is the bill of materials the push tests map onto the wire: one
// catalog component include pinned below its latest release, one image used
// by two jobs, and one job that starts a dind service under a runner tag.
func bomFixture() *pbom.PBOM {
	upToDate := false
	authorized := true
	forbidden := false
	return &pbom.PBOM{
		Includes: []pbom.Include{{
			Type:           "component",
			Location:       "gitlab.example.com/components/sast/sast",
			Project:        "components/sast",
			Version:        "3.3.0",
			LatestVersion:  "3.4.0",
			UpToDate:       &upToDate,
			ComponentName:  "sast",
			FromCatalog:    true,
			Overridden:     true,
			OverriddenJobs: []utils.OverriddenJobDetail{{JobName: "sast", OverriddenKeys: []string{"script"}}},
		}},
		ContainerImages: []pbom.ContainerImage{{
			Image:        "docker.io/node:20",
			Registry:     "docker.io",
			Name:         "node",
			Tag:          "20",
			Jobs:         []string{"build", "test"},
			Authorized:   &authorized,
			ForbiddenTag: &forbidden,
		}},
		Jobs: []pbom.JobResources{{
			Name: "test",
			Services: []pbom.ContainerImageRef{{
				Image: "docker:24.0.5-dind",
				Name:  "docker",
				Tag:   "24.0.5-dind",
			}},
			RunnerTags: []string{"docker"},
		}},
	}
}

// TestPlatformBOMFrom_WireShape pins the bom section's shape against the
// design spec (2026-09-23-dependencies-graph-design section 5): schema
// version 1, snake_case keys throughout, and the three-state booleans
// carried as pointers so an unevaluated control leaves its key out rather
// than publishing a verdict nobody computed.
func TestPlatformBOMFrom_WireShape(t *testing.T) {
	got, bound := platformBOMFrom(bomFixture())
	if bound != "" {
		t.Fatalf("platformBOMFrom refused the fixture on bound %q", bound)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("bom does not parse as JSON: %v", err)
	}

	if doc["version"] != float64(1) {
		t.Errorf("version = %v, want 1", doc["version"])
	}

	includes, _ := doc["includes"].([]any)
	if len(includes) != 1 {
		t.Fatalf("includes = %v, want exactly one", doc["includes"])
	}
	inc, _ := includes[0].(map[string]any)
	for key, want := range map[string]any{
		"type":           "component",
		"location":       "gitlab.example.com/components/sast/sast",
		"project":        "components/sast",
		"version":        "3.3.0",
		"latest_version": "3.4.0",
		"up_to_date":     false,
		"component_name": "sast",
		"from_catalog":   true,
		"overridden":     true,
	} {
		if inc[key] != want {
			t.Errorf("includes[0].%s = %#v, want %#v", key, inc[key], want)
		}
	}
	overridden, _ := inc["overridden_jobs"].([]any)
	if len(overridden) != 1 {
		t.Fatalf("includes[0].overridden_jobs = %v, want one entry", inc["overridden_jobs"])
	}
	ov, _ := overridden[0].(map[string]any)
	if ov["job"] != "sast" {
		t.Errorf("overridden_jobs[0].job = %#v, want sast", ov["job"])
	}
	if keys, _ := ov["keys"].([]any); len(keys) != 1 || keys[0] != "script" {
		t.Errorf("overridden_jobs[0].keys = %#v, want [script]", ov["keys"])
	}
	for _, absent := range []string{"archived", "has_cve", "advisories", "nested"} {
		if _, present := inc[absent]; present {
			t.Errorf("includes[0].%s is on the wire, want it omitted: nothing determined it", absent)
		}
	}

	images, _ := doc["images"].([]any)
	if len(images) != 1 {
		t.Fatalf("images = %v, want exactly one", doc["images"])
	}
	img, _ := images[0].(map[string]any)
	for key, want := range map[string]any{
		"image":         "docker.io/node:20",
		"registry":      "docker.io",
		"name":          "library/node",
		"tag":           "20",
		"authorized":    true,
		"forbidden_tag": false,
	} {
		if img[key] != want {
			t.Errorf("images[0].%s = %#v, want %#v", key, img[key], want)
		}
	}
	if jobs, _ := img["jobs"].([]any); len(jobs) != 2 || jobs[0] != "build" || jobs[1] != "test" {
		t.Errorf("images[0].jobs = %#v, want [build test]", img["jobs"])
	}

	bomJobs, _ := doc["jobs"].([]any)
	if len(bomJobs) != 1 {
		t.Fatalf("jobs = %v, want exactly one", doc["jobs"])
	}
	job, _ := bomJobs[0].(map[string]any)
	if job["name"] != "test" {
		t.Errorf("jobs[0].name = %#v, want test", job["name"])
	}
	services, _ := job["services"].([]any)
	if len(services) != 1 {
		t.Fatalf("jobs[0].services = %v, want one entry", job["services"])
	}
	svc, _ := services[0].(map[string]any)
	if svc["image"] != "docker:24.0.5-dind" || svc["name"] != "library/docker" || svc["tag"] != "24.0.5-dind" {
		t.Errorf("jobs[0].services[0] = %#v, want the dind reference", svc)
	}
	if tags, _ := job["runner_tags"].([]any); len(tags) != 1 || tags[0] != "docker" {
		t.Errorf("jobs[0].runner_tags = %#v, want [docker]", job["runner_tags"])
	}
}

// TestPlatformBOMFrom_Bounds covers the sizing rule of the design spec
// (section 4.4). The platform refuses an oversized bill with a 400 because a
// truncated one would misreport the estate, so the CLI never truncates
// either: it drops the whole section and names the bound that refused it.
// The push itself still goes, with its results intact.
func TestPlatformBOMFrom_Bounds(t *testing.T) {
	long := strings.Repeat("a", 513)
	for _, tc := range []struct {
		name string
		doc  *pbom.PBOM
		want string
	}{
		{
			name: "501 includes",
			doc:  &pbom.PBOM{Includes: make([]pbom.Include, 501)},
			want: "includes > 500",
		},
		{
			// The fixtures below carry real references and real runner tags,
			// because the bounds measure the EMITTED section: an entry the
			// filtering would drop cannot push a count over, which is the
			// whole point of measuring after the filtering.
			name: "501 images",
			doc:  &pbom.PBOM{ContainerImages: bomTestImages(501)},
			want: "images > 500",
		},
		{
			// The platform's own ceiling on the jobs an image may name
			// (bom_image_jobs). It is not in the design spec's list, and
			// without it a pipeline with one image shared by a thousand jobs
			// sits inside every other bound and loses its whole push.
			name: "an image naming 501 jobs",
			doc:  &pbom.PBOM{ContainerImages: []pbom.ContainerImage{{Image: "docker.io/node:20", Jobs: make([]string, 501)}}},
			want: "jobs per image > 500",
		},
		{
			name: "501 jobs",
			doc:  &pbom.PBOM{Jobs: bomTestJobs(501)},
			want: "jobs > 500",
		},
		{
			name: "65 services on one job",
			doc:  &pbom.PBOM{Jobs: []pbom.JobResources{{Name: "test", Services: bomTestServices(65)}}},
			want: "services per job > 64",
		},
		{
			name: "33 runner tags on one job",
			doc:  &pbom.PBOM{Jobs: []pbom.JobResources{{Name: "test", RunnerTags: make([]string, 33)}}},
			want: "runner tags per job > 32",
		},
		{
			name: "51 advisories on one include",
			doc:  &pbom.PBOM{Includes: []pbom.Include{{Type: "component", Advisories: make([]string, 51)}}},
			want: "advisories per include > 50",
		},
		{
			name: "a 513-rune include location",
			doc:  &pbom.PBOM{Includes: []pbom.Include{{Type: "component", Location: long}}},
			want: "string > 512 runes",
		},
		{
			name: "a 513-rune image name",
			doc:  &pbom.PBOM{ContainerImages: []pbom.ContainerImage{{Image: long}}},
			want: "string > 512 runes",
		},
		{
			name: "a 513-rune runner tag",
			doc:  &pbom.PBOM{Jobs: []pbom.JobResources{{Name: "test", RunnerTags: []string{long}}}},
			want: "string > 512 runes",
		},
		{
			name: "a 1025-rune remote include URL",
			doc:  &pbom.PBOM{Includes: []pbom.Include{{Type: "remote", Location: strings.Repeat("u", 1025)}}},
			want: "remote include URL > 1024 runes",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, bound := platformBOMFrom(tc.doc)
			if got != nil {
				t.Errorf("platformBOMFrom returned a section for %s: the bill is dropped whole, never truncated", tc.name)
			}
			if bound != tc.want {
				t.Errorf("bound = %q, want %q", bound, tc.want)
			}
		})
	}
}

// TestPlatformBOMFrom_RemoteURLGetsTheLongerBound is the control for the
// remote-include allowance: a 1024-rune URL is accepted where any other
// string of that length would not be, because a remote include is addressed
// by a URL and URLs are legitimately long.
func TestPlatformBOMFrom_RemoteURLGetsTheLongerBound(t *testing.T) {
	doc := &pbom.PBOM{Includes: []pbom.Include{{Type: "remote", Location: strings.Repeat("u", 1024)}}}
	got, bound := platformBOMFrom(doc)
	if bound != "" || got == nil {
		t.Fatalf("a 1024-rune remote URL was refused on bound %q", bound)
	}
	local := &pbom.PBOM{Includes: []pbom.Include{{Type: "local", Location: strings.Repeat("u", 1024)}}}
	if _, bound := platformBOMFrom(local); bound != "string > 512 runes" {
		t.Errorf("a 1024-rune LOCAL include location was accepted (bound %q): the longer allowance is the remote URL's alone", bound)
	}
}

// TestPlatformBOMFrom_StringByteBound covers the BYTE companion the platform
// puts beside its rune bound (bom_string_bytes). The rune bound alone admits
// 512 CJK runes, which are 1536 bytes, and the platform refuses those whole:
// its projected key is a composite of two such strings bound into a unique
// btree index, which Postgres caps at 2704 bytes. A bill inside every rune
// bound and over the byte one would cost the run its results, its findings
// and its score, so the CLI drops the section instead of sending it.
func TestPlatformBOMFrom_StringByteBound(t *testing.T) {
	// 512 runes of a 3-byte rune: exactly ON the rune bound, 1536 bytes over
	// the byte one.
	cjk := strings.Repeat("文", bomMaxStringRunes)
	got, bound := platformBOMFrom(&pbom.PBOM{Includes: []pbom.Include{{Type: "component", ComponentName: cjk}}})
	if got != nil {
		t.Error("platformBOMFrom returned a section the platform would refuse on bom_string_bytes: the bill is dropped whole, never truncated")
	}
	if bound != "string > 1024 bytes" {
		t.Errorf("bound = %q, want %q", bound, "string > 1024 bytes")
	}

	// The control: the same 512 runes in ASCII are 512 bytes, inside both
	// halves of the bound, and the bill goes.
	ascii := strings.Repeat("a", bomMaxStringRunes)
	got, bound = platformBOMFrom(&pbom.PBOM{Includes: []pbom.Include{{Type: "component", ComponentName: ascii}}})
	if got == nil || bound != "" {
		t.Fatalf("a 512-rune ASCII component name was refused on bound %q: the byte bound is the multi-byte string's alone", bound)
	}
}

// TestPlatformBOMFrom_RemoteURLByteBound is the same companion on the wider
// URL bound (bom_url_bytes). A remote include's location is a node key on its
// own, so the platform gives it 2048 bytes where an ordinary string gets
// 1024, and a 1024-rune URL written in 3-byte runes is inside the rune
// allowance and over that.
func TestPlatformBOMFrom_RemoteURLByteBound(t *testing.T) {
	url := strings.Repeat("文", bomMaxRemoteURLRunes) // 1024 runes, 3072 bytes
	got, bound := platformBOMFrom(&pbom.PBOM{Includes: []pbom.Include{{Type: "remote", Location: url}}})
	if got != nil {
		t.Error("platformBOMFrom returned a section the platform would refuse on bom_url_bytes: the bill is dropped whole, never truncated")
	}
	if bound != "url > 2048 bytes" {
		t.Errorf("bound = %q, want %q", bound, "url > 2048 bytes")
	}
}

// TestPlatformBOMFrom_EdgeBound covers the product bound (bom_edges). Every
// count bound of the section can be respected and the product still be
// enormous: twenty images naming five hundred jobs each is inside images >
// 500 and inside jobs per image > 500, and it projects ten thousand edges,
// which is exactly what the platform is willing to write in one ingest
// transaction. One more edge and the platform refuses the push whole.
func TestPlatformBOMFrom_EdgeBound(t *testing.T) {
	const images = 20
	if images*bomMaxJobsPerImage != bomMaxEdges {
		t.Fatalf("the fixture projects %d edges, not the %d the bound names", images*bomMaxJobsPerImage, bomMaxEdges)
	}
	// One edge per (image, job) pair, one per include: the platform's own
	// arithmetic, so the include is what takes this bill one edge over.
	bill := func(includes int) *pbom.PBOM {
		doc := &pbom.PBOM{}
		for i := 0; i < images; i++ {
			jobs := make([]string, bomMaxJobsPerImage)
			for j := range jobs {
				jobs[j] = "j" + strconv.Itoa(j)
			}
			doc.ContainerImages = append(doc.ContainerImages, pbom.ContainerImage{
				Image: "docker.io/team/app-" + strconv.Itoa(i) + ":1.0",
				Jobs:  jobs,
			})
		}
		for i := 0; i < includes; i++ {
			doc.Includes = append(doc.Includes, pbom.Include{Type: "local", Location: "local.yml"})
		}
		return doc
	}

	got, bound := platformBOMFrom(bill(0))
	if got == nil || bound != "" {
		t.Fatalf("a bill projecting exactly %d edges was refused on bound %q: the platform accepts it", bomMaxEdges, bound)
	}
	got, bound = platformBOMFrom(bill(1))
	if got != nil {
		t.Error("platformBOMFrom returned a section the platform would refuse on bom_edges: the bill is dropped whole, never truncated")
	}
	if bound != "edges > 10000" {
		t.Errorf("bound = %q, want %q", bound, "edges > 10000")
	}
}

// TestPlatformBOMFrom_EdgeBoundCountsServicesAndRunnerTags covers the other
// two terms of the projection's arithmetic. The bound above is driven entirely
// by images naming jobs, so dropping either job-side term from
// bomProjectedEdges leaves it green while the platform, which counts one edge
// per service and one per runner tag of a job (ingestion.projectedEdges),
// refuses the push whole. Each term is taken over the bound on its own here:
// one more service, then one more runner tag, on a bill sitting exactly on it.
//
// The fixture pays for most of the bound in runner tags rather than services
// because the two cost very different numbers of bytes. A service is an object
// with an image, a registry and a name; ten thousand of them serialise well
// past the 256 KiB document cap, which is checked after this bound and would
// refuse the accepted bill for the wrong reason. Runner tags are short
// strings, so the bill below stays a bill the platform would really take.
func TestPlatformBOMFrom_EdgeBoundCountsServicesAndRunnerTags(t *testing.T) {
	const (
		serviceJobs    = 40
		servicesPerJob = 50
		tagJobs        = 400
		tagsPerJob     = 20
	)
	if serviceJobs*servicesPerJob+tagJobs*tagsPerJob != bomMaxEdges {
		t.Fatalf("the fixture projects %d edges, not the %d the bound names",
			serviceJobs*servicesPerJob+tagJobs*tagsPerJob, bomMaxEdges)
	}
	// Every other count bound stays respected, with room to spare for the one
	// extra edge each case adds: the refusal under test has to be bom_edges
	// and nothing else.
	if serviceJobs+tagJobs > bomMaxJobs || servicesPerJob >= bomMaxServicesPerJob || tagsPerJob >= bomMaxRunnerTagsPerJob {
		t.Fatalf("the fixture sits on a count bound rather than the product bound: %d jobs, %d services, %d tags",
			serviceJobs+tagJobs, servicesPerJob, tagsPerJob)
	}

	// extraServices and extraTags land on the first job of each kind, which
	// is what takes the bill one edge over without touching any other count.
	bill := func(extraServices, extraTags int) *pbom.PBOM {
		doc := &pbom.PBOM{}
		for i := 0; i < serviceJobs; i++ {
			n := servicesPerJob
			if i == 0 {
				n += extraServices
			}
			services := make([]pbom.ContainerImageRef, n)
			for s := range services {
				services[s] = pbom.ContainerImageRef{Image: "svc/s" + strconv.Itoa(s)}
			}
			doc.Jobs = append(doc.Jobs, pbom.JobResources{
				Name:     "s" + strconv.Itoa(i),
				Services: services,
			})
		}
		for i := 0; i < tagJobs; i++ {
			n := tagsPerJob
			if i == 0 {
				n += extraTags
			}
			tags := make([]string, n)
			for k := range tags {
				tags[k] = "t" + strconv.Itoa(k)
			}
			doc.Jobs = append(doc.Jobs, pbom.JobResources{
				Name:       "r" + strconv.Itoa(i),
				RunnerTags: tags,
			})
		}
		return doc
	}

	got, bound := platformBOMFrom(bill(0, 0))
	if got == nil || bound != "" {
		t.Fatalf("a bill projecting exactly %d edges was refused on bound %q: the platform accepts it", bomMaxEdges, bound)
	}

	for _, tc := range []struct {
		name                     string
		extraServices, extraTags int
	}{
		{name: "one service over", extraServices: 1},
		{name: "one runner tag over", extraTags: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, bound := platformBOMFrom(bill(tc.extraServices, tc.extraTags))
			if got != nil {
				t.Error("platformBOMFrom returned a section the platform would refuse on bom_edges: the bill is dropped whole, never truncated")
			}
			if bound != "edges > 10000" {
				t.Errorf("bound = %q, want %q", bound, "edges > 10000")
			}
		})
	}
}

// TestBuildPlatformPush_CarriesTheBOM covers the wiring: a run whose
// collections and pipeline model are present pushes a bom built from them,
// with no second collection pass.
//
// The component include's origin below is shaped as the collector records it
// (dataCollectionGitlabPipelineOrigin.go: the component path split into a
// project and a component name), project included. That project is half the
// key the platform builds a component node on (dependencies-graph design spec
// 4.1), so it is asserted on the wire: a component include that reached the
// platform without it was skipped as unkeyable and the component graph came
// back empty.
func TestBuildPlatformPush_CarriesTheBOM(t *testing.T) {
	conf := &configuration.Configuration{GitlabURL: "https://gitlab.example.com", Branch: "main"}
	result := &control.AnalysisResult{
		ProjectPath: "group/app",
		ProjectID:   7,
		PipelineImageData: &gitlab.GitlabPipelineImageData{
			Images: []gitlab.GitlabPipelineImageInfo{
				{Link: "docker.io/node:20", Registry: "docker.io", Name: "node", Tag: "20", Job: "build"},
				{Link: "docker.io/node:20", Registry: "docker.io", Name: "node", Tag: "20", Job: "test"},
			},
		},
		PipelineOriginData: &gitlab.GitlabPipelineOriginData{
			Origins: []gitlab.GitlabPipelineOriginDataFull{{
				GitlabPipelineOriginDataGeneric: gitlab.GitlabPipelineOriginDataGeneric{
					OriginType:        "component",
					FromGitlabCatalog: true,
					GitlabIncludeOrigin: gitlab.IncludeOriginWithoutRef{
						Location: "gitlab.example.com/components/sast/sast",
						Project:  "components/sast",
					},
					GitlabComponent: gitlab.GitlabPipelineJobGitlabComponent{
						ComponentName:          "sast",
						ComponentLatestVersion: "3.4.0",
					},
				},
				GitlabPipelineOriginDataProjectSpecific: gitlab.GitlabPipelineOriginDataProjectSpecific{
					Version: "3.3.0",
				},
			}},
		},
		Pipeline: &ir.NormalizedPipeline{
			Jobs: []ir.Job{{
				Name:     "test",
				Services: []ir.Image{{Name: "docker", Tag: "24.0.5-dind"}},
				Tags:     []string{"docker"},
			}},
		},
	}

	body, err := buildPlatformPush(testProvider(t), conf, result, nil, ".plumber.yaml", nil)
	if err != nil {
		t.Fatalf("buildPlatformPush: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("push does not parse as JSON: %v", err)
	}
	bom, ok := raw["bom"].(map[string]any)
	if !ok {
		t.Fatalf("the push carries no bom section: %s", body)
	}
	if bom["version"] != float64(1) {
		t.Errorf("bom.version = %v, want 1", bom["version"])
	}
	includes, _ := bom["includes"].([]any)
	if len(includes) != 1 {
		t.Fatalf("bom.includes = %v, want one component include", bom["includes"])
	}
	inc, _ := includes[0].(map[string]any)
	if inc["version"] != "3.3.0" || inc["latest_version"] != "3.4.0" {
		t.Errorf("bom.includes[0] versions = %#v / %#v, want 3.3.0 / 3.4.0", inc["version"], inc["latest_version"])
	}
	if inc["project"] != "components/sast" || inc["component_name"] != "sast" {
		t.Errorf("bom.includes[0] key = %#v / %#v, want components/sast / sast: the platform keys a component node on both",
			inc["project"], inc["component_name"])
	}
	images, _ := bom["images"].([]any)
	if len(images) != 1 {
		t.Fatalf("bom.images = %v, want one image", bom["images"])
	}
	img, _ := images[0].(map[string]any)
	if jobs, _ := img["jobs"].([]any); len(jobs) != 2 {
		t.Errorf("bom.images[0].jobs = %#v, want the two jobs that use it", img["jobs"])
	}
	bomJobs, _ := bom["jobs"].([]any)
	if len(bomJobs) != 1 {
		t.Fatalf("bom.jobs = %v, want the one job with a service and a tag", bom["jobs"])
	}
	job, _ := bomJobs[0].(map[string]any)
	if tags, _ := job["runner_tags"].([]any); len(tags) != 1 || tags[0] != "docker" {
		t.Errorf("bom.jobs[0].runner_tags = %#v, want [docker]", job["runner_tags"])
	}
}

// TestBuildPlatformPush_StandaloneImageFlagsComeFromTheFindings pins the
// non-platform path (no policy runs, the row-63 standalone push): the bill's
// image flags are the run's own findings-derived verdicts. A forbidden-tag
// finding on the image's job sets forbidden_tag, an unauthorized-source
// finding clears authorized, and an image the rules judged without a finding
// is published as compliant rather than left without flags.
func TestBuildPlatformPush_StandaloneImageFlagsComeFromTheFindings(t *testing.T) {
	cases := []struct {
		name          string
		findings      []opaengine.Finding
		wantForbidden bool
		wantAuth      bool
	}{
		{name: "no image finding", wantForbidden: false, wantAuth: true},
		{
			name: "forbidden tag and unauthorized source",
			findings: []opaengine.Finding{
				{Code: string(control.CodeImageForbiddenTag), Severity: "high", Message: "floating tag", Job: "build"},
				{Code: string(control.CodeImageUnauthorizedSource), Severity: "high", Message: "untrusted registry", Job: "build"},
			},
			wantForbidden: true,
			wantAuth:      false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conf := &configuration.Configuration{GitlabURL: "https://gitlab.example.com", Branch: "main"}
			result := &control.AnalysisResult{
				ProjectPath: "group/app",
				ProjectID:   7,
				PipelineImageData: &gitlab.GitlabPipelineImageData{
					Images: []gitlab.GitlabPipelineImageInfo{
						{Link: "docker.io/node:latest", Registry: "docker.io", Name: "node", Tag: "latest", Job: "build"},
					},
				},
				Findings: tc.findings,
			}

			body, err := buildPlatformPush(testProvider(t), conf, result, nil, ".plumber.yaml", nil)
			if err != nil {
				t.Fatalf("buildPlatformPush: %v", err)
			}
			var raw struct {
				BOM struct {
					Images []map[string]any `json:"images"`
				} `json:"bom"`
			}
			if err := json.Unmarshal(body, &raw); err != nil {
				t.Fatalf("push does not parse as JSON: %v", err)
			}
			if len(raw.BOM.Images) != 1 {
				t.Fatalf("bom.images = %#v, want the one resolved image", raw.BOM.Images)
			}
			img := raw.BOM.Images[0]
			forbidden, ok := img["forbidden_tag"].(bool)
			if !ok {
				t.Fatalf("bom.images[0].forbidden_tag = %#v, want a boolean: the standalone push publishes the run's own verdict", img["forbidden_tag"])
			}
			if forbidden != tc.wantForbidden {
				t.Errorf("bom.images[0].forbidden_tag = %v, want %v", forbidden, tc.wantForbidden)
			}
			authorized, ok := img["authorized"].(bool)
			if !ok {
				t.Fatalf("bom.images[0].authorized = %#v, want a boolean: the standalone push publishes the run's own verdict", img["authorized"])
			}
			if authorized != tc.wantAuth {
				t.Errorf("bom.images[0].authorized = %v, want %v", authorized, tc.wantAuth)
			}
		})
	}
}

// TestBuildPlatformPush_OmitsTheBOMWhenABoundIsExceeded covers the refusal on
// the wire: the section is absent, and everything else about the push is
// unchanged, so a pipeline too large to describe still reports its results.
func TestBuildPlatformPush_OmitsTheBOMWhenABoundIsExceeded(t *testing.T) {
	conf := &configuration.Configuration{GitlabURL: "https://gitlab.example.com", Branch: "main"}
	origins := make([]gitlab.GitlabPipelineOriginDataFull, 501)
	for i := range origins {
		origins[i].OriginType = "local"
		origins[i].GitlabIncludeOrigin.Location = ".gitlab/ci/" + strconv.Itoa(i) + ".yml"
	}
	result := &control.AnalysisResult{
		ProjectPath:        "group/app",
		PipelineOriginData: &gitlab.GitlabPipelineOriginData{Origins: origins},
	}

	body, err := buildPlatformPush(testProvider(t), conf, result, nil, ".plumber.yaml", nil)
	if err != nil {
		t.Fatalf("buildPlatformPush: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("push does not parse as JSON: %v", err)
	}
	if _, present := raw["bom"]; present {
		t.Errorf("the push carries a bom section past the includes bound: %v", raw["bom"])
	}
	if _, present := raw["results"]; !present {
		t.Error("the refused bill took the results with it: the push must still report the run")
	}
}

// TestBuildPlatformPush_NoBOMWithoutCollections covers the empty case: a push
// built with no collected data at all carries no bom key rather than an empty
// one, which would read as a pipeline that depends on nothing.
func TestBuildPlatformPush_NoBOMWithoutCollections(t *testing.T) {
	body, err := buildPlatformPush(testProvider(t), nil, nil, nil, ".plumber.yaml", nil)
	if err != nil {
		t.Fatalf("buildPlatformPush: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("push does not parse as JSON: %v", err)
	}
	if _, present := raw["bom"]; present {
		t.Errorf("a push with no collected data carries a bom section: %v", raw["bom"])
	}
}

// TestBuildPlatformPush_NoBOMOnADegradedCollection covers the honesty rule
// the whole section rests on: the platform replaces a project's dependency
// edges with the pushed bill as ONE set, so a partial bill would delete edges
// for everything the degraded collection failed to read. A run that could not
// collect completely sends no bill at all and the platform leaves the
// project's dependencies as they were, exactly as an older CLI does.
func TestBuildPlatformPush_NoBOMOnADegradedCollection(t *testing.T) {
	conf := &configuration.Configuration{GitlabURL: "https://gitlab.example.com", Branch: "main"}
	result := &control.AnalysisResult{
		ProjectPath:            "group/app",
		DataCollectionDegraded: true,
		PipelineImageData: &gitlab.GitlabPipelineImageData{
			Images: []gitlab.GitlabPipelineImageInfo{
				{Link: "docker.io/node:20", Registry: "docker.io", Name: "node", Tag: "20", Job: "build"},
			},
		},
	}

	body, err := buildPlatformPush(testProvider(t), conf, result, nil, ".plumber.yaml", nil)
	if err != nil {
		t.Fatalf("buildPlatformPush: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("push does not parse as JSON: %v", err)
	}
	if _, present := raw["bom"]; present {
		t.Errorf("a degraded run pushed a partial bill of materials: %v", raw["bom"])
	}
}

// TestPlatformBOMFrom_DigestPinnedReferencesAreNormalised covers a defect the
// platform would store verbatim and key its graph on. The collector splits an
// image reference on the last colon without knowing about digests, so
// node@sha256:abc lands as name "node@sha256" with tag "abc". The graph's
// image key is <registry>/<name>, so a digest-pinned image would appear under
// a key that names half a digest, and its version edge would carry a bare hex
// string as a tag.
//
// The section reports the parts as they are meant to read: name is the
// repository alone, digest is the whole sha256:<hex>, and tag is empty unless
// the reference carried both. The full reference string stays exactly as the
// collector reported it (invariant I1: the platform stores what the CLI
// said).
func TestPlatformBOMFrom_DigestPinnedReferencesAreNormalised(t *testing.T) {
	for _, tc := range []struct {
		name string
		// The collector's own split, digests and all.
		image      pbom.ContainerImage
		wantName   string
		wantTag    string
		wantDigest string
	}{
		{
			name: "digest only",
			image: pbom.ContainerImage{
				Image:    "docker.io/library/node@sha256:abc",
				Registry: "docker.io",
				Name:     "library/node@sha256",
				Tag:      "abc",
			},
			wantName:   "library/node",
			wantTag:    "",
			wantDigest: "sha256:abc",
		},
		{
			name: "tag and digest",
			image: pbom.ContainerImage{
				Image:    "registry.example/team/app:1.2@sha256:def",
				Registry: "registry.example",
				Name:     "team/app",
				Tag:      "1.2@sha256",
			},
			wantName:   "team/app",
			wantTag:    "1.2",
			wantDigest: "sha256:def",
		},
		{
			name: "no digest at all",
			image: pbom.ContainerImage{
				Image:    "docker.io/node:20",
				Registry: "docker.io",
				Name:     "node",
				Tag:      "20",
			},
			wantName:   "library/node",
			wantTag:    "20",
			wantDigest: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, bound := platformBOMFrom(&pbom.PBOM{ContainerImages: []pbom.ContainerImage{tc.image}})
			if bound != "" || got == nil || len(got.Images) != 1 {
				t.Fatalf("platformBOMFrom refused the fixture on bound %q", bound)
			}
			img := got.Images[0]
			if img.Image != tc.image.Image {
				t.Errorf("image = %q, want %q: the reference string is reported as the collector said it", img.Image, tc.image.Image)
			}
			if img.Registry != tc.image.Registry {
				t.Errorf("registry = %q, want %q", img.Registry, tc.image.Registry)
			}
			if img.Name != tc.wantName {
				t.Errorf("name = %q, want %q", img.Name, tc.wantName)
			}
			if img.Tag != tc.wantTag {
				t.Errorf("tag = %q, want %q", img.Tag, tc.wantTag)
			}
			if img.Digest != tc.wantDigest {
				t.Errorf("digest = %q, want %q", img.Digest, tc.wantDigest)
			}
		})
	}
}

// TestPlatformBOMFrom_ServiceDigestIsNormalisedToo applies the same rule to a
// job's services, which reach the bill through a different collector path
// (the merged configuration's services: block, split on the last colon with
// no registry resolved at all) and would otherwise report a repository name
// ending in @sha256.
func TestPlatformBOMFrom_ServiceDigestIsNormalisedToo(t *testing.T) {
	doc := &pbom.PBOM{Jobs: []pbom.JobResources{{
		Name: "test",
		Services: []pbom.ContainerImageRef{{
			Image: "docker@sha256:abc",
			Name:  "docker@sha256",
			Tag:   "abc",
		}},
	}}}
	got, bound := platformBOMFrom(doc)
	if bound != "" || got == nil || len(got.Jobs) != 1 || len(got.Jobs[0].Services) != 1 {
		t.Fatalf("platformBOMFrom refused the fixture on bound %q", bound)
	}
	svc := got.Jobs[0].Services[0]
	if svc.Image != "docker@sha256:abc" {
		t.Errorf("service image = %q, want the reference as the collector reported it", svc.Image)
	}
	if svc.Name != "library/docker" || svc.Tag != "" || svc.Digest != "sha256:abc" {
		t.Errorf("service ref = %#v, want name library/docker, no tag, digest sha256:abc", svc)
	}
}

// TestPlatformBOMFrom_RegistryPortIsNotADigestTag guards the one shape the
// normalisation could get wrong: a registry host with a port carries a colon
// that is not a tag separator.
func TestPlatformBOMFrom_RegistryPortIsNotADigestTag(t *testing.T) {
	doc := &pbom.PBOM{ContainerImages: []pbom.ContainerImage{{
		Image:    "registry.example:5000/team/app@sha256:abc",
		Registry: "registry.example:5000",
		Name:     "team/app@sha256",
		Tag:      "abc",
	}}}
	got, bound := platformBOMFrom(doc)
	if bound != "" || got == nil || len(got.Images) != 1 {
		t.Fatalf("platformBOMFrom refused the fixture on bound %q", bound)
	}
	img := got.Images[0]
	if img.Name != "team/app" || img.Tag != "" || img.Digest != "sha256:abc" {
		t.Errorf("image = %#v, want name team/app, no tag, digest sha256:abc", img)
	}
}

// TestPlatformBOMFrom_AlwaysEmitsTheThreeArrays pins the one place on this
// wire where absence means zero rather than unknown. The platform replaces a
// project's edges with the pushed bill as ONE set, so an absent includes key
// would have to be read as "delete every include edge" while absence two
// fields away (the bom key itself, a three-state boolean) means "claim
// nothing". The three arrays are always present, empty when empty, so the
// projection never has to guess which convention applies.
func TestPlatformBOMFrom_AlwaysEmitsTheThreeArrays(t *testing.T) {
	got, bound := platformBOMFrom(&pbom.PBOM{})
	if bound != "" || got == nil {
		t.Fatalf("an empty bill was refused on bound %q", bound)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(raw) != `{"version":1,"includes":[],"images":[],"jobs":[]}` {
		t.Errorf("empty bom = %s, want the three arrays present and empty", raw)
	}
}

// TestPlatformBOMFrom_TypeAndLocationAreUnconditional matches the PBOM, which
// emits both without omitempty. An include that arrives with an empty type
// must arrive blank rather than vanish: a key the platform never sees cannot
// be validated, and spec 4.1 keys every include node on its type.
func TestPlatformBOMFrom_TypeAndLocationAreUnconditional(t *testing.T) {
	got, bound := platformBOMFrom(&pbom.PBOM{Includes: []pbom.Include{{}}})
	if bound != "" || got == nil {
		t.Fatalf("refused on bound %q", bound)
	}
	raw, err := json.Marshal(got.Includes[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var inc map[string]any
	if err := json.Unmarshal(raw, &inc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"type", "location"} {
		if _, present := inc[key]; !present {
			t.Errorf("%s is absent from an include that has none: %s", key, raw)
		}
	}
}

// TestPlatformBOMFrom_UnresolvedImagesAreOmitted covers the rule that an
// image reference the run never resolved is not a dependency at all. The
// collector marks a reference that still held a $VARIABLE after substitution;
// its registry, name and tag were parsed out of a placeholder. The platform
// keys its resource nodes on those strings and computes no verdict of its own
// (I1/I2), so pushing one would mint a fleet-wide node named after a variable
// with real consumers attached to it.
//
// The PBOM artifact still lists them, unchanged: it is an inventory of what
// the pipeline declares, placeholders included.
func TestPlatformBOMFrom_UnresolvedImagesAreOmitted(t *testing.T) {
	doc := &pbom.PBOM{ContainerImages: []pbom.ContainerImage{
		{Image: "unknown/$CI_REGISTRY_IMAGE:$TAG", Registry: "unknown", Name: "$CI_REGISTRY_IMAGE", Tag: "$TAG", Jobs: []string{"deploy"}, Unresolved: true},
		{Image: "docker.io/node:20", Registry: "docker.io", Name: "node", Tag: "20", Jobs: []string{"build"}},
	}}
	got, bound := platformBOMFrom(doc)
	if bound != "" || got == nil {
		t.Fatalf("refused on bound %q", bound)
	}
	if len(got.Images) != 1 {
		t.Fatalf("images = %#v, want the placeholder dropped and the literal kept", got.Images)
	}
	if got.Images[0].Name != "library/node" {
		t.Errorf("images[0].name = %q, want library/node", got.Images[0].Name)
	}
}

// TestPlatformBOMFrom_UnresolvedServicesAreOmitted applies the same rule to a
// job's services, by the flag the pipeline model carries and by the reference
// itself: the merged-configuration services reader resolves no variables, so
// an unsubstituted reference reaches the bill looking like a literal.
//
// Dropping the service is only half the rule. A job whose ONLY services were
// placeholders now asks a runner for nothing this run can name, and the
// section lists a job only when it does ask for something: the platform
// replaces a project's edges with the pushed bill as one set and keys nodes
// on what it receives, so a bare {"name":"deploy"} mints a job node with no
// dependency at all. It is also what the PBOM's own projection does, and the
// two documents are kept in agreement deliberately.
//
// `deploy` is the common shape that makes this reachable: a variable-templated
// service image and no tags:.
func TestPlatformBOMFrom_UnresolvedServicesAreOmitted(t *testing.T) {
	doc := &pbom.PBOM{Jobs: []pbom.JobResources{
		{Name: "flagged", Services: []pbom.ContainerImageRef{{Image: "$SVC:latest", Name: "$SVC", Tag: "latest", Unresolved: true}}},
		{Name: "deploy", Services: []pbom.ContainerImageRef{{Image: "$CI_REGISTRY_IMAGE/db:latest", Name: "$CI_REGISTRY_IMAGE/db", Tag: "latest"}}},
		{Name: "tagged", Services: []pbom.ContainerImageRef{{Image: "$CI_REGISTRY/pg:14", Name: "$CI_REGISTRY/pg", Tag: "14"}}, RunnerTags: []string{"docker"}},
		{Name: "literal", Services: []pbom.ContainerImageRef{{Image: "postgres:14", Name: "postgres", Tag: "14"}}},
	}}
	got, bound := platformBOMFrom(doc)
	if bound != "" || got == nil {
		t.Fatalf("refused on bound %q", bound)
	}
	byName := map[string]platformBOMJob{}
	for _, job := range got.Jobs {
		byName[job.Name] = job
	}

	// Nothing left to ask for: the job leaves the bill entirely rather than
	// arriving as a name with no dependency under it.
	for _, name := range []string{"flagged", "deploy"} {
		if _, listed := byName[name]; listed {
			t.Errorf("jobs[%s] = %#v is on the wire although its only services were placeholders", name, byName[name])
		}
	}

	// A runner tag is something the job asks a runner for, so the job stays
	// listed even once its placeholder service is gone, with no service.
	tagged, listed := byName["tagged"]
	if !listed {
		t.Fatalf("jobs = %#v, want the job with a runner tag kept", got.Jobs)
	}
	if len(tagged.Services) != 0 {
		t.Errorf("jobs[tagged].services = %#v, want the placeholder dropped", tagged.Services)
	}
	if !reflect.DeepEqual(tagged.RunnerTags, []string{"docker"}) {
		t.Errorf("jobs[tagged].runner_tags = %#v, want [docker]", tagged.RunnerTags)
	}

	if len(byName["literal"].Services) != 1 {
		t.Fatalf("jobs[literal].services = %#v, want the literal kept", byName["literal"].Services)
	}
}

// TestPlatformBOMFrom_BareNameGetsTheDockerHubNamespace is the point of
// putting every reference through one normalisation: `postgres` as a job
// image and `postgres` as a job service are the same upstream, so they must
// reach the platform as the same <registry>/<name> key. Docker Hub's official
// images live under library/, which is what makes the two agree.
func TestPlatformBOMFrom_BareNameGetsTheDockerHubNamespace(t *testing.T) {
	doc := &pbom.PBOM{
		ContainerImages: []pbom.ContainerImage{{Image: "docker.io/postgres:14", Registry: "docker.io", Name: "postgres", Tag: "14", Jobs: []string{"build"}}},
		Jobs:            []pbom.JobResources{{Name: "test", Services: []pbom.ContainerImageRef{{Image: "postgres:14", Name: "postgres", Tag: "14"}}}},
	}
	got, bound := platformBOMFrom(doc)
	if bound != "" || got == nil {
		t.Fatalf("refused on bound %q", bound)
	}
	img := got.Images[0]
	svc := got.Jobs[0].Services[0]
	if img.Registry != "docker.io" || img.Name != "library/postgres" || img.Tag != "14" {
		t.Errorf("image = %#v, want docker.io + library/postgres + 14", img)
	}
	if svc.Registry != "docker.io" || svc.Name != "library/postgres" || svc.Tag != "14" {
		t.Errorf("service = %#v, want docker.io + library/postgres + 14", svc)
	}
	if img.Registry+"/"+img.Name != svc.Registry+"/"+svc.Name {
		t.Errorf("the job image keys %q and the service keys %q: the same upstream must be one node", img.Registry+"/"+img.Name, svc.Registry+"/"+svc.Name)
	}
}

// TestPlatformBOMFrom_ServiceRegistryWithAPortIsKeptWhole covers the shape the
// services reader gets wrong on its own: it splits on the last colon of the
// whole reference, so registry.example.com:5000/postgres lands as the name
// registry.example.com with the tag 5000/postgres. On the wire the host keeps
// its port and the repository is the repository.
func TestPlatformBOMFrom_ServiceRegistryWithAPortIsKeptWhole(t *testing.T) {
	doc := &pbom.PBOM{Jobs: []pbom.JobResources{{
		Name:     "test",
		Services: []pbom.ContainerImageRef{{Image: "registry.example.com:5000/postgres", Name: "registry.example.com", Tag: "5000/postgres"}},
	}}}
	got, bound := platformBOMFrom(doc)
	if bound != "" || got == nil {
		t.Fatalf("refused on bound %q", bound)
	}
	svc := got.Jobs[0].Services[0]
	if svc.Registry != "registry.example.com:5000" || svc.Name != "postgres" || svc.Tag != "" {
		t.Errorf("service = %#v, want registry.example.com:5000 + postgres and no tag", svc)
	}
	if svc.Image != "registry.example.com:5000/postgres" {
		t.Errorf("service image = %q, want the reference as the collector reported it", svc.Image)
	}
}

// TestPlatformBOMFrom_DocumentSizeCap covers the ninth bound of the spec's
// sizing rule (section 4.4): the stored document is capped at 256 KiB, and a
// bill can sit inside every count, length and product bound and still be
// megabytes.
// The platform refuses an oversized push whole, which would cost the run its
// results, its findings and its score; refusing the section here costs it
// only the bill.
func TestPlatformBOMFrom_DocumentSizeCap(t *testing.T) {
	// 500 jobs of 19 services each: inside jobs > 500, inside services per
	// job > 64, every string far inside 512 runes, 9500 edges so inside the
	// product bound too, and megabytes of JSON. The service count is picked
	// to leave the edge bound untripped on purpose: this test is about the
	// one bound that cannot be reached by counting anything.
	const servicesPerJob = 19
	if bomMaxJobs*servicesPerJob > bomMaxEdges {
		t.Fatalf("the fixture projects %d edges, over the %d the product bound allows: it would trip that bound instead", bomMaxJobs*servicesPerJob, bomMaxEdges)
	}
	jobs := make([]pbom.JobResources, bomMaxJobs)
	for i := range jobs {
		jobs[i].Name = "job-" + strconv.Itoa(i)
		jobs[i].Services = make([]pbom.ContainerImageRef, servicesPerJob)
		for j := range jobs[i].Services {
			ref := "registry.example.com/team/service-" + strconv.Itoa(i) + "-" + strconv.Itoa(j) + ":1.0"
			jobs[i].Services[j] = pbom.ContainerImageRef{Image: ref, Registry: "registry.example.com", Name: "team/service", Tag: "1.0"}
		}
	}
	got, bound := platformBOMFrom(&pbom.PBOM{Jobs: jobs})
	if got != nil {
		t.Error("platformBOMFrom returned an oversized section: the bill is dropped whole, never truncated")
	}
	if bound != "document > 256 KiB" {
		t.Errorf("bound = %q, want %q", bound, "document > 256 KiB")
	}
}

// imagePolicyRun builds one APPLIED policy run over a configuration written
// inline, so a test can say exactly which controls the resolved policy
// enables. That is the only input platformImageControlsEvaluated reads, and
// it is what decides which per-image booleans the bill may carry.
func imagePolicyRun(t *testing.T, name, configYAML string) policyRun {
	t.Helper()
	pc, _, _, err := configuration.LoadPlumberConfigFromBytes([]byte(configYAML), name)
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return policyRun{
		Policies: []platform.Policy{{ID: "1111", Name: name, Enforcement: platform.EnforcementReport}},
		Config:   pc,
		Result:   &control.AnalysisResult{},
		Applied:  true,
	}
}

// imageBOMResult is a completely collected run carrying one literal image, so
// the bill has an images[] entry whose flags are the thing under test.
func imageBOMResult() *control.AnalysisResult {
	return &control.AnalysisResult{
		ProjectPath: "group/app",
		ProjectID:   7,
		PipelineImageData: &gitlab.GitlabPipelineImageData{
			Images: []gitlab.GitlabPipelineImageInfo{
				{Link: "docker.io/node:20", Registry: "docker.io", Name: "node", Tag: "20", Job: "build"},
			},
		},
	}
}

// pushedBOMImage builds a platform-mode push over the given policy runs and
// returns the bill's single image, decoded from the RAW wire bytes: the point
// of the assertion is which KEYS reach the platform, and a decode back into
// this package's own types would pass on an omitted pointer.
func pushedBOMImage(t *testing.T, runs []policyRun) map[string]any {
	t.Helper()
	conf := &configuration.Configuration{GitlabURL: "https://gitlab.example.com", Branch: "main"}
	body, err := buildPlatformPush(testProvider(t), conf, imageBOMResult(), nil, ".plumber.yaml", runs)
	if err != nil {
		t.Fatalf("buildPlatformPush: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("push does not parse as JSON: %v", err)
	}
	bom, ok := raw["bom"].(map[string]any)
	if !ok {
		t.Fatalf("the platform-mode push carries no bom section: %s", body)
	}
	images, _ := bom["images"].([]any)
	if len(images) != 1 {
		t.Fatalf("bom.images = %v, want the one collected image", bom["images"])
	}
	img, _ := images[0].(map[string]any)
	return img
}

// TestBuildPlatformPush_PlatformModeBOMCarriesOnlyTheEvaluatedImageFlag covers
// the platform-mode branch of the bill builder, which only runs when the push
// carries policy runs: the image flags are then the POLICIES' own, gated by
// which image control any applied policy actually enables.
//
// The two flags are two independent claims. A policy that pins tags without
// restricting registries evaluated the forbidden-tag control and nothing
// else, so the bill may say whether the tag is forbidden and may NOT say the
// image is authorized. Publishing authorized:true there would mint a
// compliance claim no control ever made, on every consumer of the fleet-wide
// dependency graph, and the platform computes no verdict of its own to catch
// it (I1/I2).
func TestBuildPlatformPush_PlatformModeBOMCarriesOnlyTheEvaluatedImageFlag(t *testing.T) {
	runs := []policyRun{imagePolicyRun(t, "tags-only",
		"version: \"2.0\"\ngitlab:\n  controls:\n    containerImageMustNotUseForbiddenTags:\n      enabled: true\n      tags:\n        - latest\n")}

	img := pushedBOMImage(t, runs)

	if _, present := img["forbidden_tag"]; !present {
		t.Errorf("forbidden_tag is absent from the bill although a resolved policy enables that control: %#v", img)
	}
	if _, present := img["authorized"]; present {
		t.Errorf("authorized = %#v reached the bill although no resolved policy enables the authorized-sources control: the bill would claim a verdict nobody computed", img["authorized"])
	}
}

// TestBuildPlatformPush_PlatformModeBOMOmitsBothFlagsWhenNoImageControlRan is
// the other half of the same rule: a policy that enables neither image control
// evaluated neither claim, so the bill reports the image as inventory alone.
// Absence here is the honest answer, not a default.
func TestBuildPlatformPush_PlatformModeBOMOmitsBothFlagsWhenNoImageControlRan(t *testing.T) {
	runs := []policyRun{imagePolicyRun(t, "branches-only",
		"version: \"2.0\"\ngitlab:\n  controls:\n    branchMustBeProtected:\n      enabled: true\n")}

	img := pushedBOMImage(t, runs)

	for _, flag := range []string{"forbidden_tag", "authorized"} {
		if _, present := img[flag]; present {
			t.Errorf("%s = %#v reached the bill although no resolved policy enables an image control", flag, img[flag])
		}
	}
	// The image itself is still reported: the run collected it, and the
	// inventory is a fact independent of any verdict.
	if img["image"] != "docker.io/node:20" {
		t.Errorf("image = %#v, want the collected reference reported as inventory", img["image"])
	}
}

// ---------------------------------------------------------------------------
// The bill-of-materials branch sweep.
//
// Three rounds of PR review found three separate branches of this mapping that
// no test pinned, each time the same class of gap: a guard that kept a
// garbage node off the wire, holding by accident rather than by contract. The
// tables below enumerate every branch of bomNormalizeRef, platformBOMFrom,
// platformBOMBound, bomStringBound and platformBOMDocument, so the class is
// closed rather than patched one finding at a time.
//
// The one branch not reachable from a test is the marshal failure in
// platformBOMFrom ("document not serialisable"): every type in the section is
// a plain struct of strings, bools, pointers to bools and slices of those, so
// encoding/json cannot fail on it. It is kept as an honest refusal rather
// than an ignored error.
// ---------------------------------------------------------------------------

// TestBomNormalizeRef_EveryBranch pins the one normalisation every reference
// on the wire goes through, branch by branch: the three refusals, the digest
// split, the registry detection (dot, port, neither, none, leading slash,
// Docker Hub alias), the tag split, and the library/ namespace rule with each
// of its three outcomes.
//
// The empty-name refusal is the one this table exists for. A service authored
// as nothing but a tag (`services: [":latest"]`) and an image that is nothing
// but a registry host with a trailing slash both leave the repository empty
// after the split; without the guard the Docker Hub branch would prepend
// `library/` to nothing and the bill would key a fleet-wide node on
// `docker.io/library/`, which is the node-keyed-on-nothing the whole section
// is written to prevent.
func TestBomNormalizeRef_EveryBranch(t *testing.T) {
	for _, tc := range []struct {
		name       string
		image      string
		unresolved bool
		wantOK     bool
		want       bomRef
	}{
		{
			name:   "refused: the reference is empty",
			image:  "",
			wantOK: false,
		},
		{
			name:   "refused: the reference is only whitespace",
			image:  "   ",
			wantOK: false,
		},
		{
			name:       "refused: the collector marked it unresolved",
			image:      "unknown/placeholder:1",
			unresolved: true,
			wantOK:     false,
		},
		{
			name:   "refused: the reference still holds a variable",
			image:  "$CI_REGISTRY_IMAGE/db:latest",
			wantOK: false,
		},
		{
			name:   "refused: nothing but a tag leaves no repository",
			image:  ":latest",
			wantOK: false,
		},
		{
			name:   "refused: a registry host with a trailing slash leaves no repository",
			image:  "registry.internal/",
			wantOK: false,
		},
		{
			name:   "registry by dot, tag split, library namespace added",
			image:  "docker.io/node:20",
			wantOK: true,
			want:   bomRef{Image: "docker.io/node:20", Registry: "docker.io", Name: "library/node", Tag: "20"},
		},
		{
			name:   "no registry segment at all: Docker Hub, library namespace added",
			image:  "postgres:14",
			wantOK: true,
			want:   bomRef{Image: "postgres:14", Registry: "docker.io", Name: "library/postgres", Tag: "14"},
		},
		{
			name:   "a first segment that is not a host stays part of the repository",
			image:  "myorg/app:1.2",
			wantOK: true,
			want:   bomRef{Image: "myorg/app:1.2", Registry: "docker.io", Name: "myorg/app", Tag: "1.2"},
		},
		{
			name:   "registry by port, no tag",
			image:  "registry.example.com:5000/postgres",
			wantOK: true,
			want:   bomRef{Image: "registry.example.com:5000/postgres", Registry: "registry.example.com:5000", Name: "postgres"},
		},
		{
			name:   "a Docker Hub host alias folds to the canonical host",
			image:  "index.docker.io/library/redis:7",
			wantOK: true,
			want:   bomRef{Image: "index.docker.io/library/redis:7", Registry: "docker.io", Name: "library/redis", Tag: "7"},
		},
		{
			name:   "digest only: no tag, the repository keeps its namespace",
			image:  "docker.io/library/node@sha256:abc",
			wantOK: true,
			want:   bomRef{Image: "docker.io/library/node@sha256:abc", Registry: "docker.io", Name: "library/node", Digest: "sha256:abc"},
		},
		{
			name:   "tag and digest together",
			image:  "registry.example/team/app:1.2@sha256:def",
			wantOK: true,
			want:   bomRef{Image: "registry.example/team/app:1.2@sha256:def", Registry: "registry.example", Name: "team/app", Tag: "1.2", Digest: "sha256:def"},
		},
		{
			name:   "a port in the host is not a tag, digest and all",
			image:  "registry.example:5000/team/app@sha256:abc",
			wantOK: true,
			want:   bomRef{Image: "registry.example:5000/team/app@sha256:abc", Registry: "registry.example:5000", Name: "team/app", Digest: "sha256:abc"},
		},
		{
			name:   "a non-Hub registry never gets the library namespace",
			image:  "ghcr.io/tool:1",
			wantOK: true,
			want:   bomRef{Image: "ghcr.io/tool:1", Registry: "ghcr.io", Name: "tool", Tag: "1"},
		},
		{
			// The reference STRING is reported as the collector gave it,
			// whitespace included: only the parsing is done on the trimmed
			// value. Nothing the CLI said is rewritten (I1).
			name:   "surrounding whitespace is parsed away but not rewritten",
			image:  " docker.io/node:20 ",
			wantOK: true,
			want:   bomRef{Image: " docker.io/node:20 ", Registry: "docker.io", Name: "library/node", Tag: "20"},
		},
		{
			// A leading slash is not a registry segment, so the whole string
			// is the repository. The image collector's own parser produces
			// the same shape for this input, and reporting what the CLI
			// parsed is the rule (I1); it is pinned here so a change to
			// either side shows up as a diff rather than as a silent
			// divergence between the two.
			name:   "a leading slash is kept in the repository, matching the collector",
			image:  "/postgres",
			wantOK: true,
			want:   bomRef{Image: "/postgres", Registry: "docker.io", Name: "/postgres"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := bomNormalizeRef(tc.image, tc.unresolved)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (ref %#v)", ok, tc.wantOK, got)
			}
			if !ok {
				if got != (bomRef{}) {
					t.Errorf("a refused reference returned %#v, want the zero value so no caller can use half of it", got)
				}
				return
			}
			if got != tc.want {
				t.Errorf("ref = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// TestPlatformBOMFrom_EmptyNameReferencesAreDropped is the thread's own case,
// asserted where it matters: through the section rather than on the helper.
// An image and a service that both normalise to no repository are absent, and
// the job whose only service was one of them is not listed at all.
func TestPlatformBOMFrom_EmptyNameReferencesAreDropped(t *testing.T) {
	doc := &pbom.PBOM{
		ContainerImages: []pbom.ContainerImage{
			{Image: "registry.internal/", Name: "", Jobs: []string{"build"}},
			{Image: "docker.io/node:20", Registry: "docker.io", Name: "node", Jobs: []string{"build"}},
		},
		Jobs: []pbom.JobResources{
			{Name: "tag-only-service", Services: []pbom.ContainerImageRef{{Image: ":latest", Name: ":latest"}}},
			{Name: "real", Services: []pbom.ContainerImageRef{{Image: "postgres:14", Name: "postgres", Tag: "14"}}},
		},
	}
	got, bound := platformBOMFrom(doc)
	if bound != "" || got == nil {
		t.Fatalf("refused on bound %q", bound)
	}
	if len(got.Images) != 1 || got.Images[0].Name != "library/node" {
		t.Errorf("images = %#v, want only the image that names a repository", got.Images)
	}
	if len(got.Jobs) != 1 || got.Jobs[0].Name != "real" {
		t.Errorf("jobs = %#v, want only the job left with a service that names a repository", got.Jobs)
	}
}

// TestPlatformBOMFrom_NilDocument pins the one remaining early return: no
// document is no bill, and it is NOT a bound refusal, so the caller stays
// silent rather than warning about a limit nothing exceeded.
func TestPlatformBOMFrom_NilDocument(t *testing.T) {
	got, bound := platformBOMFrom(nil)
	if got != nil || bound != "" {
		t.Errorf("platformBOMFrom(nil) = %#v, %q, want nil and no bound", got, bound)
	}
}

// TestPlatformBOMFrom_TriStateBooleansOnTheWire pins each of the five
// pointer-valued flags in both states. They are the section's only three-state
// fields: a flag no control determined must be ABSENT, never false, because
// false is a verdict and absence is the refusal to give one.
func TestPlatformBOMFrom_TriStateBooleansOnTheWire(t *testing.T) {
	yes, no := true, false
	doc := &pbom.PBOM{
		Includes: []pbom.Include{
			{Type: "component", Location: "a", UpToDate: &no, Archived: &yes, HasCVE: &no},
			{Type: "component", Location: "b"},
		},
		ContainerImages: []pbom.ContainerImage{
			{Image: "docker.io/a:1", Authorized: &yes, ForbiddenTag: &no},
			{Image: "docker.io/b:1"},
		},
	}
	got, bound := platformBOMFrom(doc)
	if bound != "" || got == nil {
		t.Fatalf("refused on bound %q", bound)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded struct {
		Includes []map[string]any `json:"includes"`
		Images   []map[string]any `json:"images"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	determined, undetermined := decoded.Includes[0], decoded.Includes[1]
	for key, want := range map[string]any{"up_to_date": false, "archived": true, "has_cve": false} {
		if determined[key] != want {
			t.Errorf("includes[0].%s = %#v, want %#v", key, determined[key], want)
		}
		if _, present := undetermined[key]; present {
			t.Errorf("includes[1].%s = %#v is on the wire although nothing determined it", key, undetermined[key])
		}
	}

	flagged, unflagged := decoded.Images[0], decoded.Images[1]
	for key, want := range map[string]any{"authorized": true, "forbidden_tag": false} {
		if flagged[key] != want {
			t.Errorf("images[0].%s = %#v, want %#v", key, flagged[key], want)
		}
		if _, present := unflagged[key]; present {
			t.Errorf("images[1].%s = %#v is on the wire although no control evaluated it", key, unflagged[key])
		}
	}
}

// TestPlatformBOMFrom_OverriddenJobsShapeAndAbsence pins both sides of the
// one nested array: an include that names overridden jobs carries them under
// the spec's own keys, and one that names none carries no key at all.
func TestPlatformBOMFrom_OverriddenJobsShapeAndAbsence(t *testing.T) {
	doc := &pbom.PBOM{Includes: []pbom.Include{
		{Type: "component", Location: "a", Overridden: true, OverriddenJobs: []utils.OverriddenJobDetail{{JobName: "sast", OverriddenKeys: []string{"script", "image"}}}},
		{Type: "component", Location: "b"},
	}}
	got, bound := platformBOMFrom(doc)
	if bound != "" || got == nil {
		t.Fatalf("refused on bound %q", bound)
	}
	if len(got.Includes[0].OverriddenJobs) != 1 {
		t.Fatalf("includes[0].overridden_jobs = %#v, want one entry", got.Includes[0].OverriddenJobs)
	}
	ov := got.Includes[0].OverriddenJobs[0]
	if ov.Job != "sast" || !reflect.DeepEqual(ov.Keys, []string{"script", "image"}) {
		t.Errorf("overridden_jobs[0] = %#v, want sast with its two keys", ov)
	}
	if got.Includes[1].OverriddenJobs != nil {
		t.Errorf("includes[1].overridden_jobs = %#v, want nil so the key stays off the wire", got.Includes[1].OverriddenJobs)
	}
}

// TestPlatformBOMBound_EveryStringField walks the string bound over every
// field the section puts on the wire. The bound exists so the platform never
// refuses a whole push over one long string, which means it has to cover
// EVERY string, not the three the earlier tests happened to name: a field
// added to the walker without its check is exactly the gap that costs a run
// its results.
//
// A reference's registry, name, tag and digest are DERIVED from the reference
// on the way to the wire, so the long string goes into the reference at the
// position that lands in the field under test. Putting it in the document's
// own registry/name/tag fields would test nothing: those values never leave
// the document.
func TestPlatformBOMBound_EveryStringField(t *testing.T) {
	long := strings.Repeat("a", bomMaxStringRunes+1)
	const wantString = "string > 512 runes"

	for _, tc := range []struct {
		name string
		doc  *pbom.PBOM
	}{
		{"include type", &pbom.PBOM{Includes: []pbom.Include{{Type: long}}}},
		{"include location", &pbom.PBOM{Includes: []pbom.Include{{Type: "local", Location: long}}}},
		{"include project", &pbom.PBOM{Includes: []pbom.Include{{Type: "project", Project: long}}}},
		{"include version", &pbom.PBOM{Includes: []pbom.Include{{Type: "component", Version: long}}}},
		{"include latest version", &pbom.PBOM{Includes: []pbom.Include{{Type: "component", LatestVersion: long}}}},
		{"include component name", &pbom.PBOM{Includes: []pbom.Include{{Type: "component", ComponentName: long}}}},
		{"include advisory", &pbom.PBOM{Includes: []pbom.Include{{Type: "component", Advisories: []string{long}}}}},
		{"overridden job name", &pbom.PBOM{Includes: []pbom.Include{{Type: "component", OverriddenJobs: []utils.OverriddenJobDetail{{JobName: long}}}}}},
		{"overridden job key", &pbom.PBOM{Includes: []pbom.Include{{Type: "component", OverriddenJobs: []utils.OverriddenJobDetail{{JobName: "a", OverriddenKeys: []string{long}}}}}}},
		{"image reference", &pbom.PBOM{ContainerImages: []pbom.ContainerImage{{Image: long}}}},
		{"image registry", &pbom.PBOM{ContainerImages: []pbom.ContainerImage{{Image: long + ".io/app:1"}}}},
		{"image name", &pbom.PBOM{ContainerImages: []pbom.ContainerImage{{Image: "docker.io/" + long + ":1"}}}},
		{"image tag", &pbom.PBOM{ContainerImages: []pbom.ContainerImage{{Image: "docker.io/app:" + long}}}},
		{"image digest", &pbom.PBOM{ContainerImages: []pbom.ContainerImage{{Image: "docker.io/app@" + long}}}},
		{"image job name", &pbom.PBOM{ContainerImages: []pbom.ContainerImage{{Image: "docker.io/app:1", Jobs: []string{long}}}}},
		{"job name", &pbom.PBOM{Jobs: []pbom.JobResources{{Name: long, RunnerTags: []string{"docker"}}}}},
		{"runner tag", &pbom.PBOM{Jobs: []pbom.JobResources{{Name: "test", RunnerTags: []string{long}}}}},
		{"service reference", &pbom.PBOM{Jobs: []pbom.JobResources{{Name: "test", Services: []pbom.ContainerImageRef{{Image: long}}}}}},
		{"service registry", &pbom.PBOM{Jobs: []pbom.JobResources{{Name: "test", Services: []pbom.ContainerImageRef{{Image: long + ".io/app:1"}}}}}},
		{"service name", &pbom.PBOM{Jobs: []pbom.JobResources{{Name: "test", Services: []pbom.ContainerImageRef{{Image: "docker.io/" + long + ":1"}}}}}},
		{"service tag", &pbom.PBOM{Jobs: []pbom.JobResources{{Name: "test", Services: []pbom.ContainerImageRef{{Image: "docker.io/app:" + long}}}}}},
		{"service digest", &pbom.PBOM{Jobs: []pbom.JobResources{{Name: "test", Services: []pbom.ContainerImageRef{{Image: "docker.io/app@" + long}}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, bound := platformBOMFrom(tc.doc)
			if got != nil {
				t.Error("an over-long string still produced a section: the bill is dropped whole, never truncated")
			}
			if bound != wantString {
				t.Errorf("bound = %q, want %q", bound, wantString)
			}
		})
	}
}

// TestPlatformBOMBound_CountsAreInclusive pins the bounds at their own edge.
// The spec says "at most 500", so exactly 500 is legal, and an off-by-one in
// either direction is a real failure: one way the CLI drops bills the
// platform would have taken, the other way it sends bills the platform
// refuses and the run loses everything.
func TestPlatformBOMBound_CountsAreInclusive(t *testing.T) {
	services := bomTestServices(bomMaxServicesPerJob)
	for _, tc := range []struct {
		name string
		doc  *pbom.PBOM
	}{
		{"exactly 500 includes", &pbom.PBOM{Includes: make([]pbom.Include, bomMaxIncludes)}},
		{"exactly 500 images", &pbom.PBOM{ContainerImages: bomTestImages(bomMaxImages)}},
		{"exactly 500 jobs", &pbom.PBOM{Jobs: bomTestJobs(bomMaxJobs)}},
		{"exactly 500 jobs on one image", &pbom.PBOM{ContainerImages: []pbom.ContainerImage{{Image: "docker.io/node:20", Jobs: make([]string, bomMaxJobsPerImage)}}}},
		{"exactly 64 services on one job", &pbom.PBOM{Jobs: []pbom.JobResources{{Name: "test", Services: services}}}},
		{"exactly 32 runner tags on one job", &pbom.PBOM{Jobs: []pbom.JobResources{{Name: "test", RunnerTags: make([]string, bomMaxRunnerTagsPerJob)}}}},
		{"exactly 50 advisories on one include", &pbom.PBOM{Includes: []pbom.Include{{Type: "component", Advisories: make([]string, bomMaxAdvisories)}}}},
		{"exactly 512 runes", &pbom.PBOM{Includes: []pbom.Include{{Type: "local", Location: strings.Repeat("a", bomMaxStringRunes)}}}},
		{"exactly 1024 runes of remote URL", &pbom.PBOM{Includes: []pbom.Include{{Type: "remote", Location: strings.Repeat("u", bomMaxRemoteURLRunes)}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, bound := platformBOMFrom(tc.doc)
			if bound != "" || got == nil {
				t.Errorf("a document exactly at the bound was refused on %q", bound)
			}
		})
	}
}

// TestPlatformBOMBound_CountsRunesNotBytes pins the unit. A location of 512
// multi-byte runes is 1536 bytes and is legal; counting bytes would refuse a
// bill that fits, and the platform counts runes.
func TestPlatformBOMBound_CountsRunesNotBytes(t *testing.T) {
	wide := strings.Repeat("éè", bomMaxStringRunes/2) // 512 runes, 1024 bytes
	if _, bound := platformBOMFrom(&pbom.PBOM{Includes: []pbom.Include{{Type: "local", Location: wide}}}); bound != "" {
		t.Errorf("512 multi-byte runes were refused on %q: the bound counts runes, not bytes", bound)
	}
	over := wide + "é"
	if _, bound := platformBOMFrom(&pbom.PBOM{Includes: []pbom.Include{{Type: "local", Location: over}}}); bound != "string > 512 runes" {
		t.Errorf("513 multi-byte runes were accepted (bound %q)", bound)
	}
}

// TestPlatformBOMDocument_EveryRefusal pins the guards that decide whether a
// run may describe its dependencies at all. Each of them exists because the
// platform replaces a project's edges with the pushed bill as ONE set, so a
// bill built on nothing, on half a collection, or on a provider this generator
// cannot read would delete real edges.
func TestPlatformBOMDocument_EveryRefusal(t *testing.T) {
	collected := func() *control.AnalysisResult {
		return &control.AnalysisResult{
			ProjectPath: "group/app",
			PipelineImageData: &gitlab.GitlabPipelineImageData{
				Images: []gitlab.GitlabPipelineImageInfo{{Link: "docker.io/node:20", Registry: "docker.io", Name: "node", Tag: "20", Job: "build"}},
			},
		}
	}
	conf := &configuration.Configuration{GitlabURL: "https://gitlab.example.com", Branch: "main"}

	if doc := platformBOMDocument(nil, conf, collected(), nil); doc != nil {
		t.Error("a nil provider produced a bill: there is no pipeline to describe")
	}
	if p, ok := providerPkg.Get("github"); ok {
		if doc := platformBOMDocument(p, conf, collected(), nil); doc != nil {
			t.Error("the GitHub path produced a bill: the platform models no GitHub resource and this generator reads GitLab collections")
		}
	}
	if doc := platformBOMDocument(testProvider(t), conf, nil, nil); doc != nil {
		t.Error("a nil result produced a bill")
	}
	degraded := collected()
	degraded.DataCollectionDegraded = true
	if doc := platformBOMDocument(testProvider(t), conf, degraded, nil); doc != nil {
		t.Error("a degraded run produced a bill: a partial bill deletes the edges the run failed to read")
	}
	if doc := platformBOMDocument(testProvider(t), conf, &control.AnalysisResult{ProjectPath: "group/app"}, nil); doc != nil {
		t.Error("a run with no collection at all produced a bill: it knows nothing about the pipeline rather than knowing it depends on nothing")
	}

	// The accepting case, with a nil conf: the bill does not read the
	// project stamp, so a caller without one still gets its dependencies.
	if doc := platformBOMDocument(testProvider(t), nil, collected(), nil); doc == nil {
		t.Error("a collected run with no conf produced no bill")
	}
}

// TestPlatformBOMDocument_NoControlsClaimsNoVerdict pins the --no-controls
// path through the bill: nothing was evaluated, so the inventory is reported
// and not one per-image flag is.
func TestPlatformBOMDocument_NoControlsClaimsNoVerdict(t *testing.T) {
	result := &control.AnalysisResult{
		ProjectPath: "group/app",
		PipelineImageData: &gitlab.GitlabPipelineImageData{
			Images: []gitlab.GitlabPipelineImageInfo{{Link: "docker.io/node:20", Registry: "docker.io", Name: "node", Tag: "20", Job: "build"}},
		},
	}
	conf := &configuration.Configuration{GitlabURL: "https://gitlab.example.com", Branch: "main", NoControls: true}

	doc := platformBOMDocument(testProvider(t), conf, result, nil)
	if doc == nil {
		t.Fatal("--no-controls produced no bill: the inventory is a collected fact, independent of any control")
	}
	got, bound := platformBOMFrom(doc)
	if bound != "" || got == nil {
		t.Fatalf("refused on bound %q", bound)
	}
	if len(got.Images) != 1 {
		t.Fatalf("images = %#v, want the collected image", got.Images)
	}
	if got.Images[0].Authorized != nil || got.Images[0].ForbiddenTag != nil {
		t.Errorf("image = %#v, want both flags nil under --no-controls: nothing was evaluated", got.Images[0])
	}
}

// TestPlatformBOMFrom_BoundsMeasureTheEmittedSection covers the order the
// bounds and the filtering run in. The bounds exist so the CLI never builds a
// bill the platform will refuse, which means they have to measure the section
// that actually goes on the wire: the filtering drops unresolved references
// and the jobs those emptied out, so a document over a bound can emit a
// section inside it.
//
// Measuring the raw document instead refuses a bill the platform would have
// taken, and that is not a harmless extra caution: the push still goes, so
// the platform keeps the project's stale dependency edges rather than the
// bill this run actually collected.
func TestPlatformBOMFrom_BoundsMeasureTheEmittedSection(t *testing.T) {
	t.Run("a placeholder-only job does not push the job count over", func(t *testing.T) {
		// 500 jobs that reach the wire, plus one whose only service is a
		// variable-templated reference and which names no runner tag, so the
		// filtering drops it entirely.
		jobs := make([]pbom.JobResources, 0, bomMaxJobs+1)
		for i := 0; i < bomMaxJobs; i++ {
			jobs = append(jobs, pbom.JobResources{Name: "job-" + strconv.Itoa(i), RunnerTags: []string{"docker"}})
		}
		jobs = append(jobs, pbom.JobResources{
			Name:     "placeholder-only",
			Services: []pbom.ContainerImageRef{{Image: "$CI_REGISTRY_IMAGE/db", Name: "$CI_REGISTRY_IMAGE/db"}},
		})

		got, bound := platformBOMFrom(&pbom.PBOM{Jobs: jobs})
		if bound != "" {
			t.Fatalf("bound = %q, want none: the emitted section holds %d jobs, which the platform accepts", bound, bomMaxJobs)
		}
		if len(got.Jobs) != bomMaxJobs {
			t.Fatalf("jobs = %d, want %d", len(got.Jobs), bomMaxJobs)
		}
	})

	t.Run("an unresolved image does not push the image count over", func(t *testing.T) {
		images := make([]pbom.ContainerImage, 0, bomMaxImages+1)
		for i := 0; i < bomMaxImages; i++ {
			images = append(images, pbom.ContainerImage{Image: "docker.io/team/app-" + strconv.Itoa(i) + ":1.0"})
		}
		images = append(images, pbom.ContainerImage{
			Image:      "unknown/$CI_REGISTRY_IMAGE:$TAG",
			Name:       "$CI_REGISTRY_IMAGE",
			Unresolved: true,
		})

		got, bound := platformBOMFrom(&pbom.PBOM{ContainerImages: images})
		if bound != "" {
			t.Fatalf("bound = %q, want none: the emitted section holds %d images, which the platform accepts", bound, bomMaxImages)
		}
		if len(got.Images) != bomMaxImages {
			t.Fatalf("images = %d, want %d", len(got.Images), bomMaxImages)
		}
	})

	t.Run("an unresolved service does not push the per-job service count over", func(t *testing.T) {
		services := make([]pbom.ContainerImageRef, 0, bomMaxServicesPerJob+1)
		for i := 0; i < bomMaxServicesPerJob; i++ {
			services = append(services, pbom.ContainerImageRef{Image: "docker.io/team/svc-" + strconv.Itoa(i) + ":1.0"})
		}
		services = append(services, pbom.ContainerImageRef{Image: "$SVC:latest", Name: "$SVC"})

		got, bound := platformBOMFrom(&pbom.PBOM{Jobs: []pbom.JobResources{{Name: "test", Services: services}}})
		if bound != "" {
			t.Fatalf("bound = %q, want none: the emitted job holds %d services, which the platform accepts", bound, bomMaxServicesPerJob)
		}
		if len(got.Jobs[0].Services) != bomMaxServicesPerJob {
			t.Fatalf("services = %d, want %d", len(got.Jobs[0].Services), bomMaxServicesPerJob)
		}
	})

	t.Run("a genuinely oversized section is still refused", func(t *testing.T) {
		// The control: once the filtering has run, 501 jobs are 501 jobs.
		jobs := make([]pbom.JobResources, 0, bomMaxJobs+1)
		for i := 0; i <= bomMaxJobs; i++ {
			jobs = append(jobs, pbom.JobResources{Name: "job-" + strconv.Itoa(i), RunnerTags: []string{"docker"}})
		}
		got, bound := platformBOMFrom(&pbom.PBOM{Jobs: jobs})
		if got != nil || bound != "jobs > 500" {
			t.Fatalf("got %#v, bound %q, want nil and %q", got, bound, "jobs > 500")
		}
	})
}

// TestPlatformBOMFrom_StringBoundsMeasureTheNormalisedName is the other half
// of measuring the emitted section: the normalisation can make a string
// LONGER than the collector's (the Docker Hub namespace adds eight runes), so
// a name inside the bound in the document can be over it on the wire. The
// platform counts what it receives.
func TestPlatformBOMFrom_StringBoundsMeasureTheNormalisedName(t *testing.T) {
	// A bare Docker Hub repository of exactly 512 runes becomes
	// "library/" + 512 = 520 runes once normalised.
	bare := strings.Repeat("a", bomMaxStringRunes)
	doc := &pbom.PBOM{ContainerImages: []pbom.ContainerImage{{Image: bare, Name: bare}}}
	got, bound := platformBOMFrom(doc)
	if got != nil {
		t.Errorf("a name that is over the bound once normalised still produced a section: %#v", got.Images)
	}
	if bound != "string > 512 runes" {
		t.Errorf("bound = %q, want %q", bound, "string > 512 runes")
	}
}

// bomTestImages, bomTestJobs and bomTestServices build fixtures that SURVIVE
// the section's filtering, so a count bound is measured against entries that
// really reach the wire. Zero-valued entries would be dropped before the
// bounds run and the count would be whatever is left, which is a test that
// passes without asserting anything.
func bomTestImages(n int) []pbom.ContainerImage {
	out := make([]pbom.ContainerImage, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, pbom.ContainerImage{Image: "docker.io/team/app-" + strconv.Itoa(i) + ":1.0"})
	}
	return out
}

func bomTestJobs(n int) []pbom.JobResources {
	out := make([]pbom.JobResources, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, pbom.JobResources{Name: "job-" + strconv.Itoa(i), RunnerTags: []string{"docker"}})
	}
	return out
}

func bomTestServices(n int) []pbom.ContainerImageRef {
	out := make([]pbom.ContainerImageRef, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, pbom.ContainerImageRef{Image: "docker.io/team/svc-" + strconv.Itoa(i) + ":1.0"})
	}
	return out
}
