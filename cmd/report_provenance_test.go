package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
)

// The JSON report carries the resolved commit (never the literal HEAD) and,
// JSON-only, the CI configuration that was actually analyzed (#443).
func TestReportCarriesCommitAndAnalyzedCIConfig(t *testing.T) {
	sha := "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"
	result := &control.AnalysisResult{
		CiValid:           true,
		HeadCommitSha:     "HEAD", // the raw, unresolved value the report must not emit
		ArtifactCommitSHA: sha,
		ArtifactRef:       "release/2.0",
		AnalyzedCIConfig: &control.AnalyzedCIConfig{
			Path:    ".gitlab-ci.yml",
			Content: "stages:\n  - build\n",
			Merged:  true,
		},
	}
	payload, err := buildAnalysisJSONReport(result, testDefaultPlumberConfig(t), complianceSummary{}, jsonOutputParams{provider: "gitlab"}, nil, nil)
	if err != nil {
		t.Fatalf("build report: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	if out["headCommitSha"] != sha {
		t.Errorf("headCommitSha = %v, want the resolved sha, never the literal HEAD", out["headCommitSha"])
	}
	if out["analyzeBranch"] != "release/2.0" {
		t.Errorf("analyzeBranch = %v, want the resolved ref", out["analyzeBranch"])
	}
	cfg, ok := out["analyzedCiConfig"].(map[string]any)
	if !ok {
		t.Fatalf("analyzedCiConfig missing or wrong type: %v", out["analyzedCiConfig"])
	}
	if cfg["path"] != ".gitlab-ci.yml" || cfg["content"] != "stages:\n  - build\n" || cfg["merged"] != true {
		t.Errorf("analyzedCiConfig = %v, want the analyzed gitlab config", cfg)
	}
}

// The analyzed CI config is a local artifact for the AI pipeline: it is written
// to the --output report but kept out of the score-push payload so the merged
// pipeline content is not exported to the hosted score service (#443).
func TestReportAnalyzedCIConfigExcludedFromScorePush(t *testing.T) {
	result := &control.AnalysisResult{
		CiValid: true,
		AnalyzedCIConfig: &control.AnalyzedCIConfig{
			Path:    ".gitlab-ci.yml",
			Content: "stages:\n  - build\n",
			Merged:  true,
		},
	}
	pc := testDefaultPlumberConfig(t)

	// The local --output report keeps it.
	local, err := buildAnalysisJSONReport(result, pc, complianceSummary{}, jsonOutputParams{provider: "gitlab"}, nil, nil)
	if err != nil {
		t.Fatalf("build local report: %v", err)
	}
	var localOut map[string]any
	_ = json.Unmarshal(local, &localOut)
	if _, present := localOut["analyzedCiConfig"]; !present {
		t.Error("analyzedCiConfig missing from the local report; it must be written to --output")
	}

	// The score-push payload drops it.
	pushed, err := buildAnalysisJSONReport(result, pc, complianceSummary{}, jsonOutputParams{provider: "gitlab", forScorePush: true}, nil, nil)
	if err != nil {
		t.Fatalf("build score-push payload: %v", err)
	}
	var pushOut map[string]any
	_ = json.Unmarshal(pushed, &pushOut)
	if _, present := pushOut["analyzedCiConfig"]; present {
		t.Error("analyzedCiConfig present in the score-push payload; the merged CI config must not be exported to the hosted service")
	}
}

// When neither a commit nor a ref resolves, the report omits headCommitSha and
// analyzeBranch rather than emitting the raw HEAD placeholder either carried.
// The report map is built empty, so an unset field is simply absent - this
// locks that guarantee symmetrically for both fields.
func TestReportOmitsUnresolvedCommit(t *testing.T) {
	result := &control.AnalysisResult{
		CiValid:           true,
		HeadCommitSha:     "HEAD", // raw values the report must not emit
		AnalyzeBranch:     "HEAD",
		ArtifactCommitSHA: "",
		ArtifactRef:       "",
	}
	payload, err := buildAnalysisJSONReport(result, testDefaultPlumberConfig(t), complianceSummary{}, jsonOutputParams{provider: "gitlab"}, nil, nil)
	if err != nil {
		t.Fatalf("build report: %v", err)
	}
	var out map[string]any
	_ = json.Unmarshal(payload, &out)
	if v, present := out["headCommitSha"]; present {
		t.Errorf("headCommitSha present (%v) with no resolved commit; it must be omitted, never HEAD", v)
	}
	if v, present := out["analyzeBranch"]; present {
		t.Errorf("analyzeBranch present (%v) with no resolved ref; it must be omitted, never HEAD", v)
	}
}

// The verifier of the hosted score service reads cliVersion, configFileSha256
// and ci to check a push against the certificate the provider's OIDC token
// attests (monorepo spec 2026-10-30, section 4.1). This pins the GitHub
// Actions path: a real config file hashes to its own sha256, and the Actions
// run identifiers are read from the runner environment.
func TestBuildAnalysisJSONReport_CarriesCLIVersionConfigHashAndCI(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_REPOSITORY", "ovh/cds")
	t.Setenv("GITHUB_RUN_ID", "123456")
	t.Setenv("GITHUB_RUN_ATTEMPT", "2")
	result := &control.AnalysisResult{CiValid: true}
	configText := "controls:\n  foo: true\n"
	pc := &configuration.PlumberConfig{Raw: configText, FileBytes: []byte(configText), Source: ".plumber.yaml"}
	out, err := buildAnalysisJSONReport(result, pc, complianceSummary{}, jsonOutputParams{provider: "github"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["cliVersion"] != Version {
		t.Fatalf("cliVersion = %v, want %v", m["cliVersion"], Version)
	}
	want := sha256.Sum256(pc.FileBytes)
	if m["configFileSha256"] != hex.EncodeToString(want[:]) {
		t.Fatalf("configFileSha256 = %v", m["configFileSha256"])
	}
	ci, ok := m["ci"].(map[string]any)
	if !ok {
		t.Fatalf("ci missing or wrong type: %v", m["ci"])
	}
	if ci["runId"] != "123456" || ci["runAttempt"] != "2" || ci["runUrl"] != "https://github.com/ovh/cds/actions/runs/123456/attempts/2" {
		t.Fatalf("ci = %v", ci)
	}
}

// Outside GitHub Actions, and with the embedded default config (no file),
// the service must never mistake either for a real push: configFileSha256
// stays empty and ci is omitted entirely rather than carrying zero values.
func TestBuildAnalysisJSONReport_DefaultConfigAndNoCI(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITHUB_RUN_ID", "")
	result := &control.AnalysisResult{CiValid: true}
	out, err := buildAnalysisJSONReport(result, nil, complianceSummary{}, jsonOutputParams{provider: "github"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["configFileSha256"] != "" {
		t.Fatalf("configFileSha256 must be empty for the embedded default, got %v", m["configFileSha256"])
	}
	if _, ok := m["ci"]; ok {
		t.Fatal("ci must be omitted outside GitHub Actions")
	}
}

// loadEmbeddedDefaultConfig (the real zero-config path, cmd/analyze_gitlab.go)
// stamps Source with the builtinDefaultConfigSource sentinel ("built-in
// default"), never the literal string "default". configFileSha256 must
// recognize that real sentinel, or a production zero-config run would hash
// the embedded default's bytes and the service would read it as a real file.
// The config is built the way production builds it, so FileBytes holds the
// embedded default and the sentinel is the only reason the hash is empty.
func TestBuildAnalysisJSONReport_EmbeddedDefaultSentinelYieldsEmptyHash(t *testing.T) {
	pc, _, _, err := loadEmbeddedDefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(pc.FileBytes) == 0 || pc.Source != builtinDefaultConfigSource {
		t.Fatalf("embedded default: len(FileBytes) = %d, Source = %q; the test needs both set", len(pc.FileBytes), pc.Source)
	}
	result := &control.AnalysisResult{CiValid: true}
	out, err := buildAnalysisJSONReport(result, pc, complianceSummary{}, jsonOutputParams{provider: "github"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["configFileSha256"] != "" {
		t.Fatalf("configFileSha256 = %v, want empty for the built-in default sentinel", m["configFileSha256"])
	}
}

// In overlay mode (extends: plumber:default) PlumberConfig.Raw holds the
// resolved (merged) YAML, not the committed file's own bytes; FileBytes is
// the field that matches sha256sum of the file on disk. configFileSha256
// must hash FileBytes, never Raw, or the hosted verifier would reject every
// push from a repo using the overlay.
func TestBuildAnalysisJSONReport_OverlayConfigHashesFileBytesNotMergedRaw(t *testing.T) {
	overlayText := "extends: plumber:default\ngithub:\n  controls:\n    foo: true\n"
	mergedText := "version: \"2.0\"\ngithub:\n  controls:\n    foo: true\n  other: stuff\n"
	pc := &configuration.PlumberConfig{
		Raw:       mergedText,
		FileBytes: []byte(overlayText),
		Source:    ".plumber.yaml",
	}
	result := &control.AnalysisResult{CiValid: true}
	out, err := buildAnalysisJSONReport(result, pc, complianceSummary{}, jsonOutputParams{provider: "github"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(pc.FileBytes)
	if m["configFileSha256"] != hex.EncodeToString(want[:]) {
		t.Fatalf("configFileSha256 = %v, want sha256(FileBytes) = %x", m["configFileSha256"], want)
	}
}

// actionsRunInfo must not emit a malformed runUrl (a URL with an empty repo
// segment, "https://github.com//actions/runs/..."): GITHUB_REPOSITORY unset
// means the environment is not a usable GitHub Actions run, so ci must be
// omitted entirely, the same as when GITHUB_RUN_ID is unset.
func TestBuildAnalysisJSONReport_CIOmittedWhenRepositoryMissing(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("GITHUB_RUN_ID", "123456")
	t.Setenv("GITHUB_RUN_ATTEMPT", "2")
	result := &control.AnalysisResult{CiValid: true}
	out, err := buildAnalysisJSONReport(result, nil, complianceSummary{}, jsonOutputParams{provider: "github"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["ci"]; ok {
		t.Fatalf("ci present (%v) with GITHUB_REPOSITORY unset; it must be omitted rather than carry a malformed runUrl", m["ci"])
	}
}

// actionsRunInfo builds runUrl from the runner environment; the hosted
// verifier compares it with certificate fields, so each default and guard
// is pinned here: an unset server falls back to github.com, a trailing slash
// on a GitHub Enterprise server never doubles, an unset attempt is "1", and
// a run without GITHUB_RUN_ID omits the ci block rather than emit an empty
// run segment.
func TestActionsRunInfo_DefaultsAndGuards(t *testing.T) {
	cases := []struct {
		name                    string
		server, runID, attempt  string
		wantOK                  bool
		wantAttempt, wantRunURL string
	}{
		{name: "server unset defaults to github.com", server: "", runID: "42", attempt: "3", wantOK: true,
			wantAttempt: "3", wantRunURL: "https://github.com/ovh/cds/actions/runs/42/attempts/3"},
		{name: "enterprise server trailing slash is trimmed", server: "https://ghe.example.com/", runID: "42", attempt: "3", wantOK: true,
			wantAttempt: "3", wantRunURL: "https://ghe.example.com/ovh/cds/actions/runs/42/attempts/3"},
		{name: "attempt unset defaults to 1", server: "https://github.com", runID: "42", attempt: "", wantOK: true,
			wantAttempt: "1", wantRunURL: "https://github.com/ovh/cds/actions/runs/42/attempts/1"},
		{name: "run id unset omits ci", server: "https://github.com", runID: "", attempt: "1", wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GITHUB_ACTIONS", "true")
			t.Setenv("GITHUB_REPOSITORY", "ovh/cds")
			t.Setenv("GITHUB_SERVER_URL", tc.server)
			t.Setenv("GITHUB_RUN_ID", tc.runID)
			t.Setenv("GITHUB_RUN_ATTEMPT", tc.attempt)
			ci, ok := actionsRunInfo()
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (ci = %v)", ok, tc.wantOK, ci)
			}
			if !tc.wantOK {
				if ci != nil {
					t.Fatalf("ci = %v, want nil", ci)
				}
				return
			}
			if ci["runId"] != tc.runID || ci["runAttempt"] != tc.wantAttempt || ci["runUrl"] != tc.wantRunURL {
				t.Fatalf("ci = %v, want runId %q runAttempt %q runUrl %q", ci, tc.runID, tc.wantAttempt, tc.wantRunURL)
			}
		})
	}
}
