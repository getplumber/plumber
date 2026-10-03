package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/provider"
)

// releaseMutableActionResult builds a minimal result carrying one finding
// (a mutable dependency in a release job, the same fixture control's own
// tests use) and a healthy Situation, so ComputeScoreForProfile("v4", ...)
// prices it for real rather than falling back to v3 (control.
// situationUnavailable requires a non-nil Situation with at least one job,
// which this provides).
func releaseMutableActionResult() *control.AnalysisResult {
	j := control.JobSituation{
		Entries: []control.EntryFact{{Kind: control.EntryMutableDependency, State: "proven", Evidence: "some/action@v1", Subject: "some/action@v1"}},
		Impact:  []control.ImpactFact{{Kind: "publishes", State: "proven", Evidence: "npm publish"}},
	}
	j.Privilege.Secrets = []string{"NPM_TOKEN"}
	j.Privilege.SecretsState = "proven"
	j.Privilege.TokenWrite = []string{"contents"}
	sit := &control.Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]control.JobSituation{"release": j}}
	finding := opaengine.Finding{
		Code:     "ISSUE-713",
		Job:      "release",
		Severity: string(control.SeverityForCode("ISSUE-713")),
		Data:     map[string]any{"uses": "some/action@v1"},
	}
	return &control.AnalysisResult{CiValid: true, Findings: []opaengine.Finding{finding}, Situation: sit}
}

// withScoreProfile sets control.ScoreProfile for the duration of the test
// and restores it afterward: the package global every analyze run reads
// (cmd/analyze_gitlab.go's --score-profile flag writes it), never mutated
// outside a save/restore pair in a test.
func withScoreProfile(t *testing.T, profile string) {
	t.Helper()
	old := control.ScoreProfile
	control.ScoreProfile = profile
	t.Cleanup(func() { control.ScoreProfile = old })
}

// TestBuildComplianceSummary_AnnotatesFindingsOnlyUnderV4 pins the wiring:
// buildComplianceSummary (the shared result path every analyze run goes
// through) annotates findings with their v4 story right after the score is
// computed, gated on scoreProfileV4(score) - the score's own ProfileID, not
// the bare flag - so a v4 run gets the full annotation and a plain v3 run
// writes nothing to any finding.
func TestBuildComplianceSummary_AnnotatesFindingsOnlyUnderV4(t *testing.T) {
	newGateFlagsCmd(t)
	gl := &provider.GitLabProvider{}
	conf := confWithDebugTrace()

	t.Run("v4", func(t *testing.T) {
		withScoreProfile(t, "v4")
		result := releaseMutableActionResult()
		s := buildComplianceSummary(gl, result, conf)
		if !scoreProfileV4(s.score) {
			t.Fatalf("score did not price under v4, got %+v", s.score)
		}
		f := result.Findings[0]
		if f.Severity != "critical" {
			t.Errorf("Severity = %q, want the contextual critical", f.Severity)
		}
		if f.Data["baseSeverity"] != "high" {
			t.Errorf("baseSeverity = %v, want the registered high", f.Data["baseSeverity"])
		}
		role, _ := f.Data["role"].(string)
		if !strings.HasPrefix(role, "Entry of path ") {
			t.Errorf("role = %q", role)
		}
		ids, _ := f.Data["pathIds"].([]string)
		if len(ids) != 1 {
			t.Errorf("pathIds = %v, want exactly one path id", ids)
		}
		expl, _ := f.Data["explanation"].(string)
		if !strings.Contains(expl, "some/action@v1") {
			t.Errorf("explanation = %q", expl)
		}
	})

	t.Run("v3 writes nothing to any finding", func(t *testing.T) {
		withScoreProfile(t, "v3")
		result := releaseMutableActionResult()
		registrySeverity := result.Findings[0].Severity
		s := buildComplianceSummary(gl, result, conf)
		if scoreProfileV4(s.score) {
			t.Fatalf("score priced under v4 on a v3 request, got %+v", s.score)
		}
		f := result.Findings[0]
		if f.Severity != registrySeverity {
			t.Errorf("Severity = %q, want the untouched registry value %q", f.Severity, registrySeverity)
		}
		if _, ok := f.Data["baseSeverity"]; ok {
			t.Errorf("baseSeverity must be absent under v3, got %v", f.Data["baseSeverity"])
		}
		if _, ok := f.Data["role"]; ok {
			t.Errorf("role must be absent under v3, got %v", f.Data["role"])
		}
	})
}

// TestBuildComplianceSummary_V4FallbackToV3AnnotatesNothing pins the other
// half of the gate: a --score-profile v4 request that control.
// situationUnavailable rejects (no Situation here) falls back to a plain v3
// score (ProfileID stays scoring-v3), and
// scoreProfileV4 reading that ProfileID correctly withholds the annotation,
// exactly as it would for a bare v3 run.
func TestBuildComplianceSummary_V4FallbackToV3AnnotatesNothing(t *testing.T) {
	newGateFlagsCmd(t)
	withScoreProfile(t, "v4")
	gl := &provider.GitLabProvider{}
	conf := confWithDebugTrace()

	registrySeverity := string(control.SeverityForCode("ISSUE-713"))
	finding := opaengine.Finding{Code: "ISSUE-713", Job: "release", Severity: registrySeverity, Data: map[string]any{"uses": "some/action@v1"}}
	// No Situation: control.situationUnavailable(result) is true, so
	// ComputeScoreForProfile("v4", ...) falls back to v3 pricing.
	result := &control.AnalysisResult{CiValid: true, Findings: []opaengine.Finding{finding}}

	s := buildComplianceSummary(gl, result, conf)
	if s.score == nil || s.score.ProfileID != control.PlumberScoreProfileID {
		t.Fatalf("want the v3 fallback profile id, got %+v", s.score)
	}
	if scoreProfileV4(s.score) {
		t.Fatalf("scoreProfileV4 must read false on a fallback score")
	}
	f := result.Findings[0]
	if f.Severity != registrySeverity {
		t.Errorf("Severity = %q, want the untouched registry value %q", f.Severity, registrySeverity)
	}
	if _, ok := f.Data["baseSeverity"]; ok {
		t.Errorf("baseSeverity must be absent on a v3 fallback, got %v", f.Data["baseSeverity"])
	}
}

// defaultGitHubPlumberConfig loads the same embedded built-in catalog a
// zero-config GitHub run uses (cmd/analyze_gitlab.go's loadEmbeddedDefaultConfig),
// so a test exercising the real legacy JSON builders (cmd/legacy_json_github.go)
// sees the same control-to-code wiring a live run does, instead of a hand-
// picked single-control config that would skip most of those builders.
func defaultGitHubPlumberConfig(t *testing.T) *configuration.PlumberConfig {
	t.Helper()
	pc, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "test-default")
	if err != nil {
		t.Fatalf("LoadPlumberConfigFromBytes: %v", err)
	}
	return pc
}

// TestBuildAnalysisJSONReport_FindingCarriesV4KeysInData is the JSON-shape
// half of the contract: under v4 a finding carries baseSeverity, role,
// pathIds and explanation alongside its usual fields, because
// AnnotateFindingsV4 writes them into the same Data map
// every per-finding JSON builder already merges onto the issue object
// (opaengine.Finding.MarshalJSON for a hypothetical flat list, and
// cmd/legacy_json.go's projectFinding for the real per-control issues[]
// blocks this report actually ships - the top-level `findings` array itself
// is deleted from every report, v3 or v4, by a pre-existing, unrelated
// cleanup (cmd/analyze_gitlab.go's `delete(output, "findings")`), so the
// per-control blocks are where this task's new keys actually have to show
// up, and the only place this test can observe them). No change needed to
// buildAnalysisJSONReport or the report's own top-level key list for this.
//
// The legacy per-issue shape (projectFinding) carries no `severity` key
// under v3; under v4 it carries the contextual one (spec section 4), next
// to baseSeverity, so a consumer never reads the registry value as the
// finding's severity.
func TestBuildAnalysisJSONReport_FindingCarriesV4KeysInData(t *testing.T) {
	newGateFlagsCmd(t)
	withScoreProfile(t, "v4")
	gh := &provider.GitHubProvider{}
	conf := configuration.NewDefaultConfiguration()
	conf.PlumberConfig = defaultGitHubPlumberConfig(t)

	result := releaseMutableActionResult()
	s := buildComplianceSummary(gh, result, conf)
	if !scoreProfileV4(s.score) {
		t.Fatalf("score did not price under v4, got %+v", s.score)
	}

	payload, err := buildAnalysisJSONReport(result, conf.PlumberConfig, s, jsonOutputParams{provider: "github"}, nil, nil)
	if err != nil {
		t.Fatalf("buildAnalysisJSONReport: %v", err)
	}
	var report map[string]any
	if err := json.Unmarshal(payload, &report); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if _, ok := report["findings"]; ok {
		t.Errorf(`"findings" must be absent from the report (pre-existing, unrelated cleanup), got %v`, report["findings"])
	}
	block, ok := report["authorizedActionSourcesResult"].(map[string]any)
	if !ok {
		t.Fatalf("authorizedActionSourcesResult = %v, want an object", report["authorizedActionSourcesResult"])
	}
	issues, ok := block["issues"].([]any)
	if !ok || len(issues) != 1 {
		t.Fatalf("issues = %v, want exactly one", block["issues"])
	}
	f, ok := issues[0].(map[string]any)
	if !ok {
		t.Fatalf("issues[0] = %v, want an object", issues[0])
	}
	if f["code"] != "ISSUE-713" {
		t.Fatalf("code = %v, want ISSUE-713", f["code"])
	}
	if f["baseSeverity"] != "high" {
		t.Errorf("baseSeverity = %v, want the registered high", f["baseSeverity"])
	}
	if f["severity"] != "critical" {
		t.Errorf("severity = %v, want the contextual critical", f["severity"])
	}
	role, _ := f["role"].(string)
	if !strings.HasPrefix(role, "Entry of path ") {
		t.Errorf("role = %v", f["role"])
	}
	pathIDs, ok := f["pathIds"].([]any)
	if !ok || len(pathIDs) != 1 {
		t.Errorf("pathIds = %v, want exactly one path id", f["pathIds"])
	}
	expl, _ := f["explanation"].(string)
	if !strings.Contains(expl, "some/action@v1") {
		t.Errorf("explanation = %v", f["explanation"])
	}
	plumberScore, ok := report["plumberScore"].(map[string]any)
	if !ok {
		t.Fatalf("plumberScore = %v, want an object", report["plumberScore"])
	}
	if plumberScore["profileId"] != control.PlumberScoreProfileIDV4 {
		t.Errorf("profileId = %v, want %q", plumberScore["profileId"], control.PlumberScoreProfileIDV4)
	}
	if _, ok := plumberScore["situation"]; !ok {
		t.Errorf("plumberScore.situation missing: the whole PlumberScoreResult must come through")
	}
	paths, _ := plumberScore["paths"].([]any)
	if len(paths) == 0 {
		t.Fatalf("plumberScore.paths = %v, want the assembled paths", plumberScore["paths"])
	}
	path, _ := paths[0].(map[string]any)
	reach, _ := path["reach"].(map[string]any)
	if _, ok := reach["secrets"]; !ok {
		t.Errorf("paths[0].reach = %v, want camelCase keys", reach)
	}
	if mods, ok := path["modifiers"].([]any); !ok || mods == nil {
		t.Errorf("paths[0].modifiers = %v, want an array, never null", path["modifiers"])
	}
}

// Under v3 the issue object keeps its legacy shape: no severity key.
func TestBuildAnalysisJSONReport_V3IssueCarriesNoSeverity(t *testing.T) {
	newGateFlagsCmd(t)
	withScoreProfile(t, "v3")
	gh := &provider.GitHubProvider{}
	conf := configuration.NewDefaultConfiguration()
	conf.PlumberConfig = defaultGitHubPlumberConfig(t)

	result := releaseMutableActionResult()
	s := buildComplianceSummary(gh, result, conf)
	payload, err := buildAnalysisJSONReport(result, conf.PlumberConfig, s, jsonOutputParams{provider: "github"}, nil, nil)
	if err != nil {
		t.Fatalf("buildAnalysisJSONReport: %v", err)
	}
	var report map[string]any
	if err := json.Unmarshal(payload, &report); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	block, _ := report["authorizedActionSourcesResult"].(map[string]any)
	issues, _ := block["issues"].([]any)
	if len(issues) != 1 {
		t.Fatalf("issues = %v, want exactly one", block["issues"])
	}
	if f, _ := issues[0].(map[string]any); f["severity"] != nil {
		t.Errorf("a v3 issue must carry no severity key, got %v", f["severity"])
	}
}
