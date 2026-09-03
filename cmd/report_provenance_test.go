package cmd

import (
	"encoding/json"
	"testing"

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
	payload, err := buildAnalysisJSONReport(result, testDefaultPlumberConfig(t), complianceSummary{}, jsonOutputParams{provider: "gitlab"})
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
	local, err := buildAnalysisJSONReport(result, pc, complianceSummary{}, jsonOutputParams{provider: "gitlab"})
	if err != nil {
		t.Fatalf("build local report: %v", err)
	}
	var localOut map[string]any
	_ = json.Unmarshal(local, &localOut)
	if _, present := localOut["analyzedCiConfig"]; !present {
		t.Error("analyzedCiConfig missing from the local report; it must be written to --output")
	}

	// The score-push payload drops it.
	pushed, err := buildAnalysisJSONReport(result, pc, complianceSummary{}, jsonOutputParams{provider: "gitlab", forScorePush: true})
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
	payload, err := buildAnalysisJSONReport(result, testDefaultPlumberConfig(t), complianceSummary{}, jsonOutputParams{provider: "gitlab"})
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
