package cmd

import (
	"encoding/json"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/provider"
)

// capabilitiesJSONFixture is a one-job GitLab pipeline whose job image matches
// the built-in secret_detection recognizer for gitleaks (capability/builtin.yaml),
// so provider.CapabilitiesOf recognizes it by `images` evidence: the shape the
// brief asks the analysis JSON test to pin (spec 4.4, the same shape the bill
// carries).
func capabilitiesJSONFixture() *control.AnalysisResult {
	return &control.AnalysisResult{
		CiValid:     true,
		ProjectPath: "group/project",
		Pipeline: &ir.NormalizedPipeline{Jobs: []ir.Job{
			{Name: "secret-scan", Image: &ir.Image{Name: "zricethezav/gitleaks", Tag: "latest"}},
		}},
	}
}

// TestBuildAnalysisJSONReport_CapabilitiesKeyPresent pins spec 4.4: the
// analysis JSON reaches the same capabilities the --pbom artifact and the
// platform push carry (provider.CapabilitiesOf, capability.Match), as a
// top-level `capabilities` array of {kind, job, tool, evidence}.
func TestBuildAnalysisJSONReport_CapabilitiesKeyPresent(t *testing.T) {
	pc := noControlsPC(t)
	result := capabilitiesJSONFixture()
	conf := &configuration.Configuration{PlumberConfig: pc}
	caps := provider.CapabilitiesOf(result, conf)
	if len(caps) != 1 {
		t.Fatalf("fixture precondition: want exactly one recognized capability, got %+v", caps)
	}

	s := buildComplianceSummary(&provider.GitLabProvider{}, result, conf)
	params := jsonOutputParams{provider: "gitlab", capabilities: caps}
	payload, err := buildAnalysisJSONReport(result, pc, s, params, nil, nil)
	if err != nil {
		t.Fatalf("build json: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatalf("parse json: %v", err)
	}
	rawCaps, ok := out["capabilities"].([]any)
	if !ok {
		t.Fatalf("capabilities key missing or not an array, got %T: %v", out["capabilities"], out["capabilities"])
	}
	if len(rawCaps) != 1 {
		t.Fatalf("capabilities has %d entries, want 1: %v", len(rawCaps), rawCaps)
	}
	entry, ok := rawCaps[0].(map[string]any)
	if !ok {
		t.Fatalf("capabilities[0] is not an object: %v", rawCaps[0])
	}
	want := map[string]any{"kind": "secret_detection", "job": "secret-scan", "tool": "gitleaks", "evidence": "images"}
	for k, v := range want {
		if entry[k] != v {
			t.Errorf("capabilities[0][%q] = %v, want %v (entry: %v)", k, entry[k], v, entry)
		}
	}
}

// TestBuildAnalysisJSONReport_CapabilitiesKeyAbsentWhenNoneRecognized pins
// the omitempty half of spec 4.4: a run that recognized nothing must not
// carry an empty `capabilities: []`, so a report from before this feature
// and a report from a run with no matching job are byte-identical on this
// key.
func TestBuildAnalysisJSONReport_CapabilitiesKeyAbsentWhenNoneRecognized(t *testing.T) {
	pc := noControlsPC(t)
	result := &control.AnalysisResult{CiValid: true, ProjectPath: "group/project"}
	conf := &configuration.Configuration{PlumberConfig: pc}
	s := buildComplianceSummary(&provider.GitLabProvider{}, result, conf)
	params := jsonOutputParams{provider: "gitlab"}
	payload, err := buildAnalysisJSONReport(result, pc, s, params, nil, nil)
	if err != nil {
		t.Fatalf("build json: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatalf("parse json: %v", err)
	}
	if v, ok := out["capabilities"]; ok {
		t.Errorf("capabilities must be absent when nothing was recognized, got %v", v)
	}
}
