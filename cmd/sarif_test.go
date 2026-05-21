package cmd

import (
	"encoding/json"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

func TestBuildSARIF_ShapeAndSeverityMapping(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: "ISSUE-701", Severity: "high", Message: "unpinned action", File: ".github/workflows/ci.yml", Line: 28},
		{Code: "ISSUE-203", Severity: "critical", Message: "debug trace", File: "./.github/workflows/ci.yml", Line: 11},
		{Code: "ISSUE-501", Severity: "critical", Message: "branch not protected"}, // repo-level, no file
	}

	doc := buildSARIF(findings)

	// Must serialize to valid JSON.
	if _, err := json.Marshal(doc); err != nil {
		t.Fatalf("SARIF does not marshal: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]

	if run.Tool.Driver.Name != "Plumber" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}
	if len(run.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(run.Results))
	}
	// Three distinct codes -> three rules.
	if len(run.Tool.Driver.Rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(run.Tool.Driver.Rules))
	}

	// Severity -> level mapping.
	levels := map[string]string{}
	for _, r := range run.Results {
		levels[r.RuleID] = r.Level
	}
	if levels["ISSUE-701"] != "error" { // high
		t.Errorf("ISSUE-701 level = %q, want error", levels["ISSUE-701"])
	}
	if levels["ISSUE-501"] != "error" { // critical
		t.Errorf("ISSUE-501 level = %q, want error", levels["ISSUE-501"])
	}

	// File/line location present and "./" stripped; region carries the line.
	var withLoc, withoutLoc int
	for _, r := range run.Results {
		switch r.RuleID {
		case "ISSUE-701":
			if len(r.Locations) != 1 {
				t.Fatalf("ISSUE-701 should have a location")
			}
			loc := r.Locations[0].PhysicalLocation
			if loc.ArtifactLocation.URI != ".github/workflows/ci.yml" {
				t.Errorf("uri = %q", loc.ArtifactLocation.URI)
			}
			if loc.Region == nil || loc.Region.StartLine != 28 {
				t.Errorf("region = %+v, want startLine 28", loc.Region)
			}
			withLoc++
		case "ISSUE-203":
			if r.Locations[0].PhysicalLocation.ArtifactLocation.URI != ".github/workflows/ci.yml" {
				t.Errorf("ISSUE-203 './' not stripped: %q", r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
			}
			withLoc++
		case "ISSUE-501":
			if len(r.Locations) != 0 {
				t.Errorf("ISSUE-501 (repo-level) should have no location")
			}
			withoutLoc++
		}
	}
	if withLoc != 2 || withoutLoc != 1 {
		t.Errorf("location counts: withLoc=%d withoutLoc=%d", withLoc, withoutLoc)
	}

	// Rules carry helpUri + security-severity from the codes registry.
	for _, r := range run.Tool.Driver.Rules {
		if r.HelpURI == "" {
			t.Errorf("rule %s missing helpUri", r.ID)
		}
		if _, ok := r.Properties["security-severity"]; !ok {
			t.Errorf("rule %s missing security-severity", r.ID)
		}
	}
}

func TestBuildSARIF_AllCodedFindingsBecomeResults(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: "ISSUE-701", Severity: "high", Message: "a"},
		{Code: "", Severity: "high", Message: "skipped"},
		{Code: "ISSUE-203", Severity: "critical", Message: "b"},
	}
	doc := buildSARIF(findings)
	if len(doc.Runs[0].Results) != 2 {
		t.Fatalf("results = %d, want 2 (empty code omitted)", len(doc.Runs[0].Results))
	}
}

func TestBuildSARIF_CleanRunIsValidEmpty(t *testing.T) {
	doc := buildSARIF(nil)
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 {
		t.Fatalf("clean SARIF malformed: %+v", doc)
	}
	if len(doc.Runs[0].Results) != 0 {
		t.Errorf("clean run should have 0 results, got %d", len(doc.Runs[0].Results))
	}
	if _, err := json.Marshal(doc); err != nil {
		t.Fatalf("clean SARIF does not marshal: %v", err)
	}
}
