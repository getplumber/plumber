package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

func TestBuildSARIF_PartialFingerprints(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: "ISSUE-701", Severity: "high", Message: "unpinned", File: ".github/workflows/ci.yml", Line: 28, Fingerprint: "deadbeefcafef00d"},
	}
	doc := buildSARIF(findings, ".plumber.yaml", "github")
	if len(doc.Runs[0].Results) != 1 {
		t.Fatalf("results = %d, want 1", len(doc.Runs[0].Results))
	}
	if got := doc.Runs[0].Results[0].PartialFingerprints["plumber/v1"]; got != "deadbeefcafef00d" {
		t.Errorf("partialFingerprints[plumber/v1] = %q, want deadbeefcafef00d", got)
	}
}

func TestBuildSARIF_ShapeAndSeverityMapping(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: "ISSUE-701", Severity: "high", Message: "unpinned action", File: ".github/workflows/ci.yml", Line: 28},
		{Code: "ISSUE-203", Severity: "critical", Message: "debug trace", File: "./.github/workflows/ci.yml", Line: 11},
		{Code: "ISSUE-501", Severity: "critical", Message: "branch not protected"}, // repo-level, no file
	}

	doc := buildSARIF(findings, ".plumber.yaml", "gitlab")

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
	// Every result must carry at least one location (GitHub Code Scanning
	// rejects location-less results); repo-level findings fall back to the
	// config file with no region.
	for _, r := range run.Results {
		if len(r.Locations) == 0 {
			t.Errorf("%s has no location; Code Scanning requires one", r.RuleID)
		}
		switch r.RuleID {
		case "ISSUE-701":
			loc := r.Locations[0].PhysicalLocation
			if loc.ArtifactLocation.URI != ".github/workflows/ci.yml" {
				t.Errorf("uri = %q", loc.ArtifactLocation.URI)
			}
			if loc.Region == nil || loc.Region.StartLine != 28 {
				t.Errorf("region = %+v, want startLine 28", loc.Region)
			}
		case "ISSUE-203":
			if r.Locations[0].PhysicalLocation.ArtifactLocation.URI != ".github/workflows/ci.yml" {
				t.Errorf("ISSUE-203 './' not stripped: %q", r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
			}
		case "ISSUE-501":
			// Repo-level: anchored to the fallback (config) file, no region.
			loc := r.Locations[0].PhysicalLocation
			if loc.ArtifactLocation.URI != ".plumber.yaml" {
				t.Errorf("ISSUE-501 should fall back to .plumber.yaml, got %q", loc.ArtifactLocation.URI)
			}
			if loc.Region != nil {
				t.Errorf("ISSUE-501 fallback location should have no region, got %+v", loc.Region)
			}
		}
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

	// Rules also carry controlName, and it resolves to the correct
	// .plumber.yaml control key.
	for _, r := range run.Tool.Driver.Rules {
		if _, ok := r.Properties["controlName"]; !ok {
			t.Errorf("rule %s missing controlName", r.ID)
		}
		if r.ID == "ISSUE-701" {
			if got := r.Properties["controlName"]; got != "actionsMustBePinnedByCommitSha" {
				t.Errorf("ISSUE-701 controlName = %v, want actionsMustBePinnedByCommitSha", got)
			}
		}
	}
}

func TestBuildSARIF_AllCodedFindingsBecomeResults(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: "ISSUE-701", Severity: "high", Message: "a"},
		{Code: "", Severity: "high", Message: "skipped"},
		{Code: "ISSUE-203", Severity: "critical", Message: "b"},
	}
	doc := buildSARIF(findings, ".plumber.yaml", "gitlab")
	if len(doc.Runs[0].Results) != 2 {
		t.Fatalf("results = %d, want 2 (empty code omitted)", len(doc.Runs[0].Results))
	}
}

func TestBuildSARIF_CleanRunIsValidEmpty(t *testing.T) {
	doc := buildSARIF(nil, ".plumber.yaml", "gitlab")
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

// Finding results carry an explicit kind: fail (the spec default, stated
// so intent is visible) and NOTHING ELSE: synthetic per-control status
// results (kind pass / notApplicable / open) were verified 2026-07-31 to
// flood GitHub Code Scanning with one junk alert per result -- Code
// Scanning ignores result.kind and alerts on every result (see the
// comment in buildSARIF). Status lives in the JSON report only.
func TestBuildSARIF_OnlyFindingResultsAllKindFail(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: "ISSUE-701", Severity: "high", Message: "unpinned", File: "wf.yml", Line: 3},
		{Code: "ISSUE-203", Severity: "critical", Message: "debug trace"},
	}
	doc := buildSARIF(findings, ".plumber.yaml", "github")
	run := doc.Runs[0]
	if len(run.Results) != len(findings) {
		t.Fatalf("results = %d, want exactly one per finding (no synthetic status results)", len(run.Results))
	}
	for _, r := range run.Results {
		if r.Kind != "fail" {
			t.Errorf("%s kind = %q, want fail (non-fail kinds create junk Code Scanning alerts)", r.RuleID, r.Kind)
		}
	}
}

// #352 review: writeSARIFToFile must not anchor a repo-level (file-less)
// finding to a config path that does not exist on disk. A zero-config run
// loads the embedded default and writes no .plumber.yaml, so anchoring to
// that phantom path would emit a Code Scanning URI mapping to no committed
// file. With no real config present the finding gets no physical location;
// with one present it anchors to it (unchanged behaviour).
func TestWriteSARIFToFile_FilelessAnchorGuardedOnConfigExistence(t *testing.T) {
	result := &control.AnalysisResult{Findings: []opaengine.Finding{
		{Code: "ISSUE-501", Severity: "critical", Message: "branch not protected"}, // no File
	}}
	orig := configFile
	defer func() { configFile = orig }()

	t.Run("absent config -> no phantom location", func(t *testing.T) {
		dir := t.TempDir()
		configFile = filepath.Join(dir, ".plumber.yaml") // does not exist
		out := filepath.Join(dir, "out.sarif")
		if err := writeSARIFToFile(result, out, "github"); err != nil {
			t.Fatalf("writeSARIFToFile: %v", err)
		}
		if sb := mustRead(t, out); strings.Contains(sb, "artifactLocation") {
			t.Errorf("file-less finding must not anchor to a non-existent config:\n%s", sb)
		}
	})

	t.Run("present config -> anchored to it", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, ".plumber.yaml")
		if err := os.WriteFile(cfg, []byte("version: \"2.0\"\n"), 0o644); err != nil {
			t.Fatalf("write cfg: %v", err)
		}
		configFile = cfg
		out := filepath.Join(dir, "out.sarif")
		if err := writeSARIFToFile(result, out, "github"); err != nil {
			t.Fatalf("writeSARIFToFile: %v", err)
		}
		if sb := mustRead(t, out); !strings.Contains(sb, "artifactLocation") {
			t.Errorf("file-less finding should anchor to the existing config:\n%s", sb)
		}
	})
}
