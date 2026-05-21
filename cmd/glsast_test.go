package cmd

import (
	"encoding/json"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

func TestBuildGLSAST_SchemaRequiredFields(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: "ISSUE-203", Severity: "critical", Message: "debug trace", File: ".gitlab-ci.yml", Line: 11},
		{Code: "ISSUE-501", Severity: "critical", Message: "branch not protected"}, // no file
	}

	rep := buildGLSAST(findings)

	if _, err := json.Marshal(rep); err != nil {
		t.Fatalf("report does not marshal: %v", err)
	}

	// Top-level required: scan + version + vulnerabilities.
	if rep.Version != glsastSchemaVersion {
		t.Errorf("version = %q, want %q", rep.Version, glsastSchemaVersion)
	}
	// scan required: scanner + analyzer (id/name/version/vendor.name), type, times, status.
	if rep.Scan.Type != "sast" {
		t.Errorf("scan.type = %q", rep.Scan.Type)
	}
	if rep.Scan.Status != "success" {
		t.Errorf("scan.status = %q, want success", rep.Scan.Status)
	}
	for _, s := range []glsastScanner{rep.Scan.Scanner, rep.Scan.Analyzer} {
		if s.ID == "" || s.Name == "" || s.Version == "" || s.Vendor.Name == "" {
			t.Errorf("scanner/analyzer missing required field: %+v", s)
		}
	}
	if rep.Scan.StartTime == "" || rep.Scan.EndTime == "" {
		t.Errorf("scan missing start/end time")
	}

	if len(rep.Vulnerabilities) != 2 {
		t.Fatalf("vulnerabilities = %d, want 2", len(rep.Vulnerabilities))
	}
	for _, v := range rep.Vulnerabilities {
		// Each vulnerability requires id + identifiers + location.
		if v.ID == "" {
			t.Errorf("vuln missing id")
		}
		if len(v.Identifiers) == 0 {
			t.Errorf("vuln %s missing identifiers", v.Name)
		}
		for _, id := range v.Identifiers {
			if id.Type == "" || id.Name == "" || id.Value == "" {
				t.Errorf("identifier missing required field: %+v", id)
			}
		}
		// severity must be a valid enum value.
		switch v.Severity {
		case "Info", "Unknown", "Low", "Medium", "High", "Critical":
		default:
			t.Errorf("vuln %s invalid severity %q", v.Name, v.Severity)
		}
	}

	// id is deterministic for the same finding.
	if got := glsastID(findings[0]); got != rep.Vulnerabilities[0].ID {
		t.Errorf("id not deterministic: %q vs %q", got, rep.Vulnerabilities[0].ID)
	}
}

func TestBuildGLSAST_LocationAlwaysPresent(t *testing.T) {
	// The schema requires `location` on every vulnerability; a finding with no
	// file must still serialize a location object (an empty {} is valid).
	rep := buildGLSAST([]opaengine.Finding{
		{Code: "ISSUE-501", Severity: "critical", Message: "no file"},
	})
	b, err := json.Marshal(rep.Vulnerabilities[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["location"]; !ok {
		t.Errorf("vulnerability is missing the required 'location' key: %s", b)
	}
}
