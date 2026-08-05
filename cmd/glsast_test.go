package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// The GitLab SAST vulnerability id must be line-independent so GitLab tracks the
// same vulnerability across runs even when unrelated code above it is edited.
func TestGLSASTID_LineIndependentAndDiscriminating(t *testing.T) {
	a := opaengine.Finding{Code: "ISSUE-701", File: "ci.yml", Job: "build", Message: "unpinned action X"}
	moved := a
	moved.Line = 999
	if glsastID(a) != glsastID(moved) {
		t.Errorf("glsast id changed when only the line moved; want line-independent")
	}
	other := a
	other.Message = "unpinned action Y"
	if glsastID(a) == glsastID(other) {
		t.Errorf("same id for two different subjects; want distinct")
	}
}

// The plumber fingerprint is exposed as a GitLab identifier so the same value
// carried in JSON / CSV / SARIF is correlatable in the SAST report too.
func TestBuildGLSAST_FingerprintIdentifier(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: "ISSUE-701", Severity: "high", Message: "x", File: "ci.yml", Line: 5, Fingerprint: "deadbeefcafef00d"},
	}
	rep := buildGLSAST(findings, "github")
	found := false
	for _, id := range rep.Vulnerabilities[0].Identifiers {
		if id.Type == "plumber-fingerprint" && id.Value == "deadbeefcafef00d" {
			found = true
		}
	}
	if !found {
		t.Errorf("no plumber-fingerprint identifier carrying the finding's fingerprint; got %+v", rep.Vulnerabilities[0].Identifiers)
	}
}

func TestBuildGLSAST_SchemaRequiredFields(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: "ISSUE-203", Severity: "critical", Message: "debug trace", File: ".gitlab-ci.yml", Line: 11},
		{Code: "ISSUE-501", Severity: "critical", Message: "branch not protected"}, // no file
	}

	rep := buildGLSAST(findings, "gitlab")

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

func TestBuildGLSAST_DescriptionIncludesFindingMessage(t *testing.T) {
	// GitLab's Vulnerability Report UI ignores the deprecated `message`
	// field, so the per-finding detail must end up in `description` to be
	// visible to users. Pick a code that has registry metadata so we also
	// confirm the generic description is preserved.
	code := "ISSUE-101"
	info := control.LookupCode(control.ErrorCode(code))
	if info == nil || info.Description == "" {
		t.Fatalf("test prerequisite: %s should have a registered description", code)
	}

	msg := `job "gitleaks" uses image from untrusted source: docker.io/zricethezav/gitleaks:v8.15.0`
	rep := buildGLSAST([]opaengine.Finding{
		{Code: code, Severity: "high", Message: msg, File: ".gitlab-ci.yml", Line: 56},
	}, "gitlab")
	if len(rep.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %d, want 1", len(rep.Vulnerabilities))
	}
	got := rep.Vulnerabilities[0].Description
	if !strings.Contains(got, info.Description) {
		t.Errorf("description dropped the generic blurb:\n got: %q\n want substring: %q", got, info.Description)
	}
	if !strings.Contains(got, msg) {
		t.Errorf("description does not include the per-finding message:\n got: %q\n want substring: %q", got, msg)
	}
}

func TestBuildGLSAST_DescriptionFallsBackToMessage(t *testing.T) {
	// A finding for an unknown code has no registry description; the
	// message should still surface in `description` rather than being lost.
	msg := "some specific detail"
	rep := buildGLSAST([]opaengine.Finding{
		{Code: "ISSUE-UNKNOWN", Severity: "low", Message: msg, File: ".gitlab-ci.yml", Line: 1},
	}, "gitlab")
	if len(rep.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %d, want 1", len(rep.Vulnerabilities))
	}
	if rep.Vulnerabilities[0].Description != msg {
		t.Errorf("description = %q, want %q", rep.Vulnerabilities[0].Description, msg)
	}
}

func TestBuildGLSAST_LocationAlwaysPresent(t *testing.T) {
	// The schema requires `location` on every vulnerability; a finding with no
	// file must still serialize a location object (an empty {} is valid).
	rep := buildGLSAST([]opaengine.Finding{
		{Code: "ISSUE-501", Severity: "critical", Message: "no file"},
	}, "gitlab")
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

func TestBuildGLSAST_ControlNameSecondIdentifier(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: "ISSUE-701", Severity: "high", Message: "unpinned action"},
	}
	rep := buildGLSAST(findings, "github")
	if len(rep.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %d, want 1", len(rep.Vulnerabilities))
	}
	ids := rep.Vulnerabilities[0].Identifiers
	if len(ids) != 2 {
		t.Fatalf("identifiers = %d, want 2", len(ids))
	}
	// The first identifier (the ISSUE code) must stay first and untouched --
	// GitLab treats identifiers[0] as the Primary Identifier for
	// cross-scan vulnerability tracking.
	if ids[0].Type != "plumber" || ids[0].Value != "ISSUE-701" {
		t.Errorf("primary identifier changed: %+v", ids[0])
	}
	if ids[1].Type != "plumber_control" || ids[1].Name != "actionsMustBePinnedByCommitSha" || ids[1].Value != "actionsMustBePinnedByCommitSha" {
		t.Errorf("control-name identifier = %+v, want type=plumber_control name/value=actionsMustBePinnedByCommitSha", ids[1])
	}
	if ids[1].URL != "" {
		t.Errorf("control-name identifier URL = %q, want empty", ids[1].URL)
	}
}

// GitLab treats the vulnerability id as its dedup key, so two distinct findings
// sharing one id are merged and a real finding silently disappears. The same
// action referenced by two steps of one job has an identical code, file, job
// and message, so the id must carry the step discriminator the fingerprint
// already encodes. Regression: the id was briefly derived from
// code|file|job|message alone, which collapsed exactly this case.
func TestGLSASTID_SameActionTwoStepsDoNotCollide(t *testing.T) {
	a := opaengine.Finding{Code: "ISSUE-713", File: "cov.yml", Job: "coverage", Message: "same message",
		Line: 216, Fingerprint: "aaaa111122223333"}
	b := opaengine.Finding{Code: "ISSUE-713", File: "cov.yml", Job: "coverage", Message: "same message",
		Line: 316, Fingerprint: "bbbb444455556666"}
	if glsastID(a) == glsastID(b) {
		t.Errorf("two findings differing only by step share GitLab id %q; the second would be dropped", glsastID(a))
	}
}

// The id must still ignore line drift: editing unrelated code above a finding
// must not make GitLab see a new vulnerability.
func TestGLSASTID_StillLineIndependent(t *testing.T) {
	a := opaengine.Finding{Code: "ISSUE-701", File: "ci.yml", Job: "build", Message: "unpinned", Fingerprint: "ffff0000ffff0000"}
	moved := a
	moved.Line = 999
	if glsastID(a) != glsastID(moved) {
		t.Errorf("glsast id changed on line drift; want line-independent")
	}
}
