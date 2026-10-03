package cmd

import (
	"testing"

	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// The demo repository under scoring-v4: the template injection (ISSUE-207,
// registered Critical) anchors a Medium path, and the persisted checkout
// credentials (ISSUE-307, registered Low) ride a Critical one. OCSF reads
// the same per-finding gate as SARIF, the GitLab SAST report and the CSV:
// with Data["baseSeverity"] present the contextual f.Severity wins, for
// the control's severity_id and for the per-severity counts alike.
func TestBuildOCSF_SeverityFollowsTheContextualSeverityUnderV4(t *testing.T) {
	injection := control.LookupCode("ISSUE-207").ControlName
	checkout := control.LookupCode("ISSUE-307").ControlName
	entries := []control.ControlEntry{
		{ControlName: injection, DisplayName: "Injection"},
		{ControlName: checkout, DisplayName: "Checkout"},
	}
	annotated := &control.AnalysisResult{CiValid: true, Findings: []opaengine.Finding{
		{Code: "ISSUE-207", Severity: "medium", Message: "injection", Job: "ci/build", Data: map[string]any{"baseSeverity": "critical"}},
		{Code: "ISSUE-307", Severity: "critical", Message: "checkout", Job: "plumber/plumber", Data: map[string]any{"baseSeverity": "low"}},
	}}
	byControl := func(result *control.AnalysisResult) map[string]ocsfComplianceFinding {
		out := map[string]ocsfComplianceFinding{}
		for _, ev := range buildOCSF(entries, result, "github", 1754179200000, "scan-1", nil) {
			out[ev.Compliance.Control] = ev
		}
		return out
	}

	got := byControl(annotated)
	if id := got[injection].SeverityID; id != 3 {
		t.Errorf("injection severity_id = %d, want 3 (contextual medium, registry critical would be 5)", id)
	}
	if id := got[checkout].SeverityID; id != 5 {
		t.Errorf("checkout severity_id = %d, want 5 (contextual critical, registry low would be 2)", id)
	}
	if c, _ := got[injection].Unmapped["plumber_severity_counts"].(control.SeverityCounts); c.Medium != 1 || c.Critical != 0 {
		t.Errorf("injection counts = %+v, want one medium", c)
	}

	// v3 (no baseSeverity): the registry, exactly as before.
	plain := &control.AnalysisResult{CiValid: true, Findings: []opaengine.Finding{
		{Code: "ISSUE-207", Severity: "medium", Message: "injection", Job: "ci/build"},
		{Code: "ISSUE-307", Severity: "critical", Message: "checkout", Job: "plumber/plumber"},
	}}
	got = byControl(plain)
	if got[injection].SeverityID != 5 || got[checkout].SeverityID != 2 {
		t.Errorf("v3 severity_id = %d/%d, want the registry 5/2", got[injection].SeverityID, got[checkout].SeverityID)
	}
	if c, _ := got[injection].Unmapped["plumber_severity_counts"].(control.SeverityCounts); c.Critical != 1 {
		t.Errorf("v3 injection counts = %+v, want one critical (registry)", c)
	}
}
