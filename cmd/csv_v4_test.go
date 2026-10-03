package cmd

import (
	"testing"

	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// Same per-finding gate as SARIF and the GitLab SAST report: csv.go is one
// of three readers that override f.Severity with the registry severity
// unconditionally. The
// severity column uses f.Severity (contextual) when the finding carries
// Data["baseSeverity"] (AnnotateFindingsV4 ran, scoring-v4), and the
// registry override exactly as today otherwise, so a v3 CSV is unchanged.
//
// No new columns are added here: buildCSV's header is a fixed, positionally
// documented layout ("Column layout: 0 code, 1 fingerprint, ... 11
// dismissed" in csv_test.go), read positionally by every existing test and,
// per that file's own comment, by report consumers. It is not an extensible
// column list the way the trailing `policies` column is (gated on
// withPolicies, appended once, never inserted among the fixed columns), so
// per the task's own instruction this change leaves the column set alone.
func TestBuildCSV_SeverityUsesContextualSeverityUnderV4(t *testing.T) {
	entries := []control.ControlEntry{
		{ControlName: "actionsMustBePinnedByCommitSha", DisplayName: "Pin"},
	}
	result := &control.AnalysisResult{
		CiValid: true,
		Findings: []opaengine.Finding{
			// ISSUE-701 is registered High; contextual Critical with the v4
			// stamp present must win over the registry.
			{Code: "ISSUE-701", Severity: "critical", Message: "annotated", Data: map[string]any{"baseSeverity": "high"}},
			// Same code, no Data["baseSeverity"]: v3 behavior, registry wins.
			{Code: "ISSUE-701", Severity: "critical", Message: "not annotated"},
		},
	}

	records := buildCSV(entries, result, false)

	bySeverity := map[string]string{}
	for _, row := range records[1:] {
		bySeverity[row[5]] = row[4] // message -> severity
	}
	if bySeverity["annotated"] != "critical" {
		t.Errorf("annotated severity = %q, want critical (contextual)", bySeverity["annotated"])
	}
	if bySeverity["not annotated"] != "high" {
		t.Errorf("not-annotated severity = %q, want high (registry, v3 behavior)", bySeverity["not annotated"])
	}
}
