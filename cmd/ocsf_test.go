package cmd

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// A failing control uses a real registered code so FindingsByControl can
// associate the finding with the control (ISSUE-701 →
// actionsMustBePinnedByCommitSha, same pairing cmd/csv_test.go relies on).
// Each failing control's embedded per-violation records carry the finding
// fingerprint, the same value the JSON / SARIF / GLSAST outputs use.
func TestBuildOCSF_FindingFingerprint(t *testing.T) {
	entries := []control.ControlEntry{{ControlName: "actionsMustBePinnedByCommitSha", DisplayName: "Pin"}}
	result := &control.AnalysisResult{
		CiValid: true,
		Findings: []opaengine.Finding{
			{Code: "ISSUE-701", Message: "x", Fingerprint: "deadbeefcafef00d"},
		},
	}
	events := buildOCSF(entries, result, "github", 1, "s")
	recs, ok := events[0].Unmapped["plumber_findings"].([]map[string]any)
	if !ok || len(recs) != 1 {
		t.Fatalf("plumber_findings = %v", events[0].Unmapped["plumber_findings"])
	}
	if recs[0]["fingerprint"] != "deadbeefcafef00d" {
		t.Errorf("plumber_findings[0].fingerprint = %v, want deadbeefcafef00d", recs[0]["fingerprint"])
	}
}

func TestBuildOCSF_FailingControl(t *testing.T) {
	entries := []control.ControlEntry{
		{ControlName: "actionsMustBePinnedByCommitSha", DisplayName: "Pin actions to SHA"},
	}
	result := &control.AnalysisResult{
		CiValid: true,
		Findings: []opaengine.Finding{
			{Code: "ISSUE-701", Severity: "high", Message: "unpinned action", Job: "build", File: "./.github/workflows/ci.yml", Line: 12},
		},
	}

	events := buildOCSF(entries, result, "github", 1754179200000, "scan-1")
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	ev := events[0]

	if ev.ClassUID != 2003 || ev.CategoryUID != 2 || ev.TypeUID != 200301 {
		t.Errorf("class/category/type = %d/%d/%d, want 2003/2/200301", ev.ClassUID, ev.CategoryUID, ev.TypeUID)
	}
	if ev.Compliance.StatusID != 3 || ev.Compliance.Status != "Fail" {
		t.Errorf("compliance status = %q/%d, want Fail/3", ev.Compliance.Status, ev.Compliance.StatusID)
	}
	if ev.SeverityID != 4 {
		t.Errorf("severity_id = %d, want 4 (high)", ev.SeverityID)
	}
	if len(ev.Compliance.Standards) != 1 || ev.Compliance.Standards[0] != "Plumber" {
		t.Errorf("standards = %v, want [Plumber]", ev.Compliance.Standards)
	}
	if len(ev.Compliance.Requirements) == 0 || ev.Compliance.Requirements[0] != "ISSUE-701" {
		t.Errorf("requirements = %v, want to contain ISSUE-701", ev.Compliance.Requirements)
	}
	if len(ev.Compliance.StatusDetails) != 1 || ev.Compliance.StatusDetails[0] != "unpinned action" {
		t.Errorf("status_details = %v, want [unpinned action]", ev.Compliance.StatusDetails)
	}
	if ev.Remediation == nil || ev.Remediation.Desc == "" {
		t.Errorf("remediation = %v, want non-empty on a failing control", ev.Remediation)
	}
	recs, ok := ev.Unmapped["plumber_findings"].([]map[string]any)
	if !ok || len(recs) != 1 {
		t.Fatalf("unmapped.plumber_findings = %v, want 1 structured record", ev.Unmapped["plumber_findings"])
	}
	if recs[0]["issue_code"] != "ISSUE-701" || recs[0]["file"] != ".github/workflows/ci.yml" || recs[0]["line"] != 12 {
		t.Errorf("plumber_findings[0] = %v, want issue_code/file/line populated", recs[0])
	}
	if ev.FindingInfo.UID != "scan-1:actionsMustBePinnedByCommitSha" {
		t.Errorf("finding_info.uid = %q, want scan-1:actionsMustBePinnedByCommitSha", ev.FindingInfo.UID)
	}
	if ev.Metadata.Version != "1.8.0" {
		t.Errorf("metadata.version = %q, want 1.8.0", ev.Metadata.Version)
	}
}

func TestBuildOCSF_PassingControlIsListed(t *testing.T) {
	entries := []control.ControlEntry{
		{ControlName: "someCleanControl", DisplayName: "Clean Control"},
	}
	result := &control.AnalysisResult{CiValid: true}

	events := buildOCSF(entries, result, "github", 1, "s")
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1 (passing controls are listed)", len(events))
	}
	if events[0].Compliance.StatusID != 1 || events[0].Compliance.Status != "Pass" {
		t.Errorf("status = %q/%d, want Pass/1", events[0].Compliance.Status, events[0].Compliance.StatusID)
	}
	if events[0].SeverityID != 1 {
		t.Errorf("severity_id = %d, want 1 (Informational) on a pass", events[0].SeverityID)
	}
	if events[0].Remediation != nil {
		t.Errorf("remediation = %v, want nil on a pass", events[0].Remediation)
	}
}

// The key regression: a clean control on a DEGRADED run is Warning, NOT Pass.
func TestBuildOCSF_DegradedCleanControlIsWarning(t *testing.T) {
	entries := []control.ControlEntry{
		{ControlName: "someControl", DisplayName: "Some Control"},
	}
	result := &control.AnalysisResult{
		CiValid:         true,
		DegradedReasons: []string{"3 workflow file(s) could not be fetched"},
	}

	events := buildOCSF(entries, result, "github", 1, "s")
	if events[0].Compliance.StatusID != 2 || events[0].Compliance.Status != "Warning" {
		t.Errorf("degraded clean control status = %q/%d, want Warning/2 (must NOT be Pass)", events[0].Compliance.Status, events[0].Compliance.StatusID)
	}
	if len(events[0].Compliance.StatusDetails) == 0 {
		t.Errorf("status_details empty, want the degraded reason surfaced")
	}
}

func TestBuildOCSF_SkippedControlIsOther(t *testing.T) {
	entries := []control.ControlEntry{
		{ControlName: "disabledControl", DisplayName: "Disabled", Skipped: true, SkipReason: "disabled in configuration"},
	}
	result := &control.AnalysisResult{CiValid: true}

	events := buildOCSF(entries, result, "github", 1, "s")
	if events[0].Compliance.StatusID != 99 || events[0].Compliance.Status != "Skipped" {
		t.Errorf("skipped control status = %q/%d, want Skipped/99", events[0].Compliance.Status, events[0].Compliance.StatusID)
	}
}

func TestBuildOCSF_EveryControlEmitted(t *testing.T) {
	entries := []control.ControlEntry{
		{ControlName: "a", DisplayName: "A"},
		{ControlName: "b", DisplayName: "B", Skipped: true},
		{ControlName: "actionsMustBePinnedByCommitSha", DisplayName: "C"},
	}
	result := &control.AnalysisResult{
		CiValid:  true,
		Findings: []opaengine.Finding{{Code: "ISSUE-701", Message: "x"}},
	}
	events := buildOCSF(entries, result, "github", 1, "s")
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3 (one per control, none omitted)", len(events))
	}
}

func TestWriteOCSFEvents_RoundTrip(t *testing.T) {
	entries := []control.ControlEntry{
		{ControlName: "actionsMustBePinnedByCommitSha", DisplayName: "Pin actions to SHA"},
		{ControlName: "cleanControl", DisplayName: "Clean"},
	}
	result := &control.AnalysisResult{
		CiValid:  true,
		Findings: []opaengine.Finding{{Code: "ISSUE-701", Severity: "high", Message: "unpinned"}},
	}
	events := buildOCSF(entries, result, "github", 1754179200000, "scan-1")

	path := t.TempDir() + "/out.ocsf.json"
	if err := writeOCSFEvents(events, path); err != nil {
		t.Fatalf("writeOCSFEvents: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var parsed []map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("output is not a JSON array: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("array length = %d, want 2 (one per control)", len(parsed))
	}
	if parsed[0]["class_uid"].(float64) != 2003 {
		t.Errorf("class_uid = %v, want 2003", parsed[0]["class_uid"])
	}
}

// TestOCSFMaxSeverityID exercises ocsfMaxSeverityID directly with two codes
// of known, different registry severities: ISSUE-701
// (actionsMustBePinnedByCommitSha) is high (control.SeverityHigh → 4) and
// ISSUE-703 (actionsMustNotCarryKnownCVEs) is critical
// (control.SeverityCritical → 5). The max across the two findings must be 5.
func TestOCSFMaxSeverityID(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: "ISSUE-701", Message: "unpinned action"},
		{Code: "ISSUE-703", Message: "known vulnerable action"},
	}

	got := ocsfMaxSeverityID(findings)
	if got != 5 {
		t.Errorf("ocsfMaxSeverityID = %d, want 5 (max of high=4 and critical=5)", got)
	}
}

// TestBuildOCSF_MultiCodeRequirements covers a control backed by 2+ ISSUE
// codes (plan scenario 6). pipelineMustIncludeTemplate carries both
// ISSUE-405 (CodeTemplateMissing) and ISSUE-406 (CodeTemplateOverridden), so
// compliance.requirements must list both, sorted, matching
// control.CodesForControl exactly.
func TestBuildOCSF_MultiCodeRequirements(t *testing.T) {
	const controlName = "pipelineMustIncludeTemplate"

	codes := control.CodesForControl(controlName)
	if len(codes) < 2 {
		t.Fatalf("control %q has %d code(s), want 2+ to exercise the multi-code path", controlName, len(codes))
	}
	want := make([]string, 0, len(codes))
	for _, c := range codes {
		want = append(want, string(c))
	}

	entries := []control.ControlEntry{
		{ControlName: controlName, DisplayName: "X"},
	}
	result := &control.AnalysisResult{CiValid: true}

	events := buildOCSF(entries, result, "gitlab", 1, "s")
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}

	got := events[0].Compliance.Requirements
	if !reflect.DeepEqual(got, want) {
		t.Errorf("requirements = %v, want %v", got, want)
	}
}

func TestBuildOCSF_FindingTypes(t *testing.T) {
	entries := []control.ControlEntry{{ControlName: "someControl", DisplayName: "X"}}
	result := &control.AnalysisResult{CiValid: true}

	events := buildOCSF(entries, result, "github", 1, "s")
	got := events[0].FindingInfo.Types
	want := []string{"CI/CD Security", "Supply Chain", "Security"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("finding_info.types = %v, want %v", got, want)
	}
	for _, ty := range got {
		if ty == "Compliance" {
			t.Errorf("types still contains %q; it should be dropped", "Compliance")
		}
	}
}
