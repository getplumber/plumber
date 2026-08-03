package cmd

import (
	"testing"

	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// Column layout: 0 code, 1 fingerprint, 2 controlName, 3 status, 4 severity,
// 5 message, 6 context, 7 file, 8 line, 9 url, 10 docUrl.
//
// ISSUE-701 maps to actionsMustBePinnedByCommitSha in the codes registry, so a
// finding with that code is associated with that control by FindingsByControl.
func TestBuildCSV_ShapeColumnsAndOrdering(t *testing.T) {
	entries := []control.ControlEntry{
		{ControlName: "actionsMustBePinnedByCommitSha", DisplayName: "Pin"},                                               // fails (has a finding)
		{ControlName: "cleanControl", DisplayName: "Clean"},                                                               // passes
		{ControlName: "disabledControl", DisplayName: "Disabled", Skipped: true, SkipReason: "disabled in configuration"}, // skipped
	}
	result := &control.AnalysisResult{
		CiValid: true,
		Findings: []opaengine.Finding{
			{Code: "ISSUE-701", Fingerprint: "abc123def4567890", Severity: "high", Message: "unpinned action", Job: "ci/build", File: "./.github/workflows/ci.yml", Line: 28, URL: "https://example.com/blob/ci.yml#L28"},
		},
	}

	records := buildCSV(entries, result)

	wantHeader := []string{"code", "fingerprint", "controlName", "status", "severity", "message", "context", "file", "line", "url", "docUrl"}
	if len(records) != 4 { // header + cleanControl(passed) + disabledControl(skipped) + actions(failed)
		t.Fatalf("records = %d, want 4", len(records))
	}
	if len(records[0]) != len(wantHeader) {
		t.Fatalf("header has %d columns, want %d", len(records[0]), len(wantHeader))
	}
	for i, col := range wantHeader {
		if records[0][i] != col {
			t.Errorf("header[%d] = %q, want %q", i, records[0][i], col)
		}
	}

	// Non-failing controls (passed, skipped) come first, in catalog order, with
	// empty finding columns (including fingerprint).
	if records[1][2] != "cleanControl" || records[1][3] != "passed" {
		t.Errorf("row1 = %v, want cleanControl/passed", records[1][:4])
	}
	if records[1][0] != "" || records[1][1] != "" {
		t.Errorf("passed row code/fingerprint = %q/%q, want empty", records[1][0], records[1][1])
	}
	if records[2][2] != "disabledControl" || records[2][3] != "skipped" {
		t.Errorf("row2 = %v, want disabledControl/skipped", records[2][:4])
	}
	if records[2][5] != "disabled in configuration" {
		t.Errorf("skipped row message = %q, want the skip reason", records[2][5])
	}

	// The failing control and its finding detail come last, with full columns,
	// including the fingerprint read straight off the finding.
	failRow := records[3]
	want := map[int]string{
		0:  "ISSUE-701",
		1:  "abc123def4567890",
		2:  "actionsMustBePinnedByCommitSha",
		3:  "failed",
		4:  "high",
		5:  "unpinned action",
		6:  "ci/build",
		7:  ".github/workflows/ci.yml",
		8:  "28",
		9:  "https://example.com/blob/ci.yml#L28",
		10: "https://getplumber.io/docs/cli/issues/ISSUE-701",
	}
	for i, w := range want {
		if failRow[i] != w {
			t.Errorf("failRow[%d] = %q, want %q", i, failRow[i], w)
		}
	}
}

// A clean run is no longer an empty file: every control is listed with its
// status. This is the whole point of the change (SARIF/old-CSV could not do it).
func TestBuildCSV_CleanRunListsEveryControl(t *testing.T) {
	entries := []control.ControlEntry{
		{ControlName: "a", DisplayName: "A"},
		{ControlName: "b", DisplayName: "B"},
	}
	result := &control.AnalysisResult{CiValid: true}

	records := buildCSV(entries, result)
	if len(records) != 3 { // header + one row per control (NOT header-only)
		t.Fatalf("records = %d, want 3 (header + one row per control)", len(records))
	}
	for _, r := range records[1:] {
		if r[3] != "passed" {
			t.Errorf("clean control status = %q, want passed", r[3])
		}
	}
}

// Non-failing controls sort ahead of failing ones even when a failing control
// appears first in the catalog.
func TestBuildCSV_NonFailingBeforeFailing(t *testing.T) {
	entries := []control.ControlEntry{
		{ControlName: "actionsMustBePinnedByCommitSha", DisplayName: "Pin"}, // fails, but is first in the catalog
		{ControlName: "cleanControl", DisplayName: "Clean"},                 // passes
	}
	result := &control.AnalysisResult{
		CiValid:  true,
		Findings: []opaengine.Finding{{Code: "ISSUE-701", Message: "x"}},
	}
	records := buildCSV(entries, result)
	if records[1][3] != "passed" {
		t.Errorf("first data row status = %q, want passed (non-failing at top)", records[1][3])
	}
	last := records[len(records)-1]
	if last[3] != "failed" {
		t.Errorf("last data row status = %q, want failed (problems at the bottom)", last[3])
	}
}

// A control that could not be verified on a degraded run is "error", with the
// reason surfaced in the message column.
func TestBuildCSV_ErrorStatusOnDegradedRun(t *testing.T) {
	entries := []control.ControlEntry{{ControlName: "someControl", DisplayName: "Some"}}
	result := &control.AnalysisResult{
		CiValid:         true,
		DegradedReasons: []string{"3 workflow file(s) could not be fetched"},
	}
	records := buildCSV(entries, result)
	if records[1][3] != "error" {
		t.Errorf("degraded clean control status = %q, want error", records[1][3])
	}
	if records[1][5] == "" {
		t.Errorf("error row message empty, want the degraded reason")
	}
}

// Codeless findings under a failing control are dropped (no stable identifier),
// mirroring the previous guard.
func TestBuildCSV_CodelessFindingSkipped(t *testing.T) {
	entries := []control.ControlEntry{{ControlName: "actionsMustBePinnedByCommitSha", DisplayName: "Pin"}}
	result := &control.AnalysisResult{
		CiValid: true,
		Findings: []opaengine.Finding{
			{Code: "", Message: "codeless"},      // dropped
			{Code: "ISSUE-701", Message: "kept"}, // kept
		},
	}
	records := buildCSV(entries, result)
	if len(records) != 2 { // header + 1 kept finding row
		t.Fatalf("records = %d, want 2 (header + 1 kept finding)", len(records))
	}
	if records[1][0] != "ISSUE-701" {
		t.Errorf("kept row code = %q, want ISSUE-701", records[1][0])
	}
}

func TestBuildCSV_LineZeroIsEmptyString(t *testing.T) {
	entries := []control.ControlEntry{{ControlName: "actionsMustBePinnedByCommitSha", DisplayName: "Pin"}}
	result := &control.AnalysisResult{
		CiValid: true,
		Findings: []opaengine.Finding{
			{Code: "ISSUE-701", Severity: "high", Message: "no line"},
		},
	}
	records := buildCSV(entries, result)
	if records[1][8] != "" { // line column
		t.Errorf("line = %q, want empty string for zero-value Line", records[1][8])
	}
}
