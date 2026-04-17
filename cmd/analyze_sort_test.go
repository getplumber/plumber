package cmd

import (
	"testing"

	"github.com/getplumber/plumber/control"
)

func TestSortControlSummariesForComplianceTable(t *testing.T) {
	s := []controlSummary{
		{name: "b", compliance: 100, issues: 0, skipped: false, bySeverity: control.SeverityCounts{}},
		{name: "a", compliance: 0, issues: 2, skipped: false, bySeverity: control.SeverityCounts{Critical: 1}},
		{name: "c", compliance: 0, issues: 1, skipped: false, bySeverity: control.SeverityCounts{High: 2}},
		{name: "z-skipped", compliance: 0, issues: 0, skipped: true},
	}
	sortControlSummariesForComplianceTable(s)
	if s[0].name != "a" || s[1].name != "c" {
		t.Fatalf("expected 0%% rows first (a then c), got %q then %q", s[0].name, s[1].name)
	}
	if s[2].name != "b" {
		t.Fatalf("expected 100%% third, got %q", s[2].name)
	}
	if s[3].name != "z-skipped" {
		t.Fatalf("expected skipped last, got %q", s[3].name)
	}
}

func TestSortControlSummariesForComplianceTable_tieSeverityThenIssues(t *testing.T) {
	s := []controlSummary{
		{name: "low-issues", compliance: 50, issues: 1, skipped: false, bySeverity: control.SeverityCounts{Medium: 1}},
		{name: "high-issues", compliance: 50, issues: 5, skipped: false, bySeverity: control.SeverityCounts{Medium: 1}},
	}
	sortControlSummariesForComplianceTable(s)
	if s[0].name != "high-issues" {
		t.Fatalf("same compliance+severity: more issues first, got %q", s[0].name)
	}
}

func TestSortControlSummariesForIssuesTable(t *testing.T) {
	s := []controlSummary{
		{name: "z-low", issues: 10, bySeverity: control.SeverityCounts{Low: 3}},
		{name: "a-crit", issues: 1, bySeverity: control.SeverityCounts{Critical: 1}},
		{name: "m-med", issues: 2, bySeverity: control.SeverityCounts{Medium: 2}},
	}
	sortControlSummariesForIssuesTable(s)
	if s[0].name != "a-crit" {
		t.Fatalf("critical first, got %q", s[0].name)
	}
	if s[1].name != "m-med" {
		t.Fatalf("medium second, got %q", s[1].name)
	}
	if s[2].name != "z-low" {
		t.Fatalf("low last, got %q", s[2].name)
	}
}

func TestSortControlSummariesForIssuesTable_sameSeverityMoreIssuesThenName(t *testing.T) {
	s := []controlSummary{
		{name: "b", issues: 1, bySeverity: control.SeverityCounts{High: 1}},
		{name: "a", issues: 3, bySeverity: control.SeverityCounts{High: 1}},
	}
	sortControlSummariesForIssuesTable(s)
	if s[0].name != "a" || s[1].name != "b" {
		t.Fatalf("same severity: more issues then name, got %q %q", s[0].name, s[1].name)
	}
}
