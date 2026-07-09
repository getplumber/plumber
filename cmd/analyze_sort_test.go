package cmd

import (
	"testing"

	"github.com/getplumber/plumber/control"
)

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
