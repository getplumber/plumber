package cmd

import (
	"reflect"
	"testing"

	"github.com/getplumber/plumber/control"
)

// TestBuildGitHubControlStats_WorkflowsMustBeValid pins the stat block of
// workflowsMustBeValid (ISSUE-423, #517). WorkflowsTotal dedupes on
// workflow name and includes reusable callees (control/github_stats.go),
// so it is not a file count: the two lines are read straight off the
// stats, with no sum pretending to be a file total.
func TestBuildGitHubControlStats_WorkflowsMustBeValid(t *testing.T) {
	stats := &control.GitHubAnalysisStats{WorkflowsTotal: 110, WorkflowFilesInvalid: 1}
	got := buildGitHubControlStats("workflowsMustBeValid", stats, nil)
	want := []statLine{
		{Label: "Workflows parsed", Value: "110"},
		{Label: "Invalid workflow files", Value: "1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}

// With no invalid workflow files, the count is zero, not omitted.
func TestBuildGitHubControlStats_WorkflowsMustBeValid_NoneInvalid(t *testing.T) {
	stats := &control.GitHubAnalysisStats{WorkflowsTotal: 5}
	got := buildGitHubControlStats("workflowsMustBeValid", stats, nil)
	want := []statLine{
		{Label: "Workflows parsed", Value: "5"},
		{Label: "Invalid workflow files", Value: "0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}
