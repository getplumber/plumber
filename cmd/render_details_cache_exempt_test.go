package cmd

import (
	"reflect"
	"testing"

	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// TestBuildGitHubControlStats_CacheWriteExemptions pins the stat block of
// untrustedTriggersMustNotWriteCache: the workflows scanned, the jobs
// flagged, and the exempted jobs that would have been flagged, named once
// each as accepted risk in the exemption line every report prints.
func TestBuildGitHubControlStats_CacheWriteExemptions(t *testing.T) {
	stats := &control.GitHubAnalysisStats{WorkflowsTotal: 3, CacheWriteExempted: []string{"triage/label", "ci/warm"}}
	findings := []opaengine.Finding{{Code: "ISSUE-705", Job: "ci/build"}}
	got := buildGitHubControlStats("untrustedTriggersMustNotWriteCache", stats, findings)
	want := []statLine{
		{Label: "Workflows Scanned", Value: "3"},
		{Label: "Jobs Granted Cache Write On Untrusted Triggers", Value: "1"},
		{Label: statExempted, Value: "ci/warm, triage/label (accepted risk: cache write granted on an untrusted trigger)"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}

// TestBuildGitHubControlStats_WorkflowsMustBeValid pins the stat block of
// workflowsMustBeValid (ISSUE-423, #517): the total includes the invalid
// files (never parsed into a workflow), named again as their own count.
func TestBuildGitHubControlStats_WorkflowsMustBeValid(t *testing.T) {
	stats := &control.GitHubAnalysisStats{WorkflowsTotal: 110, WorkflowFilesInvalid: 1}
	got := buildGitHubControlStats("workflowsMustBeValid", stats, nil)
	want := []statLine{
		{Label: "Total Workflows", Value: "111"},
		{Label: "Invalid workflow files", Value: "1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}

// With no invalid workflow files, the counts still add up (zero invalid).
func TestBuildGitHubControlStats_WorkflowsMustBeValid_NoneInvalid(t *testing.T) {
	stats := &control.GitHubAnalysisStats{WorkflowsTotal: 5}
	got := buildGitHubControlStats("workflowsMustBeValid", stats, nil)
	want := []statLine{
		{Label: "Total Workflows", Value: "5"},
		{Label: "Invalid workflow files", Value: "0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}

// With no exemption the block carries no exemption line, so no note.
func TestBuildGitHubControlStats_CacheWriteNoExemption(t *testing.T) {
	got := buildGitHubControlStats("untrustedTriggersMustNotWriteCache", &control.GitHubAnalysisStats{WorkflowsTotal: 1}, nil)
	for _, s := range got {
		if s.Label == statExempted {
			t.Errorf("no exemption, no line: %+v", got)
		}
	}
}

// TestRenderPassedControlsSummary_CacheWriteExemptions: a control that
// passed because every job it would flag is exempted still names them
// under its ✓, as accepted risk.
func TestRenderPassedControlsSummary_CacheWriteExemptions(t *testing.T) {
	groups := []findingGroup{{
		Title: "Untrusted triggers must not write the cache",
		Stats: buildGitHubControlStats("untrustedTriggersMustNotWriteCache", &control.GitHubAnalysisStats{CacheWriteExempted: []string{"triage/label"}}, nil),
	}}
	out := captureStdoutAll(t, func() { renderPassedControlsSummary(groups) })
	assertContains(t, out, "Exempted By Configuration: triage/label (accepted risk: cache write granted on an untrusted trigger)")
}
