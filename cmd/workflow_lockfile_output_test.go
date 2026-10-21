package cmd

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
)

const lockfileNote = ".github/workflows/actions.lock locks 2 step reference(s); reusable workflow calls are not covered by lockfiles and still need a commit SHA"

// workflowLockfileStats: two step refs locked by the branch's lockfile, one
// reusable-workflow call left unpinned (lockfiles do not cover it, #542).
func workflowLockfileStats() *control.GitHubAnalysisStats {
	return &control.GitHubAnalysisStats{
		ActionRefsTotal:      4,
		ActionRefsUnpinned:   1,
		WorkflowLockfilePath: ".github/workflows/actions.lock",
		ActionRefsWorkflowLockfile: []control.PinnedRef{
			{Job: "ci/build", Uses: "docker/setup-qemu-action@v3.6.0", Line: 11, PinnedVia: control.PinnedViaWorkflowLockfile},
			{Job: "ci/build", Uses: "codecov/codecov-action@v5", Line: 12, PinnedVia: control.PinnedViaWorkflowLockfile},
		},
	}
}

func TestBuildGitHubControlStats_WorkflowLockfile(t *testing.T) {
	got := buildGitHubControlStats("actionsMustBePinnedByCommitSha", workflowLockfileStats(), nil)
	want := []statLine{
		{Label: "Total Action Refs", Value: "4"},
		{Label: "Pinned By SHA", Value: "1"},
		{Label: statPinnedByImmutableRelease, Value: "0"},
		{Label: statPinnedByWorkflowLockfile, Value: "2"},
		{Label: "Not Pinned By SHA", Value: "1"},
		{Label: "Trusted-Owner Exempt", Value: "0"},
		{Label: statWorkflowLockfile, Value: lockfileNote},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}

	// Without a lockfile the block reads exactly as before.
	for _, s := range buildGitHubControlStats("actionsMustBePinnedByCommitSha", &control.GitHubAnalysisStats{ActionRefsTotal: 1}, nil) {
		if s.Label == statPinnedByWorkflowLockfile || s.Label == statWorkflowLockfile {
			t.Errorf("lockfile stat %q without a lockfile", s.Label)
		}
	}
}

func TestRenderNotes_WorkflowLockfile(t *testing.T) {
	stats := buildGitHubControlStats("actionsMustBePinnedByCommitSha", workflowLockfileStats(), nil)
	title := "Third-party actions must be pinned by commit SHA"

	failing := []findingGroup{{
		Title:    title,
		Stats:    stats,
		Findings: []detailedFinding{{Code: "ISSUE-701", Message: "octo/shared/.github/workflows/ci.yml@v1.2.0", ContextualSeverity: "high"}},
	}}
	out := captureStdoutAll(t, func() { renderFindingGroupsV4(failing, nil, nil, reportBlock) })
	assertContains(t, out, "Accepted as pinned by a workflow lockfile")
	assertContains(t, out, title+": "+lockfileNote)

	passed := captureStdoutAll(t, func() { renderPassedControlsSummary([]findingGroup{{Title: title, Stats: stats}}) })
	assertContains(t, passed, statWorkflowLockfile+": "+lockfileNote)
}

func TestBuildActionPinningBlock_WorkflowLockfile(t *testing.T) {
	payload, err := json.Marshal(buildActionPinningBlock(legacyCommon{}, &control.AnalysisResult{GitHubStats: workflowLockfileStats()}, nil))
	if err != nil {
		t.Fatal(err)
	}
	var block struct {
		Metrics struct {
			ActionRefsWorkflowLockfile int `json:"actionRefsWorkflowLockfile"`
		} `json:"metrics"`
		WorkflowLockfile     string `json:"workflowLockfile"`
		WorkflowLockfileRefs []struct {
			Job       string `json:"job"`
			Uses      string `json:"uses"`
			Line      int    `json:"line"`
			PinnedVia string `json:"pinnedVia"`
		} `json:"workflowLockfileRefs"`
	}
	if err := json.Unmarshal(payload, &block); err != nil {
		t.Fatal(err)
	}
	if block.WorkflowLockfile != ".github/workflows/actions.lock" || block.Metrics.ActionRefsWorkflowLockfile != 2 || len(block.WorkflowLockfileRefs) != 2 {
		t.Fatalf("block = %s", payload)
	}
	if r := block.WorkflowLockfileRefs[0]; r.Uses != "docker/setup-qemu-action@v3.6.0" || r.Line != 11 || r.PinnedVia != "workflow_lockfile" {
		t.Errorf("first ref = %+v", r)
	}

	// Without a lockfile no lockfile key appears.
	plain, _ := json.Marshal(buildActionPinningBlock(legacyCommon{}, &control.AnalysisResult{GitHubStats: &control.GitHubAnalysisStats{}}, nil))
	if strings.Contains(string(plain), "orkflowLockfile") {
		t.Errorf("lockfile keys without a lockfile: %s", plain)
	}
}
