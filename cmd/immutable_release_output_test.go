package cmd

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
)

func immutableReleaseStats() *control.GitHubAnalysisStats {
	return &control.GitHubAnalysisStats{
		ActionRefsTotal:    5,
		ActionRefsUnpinned: 2,
		ActionRefsExempt:   1,
		ActionRefsImmutableRelease: []control.PinnedRef{
			{Job: "ci/build", Uses: "docker/build-push-action@v7.4.0", Line: 12, PinnedVia: control.PinnedViaImmutableRelease},
			{Job: "ci/call", Uses: "octo/shared/.github/workflows/ci.yml@v1.2.0", PinnedVia: control.PinnedViaImmutableRelease},
		},
	}
}

// TestBuildGitHubControlStats_ImmutableReleaseRefs pins the ISSUE-701 stat
// block (#421): a ref accepted through an immutable release is not counted
// as pinned by SHA, gets its own count, and is named so the terminal says
// why a tag passed.
func TestBuildGitHubControlStats_ImmutableReleaseRefs(t *testing.T) {
	got := buildGitHubControlStats("actionsMustBePinnedByCommitSha", immutableReleaseStats(), nil)
	want := []statLine{
		{Label: "Total Action Refs", Value: "6"},
		{Label: "Pinned By SHA", Value: "1"},
		{Label: statPinnedByImmutableRelease, Value: "2"},
		{Label: "Not Pinned By SHA", Value: "2"},
		{Label: "Trusted-Owner Exempt", Value: "1"},
		{Label: statImmutableReleaseRefs, Value: "docker/build-push-action@v7.4.0, octo/shared/.github/workflows/ci.yml@v1.2.0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}

// TestBuildGitHubControlStats_ImmutableReleaseRefsSortedAndDeduped: the
// same immutable-release tag used by two jobs counts twice but is named
// once, and the names are sorted whatever order the jobs came in.
func TestBuildGitHubControlStats_ImmutableReleaseRefsSortedAndDeduped(t *testing.T) {
	stats := &control.GitHubAnalysisStats{
		ActionRefsTotal: 3,
		ActionRefsImmutableRelease: []control.PinnedRef{
			{Job: "ci/call", Uses: "octo/shared/.github/workflows/ci.yml@v1.2.0", PinnedVia: control.PinnedViaImmutableRelease},
			{Job: "ci/build", Uses: "docker/build-push-action@v7.4.0", Line: 12, PinnedVia: control.PinnedViaImmutableRelease},
			{Job: "ci/test", Uses: "docker/build-push-action@v7.4.0", Line: 20, PinnedVia: control.PinnedViaImmutableRelease},
		},
	}
	got := map[string]string{}
	for _, s := range buildGitHubControlStats("actionsMustBePinnedByCommitSha", stats, nil) {
		got[s.Label] = s.Value
	}
	if got[statPinnedByImmutableRelease] != "3" {
		t.Errorf("%s = %q, want \"3\" (every occurrence counts)", statPinnedByImmutableRelease, got[statPinnedByImmutableRelease])
	}
	if want := "docker/build-push-action@v7.4.0, octo/shared/.github/workflows/ci.yml@v1.2.0"; got[statImmutableReleaseRefs] != want {
		t.Errorf("%s = %q, want %q (sorted, each ref once)", statImmutableReleaseRefs, got[statImmutableReleaseRefs], want)
	}
}

// TestRenderFindingGroupsV4_ImmutableReleaseNote: the contextual report
// prints no stat block, so the accepted refs get their own note, under a
// heading of their own (they are not a configuration exemption).
func TestRenderFindingGroupsV4_ImmutableReleaseNote(t *testing.T) {
	stats := buildGitHubControlStats("actionsMustBePinnedByCommitSha", immutableReleaseStats(), nil)
	groups := []findingGroup{{
		Title:    "Actions must be pinned by commit SHA",
		Stats:    stats,
		Findings: []detailedFinding{{Code: "ISSUE-701", Message: "docker/build-push-action@v7", ContextualSeverity: "low"}},
	}}
	out := captureStdoutAll(t, func() { renderFindingGroupsV4(groups, nil, nil, reportBlock) })

	assertContains(t, out, "Accepted as pinned by an immutable release")
	assertContains(t, out, "Actions must be pinned by commit SHA: docker/build-push-action@v7.4.0, octo/shared/.github/workflows/ci.yml@v1.2.0")
	if strings.Contains(out, "Exempted by configuration") {
		t.Errorf("an immutable release is no configuration exemption:\n%s", out)
	}
}

// TestRenderPassedControlsSummary_ImmutableReleaseRefs: a control that
// passed only because its tags are immutable releases names them under its
// ✓ line.
func TestRenderPassedControlsSummary_ImmutableReleaseRefs(t *testing.T) {
	stats := buildGitHubControlStats("actionsMustBePinnedByCommitSha", immutableReleaseStats(), nil)
	groups := []findingGroup{{Title: "Actions must be pinned by commit SHA", Stats: stats}}
	out := captureStdoutAll(t, func() { renderPassedControlsSummary(groups) })

	assertContains(t, out, statImmutableReleaseRefs+": docker/build-push-action@v7.4.0, octo/shared/.github/workflows/ci.yml@v1.2.0")
	if strings.Contains(out, "Total Action Refs") {
		t.Errorf("a passed control prints its notes only, not its stats:\n%s", out)
	}
}

// TestBuildActionPinningBlock_ImmutableReleaseRefs pins the JSON side: the
// count sits in metrics, and each accepted ref is listed with the
// pinnedVia marker.
func TestBuildActionPinningBlock_ImmutableReleaseRefs(t *testing.T) {
	result := &control.AnalysisResult{GitHubStats: immutableReleaseStats()}
	payload, err := json.Marshal(buildActionPinningBlock(legacyCommon{}, result, nil))
	if err != nil {
		t.Fatal(err)
	}
	var block struct {
		Metrics struct {
			ActionRefsImmutableRelease int `json:"actionRefsImmutableRelease"`
		} `json:"metrics"`
		ImmutableReleaseRefs []map[string]any `json:"immutableReleaseRefs"`
	}
	if err := json.Unmarshal(payload, &block); err != nil {
		t.Fatal(err)
	}
	if block.Metrics.ActionRefsImmutableRelease != 2 {
		t.Errorf("metrics.actionRefsImmutableRelease = %d, want 2", block.Metrics.ActionRefsImmutableRelease)
	}
	want := []map[string]any{
		{"job": "ci/build", "uses": "docker/build-push-action@v7.4.0", "line": float64(12), "pinnedVia": "immutable_release"},
		{"job": "ci/call", "uses": "octo/shared/.github/workflows/ci.yml@v1.2.0", "pinnedVia": "immutable_release"},
	}
	if !reflect.DeepEqual(block.ImmutableReleaseRefs, want) {
		t.Fatalf("immutableReleaseRefs = %v, want %v", block.ImmutableReleaseRefs, want)
	}
}
