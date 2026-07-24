package cmd

import (
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
)

// A failing control is always built with BOTH a stats block and its findings
// (see buildProviderControlSummariesAndGroups). The bucketing must still route
// it to the failed/detailed renderer — never collapse it into the passed
// summary — or a real violation would be silently hidden.
func TestRenderFindingGroups_failingControlRendersIssues(t *testing.T) {
	groups := []findingGroup{
		{
			Title:    "Branch must be protected",
			Stats:    []statLine{{Label: "Total Branches", Value: "67"}},
			Findings: []detailedFinding{{Code: codeCritical, Message: `branch "main" must be protected`}},
		},
	}
	out := captureStdout(t, func() { renderFindingGroups(groups) })

	assertContains(t, out, "Failed Controls (1)")
	assertContains(t, out, "Issues Found")
	assertContains(t, out, string(codeCritical))
	assertContains(t, out, `branch "main" must be protected`)
	// The stat block must survive for failing controls — it carries the
	// denominator context that makes a finding legible.
	assertContains(t, out, "Total Branches: 67")
	// Single-finding header uses the singular noun.
	assertContains(t, out, "(1 issue)")
	if strings.Contains(out, "Passed Controls") {
		t.Fatalf("failing control must not appear in the passed summary, got:\n%s", out)
	}
}

// Exercises the whole classification switch: one failing (stats+findings), one
// passing (stats only), one skipped, one empty (dropped).
func TestRenderFindingGroups_bucketing(t *testing.T) {
	groups := []findingGroup{
		{Title: "fail-ctl", Stats: []statLine{{Label: "X", Value: "1"}}, Findings: []detailedFinding{{Code: codeHigh, Message: "boom"}}},
		{Title: "pass-ctl", Stats: []statLine{{Label: "Total", Value: "3"}}},
		{Title: "skip-ctl", Skipped: true, SkipReason: "disabled in configuration"},
		{Title: "empty-ctl"}, // no findings, no stats, not skipped → dropped
	}
	out := captureStdout(t, func() { renderFindingGroups(groups) })

	assertContains(t, out, "Passed Controls (1)")
	assertContains(t, out, "pass-ctl")
	assertContains(t, out, "Skipped Controls (1)")
	assertContains(t, out, "skip-ctl")
	assertContains(t, out, "Failed Controls (1)")
	assertContains(t, out, "fail-ctl")

	if strings.Contains(out, "empty-ctl") {
		t.Fatalf("empty control (no findings/stats) must be dropped entirely, got:\n%s", out)
	}
	// pass-ctl passed cleanly, so its stat block must not be printed.
	if strings.Contains(out, "Total: 3") {
		t.Fatalf("passing control stats must be collapsed, got:\n%s", out)
	}

	// The whole point of the PR: failures print last (nearest the prompt),
	// after the Passed and Skipped sections. Lock the section order in.
	passedIdx := strings.Index(out, "Passed Controls")
	skippedIdx := strings.Index(out, "Skipped Controls")
	failedIdx := strings.Index(out, "Failed Controls")
	if passedIdx < 0 || skippedIdx < 0 || failedIdx < 0 {
		t.Fatalf("all three sections must render, got passed@%d skipped@%d failed@%d:\n%s", passedIdx, skippedIdx, failedIdx, out)
	}
	if passedIdx >= skippedIdx || skippedIdx >= failedIdx {
		t.Fatalf("sections must render Passed → Skipped → Failed (failures last), got passed@%d skipped@%d failed@%d:\n%s", passedIdx, skippedIdx, failedIdx, out)
	}
}

// End-to-end (not just the isolated sort helper): the more-critical control's
// section must print AFTER the less-critical one in the rendered output.
func TestRenderFindingGroups_failingControlsSortedWorstLast(t *testing.T) {
	groups := []findingGroup{
		{Title: "critical-ctl", Findings: []detailedFinding{{Code: codeCritical, Message: "crit-a"}, {Code: codeCritical, Message: "crit-b"}}},
		{Title: "low-ctl", Findings: []detailedFinding{{Code: codeLow, Message: "low"}}},
	}
	out := captureStdout(t, func() { renderFindingGroups(groups) })

	lowIdx := strings.Index(out, "low-ctl")
	critIdx := strings.Index(out, "critical-ctl")
	if lowIdx < 0 || critIdx < 0 {
		t.Fatalf("both controls must render, got:\n%s", out)
	}
	if critIdx < lowIdx {
		t.Fatalf("most-critical control must print last (after the low one), got low@%d crit@%d:\n%s", lowIdx, critIdx, out)
	}
	// Multi-finding header uses the plural noun.
	assertContains(t, out, "(2 issues)")
}

// renderFailedControl renders three per-finding detail branches (DetailLines,
// Location, DocURL). All are live in production (analyze_gitlab.go builds them
// via detailLinesFromFinding / formatFindingLocation / code.DocURL), so a
// regression that dropped or mis-nested them must be caught. Location is also
// run through sanitizeTerminal — a control char in the path must be stripped.
func TestRenderFindingGroups_findingDetailBranches(t *testing.T) {
	groups := []findingGroup{
		{
			Title: "Branch must be protected",
			Findings: []detailedFinding{{
				Code:        codeCritical,
				Message:     "branch main non-compliant",
				DetailLines: []string{"Force push allowed", "Code owner review missing"},
				Location:    "app.yml\x07:12", // embedded BEL control char
				DocURL:      "https://docs.example/ISSUE-505",
			}},
		},
	}
	out := captureStdout(t, func() { renderFindingGroups(groups) })

	assertContains(t, out, "└─ Force push allowed")
	assertContains(t, out, "└─ Code owner review missing")
	assertContains(t, out, "↳ docs: https://docs.example/ISSUE-505")
	// The BEL is stripped, so the clean "app.yml:12" is contiguous; if
	// sanitizeTerminal were skipped the control char would split it.
	assertContains(t, out, "↳ at app.yml:12")
	if strings.ContainsRune(out, '\x07') {
		t.Fatalf("control char in Location must be sanitized out, got:\n%q", out)
	}
}

// The empty-SkipReason fallback ("disabled in configuration") is the common
// production path for a config-disabled control; assert it renders.
func TestRenderFindingGroups_skippedControlDefaultReason(t *testing.T) {
	groups := []findingGroup{
		{Title: "some-control", Skipped: true, SkipReason: ""},
	}
	out := captureStdout(t, func() { renderFindingGroups(groups) })

	assertContains(t, out, "some-control")
	assertContains(t, out, "(disabled in configuration)")
}

// A control that passed but could not fully verify carries a ⚠-prefixed caveat
// stat line. It stays in the passed bucket, but the ⚠ line must survive the
// name-only collapse (the silent-success-on-incomplete-data guard).
func TestRenderFindingGroups_passedControlKeepsCaveat(t *testing.T) {
	caveat := "⚠ Force-push & code-owner rules"
	groups := []findingGroup{
		{
			Title: "Branch must be protected",
			Stats: []statLine{
				{Label: "Total Branches", Value: "67"},
				{Label: caveat, Value: "skipped on 1 branch(es) — token lacks Administration:Read"},
			},
		},
	}
	out := captureStdout(t, func() { renderFindingGroups(groups) })

	assertContains(t, out, "Passed Controls (1)")
	assertContains(t, out, caveat)
	assertContains(t, out, "token lacks Administration:Read")
	// The non-caveat stat must still be suppressed — only the warning survives.
	if strings.Contains(out, "Total Branches: 67") {
		t.Fatalf("only caveat stat lines should survive the collapse, got:\n%s", out)
	}
}

// The caveat guard only works while the producer's label prefix and
// caveatStatLines' statCaveatPrefix agree. The test above exercises the
// collapse with a synthetic label; this one goes end-to-end through the
// REAL branchMustBeProtected stat builder (the only production caveat
// emitter) so a prefix drift on either side — a producer glyph change
// (e.g. "⚠️" with the variation selector), a prepended color code, or a
// changed statCaveatPrefix — fails the build instead of silently
// rendering a bare ✓ for a control that was never fully verified.
func TestRenderFindingGroups_passedControlCaveatFromRealStatsBuilder(t *testing.T) {
	stats := buildGitHubControlStats("branchMustBeProtected", &control.GitHubAnalysisStats{
		BranchesTotal:                    4,
		BranchesMatched:                  2,
		BranchesProtected:                2,
		BranchesProtectionDetailsUnknown: 1,
	}, nil)

	groups := []findingGroup{{Title: "Branch must be protected", Stats: stats}}
	out := captureStdout(t, func() { renderFindingGroups(groups) })

	assertContains(t, out, "Passed Controls (1)")
	assertContains(t, out, "token lacks Administration:Read")
	assertContains(t, out, "skipped on 1 branch(es)")
	// Non-caveat stats from the same real builder must still be suppressed.
	if strings.Contains(out, "Total Branches") {
		t.Fatalf("only caveat stat lines should survive the collapse, got:\n%s", out)
	}
}
