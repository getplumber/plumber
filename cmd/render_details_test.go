package cmd

import (
	"strings"
	"testing"
)

// TestRenderFindingGroups_NotEvaluableNeverRendersAsPassed pins the fix for
// a real false green: a control whose lane supplied nothing has no findings,
// so before the Not Evaluated bucket existed it fell through to "✓ Passed"
// and the terminal claimed the run had verified something it never looked
// at. A platform-mode run without include attribution puts several controls
// in that state at once.
func TestRenderFindingGroups_NotEvaluableNeverRendersAsPassed(t *testing.T) {
	out := captureStdout(t, func() {
		renderFindingGroups([]findingGroup{
			{Title: "Really Passed", Stats: []statLine{{Label: "Total", Value: "1"}}},
			{Title: "Turned Off", Skipped: true},
			{
				Title:              "Could Not Check",
				NotEvaluable:       true,
				NotEvaluableReason: "include_attribution_unavailable",
				// Stats present: this is exactly the shape that used to be
				// bucketed as passed.
				Stats: []statLine{{Label: "Total", Value: "3"}},
			},
			{Title: "Really Failed", Findings: []detailedFinding{{Code: "ISSUE-999"}}},
		})
	})

	if !strings.Contains(out, "Not Evaluated (1)") {
		t.Fatalf("a not-evaluable control needs its own bucket:\n%s", out)
	}
	if !strings.Contains(out, "include_attribution_unavailable") {
		t.Fatalf("the reason must be shown so the reader knows what is missing:\n%s", out)
	}
	if !strings.Contains(out, "Passed Controls (1)") {
		t.Fatalf("the genuinely passing control must still be counted once:\n%s", out)
	}
	// The load-bearing assertion: the not-evaluable control must not appear
	// anywhere in the passed section.
	passed := out[strings.Index(out, "Passed Controls"):strings.Index(out, "Skipped Controls")]
	if strings.Contains(passed, "Could Not Check") {
		t.Fatalf("a not-evaluable control rendered as PASSED — the false green is back:\n%s", passed)
	}
}

// TestRenderFindingGroups_NotEvaluableBeatsFindings: findings from a dead
// lane are dropped upstream, so a non-zero count here can only be stale and
// must not be shown as a real failure.
func TestRenderFindingGroups_NotEvaluableBeatsFindings(t *testing.T) {
	out := captureStdout(t, func() {
		renderFindingGroups([]findingGroup{
			{Title: "Stale", NotEvaluable: true, Findings: []detailedFinding{{Code: "ISSUE-410"}}},
		})
	})
	if !strings.Contains(out, "Not Evaluated (1)") {
		t.Fatalf("want the not-evaluated bucket:\n%s", out)
	}
	if strings.Contains(out, "Failed Controls") {
		t.Fatalf("stale findings from a dead lane must not render as a failure:\n%s", out)
	}
}

// TestRenderFindingGroups_DismissedFindingTaggedAndExcludedFromCount pins
// #447 part 2's terminal presentation: a finding the platform dismissed is
// still shown (never silently dropped), tagged so the reader knows it is
// not part of the live verdict, and left out of the issue count so "1
// issue" does not read as two.
func TestRenderFindingGroups_DismissedFindingTaggedAndExcludedFromCount(t *testing.T) {
	out := captureStdout(t, func() {
		renderFindingGroups([]findingGroup{
			{
				Title:     "Some Control",
				Dismissed: 1,
				Findings: []detailedFinding{
					{Code: "ISSUE-101", Message: "live one"},
					{Code: "ISSUE-101", Message: "dismissed one", Dismissed: true},
				},
			},
		})
	})
	if !strings.Contains(out, "1 issue, 1 dismissed") {
		t.Fatalf("want the header to read '1 issue, 1 dismissed', the live count excluding the dismissed finding:\n%s", out)
	}
	if !strings.Contains(out, "dismissed one") {
		t.Fatalf("the dismissed finding must still be shown, never silently dropped:\n%s", out)
	}
	dismissedLine := out[strings.Index(out, "dismissed one"):]
	if idx := strings.Index(dismissedLine, "\n"); idx >= 0 {
		dismissedLine = dismissedLine[:idx]
	}
	if !strings.Contains(dismissedLine, "[dismissed on the platform]") {
		t.Fatalf("the dismissed finding's own line must carry the platform tag:\n%s", out)
	}
	liveLine := out[strings.Index(out, "live one"):strings.Index(out, "dismissed one")]
	if strings.Contains(liveLine, "[dismissed on the platform]") {
		t.Fatalf("the live finding must not carry the dismissed tag:\n%s", out)
	}
}
