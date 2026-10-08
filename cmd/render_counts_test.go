package cmd

import (
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
)

// The other findings heading counts what the summary counts: one per
// distinct finding, the same finding reported twice counting once.
func TestOtherFindingsHeadingCountsWhatTheSummaryCounts(t *testing.T) {
	groups := []findingGroup{{
		Title: "checkoutMustNotPersistCredentials",
		Findings: []detailedFinding{
			{Code: "ISSUE-307", Message: "checkout persists credentials", Location: "a.yml:3", ContextualSeverity: "low"},
			{Code: "ISSUE-307", Message: "checkout persists credentials", Location: "a.yml:3", ContextualSeverity: "low"},
			{Code: "ISSUE-307", Message: "checkout persists credentials", Location: "b.yml:9", ContextualSeverity: "low"},
		},
	}}
	score := &control.PlumberScoreResult{ProfileID: control.PlumberScoreProfileIDV4, OtherFindings: &control.OtherFindingsLoss{Count: 2}}
	out := captureStdoutAll(t, func() { renderFindingGroupsV4(groups, score, nil, reportBlock) })
	if !strings.Contains(out, "Individual findings (2)") {
		t.Errorf("want the heading to count the two distinct findings:\n%s", out)
	}
}
