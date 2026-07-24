package cmd

import (
	"testing"

	"github.com/getplumber/plumber/control"
)

// Concrete registry codes with known, distinct severities, so the derived
// SeverityCounts is deterministic (see control/codes.go).
const (
	codeCritical = control.CodeImpostorCommit            // ISSUE-707, critical
	codeHigh     = control.CodeImageUnauthorizedSource   // ISSUE-101, high
	codeMedium   = control.CodeRefVersionMismatch        // ISSUE-708, medium
	codeLow      = control.CodeActionRemoteExecUnverified // ISSUE-716, low
)

// failedGroup builds a failing findingGroup whose findings carry the given
// codes — its severity tally is then derived exactly as the renderer does.
func failedGroup(title string, codes ...control.ErrorCode) findingGroup {
	items := make([]detailedFinding, 0, len(codes))
	for _, c := range codes {
		items = append(items, detailedFinding{Code: c})
	}
	return findingGroup{Title: title, Findings: items}
}

func TestSortFindingGroupsWorstLast_criticalPrintsLast(t *testing.T) {
	groups := []findingGroup{
		failedGroup("crit", codeCritical),
		failedGroup("low", codeLow),
		failedGroup("med", codeMedium),
	}
	sortFindingGroupsWorstLast(groups)
	if got := groups[len(groups)-1].Title; got != "crit" {
		t.Fatalf("critical control must print last, got %q last (order: %q, %q, %q)",
			got, groups[0].Title, groups[1].Title, groups[2].Title)
	}
	if groups[0].Title != "low" {
		t.Fatalf("least severe control must print first, got %q", groups[0].Title)
	}
}

func TestSortFindingGroupsWorstLast_moreCriticalsPrintLast(t *testing.T) {
	// Same top tier (critical), but more criticals is worse — this is
	// decided inside compareSeverityWorstFirst (critical count), so the
	// control with two criticals must print last.
	groups := []findingGroup{
		failedGroup("two-crit", codeCritical, codeCritical),
		failedGroup("one-crit", codeCritical),
	}
	sortFindingGroupsWorstLast(groups)
	if got := groups[len(groups)-1].Title; got != "two-crit" {
		t.Fatalf("more criticals must print last, got %q last", got)
	}
}

func TestSortFindingGroupsWorstLast_equalSeverityTiesBreakOnTitle(t *testing.T) {
	// Identical severity tallies (one high finding each); the only reachable
	// tie-break is the title, ascending, so "alpha" prints before "zeta".
	groups := []findingGroup{
		failedGroup("zeta", codeHigh),
		failedGroup("alpha", codeHigh),
	}
	sortFindingGroupsWorstLast(groups)
	if groups[0].Title != "alpha" || groups[1].Title != "zeta" {
		t.Fatalf("equal severity must tie-break on title asc, got %q then %q", groups[0].Title, groups[1].Title)
	}
}
