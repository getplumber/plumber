package cmd

import "testing"

func TestFilterGroupsForDegraded(t *testing.T) {
	groups := []findingGroup{
		{Title: "green-stats-only", Findings: nil},
		{Title: "has-findings", Findings: []detailedFinding{{Code: "ISSUE-103"}}},
		{Title: "skipped-disabled", Skipped: true, Findings: nil},
		{Title: "another-green", Findings: nil},
	}

	t.Run("not degraded returns input unchanged", func(t *testing.T) {
		got := filterGroupsForDegraded(groups, false)
		if len(got) != len(groups) {
			t.Fatalf("expected %d groups, got %d", len(groups), len(got))
		}
	})

	t.Run("degraded keeps only groups with findings", func(t *testing.T) {
		got := filterGroupsForDegraded(groups, true)
		if len(got) != 1 {
			t.Fatalf("expected 1 group, got %d", len(got))
		}
		if got[0].Title != "has-findings" {
			t.Fatalf("kept the wrong group: %q", got[0].Title)
		}
	})

	t.Run("degraded with no findings yields empty", func(t *testing.T) {
		clean := []findingGroup{
			{Title: "a"},
			{Title: "b", Skipped: true},
		}
		got := filterGroupsForDegraded(clean, true)
		if len(got) != 0 {
			t.Fatalf("expected 0 groups, got %d", len(got))
		}
	})
}
