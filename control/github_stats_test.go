package control

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// TestAggregate_ReusableWorkflowRefsCountTowardActionPinning locks
// the parity between the action-unpinned Rego rule (which has two
// `deny` blocks — one for steps[].uses and one for jobs.<id>.uses)
// and the Go stats counter. Without this, dashboards show
// "actionRefsUnpinned: 0" alongside N ISSUE-701 findings whenever
// the project uses reusable workflow calls — the exact bug we hit
// on facebook/react where 10 unpinned reusable WF calls appeared
// as 10 findings but 0 in the counter.
func TestAggregate_ReusableWorkflowRefsCountTowardActionPinning(t *testing.T) {
	pipeline := &ir.NormalizedPipeline{
		Jobs: []ir.Job{
			// Step-level: 1 trusted-owner SHA-pinned, 1 third-party SHA-pinned,
			// 1 third-party with mutable ref.
			{
				Name: "build",
				Uses: []ir.Action{
					{Uses: "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd"},
					{Uses: "anchore/scan-action@2.0.0"}, // not SHA, third-party → unpinned
					{Uses: "aquasecurity/trivy-action@de4ee9c3a1e0d44ac3f97d7baa4f49adf01b6b27"},
				},
			},
			// Reusable workflow call, mutable ref — was being silently
			// dropped from the counter before the fix.
			{
				Name:                 "deploy",
				ReusableWorkflowUses: "someorg/somerepo/.github/workflows/deploy.yml@v1",
			},
			// Reusable workflow call, SHA-pinned — counted but not unpinned.
			{
				Name:                 "release",
				ReusableWorkflowUses: "someorg/somerepo/.github/workflows/release.yml@abcdef0123456789abcdef0123456789abcdef01",
			},
			// Reusable workflow call to a trusted owner — exempt.
			{
				Name:                 "lint",
				ReusableWorkflowUses: "actions/reusable/.github/workflows/lint.yml@v3",
			},
		},
	}

	pc := &configuration.PlumberConfig{
		GitHub: &configuration.ProviderConfig{
			Controls: configuration.ControlsConfig{
				ActionsMustBePinnedByCommitSha: &configuration.ActionsPinnedByShaControlConfig{
					TrustedOwners: []string{"actions", "github"},
				},
			},
		},
	}

	stats := AggregateGitHubStats(pipeline, pc)

	// Expected breakdown:
	//   step-level: 1 exempt (actions/checkout), 2 in-scope (1 unpinned)
	//   reusable WF: 1 exempt (actions/reusable), 2 in-scope (1 unpinned)
	// Totals: 3 exempt, 4 in-scope, 2 unpinned.
	if stats.ActionRefsExempt != 2 {
		t.Errorf("ActionRefsExempt = %d, want 2 (1 step + 1 reusable WF)", stats.ActionRefsExempt)
	}
	if stats.ActionRefsTotal != 4 {
		t.Errorf("ActionRefsTotal = %d, want 4 (2 step-level in-scope + 2 reusable WF in-scope)", stats.ActionRefsTotal)
	}
	if stats.ActionRefsUnpinned != 2 {
		t.Errorf("ActionRefsUnpinned = %d, want 2 (1 step + 1 reusable WF)", stats.ActionRefsUnpinned)
	}
	if stats.ReusableCalls != 3 {
		t.Errorf("ReusableCalls = %d, want 3 (the three jobs with ReusableWorkflowUses set)", stats.ReusableCalls)
	}
}

// TestDangerousTriggerMetricFollowsFindings locks the
// workflowsWithDangerousTrigger metric to the ISSUE-802 findings the rule
// actually emits, rather than a structural scan of trigger names. The
// rule's fork-guard recognition lives in Rego (#235), so a workflow with
// a dangerous trigger but a `push`-event / author-association guard emits
// no finding and must not inflate the metric (#235 follow-up).
func TestDangerousTriggerMetricFollowsFindings(t *testing.T) {
	// No ISSUE-802 findings → metric 0, even if a structural pass seeded
	// a higher value.
	s := &GitHubAnalysisStats{WorkflowsWithDangerousTrigger: 2}
	ApplyGitHubFindingCounts(s, nil)
	if s.WorkflowsWithDangerousTrigger != 0 {
		t.Fatalf("no ISSUE-802 findings → metric 0, got %d", s.WorkflowsWithDangerousTrigger)
	}

	// Per-job findings collapse to their distinct workflows; other codes
	// are ignored.
	s = &GitHubAnalysisStats{}
	findings := []opaengine.Finding{
		{Code: "ISSUE-802", Job: "ci/build", File: ".github/workflows/ci.yml"},
		{Code: "ISSUE-802", Job: "ci/test", File: ".github/workflows/ci.yml"},
		{Code: "ISSUE-802", Job: "release/publish", File: ".github/workflows/release.yml"},
		{Code: "ISSUE-103", Job: "ci/build", File: ".github/workflows/ci.yml"},
	}
	ApplyGitHubFindingCounts(s, findings)
	if s.WorkflowsWithDangerousTrigger != 2 {
		t.Fatalf("expected 2 distinct flagged workflows, got %d", s.WorkflowsWithDangerousTrigger)
	}
}
