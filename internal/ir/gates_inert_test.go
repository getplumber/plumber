package ir

import "testing"

// healthyGitHubPipeline is a one-job GitHub pipeline with a trigger, a
// live runner label and no conditions: a healthy job, Inert should stay
// empty after MarkInert.
func healthyGitHubPipeline() *NormalizedPipeline {
	return &NormalizedPipeline{
		Provider:    ProviderGitHub,
		ProjectPath: "me/repo",
		Jobs: []Job{
			{Name: "ci/build", OriginFile: ".github/workflows/ci.yml", Triggers: []string{"push"}, WorkflowHasTriggers: true, RunsOn: []string{"ubuntu-22.04"}},
		},
	}
}

// TestMarkInertHealthyJobStaysEmpty pins that a job with a trigger, a
// live runner and no repository-pinned condition is left alone.
func TestMarkInertHealthyJobStaysEmpty(t *testing.T) {
	p := healthyGitHubPipeline()
	MarkInert(p)
	if p.Jobs[0].Inert != "" {
		t.Fatalf("Inert = %q, want empty", p.Jobs[0].Inert)
	}
}

// TestMarkInertRunnerLabelRetired pins the reason for a job pinned to a
// single retired runner label.
func TestMarkInertRunnerLabelRetired(t *testing.T) {
	p := healthyGitHubPipeline()
	p.Jobs[0].RunsOn = []string{"ubuntu-20.04"}
	MarkInert(p)
	if want := "runner label retired (ubuntu-20.04)"; p.Jobs[0].Inert != want {
		t.Fatalf("Inert = %q, want %q", p.Jobs[0].Inert, want)
	}
}

// TestMarkInertRunnerLabelListMixedIsNotInert pins the brief's
// conservative reading: a list mixing a retired label with a live one
// does not mark the job inert (only every label retired, or a single
// retired label, does).
func TestMarkInertRunnerLabelListMixedIsNotInert(t *testing.T) {
	p := healthyGitHubPipeline()
	p.Jobs[0].RunsOn = []string{"ubuntu-20.04", "ubuntu-22.04"}
	MarkInert(p)
	if p.Jobs[0].Inert != "" {
		t.Fatalf("Inert = %q, want empty (mixed list)", p.Jobs[0].Inert)
	}
}

// TestMarkInertRunnerLabelListAllRetired pins that a list where every
// label is retired is inert, with the first retired label named.
func TestMarkInertRunnerLabelListAllRetired(t *testing.T) {
	p := healthyGitHubPipeline()
	p.Jobs[0].RunsOn = []string{"ubuntu-20.04", "macos-11"}
	MarkInert(p)
	if want := "runner label retired (ubuntu-20.04)"; p.Jobs[0].Inert != want {
		t.Fatalf("Inert = %q, want %q", p.Jobs[0].Inert, want)
	}
}

// TestMarkInertRunnerExpressionSetsNothing pins that a computed
// `runs-on:` expression is unknown, not a retired label: MarkInert sets
// nothing for the runner even when the literal label would otherwise
// read as retired-sounding text.
func TestMarkInertRunnerExpressionSetsNothing(t *testing.T) {
	p := healthyGitHubPipeline()
	p.Jobs[0].RunsOn = nil
	p.Jobs[0].RunsOnExpression = true
	MarkInert(p)
	if p.Jobs[0].Inert != "" {
		t.Fatalf("Inert = %q, want empty (runner is an expression)", p.Jobs[0].Inert)
	}
}

// TestMarkInertWorkflowDisabled pins the reason for a job whose
// workflow state the GitHub collector read as disabled_inactivity.
func TestMarkInertWorkflowDisabled(t *testing.T) {
	p := healthyGitHubPipeline()
	p.WorkflowStates = map[string]string{".github/workflows/ci.yml": "disabled_inactivity"}
	p.WorkflowStatesKnown = true
	MarkInert(p)
	if want := "workflow disabled (disabled_inactivity)"; p.Jobs[0].Inert != want {
		t.Fatalf("Inert = %q, want %q", p.Jobs[0].Inert, want)
	}
}

// TestMarkInertWorkflowDisabledNormalizesAnAbsoluteOriginFile pins that
// the local scan's OriginFile (the absolute filesystem path, dir joined
// with the workflow file name) still matches WorkflowStates, which is
// always keyed by the repo-relative path the workflows API returns
// (".github/workflows/<file>", the same shape the remote scan's
// OriginFile already carries).
func TestMarkInertWorkflowDisabledNormalizesAnAbsoluteOriginFile(t *testing.T) {
	p := healthyGitHubPipeline()
	p.Jobs[0].OriginFile = "/home/runner/work/repo/repo/.github/workflows/ci.yml"
	p.WorkflowStates = map[string]string{".github/workflows/ci.yml": "disabled_manually"}
	p.WorkflowStatesKnown = true
	MarkInert(p)
	if want := "workflow disabled (disabled_manually)"; p.Jobs[0].Inert != want {
		t.Fatalf("Inert = %q, want %q", p.Jobs[0].Inert, want)
	}
}

// TestMarkInertActionsDisabledTakesPrecedence pins that ActionsDisabled
// (the repository-wide signal) wins over a job's own workflow state or
// runner label.
func TestMarkInertActionsDisabledTakesPrecedence(t *testing.T) {
	p := healthyGitHubPipeline()
	p.Jobs[0].RunsOn = []string{"ubuntu-20.04"}
	p.WorkflowStates = map[string]string{".github/workflows/ci.yml": "disabled_manually"}
	p.WorkflowStatesKnown = true
	p.ActionsDisabled = true
	MarkInert(p)
	if want := "actions disabled"; p.Jobs[0].Inert != want {
		t.Fatalf("Inert = %q, want %q", p.Jobs[0].Inert, want)
	}
}

// TestMarkInertNoTrigger pins the reason for a job in a workflow with no
// triggers at all: Triggers empty and WorkflowHasTriggers false (the
// GitHub collector's own signal for "no on: key, or on: with no event").
func TestMarkInertNoTrigger(t *testing.T) {
	p := healthyGitHubPipeline()
	p.Jobs[0].Triggers = nil
	p.Jobs[0].WorkflowHasTriggers = false
	MarkInert(p)
	if want := "no trigger"; p.Jobs[0].Inert != want {
		t.Fatalf("Inert = %q, want %q", p.Jobs[0].Inert, want)
	}
}

// TestMarkInertNoTriggerNeverFiresWithExistingTriggers pins the
// backward-compatibility guard: an existing fixture/test job built
// without WorkflowHasTriggers (zero value false) but with a non-empty
// Triggers list must never be marked inert for "no trigger" -- Triggers
// is checked first.
func TestMarkInertNoTriggerNeverFiresWithExistingTriggers(t *testing.T) {
	p := healthyGitHubPipeline()
	p.Jobs[0].Triggers = []string{"push"}
	p.Jobs[0].WorkflowHasTriggers = false
	MarkInert(p)
	if p.Jobs[0].Inert != "" {
		t.Fatalf("Inert = %q, want empty (Triggers is non-empty)", p.Jobs[0].Inert)
	}
}

// TestMarkInertWorkflowCallWithoutACaller pins the reason for a job
// whose workflow only runs via workflow_call, with no recorded caller.
func TestMarkInertWorkflowCallWithoutACaller(t *testing.T) {
	p := healthyGitHubPipeline()
	p.Jobs[0].Triggers = []string{"workflow_call"}
	p.Jobs[0].WorkflowHasTriggers = true
	p.Jobs[0].Callers = nil
	MarkInert(p)
	if want := "workflow_call without a caller"; p.Jobs[0].Inert != want {
		t.Fatalf("Inert = %q, want %q", p.Jobs[0].Inert, want)
	}
}

// TestMarkInertWorkflowCallWithACallerIsHealthy pins that the same job
// is left alone once a caller is recorded.
func TestMarkInertWorkflowCallWithACallerIsHealthy(t *testing.T) {
	p := healthyGitHubPipeline()
	p.Jobs[0].Triggers = []string{"workflow_call"}
	p.Jobs[0].WorkflowHasTriggers = true
	p.Jobs[0].Callers = []ReusableCaller{{Job: "ci/caller"}}
	MarkInert(p)
	if p.Jobs[0].Inert != "" {
		t.Fatalf("Inert = %q, want empty (has a caller)", p.Jobs[0].Inert)
	}
}

// TestMarkInertRunsOnlyInALiteral pins the reason for a job gated on
// `github.repository == '<other literal>'`, False for the project
// actually being scanned.
func TestMarkInertRunsOnlyInALiteral(t *testing.T) {
	p := healthyGitHubPipeline()
	p.ProjectPath = "me/repo"
	p.Jobs[0].If = "github.repository == 'other/repo'"
	MarkInert(p)
	if want := "runs only in other/repo"; p.Jobs[0].Inert != want {
		t.Fatalf("Inert = %q, want %q", p.Jobs[0].Inert, want)
	}
}

// TestMarkInertRunsInTheSameRepositoryIsHealthy pins that the same shape
// of condition, naming the project actually being scanned, is not inert.
func TestMarkInertRunsInTheSameRepositoryIsHealthy(t *testing.T) {
	p := healthyGitHubPipeline()
	p.ProjectPath = "me/repo"
	p.Jobs[0].If = "github.repository == 'me/repo'"
	MarkInert(p)
	if p.Jobs[0].Inert != "" {
		t.Fatalf("Inert = %q, want empty (same repository)", p.Jobs[0].Inert)
	}
}

// TestMarkInertIsANoOpOnGitLab pins that MarkInert never marks a GitLab
// job inert, even one that would read as "no trigger" by the same zero
// values a GitLab job always carries (GitLab jobs never set Triggers or
// WorkflowHasTriggers at all).
func TestMarkInertIsANoOpOnGitLab(t *testing.T) {
	p := &NormalizedPipeline{
		Provider: ProviderGitLab,
		Jobs:     []Job{{Name: "build"}},
	}
	MarkInert(p)
	if p.Jobs[0].Inert != "" {
		t.Fatalf("Inert = %q, want empty on GitLab", p.Jobs[0].Inert)
	}
}
