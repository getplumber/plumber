package control

import (
	"testing"

	"github.com/getplumber/plumber/internal/ir"
	"github.com/sirupsen/logrus"
)

// TestEnrichGitHubWorkflowStatesSetsPipelineFields checks that a
// successful lookup threads straight onto the pipeline.
func TestEnrichGitHubWorkflowStatesSetsPipelineFields(t *testing.T) {
	orig := fetchGitHubWorkflowStates
	t.Cleanup(func() { fetchGitHubWorkflowStates = orig })
	fetchGitHubWorkflowStates = func(host, owner, repo string) (map[string]string, bool, error) {
		return map[string]string{".github/workflows/ci.yml": "active"}, true, nil
	}

	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{{Name: "ci/build"}}}
	enrichGitHubWorkflowStates(logrus.NewEntry(logrus.New()), p, "", "acme", "widget")
	if !p.WorkflowStatesKnown {
		t.Fatal("WorkflowStatesKnown must be true on a successful fetch")
	}
	if p.WorkflowStates[".github/workflows/ci.yml"] != "active" {
		t.Fatalf("WorkflowStates = %+v", p.WorkflowStates)
	}
}

// TestEnrichGitHubWorkflowStatesDegradesQuietlyWithoutError checks the
// 403/404/network contract: known=false with a nil error.
func TestEnrichGitHubWorkflowStatesDegradesQuietlyWithoutError(t *testing.T) {
	orig := fetchGitHubWorkflowStates
	t.Cleanup(func() { fetchGitHubWorkflowStates = orig })
	fetchGitHubWorkflowStates = func(host, owner, repo string) (map[string]string, bool, error) {
		return nil, false, nil
	}

	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{{Name: "ci/build"}}}
	enrichGitHubWorkflowStates(logrus.NewEntry(logrus.New()), p, "", "acme", "widget")
	if p.WorkflowStatesKnown {
		t.Fatal("WorkflowStatesKnown must stay false on a degraded fetch")
	}
	if p.ActionsDisabled {
		t.Fatal("ActionsDisabled must stay false when the listing is not known")
	}
}

// TestActionsDisabledTrueWhenEveryKnownStateIsDisabled pins the positive
// case: every workflow the listing names is disabled_manually or
// disabled_inactivity.
func TestActionsDisabledTrueWhenEveryKnownStateIsDisabled(t *testing.T) {
	states := map[string]string{
		".github/workflows/ci.yml":      "disabled_manually",
		".github/workflows/release.yml": "disabled_inactivity",
	}
	if !actionsDisabled(states, true) {
		t.Fatal("want ActionsDisabled true when every known workflow is disabled")
	}
}

// TestActionsDisabledFalseOnAMixOfStates pins that one active workflow
// among several keeps the repository's Actions reading as enabled.
func TestActionsDisabledFalseOnAMixOfStates(t *testing.T) {
	states := map[string]string{
		".github/workflows/ci.yml":      "active",
		".github/workflows/release.yml": "disabled_manually",
	}
	if actionsDisabled(states, true) {
		t.Fatal("want ActionsDisabled false on a mix of states")
	}
}

// TestActionsDisabledFalseWhenNotKnown pins that a degraded lane (the
// listing could not be read) never derives ActionsDisabled true.
func TestActionsDisabledFalseWhenNotKnown(t *testing.T) {
	if actionsDisabled(nil, false) {
		t.Fatal("want ActionsDisabled false when the listing is not known")
	}
}

// TestActionsDisabledFalseOnAnEmptyKnownListEvenWithParsedWorkflows pins
// the correction: the workflows-listing endpoint only lists workflows
// registered on the default branch, so a repository whose workflow file
// was only just added on a feature branch answers with an empty, known
// list even though Actions is very much enabled. An empty known list
// must never read as "Actions disabled", whatever the pipeline itself
// parsed off disk or the API.
func TestActionsDisabledFalseOnAnEmptyKnownListEvenWithParsedWorkflows(t *testing.T) {
	if actionsDisabled(map[string]string{}, true) {
		t.Fatal("an empty known workflows listing must not read as Actions disabled")
	}
}

// TestActionsDisabledNeverSilencesAWorkflowAbsentFromTheListing runs the
// lane end to end: every workflow the listing names is disabled, so the
// derived flag is set, but a workflow present in the checkout and absent
// from the listing (one added on a feature branch, which the default
// branch's listing never names) still runs. Only the listed workflow's
// jobs are inert.
func TestActionsDisabledNeverSilencesAWorkflowAbsentFromTheListing(t *testing.T) {
	orig := fetchGitHubWorkflowStates
	t.Cleanup(func() { fetchGitHubWorkflowStates = orig })
	fetchGitHubWorkflowStates = func(host, owner, repo string) (map[string]string, bool, error) {
		return map[string]string{".github/workflows/nightly.yml": "disabled_manually"}, true, nil
	}
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "acme/widget", Jobs: []ir.Job{
		{Name: "nightly/build", OriginFile: ".github/workflows/nightly.yml", Triggers: []string{"schedule"}, WorkflowHasTriggers: true},
		{Name: "evil/pwn", OriginFile: ".github/workflows/evil.yml", Triggers: []string{"pull_request_target"}, WorkflowHasTriggers: true},
	}}
	enrichGitHubWorkflowStates(logrus.NewEntry(logrus.New()), p, "", "acme", "widget")
	if !p.ActionsDisabled {
		t.Fatal("every listed workflow is disabled: the derived flag must be set")
	}
	ir.MarkInert(p)
	if p.Jobs[0].Inert != "actions disabled" {
		t.Errorf("listed job Inert = %q, want actions disabled", p.Jobs[0].Inert)
	}
	if p.Jobs[1].Inert != "" {
		t.Errorf("unlisted job Inert = %q, want empty: a workflow absent from the listing still runs", p.Jobs[1].Inert)
	}
}
