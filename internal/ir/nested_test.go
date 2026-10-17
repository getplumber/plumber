package ir

import "testing"

// TestSplitDefinedIn_ReadsBothForms pins the DefinedIn locator of spec
// 2026-10-16 section 3.1: a remote container line and a local composite line.
func TestSplitDefinedIn_ReadsBothForms(t *testing.T) {
	repo, ref, file, line, ok := SplitDefinedIn("thomasboni/nested-actions-b@main:action.yml:8")
	if !ok || repo != "thomasboni/nested-actions-b" || ref != "main" || file != "action.yml" || line != 8 {
		t.Fatalf("remote: got (%q, %q, %q, %d, %v)", repo, ref, file, line, ok)
	}
	repo, ref, file, line, ok = SplitDefinedIn("acme/act@feature/x:sub/dir/action.yml:12")
	if !ok || repo != "acme/act" || ref != "feature/x" || file != "sub/dir/action.yml" || line != 12 {
		t.Fatalf("slashed ref: got (%q, %q, %q, %d, %v)", repo, ref, file, line, ok)
	}
	repo, ref, file, line, ok = SplitDefinedIn("./.github/actions/x/action.yml:4")
	if !ok || repo != "" || ref != "" || file != ".github/actions/x/action.yml" || line != 4 {
		t.Fatalf("local: got (%q, %q, %q, %d, %v)", repo, ref, file, line, ok)
	}
	for _, bad := range []string{"", "action.yml", "acme/act@main:action.yml", "acme/act:action.yml:3", "./:3"} {
		if _, _, _, _, ok := SplitDefinedIn(bad); ok {
			t.Errorf("SplitDefinedIn(%q) must refuse", bad)
		}
	}
}

// TestWorkflowDefinedIn_FromTheQualifiedOrigin pins the locator of a job
// appended from another repository's workflow (spec 3.2).
func TestWorkflowDefinedIn_FromTheQualifiedOrigin(t *testing.T) {
	if got := WorkflowDefinedIn("acme/shared/.github/workflows/build.yml@v1", 4); got != "acme/shared@v1:.github/workflows/build.yml:4" {
		t.Fatalf("got %q", got)
	}
	if got := WorkflowDefinedIn(".github/workflows/ci.yml", 4); got != "" {
		t.Fatalf("a workflow of the scanned repository has no container locator, got %q", got)
	}
}

// TestViaText_OutermostFirst pins the chain rendering of spec 6.
func TestViaText_OutermostFirst(t *testing.T) {
	if got := ViaText([]string{"a/b@v1", "c/d@v2"}); got != "a/b@v1 > c/d@v2" {
		t.Fatalf("ViaText = %q", got)
	}
}

// nestedCallPipeline is a scanned job calling another repository's
// reusable workflow under pull_request_target, guarded by callerIf, and the
// job the nested resolution appended for that call: it runs under the
// caller's events (spec 2026-10-16 section 3.2, R9) and the linker gave it
// the call (Job.Callers).
func nestedCallPipeline(callerIf string) *NormalizedPipeline {
	caller := Job{
		Name:                 "ci/call",
		OriginFile:           ".github/workflows/ci.yml",
		Triggers:             []string{"pull_request_target"},
		WorkflowHasTriggers:  true,
		If:                   callerIf,
		ReusableWorkflowUses: "acme/shared/.github/workflows/build.yml@v1",
	}
	nested := Job{
		Name:                "ci/call/build",
		OriginFile:          "acme/shared/.github/workflows/build.yml@v1",
		Triggers:            []string{"pull_request_target"},
		WorkflowHasTriggers: true,
		Nested:              true,
		Via:                 []string{"acme/shared/.github/workflows/build.yml@v1"},
		Uses:                []Action{checkoutHeadSha},
		Callers:             []ReusableCaller{{Job: "ci/call", Triggers: []string{"pull_request_target"}, If: callerIf}},
	}
	return githubPipeline(caller, nested)
}

// TestClassifyGatesNestedJobTakesItsCallersGate pins that a job appended
// from another repository's workflow runs only when its calling job does
// (spec 2026-10-16 section 3.2): the caller's `if:` gates it, so a fork
// guard on the calling job holds for the nested job too, never an
// outsider's gate read off the nested job's own condition alone.
func TestClassifyGatesNestedJobTakesItsCallersGate(t *testing.T) {
	p := nestedCallPipeline("github.event.pull_request.head.repo.full_name == github.repository")
	ClassifyGates(p)
	if g := p.Jobs[1].Gate; g == nil || g.Class != GateSameRepo {
		t.Errorf("nested job gate = %+v, want the caller's same_repo gate", g)
	}
	p = nestedCallPipeline("")
	ClassifyGates(p)
	if g := p.Jobs[1].Gate; g == nil || g.Class != GateOutsider {
		t.Errorf("nested job under an unguarded call: gate = %+v, want outsider", g)
	}
}

// TestMarkInertNestedJobFollowsItsCallersWorkflow pins that a nested job
// reads the workflow state of its calling job's workflow: its own is
// another repository's file, never in the listing, and it runs only when
// the call does.
func TestMarkInertNestedJobFollowsItsCallersWorkflow(t *testing.T) {
	p := nestedCallPipeline("")
	p.WorkflowStates = map[string]string{".github/workflows/ci.yml": "disabled_manually"}
	p.WorkflowStatesKnown = true
	MarkInert(p)
	if want := "workflow disabled (disabled_manually)"; p.Jobs[1].Inert != want {
		t.Errorf("nested job Inert = %q, want %q", p.Jobs[1].Inert, want)
	}
	p = nestedCallPipeline("")
	p.WorkflowStates = map[string]string{".github/workflows/ci.yml": "active"}
	p.WorkflowStatesKnown = true
	p.ActionsDisabled = true
	MarkInert(p)
	if want := "actions disabled"; p.Jobs[1].Inert != want {
		t.Errorf("nested job Inert = %q, want %q", p.Jobs[1].Inert, want)
	}
	p = nestedCallPipeline("")
	p.WorkflowStates = map[string]string{".github/workflows/ci.yml": "active"}
	p.WorkflowStatesKnown = true
	MarkInert(p)
	if p.Jobs[1].Inert != "" {
		t.Errorf("nested job under an active caller: Inert = %q, want empty", p.Jobs[1].Inert)
	}
}
