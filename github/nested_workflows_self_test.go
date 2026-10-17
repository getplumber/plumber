package github

import (
	"slices"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// selfReusable is the scanned repository's own reusable workflow, one job.
const selfReusable = ".github/workflows/reusable.yml"

// scannedReusableJob is the job the scan read from the checkout's
// reusable.yml. It names no composite, so a self call fetched over the
// network would be the run's first remote read.
func scannedReusableJob() ir.Job {
	return ir.Job{Name: "reusable/build", OriginFile: selfReusable, Triggers: []string{"workflow_call"}}
}

// TestResolveNested_SelfCallByAnotherNameIsNotDuplicated pins the review
// of PR 549 (finding 4297763097): when the old name still answers, the
// self call's jobs are never appended a second time as nested jobs.
func TestResolveNested_SelfCallByAnotherNameIsNotDuplicated(t *testing.T) {
	stub := newStub(map[string]string{
		"oldorg/oldrepo@v1:" + selfReusable: workflowSteps("build", "acme/setup@v1"),
		"acme/setup@v1:action.yml":          composite(),
	})
	caller := ir.Job{Name: "ci/call", OriginFile: ".github/workflows/ci.yml", ReusableWorkflowUses: "OldOrg/OldRepo/" + selfReusable + "@v1"}
	scope := nestedScope{projectPath: "neworg/newrepo", aliases: []string{"oldorg/oldrepo"}}
	p := resolveWith(t, stub, scope, caller, scannedReusableJob())
	if got := jobNames(p.Jobs); !slices.Equal(got, []string{"ci/call", "reusable/build"}) {
		t.Fatalf("jobs = %v, the self call must append nothing", got)
	}
}

// TestResolveNested_SelfCallByAnotherNameIsLocal pins the review of PR 549
// (finding 4297763097): the repository now neworg/newrepo still calls its
// own reusable.yml by its old name, oldorg/oldrepo, a name the scan knows
// for itself. The call is the repository's own: never fetched (so its
// failed read never decides the api_disabled cause, R6), and its jobs are
// never appended a second time as nested jobs.
func TestResolveNested_SelfCallByAnotherNameIsLocal(t *testing.T) {
	stub := newStub(map[string]string{})
	stub.errs["oldorg/oldrepo@v1:"+selfReusable] = true
	stub.errs["OldOrg/OldRepo@v1:"+selfReusable] = true
	caller := ir.Job{
		Name: "ci/call", OriginFile: ".github/workflows/ci.yml", OriginLine: 9,
		ReusableWorkflowUses: "OldOrg/OldRepo/" + selfReusable + "@v1",
	}
	scope := nestedScope{projectPath: "neworg/newrepo", aliases: []string{"oldorg/oldrepo"}}
	p := resolveWith(t, stub, scope, caller, scannedReusableJob())
	if got := jobNames(p.Jobs); !slices.Equal(got, []string{"ci/call", "reusable/build"}) {
		t.Fatalf("jobs = %v, the self call must append nothing", got)
	}
	if p.NestedUnresolvedCause != "" || len(p.UnexpandedActions) != 0 {
		t.Fatalf("a self call is never a remote read: cause %q, unexpanded %+v", p.NestedUnresolvedCause, p.UnexpandedActions)
	}
	if n := stub.calls["OldOrg/OldRepo@v1:"+selfReusable] + stub.calls["oldorg/oldrepo@v1:"+selfReusable]; n != 0 {
		t.Fatalf("the self call was fetched %d times, want 0", n)
	}
}

// TestResolveNested_NestedSelfCallIsNotAppendedAgain pins the review of PR
// 549 (finding 4297763097) on the path reachable with the scanned path
// alone: a workflow of another repository calls back into the scanned
// repository's reusable.yml. Its jobs are already the scan's, so they are
// never appended a second time, and the call is never fetched, so its
// failed read never counts as a remote read (R6).
func TestResolveNested_NestedSelfCallIsNotAppendedAgain(t *testing.T) {
	x := "acme/shared/.github/workflows/x.yml@v1"
	stub := newStub(map[string]string{
		"acme/shared@v1:.github/workflows/x.yml": workflowCall("x", "ACME/App/"+selfReusable+"@v1"),
	})
	stub.errs["ACME/App@v1:"+selfReusable] = true
	stub.errs["acme/app@v1:"+selfReusable] = true
	caller := ir.Job{Name: "ci/x", OriginFile: ".github/workflows/ci.yml", ReusableWorkflowUses: x}
	p := resolveWith(t, stub, nestedScope{projectPath: "acme/app"}, caller, scannedReusableJob())
	if got := jobNames(p.Jobs); !slices.Equal(got, []string{"ci/x", "ci/x/x", "reusable/build"}) {
		t.Fatalf("jobs = %v, the nested self call must append nothing", got)
	}
	if p.NestedUnresolvedCause != "" || len(p.UnexpandedActions) != 0 {
		t.Fatalf("cause %q, unexpanded %+v", p.NestedUnresolvedCause, p.UnexpandedActions)
	}
	if n := stub.calls["ACME/App@v1:"+selfReusable] + stub.calls["acme/app@v1:"+selfReusable]; n != 0 {
		t.Fatalf("the self call was fetched %d times, want 0", n)
	}
}
