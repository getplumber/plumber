package github

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// diamondWorkflows is the whole-branch review's shape (finding 1): w0 to
// w<depth-1> each have two jobs, x and y, both calling the next workflow,
// the last one runs a step. Every call of a cached workflow appends its
// jobs again, so the job count doubles at every level for one fetch each.
func diamondWorkflows(depth int) map[string]string {
	files := map[string]string{}
	for i := range depth {
		next := fmt.Sprintf("acme/shared/.github/workflows/w%d.yml@v1", i+1)
		files[fmt.Sprintf("acme/shared@v1:.github/workflows/w%d.yml", i)] = "on:\n  workflow_call:\njobs:\n  x:\n    uses: " + next + "\n  y:\n    uses: " + next + "\n"
	}
	files[fmt.Sprintf("acme/shared@v1:.github/workflows/w%d.yml", depth)] = sharedWorkflow
	return files
}

func nestedJobCount(p *ir.NormalizedPipeline) int {
	n := 0
	for _, j := range p.Jobs {
		if j.Nested {
			n++
		}
	}
	return n
}

// TestResolveNested_WorkflowDiamondStaysBounded pins SECURITY item 2 and
// spec 4.3 / R3 (whole-branch review finding 1, coordinator ruling 1): a
// diamond of reusable workflow calls appends at most MaxNestedJobs nested
// jobs, the run degrades (budget) and the calls left are listed with
// reason budget, while each call of one workflow still appends its own
// copy of the callee's jobs below the cap.
func TestResolveNested_WorkflowDiamondStaysBounded(t *testing.T) {
	stub := newStub(diamondWorkflows(16))
	caller := ir.Job{Name: "ci/call", OriginFile: ".github/workflows/ci.yml", ReusableWorkflowUses: "acme/shared/.github/workflows/w0.yml@v1"}
	p := resolveWith(t, stub, nestedScope{}, caller)
	if n := nestedJobCount(p); n > MaxNestedJobs {
		t.Fatalf("%d nested jobs appended, the cap is %d", n, MaxNestedJobs)
	}
	if !p.NestedBudgetExceeded || p.NestedJobsOverflow == 0 {
		t.Fatalf("past the cap the run degrades: exceeded=%v jobsOverflow=%d", p.NestedBudgetExceeded, p.NestedJobsOverflow)
	}
	budget := 0
	for _, u := range p.UnexpandedActions {
		if u.Reason == ir.UnexpandedBudget {
			budget++
			if !strings.HasPrefix(u.Uses, "acme/shared/.github/workflows/w") {
				t.Fatalf("a budget entry names a workflow call, got %+v", u)
			}
		}
	}
	if budget != p.NestedJobsOverflow {
		t.Fatalf("NestedJobsOverflow = %d, want the %d budget calls listed", p.NestedJobsOverflow, budget)
	}
}

// TestResolveNested_WorkflowDiamondWithinTheCapIsWhole pins the other half
// of coordinator ruling 1: below the cap the semantics are unchanged, two
// jobs calling one workflow are two sets of nested jobs, nothing degrades.
func TestResolveNested_WorkflowDiamondWithinTheCapIsWhole(t *testing.T) {
	stub := newStub(diamondWorkflows(3))
	caller := ir.Job{Name: "ci/call", OriginFile: ".github/workflows/ci.yml", ReusableWorkflowUses: "acme/shared/.github/workflows/w0.yml@v1"}
	p := resolveWith(t, stub, nestedScope{}, caller)
	// 2 + 4 + 8 calling jobs, then 8 copies of the last workflow's job.
	if n := nestedJobCount(p); n != 2+4+8+8 {
		t.Fatalf("%d nested jobs, want %d", n, 2+4+8+8)
	}
	if p.NestedBudgetExceeded || p.NestedJobsOverflow != 0 || len(p.UnexpandedActions) != 0 {
		t.Fatalf("within the cap nothing degrades: %+v", p.UnexpandedActions)
	}
}

// TestResolveNested_StraightWorkflowChainUnchanged pins coordinator ruling
// 1 on the straight chain: one call per level stays whole.
func TestResolveNested_StraightWorkflowChainUnchanged(t *testing.T) {
	files := map[string]string{}
	for i := range 9 {
		files[fmt.Sprintf("acme/shared@v1:.github/workflows/w%d.yml", i)] = workflowCall("x", fmt.Sprintf("acme/shared/.github/workflows/w%d.yml@v1", i+1))
	}
	files["acme/shared@v1:.github/workflows/w9.yml"] = sharedWorkflow
	stub := newStub(files)
	caller := ir.Job{Name: "ci/call", OriginFile: ".github/workflows/ci.yml", ReusableWorkflowUses: "acme/shared/.github/workflows/w0.yml@v1"}
	p := resolveWith(t, stub, nestedScope{}, caller)
	if n := nestedJobCount(p); n != 10 {
		t.Fatalf("%d nested jobs, want 10", n)
	}
	if p.NestedBudgetExceeded || len(p.UnexpandedActions) != 0 {
		t.Fatalf("a straight chain within the cap stays whole: %+v", p.UnexpandedActions)
	}
}

// TestResolveNested_InvalidWorkflowCallNeverFetched pins SECURITY item 1
// and coordinator ruling 4 for called workflows: an owner, repository,
// path or ref outside GitHub's grammar is never fetched, it is listed with
// reason fetch and named in a warning.
func TestResolveNested_InvalidWorkflowCallNeverFetched(t *testing.T) {
	stub := newStub(map[string]string{
		"acme/shared@v1:.github/workflows/x.yml": "on:\n  workflow_call:\njobs:\n" +
			"  a:\n    uses: ../../user?/.github/workflows/x.yml@v1\n" +
			"  b:\n    uses: acme/other/.github/workflows/x.yml@v1#frag\n" +
			"  c:\n    uses: acme/other/.github/../../x.yml@v1\n" +
			"  d:\n    uses: acme/other/.github/workflows/ok.yml@v1\n",
		"acme/other@v1:.github/workflows/ok.yml": workflowSteps("y"),
	})
	caller := ir.Job{Name: "ci/call", OriginFile: ".github/workflows/ci.yml", ReusableWorkflowUses: "acme/shared/.github/workflows/x.yml@v1"}
	p := resolveWith(t, stub, nestedScope{}, caller)
	for key := range stub.calls {
		if strings.Contains(key, "..") || strings.Contains(key, "#") || strings.Contains(key, "?") {
			t.Fatalf("an invalid workflow call was fetched: %s", key)
		}
	}
	if stub.calls["acme/other@v1:.github/workflows/ok.yml"] != 1 {
		t.Fatalf("a valid call round-trips, calls %v", stub.calls)
	}
	fetch, invalid := map[string]bool{}, map[string]bool{}
	for _, u := range p.UnexpandedActions {
		if u.Reason == ir.UnexpandedFetch {
			fetch[u.Uses], invalid[u.Uses] = true, u.Invalid
		}
	}
	for _, u := range []string{"../../user?/.github/workflows/x.yml@v1", "acme/other/.github/workflows/x.yml@v1#frag"} {
		if !fetch[u] || !invalid[u] {
			t.Errorf("%s is not listed with reason fetch and its invalid mark: %+v", u, p.UnexpandedActions)
		}
	}
	if len(p.AdvisoryWarnings) != 0 {
		t.Errorf("an invalid call adds no warning of its own (re-review N2), got %q", p.AdvisoryWarnings)
	}
	if !fetch["acme/other/.github/../../x.yml@v1"] {
		t.Errorf("a climbing path stays reason fetch: %+v", p.UnexpandedActions)
	}
}

// TestResolveNested_OversizedFirstWorkflowIsThatCallOnly pins the
// re-review N1 for called workflows (spec 4.3, R6): a workflow past the
// 1 MiB bound read first is that call's reason fetch, never the run-wide
// cause, and the next call still expands.
func TestResolveNested_OversizedFirstWorkflowIsThatCallOnly(t *testing.T) {
	stub := newStub(map[string]string{
		"aaa/big@v1:.github/workflows/x.yml":     sharedWorkflow + "# " + strings.Repeat("x", 2<<20) + "\n",
		"acme/shared@v1:.github/workflows/y.yml": workflowSteps("y", "evil/c@main"),
	})
	p := resolveWith(t, stub, nestedScope{},
		ir.Job{Name: "ci/a", OriginFile: ".github/workflows/ci.yml", ReusableWorkflowUses: "aaa/big/.github/workflows/x.yml@v1"},
		ir.Job{Name: "ci/b", OriginFile: ".github/workflows/ci.yml", ReusableWorkflowUses: "acme/shared/.github/workflows/y.yml@v1"})
	if p.NestedUnresolvedCause != "" {
		t.Fatalf("an oversized workflow is no run-wide cause, got %q", p.NestedUnresolvedCause)
	}
	if got, want := unexpandedSet(p.UnexpandedActions), []string{"aaa/big/.github/workflows/x.yml@v1 |  | fetch"}; !slices.Equal(got, want) {
		t.Fatalf("unexpanded = %q, want %q", got, want)
	}
	if j := jobByName(p, "ci/b/y"); j == nil || len(j.Uses) != 1 || j.Uses[0].Uses != "evil/c@main" {
		t.Fatalf("the next call expands, got %v", jobNames(p.Jobs))
	}
}
