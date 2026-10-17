package github

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

const sharedWorkflow = "on:\n  workflow_call:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: acme/setup@v1\n"

// TestResolveNested_CrossRepoReusableWorkflow pins spec 3.2: the callee is
// fetched at its ref, its jobs are appended as nested jobs of the caller,
// linked with the caller's context, their composites expanded with the
// full chain, every entry at the calling job's line (R9).
func TestResolveNested_CrossRepoReusableWorkflow(t *testing.T) {
	stub := newStub(map[string]string{
		"acme/shared@v1:.github/workflows/build.yml": sharedWorkflow,
		"acme/setup@v1:action.yml":                   composite("evil/e@main"),
	})
	call := "acme/shared/.github/workflows/build.yml@v1"
	caller := ir.Job{
		Name: "ci/call", OriginFile: ".github/workflows/ci.yml", OriginLine: 9,
		Triggers: []string{"push"}, Permissions: map[string]any{"contents": "write"},
		ReusableWorkflowUses: call, SecretsInherit: true,
	}
	p := resolveWith(t, stub, nestedScope{}, caller)
	linkReusableCallers(p.Jobs, p.ProjectPath)

	var callee *ir.Job
	for i := range p.Jobs {
		if p.Jobs[i].Name == "ci/call/build" {
			callee = &p.Jobs[i]
		}
	}
	if callee == nil {
		t.Fatalf("the callee job must be appended as ci/call/build, got %v", jobNames(p.Jobs))
	}
	if !callee.Nested || !slices.Equal(callee.Via, []string{call}) || callee.OriginFile != call {
		t.Fatalf("callee = {Nested:%v Via:%v OriginFile:%q}", callee.Nested, callee.Via, callee.OriginFile)
	}
	if len(callee.Callers) != 1 || callee.Callers[0].Job != "ci/call" || !callee.Callers[0].SecretsInherit || !slices.Equal(callee.Callers[0].Triggers, []string{"push"}) {
		t.Fatalf("callers = %+v, want the calling job's context", callee.Callers)
	}
	for _, j := range p.Jobs {
		if j.Name == "ci/call" && !slices.Equal(j.ReusableCallees, []string{"ci/call/build"}) {
			t.Fatalf("caller ReusableCallees = %v", j.ReusableCallees)
		}
	}
	want := []string{
		"acme/setup@v1 | " + call + " | acme/shared@v1:.github/workflows/build.yml:7 | 9",
		"evil/e@main | " + call + " > acme/setup@v1 | acme/setup@v1:action.yml:7 | 9",
	}
	if got := entries(*callee); !slices.Equal(got, want) {
		t.Fatalf("callee entries:\n got %q\nwant %q", got, want)
	}
}

// TestResolveNested_WorkflowCycleTerminates pins spec 4.3 for workflows:
// a.yml calls b.yml (relative, in the callee's own repository) which
// calls a.yml, and the walk stops at the cycle with a.yml fetched once.
func TestResolveNested_WorkflowCycleTerminates(t *testing.T) {
	stub := newStub(map[string]string{
		"acme/shared@v1:.github/workflows/a.yml": "on:\n  workflow_call:\njobs:\n  a:\n    uses: ./.github/workflows/b.yml\n",
		"acme/shared@v1:.github/workflows/b.yml": "on:\n  workflow_call:\njobs:\n  b:\n    uses: acme/shared/.github/workflows/a.yml@v1\n",
	})
	caller := ir.Job{Name: "ci/call", OriginFile: ".github/workflows/ci.yml", ReusableWorkflowUses: "acme/shared/.github/workflows/a.yml@v1"}
	p := resolveWith(t, stub, nestedScope{}, caller)
	if got := jobNames(p.Jobs); !slices.Equal(got, []string{"ci/call", "ci/call/a", "ci/call/a/b"}) {
		t.Fatalf("jobs = %v", got)
	}
	if n := stub.calls["acme/shared@v1:.github/workflows/a.yml"]; n != 1 {
		t.Fatalf("a.yml fetched %d times, want 1", n)
	}
}

// TestResolveNested_UnreadableWorkflowIsListed pins spec 4.3: a called
// workflow that cannot be read (the API otherwise answering: the first
// read of the run, the composite acme/other, succeeded) is listed with
// reason fetch and the run is neither degraded nor marked unresolved.
func TestResolveNested_UnreadableWorkflowIsListed(t *testing.T) {
	stub := newStub(map[string]string{"acme/other@v1:action.yml": composite()})
	stub.errs["acme/shared@v1:.github/workflows/build.yml"] = true
	caller := ir.Job{Name: "ci/call", ReusableWorkflowUses: "acme/shared/.github/workflows/build.yml@v1"}
	p := resolveWith(t, stub, nestedScope{}, oneJob("acme/other@v1"), caller)
	if len(p.UnexpandedActions) != 1 || p.UnexpandedActions[0].Uses != caller.ReusableWorkflowUses || p.UnexpandedActions[0].Reason != ir.UnexpandedFetch {
		t.Fatalf("unexpanded = %+v", p.UnexpandedActions)
	}
	if p.NestedUnresolvedCause != "" || p.NestedBudgetExceeded {
		t.Fatalf("one unreadable workflow only warns: %+v", p)
	}
}

// TestResolveNested_FirstWorkflowFetchErrorUnresolves pins spec section 7
// (R6), review of PR 549: the FIRST remote read of the run, a called
// workflow's file answering fetchError (rate limit or network), leaves
// the whole closure unresolved through readWorkflow's entry into
// noteStatus, same as the composite-action path, the direct call listed
// api_disabled.
func TestResolveNested_FirstWorkflowFetchErrorUnresolves(t *testing.T) {
	stub := newStub(nil)
	stub.errs["acme/shared@v1:.github/workflows/build.yml"] = true
	caller := ir.Job{Name: "ci/call", ReusableWorkflowUses: "acme/shared/.github/workflows/build.yml@v1"}
	p := resolveWith(t, stub, nestedScope{}, caller)
	if p.NestedUnresolvedCause != "the first action definition could not be fetched (rate limit or network)" {
		t.Fatalf("cause = %q, want the first-read fetchError sentence", p.NestedUnresolvedCause)
	}
	if p.NestedBudgetExceeded {
		t.Fatal("a first-read fetch error is R6, never the budget")
	}
	for _, j := range p.Jobs {
		if j.Nested {
			t.Fatalf("R6 drops the appended jobs, got %v", jobNames(p.Jobs))
		}
	}
	want := []string{caller.ReusableWorkflowUses + " |  | api_disabled"}
	if got := unexpandedSet(p.UnexpandedActions); !slices.Equal(got, want) {
		t.Fatalf("unexpanded = %q, want %q", got, want)
	}
}

// workflowCall is a callee workflow whose one job, at line 4, calls uses.
func workflowCall(job, uses string) string {
	return "on:\n  workflow_call:\njobs:\n  " + job + ":\n    uses: " + uses + "\n"
}

// workflowSteps is a callee workflow whose one job runs the steps, the
// first `uses:` at line 7.
func workflowSteps(job string, uses ...string) string {
	s := "on:\n  workflow_call:\njobs:\n  " + job + ":\n    runs-on: ubuntu-latest\n    steps:\n"
	for _, u := range uses {
		s += "      - uses: " + u + "\n"
	}
	return s
}

func jobByName(p *ir.NormalizedPipeline, name string) *ir.Job {
	for i := range p.Jobs {
		if p.Jobs[i].Name == name {
			return &p.Jobs[i]
		}
	}
	return nil
}

func unexpandedSet(us []ir.UnexpandedAction) []string {
	out := make([]string, 0, len(us))
	for _, u := range us {
		out = append(out, u.Uses+" | "+strings.Join(u.Via, " > ")+" | "+u.Reason)
	}
	sort.Strings(out)
	return out
}

// anchorModule emits one job-level finding per job and one entry finding
// per entry at the entry's line, the two shapes the controls emit.
const anchorModule = `package anchortoy

deny contains f if {
	some job in input.pipeline.jobs
	f := {"code": "TOY-1", "severity": "low", "message": "job", "job": job.name}
}

deny contains f if {
	some job in input.pipeline.jobs
	some a in job.uses
	f := {"code": "TOY-2", "severity": "low", "message": a.uses, "job": job.name, "line": a.line}
}`

// TestResolveNested_ChainedCallAnchorsOnTheScannedStep pins R9 and spec
// 3.2 (coordinator ruling 7, review M1): the scanned job at line 9 calls
// X, whose job calls Y. Y's entries carry line 9, never X's job line, and
// every finding on a nested job lands on the scanned workflow file and
// line through the engine, never on a file of another repository.
func TestResolveNested_ChainedCallAnchorsOnTheScannedStep(t *testing.T) {
	x := "acme/shared/.github/workflows/x.yml@v1"
	y := "acme/other/.github/workflows/y.yml@v1"
	stub := newStub(map[string]string{
		"acme/shared@v1:.github/workflows/x.yml": workflowCall("x", y),
		"acme/other@v1:.github/workflows/y.yml":  workflowSteps("y", "acme/setup@v1"),
		"acme/setup@v1:action.yml":               composite("evil/e@main"),
	})
	caller := ir.Job{Name: "ci/call", OriginFile: ".github/workflows/ci.yml", OriginLine: 9, Triggers: []string{"push"}, ReusableWorkflowUses: x}
	p := resolveWith(t, stub, nestedScope{}, caller)
	linkReusableCallers(p.Jobs, p.ProjectPath)
	yj := jobByName(p, "ci/call/x/y")
	if yj == nil {
		t.Fatalf("jobs = %v", jobNames(p.Jobs))
	}
	want := []string{
		"acme/setup@v1 | " + x + " > " + y + " | acme/other@v1:.github/workflows/y.yml:7 | 9",
		"evil/e@main | " + x + " > " + y + " > acme/setup@v1 | acme/setup@v1:action.yml:7 | 9",
	}
	if got := entries(*yj); !slices.Equal(got, want) {
		t.Fatalf("Y entries:\n got %q\nwant %q", got, want)
	}

	engine := opa.New()
	engine.LoadModule("anchortoy", anchorModule)
	fs, failed, err := engine.EvaluateModules(context.Background(), p, nil)
	if err != nil || len(failed) > 0 {
		t.Fatalf("evaluate: %v %v", err, failed)
	}
	nested := 0
	for _, f := range fs {
		j := jobByName(p, f.Job)
		if j == nil || !j.Nested {
			continue
		}
		nested++
		if f.File != ".github/workflows/ci.yml" || f.Line != 9 {
			t.Errorf("%s on %s (%s) lands at %s:%d, want .github/workflows/ci.yml:9", f.Code, f.Job, f.Message, f.File, f.Line)
		}
	}
	if nested != 4 {
		t.Fatalf("want 4 findings on the two nested jobs (two job-level, two entries of Y), got %d", nested)
	}
}

// TestResolveNested_SharedWorkflowCountsOnce pins spec 4.3 and R8 (review
// M2): the budget counts a workflow's container key once, at first sight.
// 101 scanned jobs call one shared workflow, whose job calls a second
// one: the second is read once, counted once, and nothing overflows.
func TestResolveNested_SharedWorkflowCountsOnce(t *testing.T) {
	x := "acme/shared/.github/workflows/x.yml@v1"
	stub := newStub(map[string]string{
		"acme/shared@v1:.github/workflows/x.yml": workflowCall("x", "acme/notify/.github/workflows/y.yml@v1"),
		"acme/notify@v1:.github/workflows/y.yml": workflowSteps("y"),
	})
	var jobs []ir.Job
	for i := 0; i <= MaxNestedContainers; i++ {
		jobs = append(jobs, ir.Job{Name: "ci/call" + strconv.Itoa(i), ReusableWorkflowUses: x})
	}
	p := resolveWith(t, stub, nestedScope{}, jobs...)
	if p.NestedBudgetExceeded || len(p.UnexpandedActions) != 0 {
		t.Fatalf("one nested workflow must not overflow: exceeded=%v unexpanded=%+v", p.NestedBudgetExceeded, p.UnexpandedActions)
	}
	if n := stub.calls["acme/notify@v1:.github/workflows/y.yml"]; n != 1 {
		t.Fatalf("y.yml read %d times, want 1", n)
	}
	if jobByName(p, "ci/call100/x/y") == nil {
		t.Fatalf("every call keeps its own copy, got %v", jobNames(p.Jobs))
	}
}

// TestResolveWorkflows_TwoNestedCallersCountOneContainer pins R8 (review
// M2) on the counter itself: two nested calls of one workflow cost one.
func TestResolveWorkflows_TwoNestedCallersCountOneContainer(t *testing.T) {
	t.Setenv(EnvDisableGitHubAPI, "0")
	t.Setenv(EnvMetadataToken, "test-token")
	stub := newStub(map[string]string{
		"acme/a@v1:.github/workflows/a.yml":      workflowCall("a", "acme/notify/.github/workflows/y.yml@v1"),
		"acme/b@v1:.github/workflows/b.yml":      workflowCall("b", "acme/notify/.github/workflows/y.yml@v1"),
		"acme/notify@v1:.github/workflows/y.yml": workflowSteps("y"),
	})
	p := &ir.NormalizedPipeline{ProjectPath: "acme/app", Jobs: []ir.Job{
		{Name: "ci/a", ReusableWorkflowUses: "acme/a/.github/workflows/a.yml@v1"},
		{Name: "ci/b", ReusableWorkflowUses: "acme/b/.github/workflows/b.yml@v1"},
	}}
	w := &nestedWalk{defs: newDefinitionFetcher(stub.fetch, nil), scope: nestedScope{projectPath: "acme/app"}, byKey: map[string]*nestedContainer{}}
	w.resolveWorkflows(p)
	if w.fetched != 1 {
		t.Fatalf("fetched = %d, want 1 (the direct calls never count, y.yml once)", w.fetched)
	}
}

// TestResolveNested_WorkflowPastTheBudget pins R3 for workflows: past
// MaxNestedContainers a nested workflow call is not read, it is listed
// with reason budget and the pipeline says the budget was exceeded.
func TestResolveNested_WorkflowPastTheBudget(t *testing.T) {
	files := map[string]string{}
	var children []string
	for i := 1; i <= MaxNestedContainers; i++ {
		children = append(children, "acme/x"+strconv.Itoa(i)+"@v1")
		files["acme/x"+strconv.Itoa(i)+"@v1:action.yml"] = composite()
	}
	files["acme/root@v1:action.yml"] = composite(children...)
	x := "acme/shared/.github/workflows/x.yml@v1"
	y := "acme/notify/.github/workflows/y.yml@v1"
	files["acme/shared@v1:.github/workflows/x.yml"] = workflowCall("x", y)
	files["acme/notify@v1:.github/workflows/y.yml"] = workflowSteps("y")
	stub := newStub(files)
	p := resolveWith(t, stub, nestedScope{}, oneJob("acme/root@v1"), ir.Job{Name: "ci/call", ReusableWorkflowUses: x})
	if !p.NestedBudgetExceeded {
		t.Fatal("past the budget the pipeline must say so")
	}
	if got, want := unexpandedSet(p.UnexpandedActions), []string{y + " | " + x + " | budget"}; !slices.Equal(got, want) {
		t.Fatalf("unexpanded = %q, want %q", got, want)
	}
	if stub.calls["acme/notify@v1:.github/workflows/y.yml"] != 0 {
		t.Fatal("the workflow past the budget must not be read")
	}
}

// TestResolveNested_WorkflowsUnderR6 pins R6 for workflows (review L1,
// L2): once the closure cannot be resolved, the appended jobs are dropped
// and the terminal list holds the direct references only, each once,
// api_disabled, an earlier fetch reason of a direct call replaced.
func TestResolveNested_WorkflowsUnderR6(t *testing.T) {
	t.Setenv(EnvDisableGitHubAPI, "0")
	t.Setenv(EnvMetadataToken, "test-token")
	x := "acme/shared/.github/workflows/x.yml@v1"
	z := "acme/broken/.github/workflows/z.yml@v1"
	stub := newStub(map[string]string{
		"acme/other@v1:action.yml":               composite(),
		"acme/shared@v1:.github/workflows/x.yml": workflowSteps("x", "acme/late@v1"),
	})
	stub.errs["acme/broken@v1:.github/workflows/z.yml"] = true
	fetch := func(owner, repo, ref, p string) (string, fetchStatus) {
		if owner == "acme" && repo == "late" {
			return "", fetchDisabled
		}
		return stub.fetch(owner, repo, ref, p)
	}
	p := &ir.NormalizedPipeline{ProjectPath: "acme/app", Jobs: []ir.Job{
		oneJob("acme/other@v1"),
		{Name: "ci/x", ReusableWorkflowUses: x},
		{Name: "ci/z", ReusableWorkflowUses: z},
	}}
	resolveNestedActions(p, newDefinitionFetcher(fetch, nil), nestedScope{projectPath: "acme/app"})
	if p.NestedUnresolvedCause == "" {
		t.Fatal("the offline answer must set the R6 cause")
	}
	for _, j := range p.Jobs {
		if j.Nested {
			t.Fatalf("R6 drops the appended jobs, got %v", jobNames(p.Jobs))
		}
	}
	want := []string{z + " |  | api_disabled", "acme/other@v1 |  | api_disabled", x + " |  | api_disabled"}
	if got := unexpandedSet(p.UnexpandedActions); !slices.Equal(got, want) {
		t.Fatalf("unexpanded = %q, want %q", got, want)
	}
}

// TestResolveNested_RelativeStepOfACalleeIsTheScannedWorkspace pins spec
// 3.3 (plan ruling 14, the live probe): a called workflow runs in the
// caller's workspace, so its `./x` step is the SCANNED repository's
// composite, never the callee repository's.
func TestResolveNested_RelativeStepOfACalleeIsTheScannedWorkspace(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "actions", "local")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "action.yml"), []byte(composite("acme/e@v1")), 0o600); err != nil {
		t.Fatal(err)
	}
	x := "acme/shared/.github/workflows/x.yml@v1"
	stub := newStub(map[string]string{
		"acme/shared@v1:.github/workflows/x.yml":          workflowSteps("x", "./.github/actions/local"),
		"acme/shared@v1:.github/actions/local/action.yml": composite("evil/never@v1"),
		"acme/e@v1:action.yml":                            composite(),
	})
	caller := ir.Job{Name: "ci/call", OriginLine: 9, ReusableWorkflowUses: x}
	p := resolveWith(t, stub, nestedScope{readLocal: diskReader(root), localOnDisk: true}, caller)
	xj := jobByName(p, "ci/call/x")
	if xj == nil {
		t.Fatalf("jobs = %v", jobNames(p.Jobs))
	}
	want := []string{
		"./.github/actions/local | " + x + " | acme/shared@v1:.github/workflows/x.yml:7 | 9",
		"acme/e@v1 | " + x + " > ./.github/actions/local | ./.github/actions/local/action.yml:7 | 9",
	}
	if got := entries(*xj); !slices.Equal(got, want) {
		t.Fatalf("entries:\n got %q\nwant %q", got, want)
	}
	if n := stub.calls["acme/shared@v1:.github/actions/local/action.yml"]; n != 0 {
		t.Fatal("a relative step never reads the callee's repository")
	}
}

// TestResolveNested_CalleeJobIDOutsideTheGrammarIsSkipped pins the
// ingestion hardening rule (review L3): a callee job id GitHub would
// reject is untrusted input, never appended, and named in a warning.
func TestResolveNested_CalleeJobIDOutsideTheGrammarIsSkipped(t *testing.T) {
	stub := newStub(map[string]string{
		"acme/shared@v1:.github/workflows/x.yml": "on:\n  workflow_call:\njobs:\n  ok:\n    runs-on: x\n  a/b:\n    runs-on: x\n  9lives:\n    runs-on: x\n",
	})
	caller := ir.Job{Name: "ci/call", ReusableWorkflowUses: "acme/shared/.github/workflows/x.yml@v1"}
	p := resolveWith(t, stub, nestedScope{}, caller)
	if got := jobNames(p.Jobs); !slices.Equal(got, []string{"ci/call", "ci/call/ok"}) {
		t.Fatalf("jobs = %v", got)
	}
	joined := strings.Join(p.AdvisoryWarnings, "\n")
	if !strings.Contains(joined, `"a/b"`) || !strings.Contains(joined, `"9lives"`) {
		t.Fatalf("warnings = %q, want both skipped ids named", p.AdvisoryWarnings)
	}
}

// TestResolveNested_CalleeJobIDWarningBoundsTheID pins the review of PR
// 549: a callee job id outside jobIDGrammar is untrusted input, and the
// maxWarnedJobID truncation keeps an unbounded attacker-controlled id
// from being embedded verbatim in AdvisoryWarnings, the same way the
// sibling maxWarnedReference bound is pinned for the fetch warning.
func TestResolveNested_CalleeJobIDWarningBoundsTheID(t *testing.T) {
	ref := "acme/shared/.github/workflows/x.yml@v1"
	long := strings.Repeat("a", 200) + "/" + strings.Repeat("b", 199)
	if n := len([]rune(long)); n != 400 {
		t.Fatalf("setup: long id is %d runes, want 400", n)
	}
	stub := newStub(map[string]string{
		"acme/shared@v1:.github/workflows/x.yml": "on:\n  workflow_call:\njobs:\n  ok:\n    runs-on: x\n  " + long + ":\n    runs-on: x\n",
	})
	caller := ir.Job{Name: "ci/call", ReusableWorkflowUses: ref}
	p := resolveWith(t, stub, nestedScope{}, caller)
	if got := jobNames(p.Jobs); !slices.Equal(got, []string{"ci/call", "ci/call/ok"}) {
		t.Fatalf("jobs = %v, the oversized invalid id must not be appended", got)
	}
	var warning string
	for _, w := range p.AdvisoryWarnings {
		if strings.Contains(w, ref) && strings.Contains(w, "was not resolved") {
			warning = w
		}
	}
	if warning == "" {
		t.Fatalf("warnings = %q, want one naming %s", p.AdvisoryWarnings, ref)
	}
	if strings.Contains(warning, long) {
		t.Fatalf("warning quotes the full 400-rune id unbounded: %q", warning)
	}
	quoted := strings.TrimSuffix(strings.TrimPrefix(warning, `the job "`), `" of `+ref+` was not resolved, its id is not a valid GitHub job id`)
	if quoted == warning {
		t.Fatalf("warning shape changed, cannot extract the quoted id: %q", warning)
	}
	if n := len([]rune(quoted)); n == 0 || n > maxWarnedJobID {
		t.Fatalf("quoted id is %d runes, want 1..%d", n, maxWarnedJobID)
	}
	if !strings.HasPrefix(long, quoted) {
		t.Fatalf("quoted id %q is not a prefix of the original id", quoted)
	}
}

// TestResolveNested_EscapingWorkflowPathNeverFetched pins spec 3.3 and the
// ingestion hardening rule (Task 1 round addendum): a workflow path that
// climbs out of its repository is never read, is listed with reason
// fetch, and, the only call of the run, is not its first remote read
// (no R6 cause).
func TestResolveNested_EscapingWorkflowPathNeverFetched(t *testing.T) {
	stub := newStub(map[string]string{})
	bad := "acme/shared/../../evil/.github/workflows/x.yml@v1"
	p := resolveWith(t, stub, nestedScope{}, ir.Job{Name: "ci/call", ReusableWorkflowUses: bad})
	if got, want := unexpandedSet(p.UnexpandedActions), []string{bad + " |  | fetch"}; !slices.Equal(got, want) {
		t.Fatalf("unexpanded = %q, want %q", got, want)
	}
	if p.NestedUnresolvedCause != "" {
		t.Fatalf("a refused path is not a read, cause = %q", p.NestedUnresolvedCause)
	}
	for key, n := range stub.calls {
		if strings.Contains(key, "workflows") && n > 0 {
			t.Fatalf("an escaping path must never be fetched, got %q", key)
		}
	}
}

// TestLinkReusableCallers_NestedJobAlwaysHasItsCaller pins R9 and the
// ruling on M3 (review): every appended job carries its calling job in
// Callers, even when the callee's `on:` does not name workflow_call, so
// its findings always anchor in the scanned repository.
func TestLinkReusableCallers_NestedJobAlwaysHasItsCaller(t *testing.T) {
	stub := newStub(map[string]string{
		"acme/shared@v1:.github/workflows/x.yml": "on: push\njobs:\n  x:\n    runs-on: x\n",
	})
	caller := ir.Job{Name: "ci/call", OriginFile: ".github/workflows/ci.yml", OriginLine: 9, ReusableWorkflowUses: "acme/shared/.github/workflows/x.yml@v1"}
	p := resolveWith(t, stub, nestedScope{}, caller)
	linkReusableCallers(p.Jobs, p.ProjectPath)
	xj := jobByName(p, "ci/call/x")
	if xj == nil || len(xj.Callers) != 1 || xj.Callers[0].Job != "ci/call" {
		t.Fatalf("callee = %+v", xj)
	}
}
