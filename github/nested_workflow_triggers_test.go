package github

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// prHeadWorkflow is a called workflow whose one job checks out the pull
// request head and runs it, its `on:` the given events.
func prHeadWorkflow(job string, on ...string) string {
	s := "on:\n"
	for _, e := range on {
		s += "  " + e + ":\n"
	}
	return s + "jobs:\n  " + job + ":\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: npm test\n"
}

// TestResolveNested_NestedJobTakesTheCallersTriggers pins spec 3.2 / R9
// (review of PR 549, finding on ISSUE-804): a nested job runs for its
// calling job, so it carries the calling job's triggers, never the
// callee's own `on:`. A push caller of a callee declaring workflow_call
// and pull_request_target yields push, and so does every job of a two
// level chain (caller push, callee A, callee B).
func TestResolveNested_NestedJobTakesTheCallersTriggers(t *testing.T) {
	a := "acme/shared/.github/workflows/a.yml@v1"
	b := "acme/other/.github/workflows/b.yml@v1"
	stub := newStub(map[string]string{
		"acme/shared@v1:.github/workflows/a.yml": "on:\n  workflow_call:\n  pull_request_target:\njobs:\n  a:\n    uses: " + b + "\n",
		"acme/other@v1:.github/workflows/b.yml":  prHeadWorkflow("b", "workflow_call", "pull_request_target"),
	})
	caller := ir.Job{Name: "ci/call", OriginFile: ".github/workflows/ci.yml", OriginLine: 9, Triggers: []string{"push"}, ReusableWorkflowUses: a}
	p := resolveWith(t, stub, nestedScope{}, caller)
	for _, name := range []string{"ci/call/a", "ci/call/a/b"} {
		j := jobByName(p, name)
		if j == nil {
			t.Fatalf("jobs = %v, want %s", jobNames(p.Jobs), name)
		}
		if !slices.Equal(j.Triggers, []string{"push"}) {
			t.Errorf("%s triggers = %v, want the calling job's [push]", name, j.Triggers)
		}
	}
}

// TestResolveNested_NestedJobTakesTheCallersEventFilters pins spec 3.2 /
// R9 (review of PR 549, takeCallerEvents coverage): the filters read off
// the calling job's `on:` (workflow_run upstreams, push branches and tags,
// their ignore lists) are cloned onto every job of a two level chain, read
// by dangerous_triggers (workflowRunWorkflows) and the situation facts
// (push filters).
func TestResolveNested_NestedJobTakesTheCallersEventFilters(t *testing.T) {
	a := "acme/shared/.github/workflows/a.yml@v1"
	b := "acme/other/.github/workflows/b.yml@v1"
	stub := newStub(map[string]string{
		"acme/shared@v1:.github/workflows/a.yml": "on:\n  workflow_call:\n  push:\n    branches: [dev]\njobs:\n  a:\n    uses: " + b + "\n",
		"acme/other@v1:.github/workflows/b.yml":  prHeadWorkflow("b", "workflow_call", "workflow_run"),
	})
	caller := ir.Job{
		Name: "ci/call", OriginFile: ".github/workflows/ci.yml", OriginLine: 9, ReusableWorkflowUses: a,
		Triggers:             []string{"push", "workflow_run"},
		WorkflowHasTriggers:  true,
		TriggerTypes:         map[string][]string{"workflow_run": {"completed"}},
		WorkflowRunWorkflows: []string{"Build"},
		PushBranches:         []string{"main"},
		PushBranchesIgnore:   []string{"wip/**"},
		PushTags:             []string{"v*"},
		PushTagsIgnore:       []string{"v0.*"},
	}
	p := resolveWith(t, stub, nestedScope{}, caller)
	for _, name := range []string{"ci/call/a", "ci/call/a/b"} {
		j := jobByName(p, name)
		if j == nil {
			t.Fatalf("jobs = %v, want %s", jobNames(p.Jobs), name)
		}
		for _, c := range []struct {
			field     string
			got, want []string
		}{
			{"WorkflowRunWorkflows", j.WorkflowRunWorkflows, caller.WorkflowRunWorkflows},
			{"PushBranches", j.PushBranches, caller.PushBranches},
			{"PushBranchesIgnore", j.PushBranchesIgnore, caller.PushBranchesIgnore},
			{"PushTags", j.PushTags, caller.PushTags},
			{"PushTagsIgnore", j.PushTagsIgnore, caller.PushTagsIgnore},
		} {
			if !slices.Equal(c.got, c.want) {
				t.Errorf("%s %s = %v, want the calling job's %v", name, c.field, c.got, c.want)
			}
		}
		// The gate and inert passes (ir.ClassifyGates, ir.MarkInert) read
		// the types: filters and the declared events off the job too.
		if !j.WorkflowHasTriggers || !slices.Equal(j.TriggerTypes["workflow_run"], []string{"completed"}) {
			t.Errorf("%s WorkflowHasTriggers = %v, TriggerTypes = %v, want the calling job's", name, j.WorkflowHasTriggers, j.TriggerTypes)
		}
	}
	if j := jobByName(p, "ci/call/a"); j != nil && len(j.PushBranches) > 0 {
		j.PushBranches[0] = "mutated"
		if caller.PushBranches[0] != "main" {
			t.Error("the nested job shares the caller's slice, want a clone")
		}
	}
}

// TestResolveNested_TriggerGatedRulesJudgeTheCallersContext pins spec 3.2
// / R9 through the embedded controls (review of PR 549): ISSUE-804 and
// ISSUE-802 judge a nested job under its calling job's triggers, and so
// does ISSUE-705 (issue #533) on a callee job granted cache-mode: write. A
// push caller of a callee whose own `on:` lists the rule's event
// (pull_request_target for 804, issue_comment for 802 and 705) is silent, a caller
// under that event of a workflow_call only callee fires, on the nested
// job, at the scanned workflow's file and line. A workflow_run caller
// (review of PR 549) hands its upstreams to the nested job: an in-scan
// upstream that runs on push only is trusted and ISSUE-802 stays silent,
// a pull_request upstream is not and ISSUE-802 fires.
func TestResolveNested_TriggerGatedRulesJudgeTheCallersContext(t *testing.T) {
	engine := opa.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	call := "acme/shared/.github/workflows/build.yml@v1"
	cases := []struct {
		code, trigger string
		on            []string
		upstream      string
		fire          bool
	}{
		{"ISSUE-804", "push", []string{"workflow_call", "pull_request_target"}, "", false},
		{"ISSUE-804", "pull_request_target", []string{"workflow_call"}, "", true},
		{"ISSUE-802", "push", []string{"workflow_call", "issue_comment"}, "", false},
		{"ISSUE-802", "issue_comment", []string{"workflow_call"}, "", true},
		{"ISSUE-802", "workflow_run", []string{"workflow_call"}, "push", false},
		{"ISSUE-802", "workflow_run", []string{"workflow_call"}, "pull_request", true},
		{"ISSUE-705", "push", []string{"workflow_call", "issue_comment"}, "", false},
		{"ISSUE-705", "issue_comment", []string{"workflow_call"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.code+" caller on "+tc.trigger+" upstream "+tc.upstream, func(t *testing.T) {
			callee := prHeadWorkflow("build", tc.on...)
			if tc.code == "ISSUE-705" {
				callee = strings.Replace(callee, "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    cache-mode: write\n", 1)
			}
			stub := newStub(map[string]string{"acme/shared@v1:.github/workflows/build.yml": callee})
			caller := ir.Job{Name: "ci/call", OriginFile: ".github/workflows/ci.yml", OriginLine: 9, Triggers: []string{tc.trigger}, ReusableWorkflowUses: call}
			jobs := []ir.Job{caller}
			if tc.upstream != "" {
				caller.WorkflowRunWorkflows = []string{"Upstream"}
				jobs = []ir.Job{caller, {Name: "upstream/test", OriginFile: ".github/workflows/upstream.yml", OriginLine: 5, WorkflowName: "Upstream", Triggers: []string{tc.upstream}}}
			}
			p := resolveWith(t, stub, nestedScope{}, jobs...)
			linkReusableCallers(p.Jobs, p.ProjectPath)
			fs, failed, err := engine.EvaluateModules(context.Background(), p, nil)
			if err != nil || len(failed) > 0 {
				t.Fatalf("evaluate: %v %v", err, failed)
			}
			var hits []opa.Finding
			for _, f := range fs {
				if f.Code == tc.code {
					hits = append(hits, f)
				}
			}
			if !tc.fire {
				if len(hits) != 0 {
					t.Fatalf("%s must be silent under this caller, got %+v", tc.code, hits)
				}
				return
			}
			if len(hits) != 1 || hits[0].Job != "ci/call/build" {
				t.Fatalf("%s must fire once on the nested job, got %+v", tc.code, hits)
			}
			if hits[0].File != ".github/workflows/ci.yml" || hits[0].Line != 9 {
				t.Errorf("%s lands at %s:%d, want the caller's .github/workflows/ci.yml:9", tc.code, hits[0].File, hits[0].Line)
			}
		})
	}
}
