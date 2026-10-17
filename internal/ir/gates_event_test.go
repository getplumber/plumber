package ir

import (
	"slices"
	"testing"
)

// TestClassifyGateEventExcludesThePrivilegedEvent pins the event family: a
// condition False for every outsider type of the privileged trigger
// because it names other events (github.event_name, or an event.action
// the trigger never produces) proves the privileged run never executes
// the job, a strong gate (no_outsider) that, like same_repo, holds only
// alone: a label, an actor or a maintainer's type next to it in a
// disjunction lets in whoever satisfies that branch.
func TestClassifyGateEventExcludesThePrivilegedEvent(t *testing.T) {
	cases := []struct {
		name, cond string
		class      GateClass
		reason     string
	}{
		{"another event", "github.event_name == 'push'", GateNoOutsider, "event push"},
		{"the privileged event excluded", "github.event_name != 'pull_request_target'", GateNoOutsider, "event pull_request_target"},
		{"a list of other events", `contains(fromJSON('["push","schedule"]'), github.event_name)`, GateNoOutsider, "event"},
		{"another event, wrapped", "${{ github.event_name == 'push' }}", GateNoOutsider, "event push"},
		{"an action the trigger never produces", "github.event.action == 'completed'", GateNoOutsider, "event completed"},
		{"another event and an outsider's action", "github.event_name == 'push' && github.event.action == 'opened'", GateNoOutsider, "event push"},
		{"another event or a label reads the label", "github.event_name == 'push' || github.event.label.name == 'ok'", GateMaintainerApproved, "label ok"},
		{"another event or an actor reads the actor", "github.event_name == 'push' || github.actor == 'renovate[bot]'", GateMaintainerApproved, "actor renovate[bot]"},
		{"another event or a maintainer's action reads the condition", "github.event_name == 'push' || github.event.action == 'labeled'", GateMaintainerApproved, "condition"},
		{"a maintainer's action alone stays the condition", "github.event.action == 'labeled'", GateMaintainerApproved, "condition"},
		{"another event or the same repository reads same_repo", "github.event_name == 'push' || github.event.pull_request.head.repo.full_name == github.repository", GateSameRepo, "same repository"},
		{"the privileged event itself is an outsider's", "github.event_name == 'pull_request_target'", GateOutsider, ""},
		{"another event or an unknown input is unknown", "github.event_name == 'push' || inputs.mode == 'x'", GateUnknown, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyGate(Job{Name: "j", If: tc.cond}, nil, "pull_request_target", nil, Environment{}, false, "")
			if got.Class != tc.class || got.Reason != tc.reason {
				t.Fatalf("gate = %+v, want %s %q", got, tc.class, tc.reason)
			}
		})
	}
}

// TestClassifyGatesEventGateIsPerTrigger pins that the event gate is read
// per privileged trigger and the weakest wins: a job on [push,
// pull_request_target] run on push only has no outsider's run at all; a
// job on [pull_request_target, issue_comment] run on issue_comment only is
// an outsider's through the comment.
func TestClassifyGatesEventGateIsPerTrigger(t *testing.T) {
	p := githubPipeline(
		Job{Name: "ci/push-only", Triggers: []string{"push", "pull_request_target"}, If: "github.event_name == 'push'"},
		Job{Name: "ci/comment-only", Triggers: []string{"pull_request_target", "issue_comment"}, If: "github.event_name == 'issue_comment'"},
	)
	ClassifyGates(p)
	if g := p.Jobs[0].Gate; g == nil || g.Class != GateNoOutsider || g.Reason != "event push" {
		t.Errorf("push-only gate = %+v, want no_outsider event push", g)
	}
	if g := p.Jobs[1].Gate; g == nil || g.Class != GateOutsider {
		t.Errorf("comment-only gate = %+v, want outsider", g)
	}
}

// warmCaller is the calling job of the cache-warming shape: ci.yml on
// [push, pull_request_target] calling _warm.yml, its if: as given.
func warmCaller(cond string) Job {
	return Job{Name: "ci/warm-cache", Triggers: []string{"push", "pull_request_target"}, If: cond, ReusableWorkflowUses: "./.github/workflows/_warm.yml"}
}

// warmCallee is the called job of the cache-warming shape, its callers as
// given.
func warmCallee(callers ...ReusableCaller) Job {
	return Job{Name: "_warm/warm", Triggers: []string{"workflow_call"}, Callers: callers}
}

func warmCall(job, cond string, triggers ...string) ReusableCaller {
	return ReusableCaller{Job: job, If: cond, Triggers: triggers}
}

// TestClassifyGatesCalledJobTakesItsCallersGate pins that a job of a
// reusable workflow, which runs under its caller's event, takes the
// weakest gate among its callers, each the calling job's own gate under
// the caller's privileged triggers: a call made on push only lets no
// outsider in, an ungated call lets one in, and of two calls the weaker
// decides. A caller that is not among the jobs (another repository's, or
// one the scan does not have) is unknown, never an outsider's by default
// and never a strong gate. A caller with no privileged trigger gives the
// called job no privileged run, so no gate.
func TestClassifyGatesCalledJobTakesItsCallersGate(t *testing.T) {
	const pushOnly = "github.event_name == 'push'"
	cases := []struct {
		name   string
		jobs   []Job
		class  GateClass
		reason string
	}{
		{"called on push only", []Job{warmCaller(pushOnly), warmCallee(warmCall("ci/warm-cache", pushOnly, "pull_request_target", "push"))}, GateNoOutsider, "event push"},
		{"called on every event", []Job{warmCaller(""), warmCallee(warmCall("ci/warm-cache", "", "pull_request_target", "push"))}, GateOutsider, ""},
		{"one gated and one ungated call", []Job{
			warmCaller(pushOnly),
			{Name: "other/warm", Triggers: []string{"pull_request_target"}, ReusableWorkflowUses: "./.github/workflows/_warm.yml"},
			warmCallee(warmCall("ci/warm-cache", pushOnly, "pull_request_target", "push"), warmCall("other/warm", "", "pull_request_target")),
		}, GateOutsider, ""},
		{"a caller the scan does not have", []Job{warmCallee(warmCall("elsewhere/warm", pushOnly, "pull_request_target"))}, GateUnknown, ""},
		{"a label on the caller", []Job{
			{Name: "ci/warm-cache", Triggers: []string{"pull_request_target"}, If: "github.event.label.name == 'warm'"},
			warmCallee(warmCall("ci/warm-cache", "github.event.label.name == 'warm'", "pull_request_target")),
		}, GateMaintainerApproved, "label warm"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := githubPipeline(tc.jobs...)
			ClassifyGates(p)
			g := p.Jobs[len(p.Jobs)-1].Gate
			if g == nil || g.Class != tc.class || g.Reason != tc.reason {
				t.Fatalf("called job gate = %+v, want %s %q", g, tc.class, tc.reason)
			}
		})
	}

	p := githubPipeline(
		Job{Name: "ci/warm-cache", Triggers: []string{"push"}},
		warmCallee(warmCall("ci/warm-cache", "", "push")),
	)
	ClassifyGates(p)
	if g := p.Jobs[1].Gate; g != nil {
		t.Errorf("push-only caller: called job gate = %+v, want none", g)
	}
}

// TestClassifyGatesCalledJobKeepsItsOwnCondition pins that a called job's
// own if: still holds under its caller's event: run on push only itself,
// an ungated pull_request_target call lets no outsider in either.
func TestClassifyGatesCalledJobKeepsItsOwnCondition(t *testing.T) {
	callee := warmCallee(warmCall("ci/warm-cache", "", "pull_request_target", "push"))
	callee.If = "github.event_name == 'push'"
	p := githubPipeline(warmCaller(""), callee)
	ClassifyGates(p)
	if g := p.Jobs[1].Gate; g == nil || g.Class != GateNoOutsider {
		t.Errorf("called job gate = %+v, want no_outsider", g)
	}
}

// TestEveryOutsiderTypeIsADeliveredType pins that the activity types a
// trigger delivers include every one an outsider produces on it, so an
// outsider's own action never reads as another event's run.
func TestEveryOutsiderTypeIsADeliveredType(t *testing.T) {
	for trigger, types := range canonicalOutsiderTypes {
		delivered, ok := triggerActivityTypes[trigger]
		if !ok {
			t.Errorf("%s: no delivered types", trigger)
			continue
		}
		for _, ty := range types {
			if !slices.Contains(delivered, ty) {
				t.Errorf("%s: %s not delivered", trigger, ty)
			}
		}
	}
}

// TestPullRequestTargetRunsOnTheBaseRef pins the refs of a pull request
// run: pull_request_target runs on the base branch (github.ref
// refs/heads/<base>, github.ref_name <base>, the default branch when the
// pipeline names none), so a condition on the default branch's ref is
// True for an outsider's pull request; pull_request runs on the merge ref
// (refs/pull/<n>/merge), so the same condition stays False there. Both
// carry github.base_ref, the base branch.
func TestPullRequestTargetRunsOnTheBaseRef(t *testing.T) {
	job := Job{Name: "j", If: "github.ref == 'refs/heads/main'"}
	if g := ClassifyGate(job, nil, "pull_request_target", nil, Environment{}, false, ""); g.Class != GateOutsider {
		t.Errorf("pull_request_target, ref main: gate = %+v, want outsider", g)
	}
	if g := ClassifyGate(job, nil, "pull_request", nil, Environment{}, false, ""); g.Class != GateMaintainerApproved || g.Reason != "condition" {
		t.Errorf("pull_request, ref main: gate = %+v, want maintainer_approved condition", g)
	}
	develop := Job{Name: "j", If: "github.ref_name == 'develop' && github.base_ref == 'develop'"}
	if g := ClassifyGate(develop, nil, "pull_request_target", nil, Environment{}, false, "develop"); g.Class != GateOutsider {
		t.Errorf("pull_request_target, default branch develop: gate = %+v, want outsider", g)
	}

	// An outsider opens a pull request against any existing branch: a
	// condition naming a branch other than the default one is unknown
	// (the outsider's entry, one tier down), never a maintainer's cap.
	for _, tc := range []struct {
		cond  string
		class GateClass
	}{
		{"github.ref == 'refs/heads/main'", GateOutsider},
		{"github.base_ref == 'main'", GateOutsider},
		{"github.ref == 'refs/heads/release'", GateUnknown},
		{"github.base_ref != 'main'", GateUnknown},
		{"github.ref_name == 'release'", GateUnknown},
		// One literal off the default branch leaves the base unresolved
		// for the whole condition: unknown, the safe side of outsider.
		{"github.ref == 'refs/heads/main' || github.base_ref == 'release'", GateUnknown},
	} {
		if g := ClassifyGate(Job{Name: "j", If: tc.cond}, nil, "pull_request_target", nil, Environment{}, false, ""); g.Class != tc.class {
			t.Errorf("pull_request_target, %s: gate = %+v, want %s", tc.cond, g, tc.class)
		}
	}
	// A predecessor's condition counts too: naming release there leaves
	// the base unresolved for the whole walk, so the predecessor never
	// reads False on main (a maintainer's cap) for the job after it.
	pred := Job{Name: "a", If: "github.base_ref == 'release'"}
	after := Job{Name: "b", If: "github.base_ref == 'main'", Needs: []string{"a"}}
	if g := ClassifyGate(after, map[string]Job{"a": pred, "b": after}, "pull_request_target", nil, Environment{}, false, ""); g.Class != GateUnknown {
		t.Errorf("predecessor on release: gate = %+v, want unknown", g)
	}
	// A predecessor's step condition counts the same way: the step
	// naming release leaves the base unresolved for the whole walk.
	predStep := Job{
		Name:      "a",
		Scripts:   []string{`echo "go=1" >> $GITHUB_OUTPUT`},
		ScriptIfs: []string{"github.base_ref == 'release'"},
	}
	if g := ClassifyGate(after, map[string]Job{"a": predStep, "b": after}, "pull_request_target", nil, Environment{}, false, ""); g.Class != GateUnknown {
		t.Errorf("predecessor step on release: gate = %+v, want unknown", g)
	}

	cases := []struct {
		trigger, base, ref, want string
	}{
		{"pull_request_target", "", "github.ref", "refs/heads/main"},
		{"pull_request_target", "", "github.ref_name", "main"},
		{"pull_request_target", "develop", "github.ref_name", "develop"},
		{"pull_request_target", "", "github.base_ref", "main"},
		{"pull_request", "", "github.ref", "refs/pull/1/merge"},
		{"pull_request", "", "github.ref_name", "1/merge"},
		{"pull_request", "develop", "github.base_ref", "develop"},
	}
	for _, c := range cases {
		got, ok := newOutsiderFacts(c.trigger, "opened", Job{}, nil, c.base).Resolve(c.ref)
		if !ok || got != c.want {
			t.Errorf("%s %s (base %q) = %q %v, want %q", c.trigger, c.ref, c.base, got, ok, c.want)
		}
	}
	// The outsider names their own branch, any value they like: no literal
	// comparison of it is settled either way.
	if _, ok := newOutsiderFacts("pull_request_target", "opened", Job{}, nil, "").Resolve("github.head_ref"); ok {
		t.Error("github.head_ref resolved")
	}
	if _, ok := newOutsiderFacts("issue_comment", "created", Job{}, nil, "").Resolve("github.base_ref"); ok {
		t.Error("github.base_ref resolved on issue_comment, which carries none")
	}
}

// TestClassifyGatesReadsTheDefaultBranch pins that the pipeline's default
// branch is the pull_request_target base.
func TestClassifyGatesReadsTheDefaultBranch(t *testing.T) {
	p := githubPipeline(Job{Name: "ci/j", Triggers: []string{"pull_request_target"}, If: "github.ref == 'refs/heads/develop'"})
	p.DefaultBranch = "develop"
	ClassifyGates(p)
	if g := p.Jobs[0].Gate; g == nil || g.Class != GateOutsider {
		t.Errorf("gate = %+v, want outsider", g)
	}
}
