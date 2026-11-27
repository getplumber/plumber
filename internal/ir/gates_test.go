package ir

import (
	"reflect"
	"testing"
)

// TestClassifyGateLabelGate covers a job gated on a workflow types filter
// that only a maintainer can produce (`labeled`) and whose own condition
// additionally checks for a specific label. Its checkout pins the pull
// request head SHA, so PinnedSha must come back true alongside the
// maintainer_approved class.
func TestClassifyGateLabelGate(t *testing.T) {
	job := Job{
		Name: "deploy",
		If:   "contains(github.event.pull_request.labels.*.name, 'tests:run-cloud')",
		Uses: []Action{
			{Uses: "actions/checkout@v4", With: map[string]any{"ref": "${{ github.event.pull_request.head.sha }}"}},
		},
	}
	got := ClassifyGate(job, nil, "pull_request", []string{"labeled"}, Environment{}, false, "", "")
	if got.Class != GateMaintainerApproved {
		t.Fatalf("Class = %q, want %q", got.Class, GateMaintainerApproved)
	}
	if !got.PinnedSha {
		t.Fatal("PinnedSha = false, want true")
	}
	if got.Reason != "label tests:run-cloud" {
		t.Fatalf("Reason = %q, want %q", got.Reason, "label tests:run-cloud")
	}
}

// TestClassifyGateAuthorGate covers a job gated on the triggering actor's
// identity, which the model never lets an outsider satisfy.
func TestClassifyGateAuthorGate(t *testing.T) {
	job := Job{
		Name: "automerge",
		If:   "github.actor == 'dependabot[bot]'",
	}
	got := ClassifyGate(job, nil, "pull_request_target", nil, Environment{}, false, "", "")
	if got.Class != GateMaintainerApproved {
		t.Fatalf("Class = %q, want %q", got.Class, GateMaintainerApproved)
	}
	if got.Reason != "actor dependabot[bot]" {
		t.Fatalf("Reason = %q, want %q", got.Reason, "actor dependabot[bot]")
	}
}

// TestClassifyGatePullRequestAuthorGate covers a job gated on the pull
// request's author, the one identity reference whose reason reads
// "author": an outsider can make a bot the actor of an event on their
// own pull request, never its author.
func TestClassifyGatePullRequestAuthorGate(t *testing.T) {
	job := Job{Name: "automerge", If: "github.event.pull_request.user.login == 'dependabot[bot]'"}
	got := ClassifyGate(job, nil, "pull_request_target", nil, Environment{}, false, "", "")
	if got.Class != GateMaintainerApproved || got.Reason != "author dependabot[bot]" {
		t.Fatalf("gate = %+v", got)
	}
}

// TestClassifyGateSameRepo covers a workflow_run job whose condition
// requires the triggering workflow's head repository to be the scanned
// repository itself, which a fork can never satisfy.
func TestClassifyGateSameRepo(t *testing.T) {
	job := Job{
		Name: "publish",
		If:   "github.event.workflow_run.head_repository.full_name == github.repository",
	}
	got := ClassifyGate(job, nil, "workflow_run", nil, Environment{}, false, "", "")
	if got.Class != GateSameRepo {
		t.Fatalf("Class = %q, want %q", got.Class, GateSameRepo)
	}
	if got.Reason != "same repository" {
		t.Fatalf("Reason = %q, want %q", got.Reason, "same repository")
	}
}

// TestClassifyGateUngatedOutsider covers a job with no condition at all on
// a pull_request_target trigger restricted to the two most common
// outsider-producible types: any fork PR reaches it.
func TestClassifyGateUngatedOutsider(t *testing.T) {
	job := Job{
		Name: "build",
	}
	got := ClassifyGate(job, nil, "pull_request_target", []string{"opened", "synchronize"}, Environment{}, false, "", "")
	if got.Class != GateOutsider {
		t.Fatalf("Class = %q, want %q", got.Class, GateOutsider)
	}
}

// TestClassifyGateNeedsChainOutput covers a job gated through a
// predecessor's output rather than its own condition: "policy" only
// writes run_privileged=true to $GITHUB_OUTPUT under a label-gated step,
// so "deploy" reading that output stays closed to an outsider even
// though its own `If` never mentions a label.
func TestClassifyGateNeedsChainOutput(t *testing.T) {
	policy := Job{
		Name:      "policy",
		Scripts:   []string{`echo "run_privileged=true" >> $GITHUB_OUTPUT`},
		ScriptIfs: []string{"contains(github.event.pull_request.labels.*.name, 'ok-to-run')"},
	}
	deploy := Job{
		Name:  "deploy",
		If:    "needs.policy.outputs.run_privileged == 'true'",
		Needs: []string{"policy"},
	}
	byName := map[string]Job{"policy": policy, "deploy": deploy}
	got := ClassifyGate(deploy, byName, "pull_request_target", nil, Environment{}, false, "", "")
	if got.Class != GateMaintainerApproved {
		t.Fatalf("Class = %q, want %q (reason %q)", got.Class, GateMaintainerApproved, got.Reason)
	}
}

// TestClassifyGateNeedsOutputTheOutsiderSets pins the other side of
// TestClassifyGateNeedsChainOutput: when the step writing the output
// runs for an outsider (unconditional, or under a condition True for
// their event), the value it writes is read and compared, so "deploy"
// is reachable by an outsider. Misreading that value (a trailing quote
// kept, say) would downgrade an outsider-reachable privileged job.
func TestClassifyGateNeedsOutputTheOutsiderSets(t *testing.T) {
	deploy := Job{
		Name:  "deploy",
		If:    "needs.policy.outputs.run_privileged == 'true'",
		Needs: []string{"policy"},
	}
	scripts := []string{
		`echo "run_privileged=true" >> $GITHUB_OUTPUT`,
		// A sibling output whose name ends in the wanted name is written
		// first: it must not be read as the gate's value.
		"echo \"dry_run_privileged=false\" >> \"$GITHUB_OUTPUT\"\necho \"run_privileged=true\" >> \"$GITHUB_OUTPUT\"",
	}
	for _, script := range scripts {
		for _, stepIf := range []string{"", "github.event_name == 'pull_request_target'"} {
			policy := Job{
				Name:      "policy",
				Scripts:   []string{script},
				ScriptIfs: []string{stepIf},
			}
			byName := map[string]Job{"policy": policy, "deploy": deploy}
			got := ClassifyGate(deploy, byName, "pull_request_target", nil, Environment{}, false, "", "")
			if got.Class != GateOutsider {
				t.Errorf("script %q, step if %q: Class = %q, want %q (reason %q)", script, stepIf, got.Class, GateOutsider, got.Reason)
			}
		}
	}
}

// TestScriptOutputValueReadsTheLiteral pins the value scan on the
// common shapes of a $GITHUB_OUTPUT write: double-quoted, single-
// quoted, unquoted and followed by a space, and the last line of a
// multi-line script.
func TestScriptOutputValueReadsTheLiteral(t *testing.T) {
	cases := []struct {
		script, want string
		ok           bool
	}{
		{`echo "run=true" >> $GITHUB_OUTPUT`, "true", true},
		{`echo 'run=yes' >> "$GITHUB_OUTPUT"`, "yes", true},
		{`echo run=on >> $GITHUB_OUTPUT`, "on", true},
		{"echo hi\necho run=1\t>> $GITHUB_OUTPUT", "1", true},
		{"echo run=last >> $GITHUB_OUTPUT\n", "last", true},
		{`echo "run=true"`, "", false},
		{`echo "other=true" >> $GITHUB_OUTPUT`, "", false},
		// A redirect or another shell operator glued to the value ends
		// it: `true>>$GITHUB_OUTPUT` writes the literal true.
		{`echo run=true>>$GITHUB_OUTPUT`, "true", true},
		{`echo run=on>$GITHUB_OUTPUT`, "on", true},
		{`(echo run=yes)>>$GITHUB_OUTPUT`, "yes", true},
		{`echo run=no;echo other=1 >> $GITHUB_OUTPUT`, "no", true},
		// A value computed at run time (an expression, a variable, a
		// command substitution) is no settled literal: the gate stays
		// unknown rather than closing on a truncated prefix.
		{"echo \"run=${{ contains(github.event.pull_request.title, 'deploy') }}\" >> \"$GITHUB_OUTPUT\"", "", false},
		{`echo "run=$FLAG" >> $GITHUB_OUTPUT`, "", false},
		{`echo "run=$(cat flag)" >> $GITHUB_OUTPUT`, "", false},
		// An output whose name ends in the wanted name is another output:
		// dry_run=false must never be read as run=false.
		{"echo \"dry_run=false\" >> \"$GITHUB_OUTPUT\"\necho \"run=true\" >> \"$GITHUB_OUTPUT\"", "true", true},
		{`echo "dry_run=false" >> $GITHUB_OUTPUT`, "", false},
		{`echo "run=true dry_run=false" >> $GITHUB_OUTPUT`, "true", true},
	}
	for _, c := range cases {
		got, ok := scriptOutputValue(c.script, "run")
		if got != c.want || ok != c.ok {
			t.Errorf("scriptOutputValue(%q) = %q %v, want %q %v", c.script, got, ok, c.want, c.ok)
		}
	}
}

// TestClassifyGateStatusFunctionOutlivesTheNeedsChain pins that a
// dependent whose `if:` calls a status function (always(), failure(),
// cancelled(), a negated success()) runs even when its predecessor was
// skipped, so a predecessor's same-repository gate never closes it: its
// own condition decides. always() is true, so alone it lets the outsider
// in (job `always` of test/2026-11-27-always-after-skipped-gate,
// getplumber-examples/github-actions-miscellaneous-knowledge, run
// 45994252328: it ran on the fork pull request that skipped `gate`); the
// other status functions say nothing the model knows and stay unknown.
func TestClassifyGateStatusFunctionOutlivesTheNeedsChain(t *testing.T) {
	check := Job{Name: "check", If: "github.event.pull_request.head.repo.full_name == github.repository"}
	cases := []struct {
		name, cond string
		want       GateClass
	}{
		{"always() alone is outsider", "always()", GateOutsider},
		{"always() or an event the outsider produces is outsider", "always() || github.event_name == 'pull_request_target'", GateOutsider},
		{"not failure and not cancelled is unknown", "!failure() && !cancelled()", GateUnknown},
		{"a negated success() is unknown", "!success()", GateUnknown},
		{"a plain condition still inherits the predecessor's gate", "github.event_name == 'pull_request_target'", GateSameRepo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deploy := Job{Name: "deploy", If: tc.cond, Needs: []string{"check"}}
			byName := map[string]Job{"check": check, "deploy": deploy}
			got := ClassifyGate(deploy, byName, "pull_request_target", nil, Environment{}, false, "", "")
			if got.Class != tc.want {
				t.Fatalf("gate = %+v, want %s", got, tc.want)
			}
		})
	}
}

// TestClassifyGateReadsASkippedPredecessorBack pins what a condition that
// outlives the `needs` chain (always()) reads from a predecessor closed
// to forks: needs.<job>.result is "skipped" and its outputs are empty, so
// "run only if the gate job succeeded" keeps the gate, for the job and
// for the job behind it. A condition the skip does not close lets the
// outsider in, and a predecessor the outsider's run does not skip gives
// no result: the guard is never invented.
//
// The first three rows are jobs always-result-success, always-output and
// always-result-skipped of test/2026-11-27-always-after-skipped-gate
// (getplumber-examples/github-actions-miscellaneous-knowledge, run
// 45994252328, a fork pull request): the first two were skipped with the
// job behind them (behind-closed), the third ran.
func TestClassifyGateReadsASkippedPredecessorBack(t *testing.T) {
	const sameRepo = "github.event.workflow_run.head_repository.full_name == github.repository"
	writesGo := []string{`echo "go=true" >> "$GITHUB_OUTPUT"`}
	cases := []struct {
		name string
		gate Job
		cond string
		want GateClass
	}{
		{"the result of a skipped gate is not success", Job{If: sameRepo},
			"always() && needs.gate.result == 'success'", GateSameRepo},
		{"an output of a skipped gate is empty", Job{If: sameRepo, Scripts: writesGo},
			"always() && needs.gate.outputs.go == 'true'", GateSameRepo},
		{"a job that asks for the skip runs", Job{If: sameRepo},
			"always() && needs.gate.result == 'skipped'", GateOutsider},
		{"always() or the result runs", Job{If: sameRepo},
			"always() || needs.gate.result == 'success'", GateOutsider},
		{"an open gate gives no result", Job{},
			"always() && needs.gate.result == 'success'", GateUnknown},
		{"an open gate keeps the output it writes", Job{Scripts: writesGo},
			"always() && needs.gate.outputs.go == 'true'", GateOutsider},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gate := tc.gate
			gate.Name = "gate"
			ready := Job{Name: "ready", If: tc.cond, Needs: []string{"gate"}}
			build := Job{Name: "build", Needs: []string{"ready"}}
			byName := map[string]Job{"gate": gate, "ready": ready, "build": build}
			// `build` has no condition of its own: closed with `ready`,
			// open otherwise.
			wantReady, wantBuild := Gate{Class: tc.want}, Gate{Class: GateOutsider}
			if tc.want == GateSameRepo {
				wantReady.Reason = "same repository"
				wantBuild = wantReady
			}
			for job, want := range map[string]Gate{"ready": wantReady, "build": wantBuild} {
				got := ClassifyGate(byName[job], byName, "workflow_run", []string{"completed"}, Environment{}, false, "", "")
				if got.Class != want.Class || got.Reason != want.Reason {
					t.Errorf("%s: gate = %+v, want %s %q", job, got, want.Class, want.Reason)
				}
			}
		})
	}
}

// TestClassifyGateAlwaysNextToTheOwnName pins the checkout job that
// carries `always() && github.repository == '<own name>'` behind a job
// closed to forks: both halves are true for the outsider, so it is
// theirs (job always-own-name of
// test/2026-11-27-always-after-skipped-gate, run 45994252328: it ran on
// the fork pull request). With no project path the own name cannot be
// told from another repository's and the gate stays unknown.
func TestClassifyGateAlwaysNextToTheOwnName(t *testing.T) {
	gate := Job{Name: "gate", If: "github.event.pull_request.head.repo.full_name == github.repository"}
	build := Job{Name: "build", If: "always() && github.repository == '" + ownNameRepository + "'", Needs: []string{"gate"}}
	byName := map[string]Job{"gate": gate, "build": build}
	for repository, want := range map[string]GateClass{ownNameRepository: GateOutsider, "": GateUnknown} {
		got := ClassifyGate(build, byName, "pull_request_target", nil, Environment{}, false, "", repository)
		if got.Class != want {
			t.Errorf("repository %q: gate = %+v, want %s", repository, got, want)
		}
	}
}

// TestClassifyGateFindsTheNeededJobInItsWorkflow pins that a condition's
// needs.<job> is read inside the workflow of the job being classified:
// the provider names jobs "<workflow>/<job>" while a condition names the
// bare job id, and another workflow's job of the same id has no say.
func TestClassifyGateFindsTheNeededJobInItsWorkflow(t *testing.T) {
	const sameRepo = "github.event.workflow_run.head_repository.full_name == github.repository"
	const goOutput = `echo "go=true" >> "$GITHUB_OUTPUT"`
	const readsGoOutput = "always() && needs.gate.outputs.go == 'true'"
	byName := map[string]Job{
		"publish/gate":  {Name: "publish/gate", If: sameRepo},
		"publish/ready": {Name: "publish/ready", If: "always() && needs.gate.result == 'success'", Needs: []string{"publish/gate"}},
		"publish/build": {Name: "publish/build", Needs: []string{"publish/ready"}},
		"other/gate":    {Name: "other/gate"},
		"other/ready":   {Name: "other/ready", If: "always() && needs.gate.result == 'success'", Needs: []string{"other/gate"}},
		// The same lookup for needs.<job>.outputs.*: `go` is written by
		// the gate of each workflow, skipped for the outsider in one and
		// run in the other.
		"release/gate":  {Name: "release/gate", If: sameRepo, Scripts: []string{goOutput}, ScriptIfs: []string{""}},
		"release/ready": {Name: "release/ready", If: readsGoOutput, Needs: []string{"release/gate"}},
		"open/gate":     {Name: "open/gate", Scripts: []string{goOutput}, ScriptIfs: []string{""}},
		"open/ready":    {Name: "open/ready", If: readsGoOutput, Needs: []string{"open/gate"}},
	}
	for name, want := range map[string]GateClass{
		"publish/ready": GateSameRepo,
		"publish/build": GateSameRepo,
		"other/ready":   GateUnknown,
		"release/ready": GateSameRepo,
		"open/ready":    GateOutsider,
	} {
		got := ClassifyGate(byName[name], byName, "workflow_run", []string{"completed"}, Environment{}, false, "", "")
		if got.Class != want {
			t.Errorf("%s: gate = %+v, want %s", name, got, want)
		}
	}
}

// TestClassifyGateResultCycleStops pins that two jobs whose conditions
// read each other's result resolve to unknown instead of recursing
// without end: an untrusted workflow writes these conditions.
func TestClassifyGateResultCycleStops(t *testing.T) {
	a := Job{Name: "a", If: "always() && needs.b.result == 'success'", Needs: []string{"b"}}
	b := Job{Name: "b", If: "always() && needs.a.result == 'success'", Needs: []string{"a"}}
	byName := map[string]Job{"a": a, "b": b}
	got := ClassifyGate(a, byName, "workflow_run", []string{"completed"}, Environment{}, false, "", "")
	if got.Class != GateUnknown {
		t.Fatalf("gate = %+v, want unknown", got)
	}
}

// TestClassifyGateEventTypes pins the two type lists: a type an outsider
// produces (closing their own pull request, editing their own comment,
// requesting a run, opening a discussion) lets them in; a type only a
// maintainer produces (a label) is a maintainer's gate; a type in neither
// list is unknown, never a maintainer's gate.
func TestClassifyGateEventTypes(t *testing.T) {
	cases := []struct {
		trigger, typ string
		want         GateClass
	}{
		{"pull_request_target", "closed", GateOutsider},
		{"pull_request_target", "converted_to_draft", GateOutsider},
		{"issue_comment", "edited", GateOutsider},
		{"issue_comment", "deleted", GateOutsider},
		{"pull_request_review", "dismissed", GateOutsider},
		{"workflow_run", "requested", GateOutsider},
		{"workflow_run", "in_progress", GateOutsider},
		{"issues", "reopened", GateOutsider},
		{"discussion", "created", GateOutsider},
		{"discussion", "category_changed", GateOutsider},
		{"pull_request_target", "labeled", GateMaintainerApproved},
		{"pull_request_target", "auto_merge_enabled", GateMaintainerApproved},
		{"issues", "milestoned", GateMaintainerApproved},
		{"pull_request_target", "some_future_type", GateUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.trigger+" "+tc.typ, func(t *testing.T) {
			got := ClassifyGate(Job{Name: "j"}, nil, tc.trigger, []string{tc.typ}, Environment{}, false, "", "")
			if got.Class != tc.want {
				t.Fatalf("gate = %+v, want %s", got, tc.want)
			}
		})
	}
	// A maintainer type next to an unknown one is unknown, never a gate.
	got := ClassifyGate(Job{Name: "j"}, nil, "pull_request_target", []string{"labeled", "some_future_type"}, Environment{}, false, "", "")
	if got.Class != GateUnknown {
		t.Fatalf("labeled + some_future_type: gate = %+v, want unknown", got)
	}
}

// TestClassifyGateUnknownInput covers a condition that reads a fact this
// package's model never defines (a workflow_dispatch input): the
// classifier must own up to not knowing rather than guessing.
func TestClassifyGateUnknownInput(t *testing.T) {
	job := Job{
		Name: "release",
		If:   "inputs.mode == 'full'",
	}
	got := ClassifyGate(job, nil, "pull_request", nil, Environment{}, false, "", "")
	if got.Class != GateUnknown {
		t.Fatalf("Class = %q, want %q", got.Class, GateUnknown)
	}
	if !reflect.DeepEqual(got.Unknown, []string{"inputs.mode"}) {
		t.Fatalf("Unknown = %v, want [inputs.mode]", got.Unknown)
	}
}

// TestClassifyGateEnvironmentRequiredReviewers covers the controller-added
// Environment lane: a known environment with required reviewers is a
// maintainer gate regardless of the job's own condition.
func TestClassifyGateEnvironmentRequiredReviewers(t *testing.T) {
	job := Job{Name: "deploy-prod"}
	env := Environment{Name: "production", RequiredReviewers: true}
	got := ClassifyGate(job, nil, "pull_request_target", nil, env, true, "", "")
	if got.Class != GateMaintainerApproved {
		t.Fatalf("Class = %q, want %q", got.Class, GateMaintainerApproved)
	}
	if got.Reason != "environment production requires reviewers" {
		t.Fatalf("Reason = %q, want %q", got.Reason, "environment production requires reviewers")
	}
}

// TestClassifyGateEnvironmentUnknownIgnored covers the case where the
// environment's protection rules are not known: the environment must not
// contribute to classification, and an otherwise ungated job stays
// outsider.
func TestClassifyGateEnvironmentUnknownIgnored(t *testing.T) {
	job := Job{Name: "deploy-prod"}
	env := Environment{Name: "production", RequiredReviewers: true, Known: false}
	got := ClassifyGate(job, nil, "pull_request_target", []string{"opened"}, env, false, "", "")
	if got.Class != GateOutsider {
		t.Fatalf("Class = %q, want %q", got.Class, GateOutsider)
	}
}

// TestClassifyGateReadyForReviewOutsider covers a job gated only on the
// pull_request event action itself: an outsider taking their own draft
// pull request out of draft produces the ready_for_review action
// without any maintainer involved, so an ungated types filter must
// still reach it.
func TestClassifyGateReadyForReviewOutsider(t *testing.T) {
	job := Job{
		Name: "build",
		If:   "github.event.action == 'ready_for_review'",
	}
	got := ClassifyGate(job, nil, "pull_request", nil, Environment{}, false, "", "")
	if got.Class != GateOutsider {
		t.Fatalf("Class = %q, want %q (reason %q)", got.Class, GateOutsider, got.Reason)
	}
}

// TestClassifyGateNeedsOutputCycleIsUnknownNotCrash covers two jobs whose
// output-gating step conditions read each other's output
// (needs.a.outputs.out and needs.b.outputs.out): a workflow this
// adversarial is untrusted input, so resolving it must come back
// unknown rather than recursing without end.
func TestClassifyGateNeedsOutputCycleIsUnknownNotCrash(t *testing.T) {
	a := Job{
		Name:      "a",
		Scripts:   []string{`echo "out=1" >> $GITHUB_OUTPUT`},
		ScriptIfs: []string{"needs.b.outputs.out == '1'"},
	}
	b := Job{
		Name:      "b",
		Scripts:   []string{`echo "out=1" >> $GITHUB_OUTPUT`},
		ScriptIfs: []string{"needs.a.outputs.out == '1'"},
	}
	deploy := Job{
		Name:  "deploy",
		If:    "needs.a.outputs.out == '1'",
		Needs: []string{"a"},
	}
	byName := map[string]Job{"a": a, "b": b, "deploy": deploy}

	got := ClassifyGate(deploy, byName, "pull_request_target", nil, Environment{}, false, "", "")
	if got.Class != GateUnknown {
		t.Fatalf("Class = %q, want %q (reason %q, unknown %v)", got.Class, GateUnknown, got.Reason, got.Unknown)
	}
}

// TestClassifyGateStrongClassesHoldAlone pins that the two gates that
// remove a path (a bot as the pull request's author, the same
// repository) are read only when the condition stays False with every
// other fact family hidden: an actor check or a merge next to them in a
// disjunction lets in whoever satisfies that other branch, so the
// weakest family that opens the condition names the gate instead.
func TestClassifyGateStrongClassesHoldAlone(t *testing.T) {
	cases := []struct {
		name, cond string
		class      GateClass
		reason     string
	}{
		{"author or actor reads the actor", "github.event.pull_request.user.login == 'dependabot[bot]' || github.actor == 'dependabot[bot]'", GateMaintainerApproved, "actor dependabot[bot]"},
		{"author or merged reads merged", "github.event.pull_request.user.login == 'dependabot[bot]' || github.event.pull_request.merged == true", GateMaintainerApproved, "merged"},
		{"a plain author check still reads the author", "github.event.pull_request.user.login == 'dependabot[bot]'", GateMaintainerApproved, "author dependabot[bot]"},
		{"a plain same-repository check still reads same_repo", "github.event.pull_request.head.repo.full_name == github.repository", GateSameRepo, "same repository"},
		{"same repository or actor reads the actor", "github.event.pull_request.head.repo.full_name == github.repository || github.actor == 'renovate[bot]'", GateMaintainerApproved, "actor renovate[bot]"},
		{"author and same repository both hold alone", "github.event.pull_request.user.login == 'dependabot[bot]' && github.event.pull_request.head.repo.full_name == github.repository", GateMaintainerApproved, "author dependabot[bot]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyGate(Job{Name: "j", If: tc.cond}, nil, "pull_request_target", nil, Environment{}, false, "", "")
			if got.Class != tc.class || got.Reason != tc.reason {
				t.Fatalf("gate = %+v, want %s %q", got, tc.class, tc.reason)
			}
		})
	}
}

// TestClassifyGateBareForkGuardIsSameRepo pins the most common fork
// guard, the bare boolean `!github.event.pull_request.head.repo.fork`:
// a fork pull request never satisfies it, so the job is same-repo
// gated, not unknown.
func TestClassifyGateBareForkGuardIsSameRepo(t *testing.T) {
	for _, cond := range []string{
		"${{ !github.event.pull_request.head.repo.fork }}",
		"!github.event.pull_request.head.repo.fork",
	} {
		job := Job{Name: "build", If: cond}
		got := ClassifyGate(job, nil, "pull_request_target", nil, Environment{}, false, "", "")
		if got.Class != GateSameRepo {
			t.Errorf("%s: Class = %q, want %q (reason %q, unknown %v)", cond, got.Class, GateSameRepo, got.Reason, got.Unknown)
		}
	}
}

// TestClassifyGateNeedsOutputComputedFromTheEventIsUnknown pins that an
// output written from an expression over the event (a pull request
// title an outsider controls) is not read as a settled literal: the
// gate on it is unknown, never maintainer-approved.
func TestClassifyGateNeedsOutputComputedFromTheEventIsUnknown(t *testing.T) {
	check := Job{
		Name:    "check",
		Scripts: []string{"echo \"deploy=${{ contains(github.event.pull_request.title, 'deploy') }}\" >> \"$GITHUB_OUTPUT\""},
	}
	deploy := Job{
		Name:  "deploy",
		If:    "needs.check.outputs.deploy == 'true'",
		Needs: []string{"check"},
	}
	byName := map[string]Job{"check": check, "deploy": deploy}
	got := ClassifyGate(deploy, byName, "pull_request_target", nil, Environment{}, false, "", "")
	if got.Class != GateUnknown {
		t.Fatalf("Class = %q, want %q (reason %q)", got.Class, GateUnknown, got.Reason)
	}
}

// ownNameRepository is the scanned repository of the #640 cases.
const ownNameRepository = "my-org/my-repo"

// TestClassifyGateOwnRepositoryNameGatesNothing pins getplumber/plumber#640:
// `github.repository` is the repository the workflow runs in, the base
// repository on pull_request_target and on workflow_run, so a comparison
// with the scanned repository's own name is true for a fork's pull
// request too. Proven on GitHub by the branch
// test/2026-11-27-repository-name-condition of
// getplumber-examples/github-actions-miscellaneous-knowledge: the
// own-name job ran for the fork pull request, checked out its commit and
// read the secret (runs 45973998287 on pull_request_target, 45974025370
// on workflow_run).
func TestClassifyGateOwnRepositoryNameGatesNothing(t *testing.T) {
	cases := []struct {
		name    string
		trigger string
		cond    string
	}{
		{"pull_request_target", "pull_request_target", "github.repository == 'my-org/my-repo'"},
		{"workflow_run", "workflow_run", "github.repository == 'my-org/my-repo'"},
		{"another case of the name", "pull_request_target", "github.repository == 'My-Org/My-Repo'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyGate(Job{Name: "build", If: tc.cond}, nil, tc.trigger, nil, Environment{}, false, "", ownNameRepository)
			if got.Class != GateOutsider {
				t.Errorf("gate = %+v, want %q", got, GateOutsider)
			}
		})
	}
}

// TestClassifyGateSameRepoWithTheScannedRepository pins the other side of
// the same test branch: comparing the head repository with
// github.repository did skip the fork's job (the head-repo job), whatever
// the scanned repository is called, the model's own fork name included.
func TestClassifyGateSameRepoWithTheScannedRepository(t *testing.T) {
	conds := map[string]string{
		"pull_request_target": "github.event.pull_request.head.repo.full_name == github.repository",
		"workflow_run":        "github.event.workflow_run.head_repository.full_name == github.repository",
	}
	for _, repository := range []string{ownNameRepository, headRepoFullName, "Fork/Repo"} {
		for trigger, cond := range conds {
			got := ClassifyGate(Job{Name: "build", If: cond}, nil, trigger, nil, Environment{}, false, "", repository)
			if got.Class != GateSameRepo || got.Reason != "same repository" {
				t.Errorf("repository %q on %s: gate = %+v, want same_repo", repository, trigger, got)
			}
		}
	}
}

// TestClassifyGateAnotherRepositoryNameStaysClosed: a literal naming
// another repository is false in the scanned one, for everyone. The job
// stays closed here (MarkInert is what reports it as never running).
func TestClassifyGateAnotherRepositoryNameStaysClosed(t *testing.T) {
	got := ClassifyGate(Job{Name: "build", If: "github.repository == 'upstream/project'"}, nil, "pull_request_target", nil, Environment{}, false, "", ownNameRepository)
	if got.Class != GateMaintainerApproved || got.Reason != "condition" {
		t.Errorf("gate = %+v, want maintainer_approved, condition", got)
	}
}

// TestClassifyGateRepositoryLiteralWithoutThePath: with no project path
// the model cannot tell the repository's own name from another one, so a
// comparison with a literal stays unresolved: unknown on the job that
// carries it, and never a closed job for the one that needs it. Without a
// literal the stand-in still answers the same-repository check.
func TestClassifyGateRepositoryLiteralWithoutThePath(t *testing.T) {
	own := Job{Name: "build", If: "github.repository == 'my-org/my-repo'"}
	got := ClassifyGate(own, nil, "pull_request_target", nil, Environment{}, false, "", "")
	if got.Class != GateUnknown || !reflect.DeepEqual(got.Unknown, []string{"github.repository"}) {
		t.Errorf("own if: gate = %+v, want unknown on github.repository", got)
	}

	after := Job{Name: "after", Needs: []string{"build"}}
	got = ClassifyGate(after, map[string]Job{"build": own, "after": after}, "pull_request_target", nil, Environment{}, false, "", "")
	if got.Class != GateOutsider {
		t.Errorf("needed job: gate = %+v, want outsider", got)
	}

	same := Job{Name: "build", If: "github.event.pull_request.head.repo.full_name == github.repository"}
	got = ClassifyGate(same, nil, "pull_request_target", nil, Environment{}, false, "", "")
	if got.Class != GateSameRepo {
		t.Errorf("same repository: gate = %+v, want same_repo", got)
	}
}

// TestClassifyGateStrongestNeededJobWins pins the second effect of #640:
// a job that needs several jobs closed to the outsider runs only when all
// of them ran, so the strongest of their gates is its own, whatever the
// order of `needs`.
func TestClassifyGateStrongestNeededJobWins(t *testing.T) {
	label := Job{Name: "label", If: "contains(github.event.pull_request.labels.*.name, 'safe to test')"}
	gate := Job{Name: "gate", If: "github.event.pull_request.head.repo.full_name == github.repository"}
	for _, needs := range [][]string{{"label", "gate"}, {"gate", "label"}} {
		build := Job{Name: "build", Needs: needs}
		byName := map[string]Job{"label": label, "gate": gate, "build": build}
		got := ClassifyGate(build, byName, "pull_request_target", nil, Environment{}, false, "", ownNameRepository)
		if got.Class != GateSameRepo || got.Reason != "same repository" {
			t.Errorf("needs %v: gate = %+v, want same_repo", needs, got)
		}
	}

	// The job's own condition counts with the jobs it needs.
	build := Job{Name: "build", Needs: []string{"label"}, If: gate.If}
	got := ClassifyGate(build, map[string]Job{"label": label, "build": build}, "pull_request_target", nil, Environment{}, false, "", ownNameRepository)
	if got.Class != GateSameRepo {
		t.Errorf("own condition: gate = %+v, want same_repo", got)
	}
}

// TestClassifyGateIssue640NeedsOrder is the workflow of #640: `ready`
// carries the repository's own name behind always(), `gate` the
// same-repository check. `ready` closes nothing, so `gate` decides in
// both orders.
func TestClassifyGateIssue640NeedsOrder(t *testing.T) {
	ready := Job{Name: "ready", If: "always() && github.repository == 'my-org/my-repo'"}
	gate := Job{Name: "gate", If: "github.event.workflow_run.head_repository.full_name == github.repository"}
	for _, needs := range [][]string{{"ready", "gate"}, {"gate", "ready"}} {
		build := Job{Name: "build", Needs: needs}
		byName := map[string]Job{"ready": ready, "gate": gate, "build": build}
		got := ClassifyGate(build, byName, "workflow_run", nil, Environment{}, false, "", ownNameRepository)
		if got.Class != GateSameRepo || got.Reason != "same repository" {
			t.Errorf("needs %v: gate = %+v, want same_repo", needs, got)
		}
	}
}

// TestClassifyGateOwnRepositoryOwnerGatesNothing: github.repository_owner
// is the owner of the repository the workflow runs in, the scanned one's
// on a fork pull request too, like github.repository (#640). Comparing
// it with that owner keeps no outsider out.
func TestClassifyGateOwnRepositoryOwnerGatesNothing(t *testing.T) {
	cases := []struct {
		name    string
		trigger string
		cond    string
	}{
		{"pull_request_target", "pull_request_target", "github.repository_owner == 'my-org'"},
		{"workflow_run", "workflow_run", "github.repository_owner == 'my-org'"},
		{"another case of the owner", "pull_request_target", "github.repository_owner == 'My-Org'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyGate(Job{Name: "build", If: tc.cond}, nil, tc.trigger, nil, Environment{}, false, "", ownNameRepository)
			if got.Class != GateOutsider {
				t.Errorf("gate = %+v, want %q", got, GateOutsider)
			}
		})
	}

	// Next to the same-repository check, that check is the gate.
	both := "github.repository_owner == 'my-org' && github.event.pull_request.head.repo.full_name == github.repository"
	got := ClassifyGate(Job{Name: "build", If: both}, nil, "pull_request_target", nil, Environment{}, false, "", ownNameRepository)
	if got.Class != GateSameRepo {
		t.Errorf("with the same-repository check: gate = %+v, want same_repo", got)
	}
}

// TestClassifyGateAnotherRepositoryOwnerStaysClosed: a literal naming
// another owner is false in the scanned repository, for everyone, as a
// literal naming another repository is.
func TestClassifyGateAnotherRepositoryOwnerStaysClosed(t *testing.T) {
	got := ClassifyGate(Job{Name: "build", If: "github.repository_owner == 'upstream'"}, nil, "pull_request_target", nil, Environment{}, false, "", ownNameRepository)
	if got.Class != GateMaintainerApproved || got.Reason != "condition" {
		t.Errorf("gate = %+v, want maintainer_approved, condition", got)
	}
}

// TestClassifyGateRepositoryOwnerLiteralWithoutThePath: with no project
// path the model cannot tell the repository's own owner from another
// one, so a comparison with a literal stays unresolved, on the job that
// carries it and for the one that needs it.
func TestClassifyGateRepositoryOwnerLiteralWithoutThePath(t *testing.T) {
	own := Job{Name: "build", If: "github.repository_owner == 'my-org'"}
	got := ClassifyGate(own, nil, "pull_request_target", nil, Environment{}, false, "", "")
	if got.Class != GateUnknown || !reflect.DeepEqual(got.Unknown, []string{"github.repository_owner"}) {
		t.Errorf("own if: gate = %+v, want unknown on github.repository_owner", got)
	}

	after := Job{Name: "after", Needs: []string{"build"}}
	got = ClassifyGate(after, map[string]Job{"build": own, "after": after}, "pull_request_target", nil, Environment{}, false, "", "")
	if got.Class != GateOutsider {
		t.Errorf("needed job: gate = %+v, want outsider", got)
	}
}

// TestClassifyGateEqualNeededJobsFollowNeedsOrder pins the tie of
// closedGate: among closed jobs of equal strength the first in `needs`
// order names the class and the reason.
func TestClassifyGateEqualNeededJobsFollowNeedsOrder(t *testing.T) {
	jobs := map[string]Job{
		"x":     {Name: "x", If: "contains(github.event.pull_request.labels.*.name, 'x')"},
		"y":     {Name: "y", If: "contains(github.event.pull_request.labels.*.name, 'y')"},
		"same":  {Name: "same", If: "github.event.pull_request.head.repo.full_name == github.repository"},
		"event": {Name: "event", If: "github.event_name == 'push'"},
	}
	cases := []struct {
		needs []string
		class GateClass
		// reason is checked when set.
		reason string
	}{
		{[]string{"x", "y"}, GateMaintainerApproved, "label x"},
		{[]string{"y", "x"}, GateMaintainerApproved, "label y"},
		{[]string{"same", "event"}, GateSameRepo, "same repository"},
		{[]string{"event", "same"}, GateNoOutsider, ""},
	}
	for _, tc := range cases {
		build := Job{Name: "build", Needs: tc.needs}
		byName := map[string]Job{"build": build}
		for _, n := range tc.needs {
			byName[n] = jobs[n]
		}
		got := ClassifyGate(build, byName, "pull_request_target", nil, Environment{}, false, "", ownNameRepository)
		if got.Class != tc.class || (tc.reason != "" && got.Reason != tc.reason) {
			t.Errorf("needs %v: gate = %+v, want %s %q", tc.needs, got, tc.class, tc.reason)
		}
	}
}

// TestClassifyGateBotAuthorHoldsOverAWeakerGate: a gate on a bot as the
// pull request's author lets no outsider in, so among closed jobs it
// holds over a label or an actor gate of the same class, in any order of
// `needs` and when it sits on the job's own `if:`.
func TestClassifyGateBotAuthorHoldsOverAWeakerGate(t *testing.T) {
	const want = "author dependabot[bot]"
	author := Job{Name: "author", If: "github.event.pull_request.user.login == 'dependabot[bot]'"}
	weaker := map[string]Job{
		"actor": {Name: "actor", If: "github.actor == 'dependabot[bot]'"},
		"label": {Name: "label", If: "contains(github.event.pull_request.labels.*.name, 'safe to test')"},
	}
	for name, other := range weaker {
		for _, needs := range [][]string{{name, "author"}, {"author", name}} {
			build := Job{Name: "build", Needs: needs}
			byName := map[string]Job{name: other, "author": author, "build": build}
			got := ClassifyGate(build, byName, "pull_request_target", nil, Environment{}, false, "", ownNameRepository)
			if !got.BotAuthor() || got.Reason != want {
				t.Errorf("needs %v: gate = %+v, want %q", needs, got, want)
			}
		}

		// The needed job comes first in the closed list: the job's own
		// author check still holds.
		build := Job{Name: "build", Needs: []string{name}, If: author.If}
		got := ClassifyGate(build, map[string]Job{name: other, "build": build}, "pull_request_target", nil, Environment{}, false, "", ownNameRepository)
		if !got.BotAuthor() || got.Reason != want {
			t.Errorf("own condition after %s: gate = %+v, want %q", name, got, want)
		}
	}
}

// TestGateBotAuthor pins what counts as the bot-author gate: the pull
// request's author naming a "[bot]" login, never a bot as the actor, a
// person as the author, or another class.
func TestGateBotAuthor(t *testing.T) {
	cases := []struct {
		gate Gate
		want bool
	}{
		{Gate{Class: GateMaintainerApproved, Reason: "author dependabot[bot]"}, true},
		{Gate{Class: GateMaintainerApproved, Reason: "actor dependabot[bot]"}, false},
		{Gate{Class: GateMaintainerApproved, Reason: "author octocat"}, false},
		{Gate{Class: GateMaintainerApproved, Reason: "label safe to test"}, false},
		{Gate{Class: GateOutsider, Reason: "author dependabot[bot]"}, false},
	}
	for _, tc := range cases {
		if got := tc.gate.BotAuthor(); got != tc.want {
			t.Errorf("%+v: BotAuthor = %v, want %v", tc.gate, got, tc.want)
		}
	}
}
