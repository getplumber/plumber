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
	got := ClassifyGate(job, nil, "pull_request", []string{"labeled"}, Environment{}, false, "")
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
	got := ClassifyGate(job, nil, "pull_request_target", nil, Environment{}, false, "")
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
	got := ClassifyGate(job, nil, "pull_request_target", nil, Environment{}, false, "")
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
	got := ClassifyGate(job, nil, "workflow_run", nil, Environment{}, false, "")
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
	got := ClassifyGate(job, nil, "pull_request_target", []string{"opened", "synchronize"}, Environment{}, false, "")
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
	got := ClassifyGate(deploy, byName, "pull_request_target", nil, Environment{}, false, "")
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
			got := ClassifyGate(deploy, byName, "pull_request_target", nil, Environment{}, false, "")
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
// own condition decides, the predecessor adding nothing but unknown.
func TestClassifyGateStatusFunctionOutlivesTheNeedsChain(t *testing.T) {
	check := Job{Name: "check", If: "github.event.pull_request.head.repo.full_name == github.repository"}
	cases := []struct {
		name, cond string
		want       GateClass
	}{
		{"always() alone is unknown", "always()", GateUnknown},
		{"always() or an event the outsider produces is outsider", "always() || github.event_name == 'pull_request_target'", GateOutsider},
		{"not failure and not cancelled is unknown", "!failure() && !cancelled()", GateUnknown},
		{"a negated success() is unknown", "!success()", GateUnknown},
		{"a plain condition still inherits the predecessor's gate", "github.event_name == 'pull_request_target'", GateSameRepo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deploy := Job{Name: "deploy", If: tc.cond, Needs: []string{"check"}}
			byName := map[string]Job{"check": check, "deploy": deploy}
			got := ClassifyGate(deploy, byName, "pull_request_target", nil, Environment{}, false, "")
			if got.Class != tc.want {
				t.Fatalf("gate = %+v, want %s", got, tc.want)
			}
		})
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
			got := ClassifyGate(Job{Name: "j"}, nil, tc.trigger, []string{tc.typ}, Environment{}, false, "")
			if got.Class != tc.want {
				t.Fatalf("gate = %+v, want %s", got, tc.want)
			}
		})
	}
	// A maintainer type next to an unknown one is unknown, never a gate.
	got := ClassifyGate(Job{Name: "j"}, nil, "pull_request_target", []string{"labeled", "some_future_type"}, Environment{}, false, "")
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
	got := ClassifyGate(job, nil, "pull_request", nil, Environment{}, false, "")
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
	got := ClassifyGate(job, nil, "pull_request_target", nil, env, true, "")
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
	got := ClassifyGate(job, nil, "pull_request_target", []string{"opened"}, env, false, "")
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
	got := ClassifyGate(job, nil, "pull_request", nil, Environment{}, false, "")
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

	got := ClassifyGate(deploy, byName, "pull_request_target", nil, Environment{}, false, "")
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
			got := ClassifyGate(Job{Name: "j", If: tc.cond}, nil, "pull_request_target", nil, Environment{}, false, "")
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
		got := ClassifyGate(job, nil, "pull_request_target", nil, Environment{}, false, "")
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
	got := ClassifyGate(deploy, byName, "pull_request_target", nil, Environment{}, false, "")
	if got.Class != GateUnknown {
		t.Fatalf("Class = %q, want %q (reason %q)", got.Class, GateUnknown, got.Reason)
	}
}
