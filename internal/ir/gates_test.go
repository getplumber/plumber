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
	got := ClassifyGate(job, nil, "pull_request", []string{"labeled"}, Environment{}, false)
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
	got := ClassifyGate(job, nil, "pull_request_target", nil, Environment{}, false)
	if got.Class != GateMaintainerApproved {
		t.Fatalf("Class = %q, want %q", got.Class, GateMaintainerApproved)
	}
	if got.Reason != "author dependabot[bot]" {
		t.Fatalf("Reason = %q, want %q", got.Reason, "author dependabot[bot]")
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
	got := ClassifyGate(job, nil, "workflow_run", nil, Environment{}, false)
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
	got := ClassifyGate(job, nil, "pull_request_target", []string{"opened", "synchronize"}, Environment{}, false)
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
	got := ClassifyGate(deploy, byName, "pull_request_target", nil, Environment{}, false)
	if got.Class != GateMaintainerApproved {
		t.Fatalf("Class = %q, want %q (reason %q)", got.Class, GateMaintainerApproved, got.Reason)
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
	got := ClassifyGate(job, nil, "pull_request", nil, Environment{}, false)
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
	got := ClassifyGate(job, nil, "pull_request_target", nil, env, true)
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
	got := ClassifyGate(job, nil, "pull_request_target", []string{"opened"}, env, false)
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
	got := ClassifyGate(job, nil, "pull_request", nil, Environment{}, false)
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

	got := ClassifyGate(deploy, byName, "pull_request_target", nil, Environment{}, false)
	if got.Class != GateUnknown {
		t.Fatalf("Class = %q, want %q (reason %q, unknown %v)", got.Class, GateUnknown, got.Reason, got.Unknown)
	}
}
