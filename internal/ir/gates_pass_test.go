package ir

import "testing"

// checkoutHeadSha is the actions/checkout step pinned to the pull request
// head commit, the clickhouse-go and Frogbot shapes.
var checkoutHeadSha = Action{Uses: "actions/checkout@v5", With: map[string]any{"ref": "${{ github.event.pull_request.head.sha }}"}}

func githubPipeline(jobs ...Job) *NormalizedPipeline {
	return &NormalizedPipeline{Provider: ProviderGitHub, Jobs: jobs}
}

// TestClassifyGatesStoresTheLabelGate pins the clickhouse-go shape: a
// pull_request_target on types: [labeled] whose job tests the label and
// checks out the head commit is maintainer approved, pinned to the SHA.
func TestClassifyGatesStoresTheLabelGate(t *testing.T) {
	p := githubPipeline(Job{
		Name:         "ci/cloud",
		Triggers:     []string{"pull_request_target"},
		TriggerTypes: map[string][]string{"pull_request_target": {"labeled"}},
		If:           "github.event.label.name == 'tests:run-cloud'",
		Uses:         []Action{checkoutHeadSha},
	})
	ClassifyGates(p)
	g := p.Jobs[0].Gate
	if g == nil || g.Class != GateMaintainerApproved || g.Reason != "label tests:run-cloud" || !g.PinnedSha {
		t.Errorf("gate = %+v", g)
	}
}

// TestClassifyGatesReadsTheJobEnvironment pins the Frogbot shape: the
// environment named by the job, looked up among the repository's
// environments, gates it when its rules require an approval and the rules
// were read.
func TestClassifyGatesReadsTheJobEnvironment(t *testing.T) {
	job := Job{Name: "frogbot/scan", Triggers: []string{"pull_request_target"}, Environment: "frogbot", Uses: []Action{checkoutHeadSha}}
	p := githubPipeline(job)
	p.Environments = []Environment{{Name: "frogbot", Known: true, RequiredReviewers: true}}
	p.EnvironmentsKnown = true
	ClassifyGates(p)
	if g := p.Jobs[0].Gate; g == nil || g.Class != GateMaintainerApproved || g.Reason != "environment frogbot requires reviewers" || !g.PinnedSha {
		t.Errorf("gate = %+v", g)
	}

	// The same environment without a rule protects nothing.
	p = githubPipeline(job)
	p.Environments = []Environment{{Name: "frogbot", Known: true}}
	p.EnvironmentsKnown = true
	ClassifyGates(p)
	if g := p.Jobs[0].Gate; g == nil || g.Class != GateOutsider {
		t.Errorf("gate = %+v", g)
	}
}

// TestClassifyGatesTakesTheWeakestTrigger pins that a job carrying several
// privileged triggers holds the weakest gate among them: one trigger an
// outsider fires on their own makes the job an outsider's.
func TestClassifyGatesTakesTheWeakestTrigger(t *testing.T) {
	p := githubPipeline(Job{
		Name:         "ci/cloud",
		Triggers:     []string{"issue_comment", "pull_request_target"},
		TriggerTypes: map[string][]string{"pull_request_target": {"labeled"}},
	})
	ClassifyGates(p)
	if g := p.Jobs[0].Gate; g == nil || g.Class != GateOutsider {
		t.Errorf("gate = %+v", g)
	}
}

// TestClassifyGatesLeavesUnprivilegedAndGitLabJobsAlone pins that a job
// without a privileged trigger, and every GitLab job, carries no gate.
func TestClassifyGatesLeavesUnprivilegedAndGitLabJobsAlone(t *testing.T) {
	p := githubPipeline(Job{Name: "ci/build", Triggers: []string{"push", "pull_request"}})
	ClassifyGates(p)
	if g := p.Jobs[0].Gate; g != nil {
		t.Errorf("unprivileged gate = %+v", g)
	}
	gl := &NormalizedPipeline{Provider: ProviderGitLab, Jobs: []Job{{Name: "build", Triggers: []string{"pull_request_target"}}}}
	ClassifyGates(gl)
	if g := gl.Jobs[0].Gate; g != nil {
		t.Errorf("GitLab gate = %+v", g)
	}
}

// TestWeakerGate orders the classes from the outsider's side: outsider,
// unknown, maintainer approved, same repository.
func TestWeakerGate(t *testing.T) {
	order := []GateClass{GateOutsider, GateUnknown, GateMaintainerApproved, GateSameRepo}
	for i, a := range order {
		for j, b := range order {
			got := weakerGate(Gate{Class: a}, Gate{Class: b}).Class
			want := a
			if j < i {
				want = b
			}
			if got != want {
				t.Errorf("weakerGate(%s, %s) = %s, want %s", a, b, got, want)
			}
		}
	}
}

// TestClassifyGatesUnmodeledPrivilegedTriggerIsOutsider pins that a
// privileged trigger the condition evaluator does not model (fork,
// gollum) lets an outsider in: a same-repository condition, which no
// fork event ever carries, decides nothing for it.
func TestClassifyGatesUnmodeledPrivilegedTriggerIsOutsider(t *testing.T) {
	p := githubPipeline(Job{
		Name:     "ci/sync",
		Triggers: []string{"fork", "pull_request_target"},
		If:       "github.event.pull_request.head.repo.full_name == github.repository",
	})
	ClassifyGates(p)
	if g := p.Jobs[0].Gate; g == nil || g.Class != GateOutsider {
		t.Errorf("gate = %+v", g)
	}
}

// TestCheckoutPinnedShaNeedsEveryHeadCheckoutPinned pins that a job is
// pinned to the approved head commit only when every checkout of the pull
// request head in it is a commit SHA: one by branch name runs whatever
// was pushed after the approval.
func TestCheckoutPinnedShaNeedsEveryHeadCheckoutPinned(t *testing.T) {
	byRef := Action{Uses: "actions/checkout@v5", With: map[string]any{"ref": "${{ github.event.pull_request.head.ref }}"}}
	base := Action{Uses: "actions/checkout@v5"}
	if checkoutPinnedSha(Job{Uses: []Action{checkoutHeadSha, byRef}}) {
		t.Error("a head.sha and a head.ref checkout read as pinned")
	}
	if !checkoutPinnedSha(Job{Uses: []Action{base, checkoutHeadSha}}) {
		t.Error("a base and a head.sha checkout read as not pinned")
	}
	if checkoutPinnedSha(Job{Uses: []Action{base}}) {
		t.Error("a base checkout alone read as pinned")
	}
}

// issuesOrLabel is a job on issues and on a labeled pull_request_target,
// running on every issue or on a pull request labelled ok.
func issuesOrLabel() Job {
	return Job{
		Name:         "triage/run",
		Triggers:     []string{"issues", "pull_request_target"},
		TriggerTypes: map[string][]string{"pull_request_target": {"labeled"}},
		If:           "github.event_name == 'issues' || github.event.label.name == 'ok'",
	}
}

// TestClassifyGatesCoversEveryOutsiderTrigger pins that the gate covers
// every trigger an outsider can fire that the job carries, not only the
// privileged ones: anyone can open an issue, so the job is an outsider's
// whatever its pull_request_target label says.
func TestClassifyGatesCoversEveryOutsiderTrigger(t *testing.T) {
	p := githubPipeline(issuesOrLabel())
	ClassifyGates(p)
	if g := p.Jobs[0].Gate; g == nil || g.Class != GateOutsider {
		t.Errorf("gate = %+v", g)
	}
}

// TestPullRequestRunHasNoPrivilegeToGate pins that a fork pull_request run,
// which holds no secret and a read-only token, never weakens the gate of
// the job's privileged run: the labelled pull_request_target stays a
// maintainer's.
func TestPullRequestRunHasNoPrivilegeToGate(t *testing.T) {
	p := githubPipeline(Job{
		Name:         "ci/cloud",
		Triggers:     []string{"pull_request", "pull_request_target"},
		TriggerTypes: map[string][]string{"pull_request_target": {"labeled"}},
		If:           "github.event_name == 'pull_request' || github.event.label.name == 'ok'",
	})
	ClassifyGates(p)
	if g := p.Jobs[0].Gate; g == nil || g.Class != GateMaintainerApproved || g.Reason != "label ok" {
		t.Errorf("gate = %+v", g)
	}
}

// TestClassifiedTriggersAreTheUnion pins that the triggers ClassifyGates
// decides a gate for are the privileged ones together with every trigger
// the condition model knows whose run is privileged (all but
// pull_request).
func TestClassifiedTriggersAreTheUnion(t *testing.T) {
	want := map[string]bool{}
	for _, tr := range PrivilegedTriggers {
		want[tr] = true
	}
	for tr := range canonicalOutsiderTypes {
		if tr != "pull_request" {
			want[tr] = true
		}
	}
	got := map[string]bool{}
	for _, tr := range classifiedTriggers {
		if got[tr] {
			t.Errorf("%s listed twice", tr)
		}
		got[tr] = true
	}
	if len(got) != len(want) {
		t.Errorf("classified %v, want %v", classifiedTriggers, want)
	}
	for tr := range want {
		if !got[tr] {
			t.Errorf("%s not classified", tr)
		}
	}
}

// TestLabelReasonIsTheLabelsOwnLiteral pins that the label a gate names is
// the literal its own comparison reads, never one of another clause:
// 'issues' belongs to the event-name test.
func TestLabelReasonIsTheLabelsOwnLiteral(t *testing.T) {
	g := ClassifyGate(issuesOrLabel(), nil, "pull_request_target", []string{"labeled"}, Environment{}, false)
	if g.Class != GateMaintainerApproved || g.Reason != "label ok" {
		t.Errorf("gate = %+v", g)
	}
	other := Job{Name: "x", If: "github.event.label.name == github.event.inputs.wanted"}
	if g := ClassifyGate(other, nil, "pull_request_target", []string{"labeled"}, Environment{}, false); g.Reason != "label" && g.Reason != "types labeled" {
		t.Errorf("label compared to a reference: %+v", g)
	}
}

// IsPRHeadRef and IsPRHeadShaRef read a checkout ref, wrapped or not.
func TestPRHeadRefs(t *testing.T) {
	for ref, want := range map[string][2]bool{
		"${{ github.event.pull_request.head.sha }}":  {true, true},
		"github.event.workflow_run.head_sha":         {true, true},
		"${{ github.event.pull_request.head.ref }}":  {true, false},
		"${{ github.head_ref }}":                     {true, false},
		"refs/pull/${{ github.event.number }}/merge": {true, false},
		"main": {false, false},
	} {
		if got := [2]bool{IsPRHeadRef(ref), IsPRHeadShaRef(ref)}; got != want {
			t.Errorf("%s: %v, want %v", ref, got, want)
		}
	}
}
