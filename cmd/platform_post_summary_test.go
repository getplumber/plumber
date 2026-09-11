package cmd

import (
	"errors"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/internal/platform"
	providerPkg "github.com/getplumber/plumber/provider"
	"github.com/spf13/cobra"
)

// This file covers the step between the platform's answer and what the badge
// and the merge-request comment say: platformPostSummary and its
// blockingPolicyKeys helper. The control-layer tests build a
// PlatformPostSummary by hand and assert the RENDERING; the translation from
// the real runs plus the real gate response is what is asserted here, and a
// wrong Blocking flag here is published in a comment posted with Plumber's
// identity (spec s5).

// scoredRun is an applied run of one policy with the given letter and final
// points, the shape the mapping reads.
func scoredRun(name, id, enforcement, letter string, finalPoints float64) policyRun {
	return policyRun{
		Policies: []platform.Policy{{ID: id, Name: name, Enforcement: platform.Enforcement(enforcement)}},
		Score:    &control.PlumberScoreResult{Score: letter, FinalPoints: finalPoints},
		Applied:  true,
	}
}

// unappliedRun is a policy the CLI evaluated nothing for: no score at all, a
// reason instead. Its line must carry no letter and no points rather than a
// zero that reads as a verdict.
func unappliedRun(name, id, reason string) policyRun {
	return policyRun{
		Policies: []platform.Policy{{ID: id, Name: name, Enforcement: platform.EnforcementReport}},
		Applied:  false,
		Reason:   reason,
	}
}

func TestPlatformPostSummary_MapsTheRunsAndTheGate(t *testing.T) {
	runs := []policyRun{
		// 66.6 ROUNDS to 67, the same rounding the push applies, so the badge,
		// the comment and the pushed record cannot disagree by a point.
		scoredRun("Prod", "id-prod", "block", "C", 66.6),
		unappliedRun("Later", "id-later", "no control enabled"),
	}
	verdict := &platformVerdict{
		Gate: &platformGate{Evaluated: true, Blocking: true, Policies: []platformGatePolicy{
			{ID: "id-prod", Name: "Prod", Enforcement: "block", Blocking: true, LiveFailCount: 2},
			{ID: "id-later", Name: "Later", Enforcement: "report", Blocking: false},
		}},
		GlobalScore: &platformScore{Letter: "B", Points: 83},
	}

	got := platformPostSummary(runs, verdict)

	if !got.HasGlobal || got.GlobalLetter != "B" || got.GlobalPoints != 83 {
		t.Errorf("the global score is the platform's own: HasGlobal=%v letter=%q points=%d",
			got.HasGlobal, got.GlobalLetter, got.GlobalPoints)
	}
	want := []control.PlatformPolicyLine{
		{Name: "Prod", Enforcement: "block", Letter: "C", FinalPoints: 67, Blocking: true},
		{Name: "Later", Enforcement: "report", Letter: "", FinalPoints: 0, Blocking: false},
	}
	if len(got.Policies) != len(want) {
		t.Fatalf("one line per resolved policy, got %#v", got.Policies)
	}
	for i, w := range want {
		if got.Policies[i] != w {
			t.Errorf("policy line %d = %#v, want %#v", i, got.Policies[i], w)
		}
	}
}

// The derived "[Plumber default]" placeholder carries the nil uuid and the
// gate has no id for it, so the name is the only handle. Dropping the
// name-keyed fallback would render a policy the platform blocks as
// "Blocking: no".
func TestPlatformPostSummary_DerivedPlaceholderIsMatchedByName(t *testing.T) {
	runs := []policyRun{{
		Policies: []platform.Policy{{ID: platform.NilUUID, Name: "[Plumber default]", Enforcement: platform.EnforcementReport}},
		Score:    &control.PlumberScoreResult{Score: "A", FinalPoints: 95},
		Applied:  true,
	}}
	verdict := &platformVerdict{Gate: &platformGate{Evaluated: true, Blocking: true, Policies: []platformGatePolicy{
		{Name: "[Plumber default]", Enforcement: "report", Blocking: true, LiveFailCount: 1},
	}}}

	got := platformPostSummary(runs, verdict)

	if len(got.Policies) != 1 || !got.Policies[0].Blocking {
		t.Fatalf("the placeholder is blocked by name, the only handle the gate gives it: %#v", got.Policies)
	}
}

// A run whose policy shares a name with a DIFFERENT gate id, and vice versa,
// must not borrow the other's answer: the two prefixes keep an id from ever
// matching a name.
func TestPlatformPostSummary_IdAndNameNamespacesDoNotCross(t *testing.T) {
	runs := []policyRun{scoredRun("Prod", "id-prod", "block", "C", 66)}
	verdict := &platformVerdict{Gate: &platformGate{Evaluated: true, Blocking: true, Policies: []platformGatePolicy{
		// A blocking gate entry whose ID happens to be the run policy's NAME.
		{ID: "Prod", Name: "id-prod", Enforcement: "block", Blocking: true},
	}}}

	got := platformPostSummary(runs, verdict)

	if got.Policies[0].Blocking {
		t.Errorf("an id must never match a name: %#v", got.Policies[0])
	}
}

func TestPlatformPostSummary_NoVerdictAndNoGate(t *testing.T) {
	runs := []policyRun{scoredRun("Prod", "id-prod", "block", "C", 66)}

	t.Run("a nil verdict has no global score and blocks nothing", func(t *testing.T) {
		got := platformPostSummary(runs, nil)
		if got.HasGlobal || got.GlobalLetter != "" || got.GlobalPoints != 0 {
			t.Errorf("no push answer is no score, never a locally computed one: %#v", got)
		}
		if len(got.Policies) != 1 || got.Policies[0].Blocking {
			t.Errorf("nothing may be reported as blocking without a gate: %#v", got.Policies)
		}
	})

	t.Run("a fail-open verdict still publishes the global score it carried", func(t *testing.T) {
		got := platformPostSummary(runs, &platformVerdict{
			GlobalScore: &platformScore{Letter: "B", Points: 83},
			Unavailable: platformGateNoVerdictLine,
		})
		if !got.HasGlobal || got.GlobalLetter != "B" {
			t.Errorf("the gate is missing, the score the platform sent is not: %#v", got)
		}
		if got.Policies[0].Blocking {
			t.Errorf("no gate means nothing blocks: %#v", got.Policies[0])
		}
	})

	// The letter is passed through verbatim, NOT sanitized here: whether it
	// may be published is answered once for the badge and the comment by
	// control.hasPublishableGlobal (the closed A-E set), which is where
	// control/platform_post_test.go asserts it. This is the record that the
	// mapping does not silently drop or rewrite what the platform sent.
	t.Run("an out-of-set letter reaches the summary unchanged", func(t *testing.T) {
		got := platformPostSummary(runs, &platformVerdict{
			GlobalScore: &platformScore{Letter: "A)](https://elsewhere", Points: 83},
		})
		if !got.HasGlobal || got.GlobalLetter != "A)](https://elsewhere" {
			t.Errorf("the mapping reports what the platform sent: %#v", got)
		}
	})
}

func TestBlockingPolicyKeys(t *testing.T) {
	t.Run("only the blocking entries, indexed by id AND by name", func(t *testing.T) {
		keys := blockingPolicyKeys(&platformVerdict{Gate: &platformGate{Policies: []platformGatePolicy{
			{ID: "id-prod", Name: "Prod", Blocking: true},
			{ID: "id-a", Name: "A", Blocking: false},
			{Name: "[Plumber default]", Blocking: true},
			{ID: "id-empty-name", Blocking: true},
		}}})
		want := map[string]bool{
			"id:id-prod":             true,
			"name:Prod":              true,
			"name:[Plumber default]": true,
			"id:id-empty-name":       true,
		}
		if len(keys) != len(want) {
			t.Fatalf("keys = %#v, want %#v", keys, want)
		}
		for k := range want {
			if !keys[k] {
				t.Errorf("missing key %q: %#v", k, keys)
			}
		}
	})

	for _, tc := range []struct {
		name string
		v    *platformVerdict
	}{
		{"a nil verdict", nil},
		{"a verdict with no gate", &platformVerdict{Unavailable: platformGateNoVerdictLine}},
	} {
		t.Run(tc.name+" indexes nothing", func(t *testing.T) {
			if keys := blockingPolicyKeys(tc.v); len(keys) != 0 {
				t.Errorf("keys = %#v, want empty", keys)
			}
		})
	}
}

// postActionsRecorder is the real provider with PostAnalysisActions replaced
// by a capture, so a flow test can assert what runPostActions actually handed
// the badge and the merge-request comment. Every other method is the real
// provider's, so the evaluation, the push and the verdict are production's.
type postActionsRecorder struct {
	providerPkg.Provider
	got    *providerPkg.PostActionSummary
	called *bool
}

func (r postActionsRecorder) PostAnalysisActions(_ *cobra.Command, _ *control.AnalysisResult, _ *configuration.Configuration, s providerPkg.PostActionSummary) error {
	*r.got = s
	*r.called = true
	return nil
}

// The whole pas.Platform wiring end to end. Every other platform-mode flow
// test drives the pipeline with cmd == nil, which returns from runPostActions
// before its platform branch, so this is the only test where the badge and
// the comment's actual input is produced by the production path.
func TestPlatformFlow_PostActionsReceiveThePlatformVerdict(t *testing.T) {
	cmd := newGateFlagsCmd(t)
	origPrint := printOutput
	printOutput = false
	defer func() { printOutput = origPrint }()

	a := policyWithTree("A", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig)
	prod := policyWithTree("Prod", "pipelineMustNotUseDockerInDocker", `{"enabled":true}`)
	prod.Enforcement = platform.EnforcementBlock
	conf := confWithPolicies(t, a, prod)

	var pushed []byte
	srv := pushServer(t, 200, `{"gate":{"evaluated":true,"blocking":true,"policies":[`+
		`{"id":"`+a.ID+`","name":"A","enforcement":"report","blocking":false,"live_fail_count":1},`+
		`{"id":"`+prod.ID+`","name":"Prod","enforcement":"block","blocking":true,"live_fail_count":0}]},`+
		`"global_score":{"letter":"B","points":83}}`, &pushed)
	defer srv.Close()
	restore := withPlatformTestEnv(t, srv.URL, "tok")
	defer restore()

	var got providerPkg.PostActionSummary
	called := false
	rec := postActionsRecorder{Provider: testProvider(t), got: &got, called: &called}

	var err error
	_ = captureStderr(t, func() {
		err = presentResultWithProvider(rec, cmd, debugTraceResult(), conf)
	})
	var gateErr *PlatformGateError
	if !errors.As(err, &gateErr) {
		t.Fatalf("exit must be the platform's blocking verdict, got %v", err)
	}
	if !called {
		t.Fatal("the post actions must run: with cmd nil the platform branch is never reached")
	}
	if got.Platform == nil {
		t.Fatal("a platform-mode run hands the post actions the platform's summary")
	}
	if got.Passed {
		t.Error("Passed is the platform's gate answer, and this gate blocks")
	}
	if got.Score != nil {
		t.Errorf("there is no run-level score in platform mode, got %#v", got.Score)
	}
	if !got.Platform.HasGlobal || got.Platform.GlobalLetter != "B" || got.Platform.GlobalPoints != 83 {
		t.Errorf("the headline is the platform's global score: %#v", got.Platform)
	}
	if len(got.Platform.Policies) != 2 {
		t.Fatalf("one line per resolved policy: %#v", got.Platform.Policies)
	}
	byName := map[string]control.PlatformPolicyLine{}
	for _, line := range got.Platform.Policies {
		byName[line.Name] = line
	}
	if line := byName["Prod"]; !line.Blocking || line.Enforcement != "block" {
		t.Errorf("Prod is the policy the platform blocks: %#v", line)
	}
	if line := byName["A"]; line.Blocking || line.Enforcement != "report" {
		t.Errorf("A is reported, not blocking: %#v", line)
	}
}
