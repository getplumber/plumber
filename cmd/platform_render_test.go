package cmd

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/platform"
)

// debugTraceControlConfigWide is a SECOND debug-trace configuration that
// still fires on the fixture's CI_DEBUG_TRACE job but fingerprints
// differently from debugTraceControlConfig, so two policies can each own a
// failing section instead of collapsing into one.
const debugTraceControlConfigWide = `{"enabled":true,"forbiddenVariables":["CI_DEBUG_TRACE","CI_DEBUG_SERVICES"]}`

// captureStdoutAll redirects os.Stdout for the duration of fn and returns
// everything written. The shared captureStdout reads once into a 16 KiB
// buffer, which a full policy section (control blocks plus the score banner)
// overflows and, worse, deadlocks on: the pipe fills while fn is still
// printing. Draining through a goroutine (like captureStderr) is the only
// safe capture for these renderers.
func captureStdoutAll(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	_ = w.Close()
	os.Stdout = old
	return <-done
}

// Spec s3: one section per fingerprint group, in /context order, the header
// listing every policy name in the group, and one score banner per run.
func TestRenderPolicySections_OneSectionPerRun_SharedNamesCollapsed(t *testing.T) {
	a := policyWithTree("A", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig)
	b := policyWithTree("B", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig)
	c := policyWithTree("C", "pipelineMustNotUseDockerInDocker", `{"enabled":true}`)
	c.Enforcement = platform.EnforcementBlock
	eighty := 80
	c.MinPoints = &eighty
	conf := confWithPolicies(t, a, b, c)
	runs := evaluatePlatformPolicies(testProvider(t), conf, debugTraceResult())

	out := captureStdoutAll(t, func() { renderPolicySections(testProvider(t), conf, runs, nil, nil) })

	assertContains(t, out, "== Policy: A, B  [report]")
	assertContains(t, out, "== Policy: C  [block, min_points 80]")
	if strings.Index(out, "== Policy: A, B") > strings.Index(out, "== Policy: C") {
		t.Fatal("sections must follow /context order")
	}
	assertContains(t, out, "Failed Controls (1)") // the debug-trace finding under A, B
	assertContains(t, out, "Plumber Score")       // the per-policy banner
	if strings.Count(out, "Plumber Score") != 2 {
		t.Fatalf("want one banner per run, got %d", strings.Count(out, "Plumber Score"))
	}
}

// R3: a run that was not applied says why and prints no banner - an empty
// verdict would read as a policy that found nothing wrong.
func TestRenderPolicySections_NotAppliedRunSaysWhy(t *testing.T) {
	bad := policyWithTree("Bad", "pipelineMustNotEnableDebugTrace", `{"enabled": not-json`)
	conf := confWithPolicies(t, bad)
	runs := evaluatePlatformPolicies(testProvider(t), conf, debugTraceResult())

	out := captureStdoutAll(t, func() { renderPolicySections(testProvider(t), conf, runs, nil, nil) })

	assertContains(t, out, "== Policy: Bad  [report]")
	assertContains(t, out, "control tree could not be applied")
	assertContains(t, out, "nothing evaluated")
	if strings.Contains(out, "Plumber Score") {
		t.Fatal("an un-applied run must not print a score banner")
	}
}

// R1: the derived placeholder says the platform has no policy for the
// project, so nobody reads "[Plumber default]" as a configured policy.
func TestRenderPolicySections_DerivedSaysWhereTheConfigCameFrom(t *testing.T) {
	conf := confWithPolicies(t, derivedDefaultPolicy())
	runs := evaluatePlatformPolicies(testProvider(t), conf, debugTraceResult())

	out := captureStdoutAll(t, func() { renderPolicySections(testProvider(t), conf, runs, nil, nil) })

	assertContains(t, out, "== Policy: [Plumber default]  [report]")
	assertContains(t, out, "the platform has no policy for this project")
}

// R2: a policy declaring no control is applied and honest about the empty
// set it evaluated.
func TestRenderPolicySections_NoControlsDeclared(t *testing.T) {
	conf := confWithPolicies(t, platform.Policy{
		ID:          "11111111-1111-1111-1111-111111111111",
		Name:        "Empty",
		Enforcement: platform.EnforcementReport,
	})
	runs := evaluatePlatformPolicies(testProvider(t), conf, debugTraceResult())

	out := captureStdoutAll(t, func() { renderPolicySections(testProvider(t), conf, runs, nil, nil) })

	assertContains(t, out, "== Policy: Empty  [report]")
	assertContains(t, out, "declares no controls, nothing evaluated")
	// Row 45: an empty control set evaluated nothing, so no score banner
	// follows the reason line - the same absence R3's un-applied case gets.
	if strings.Contains(out, "Plumber Score") {
		t.Fatalf("a policy declaring no controls must print no score banner, got:\n%s", out)
	}
}

// Row 45: a policy whose only declared control is config_required (#459)
// evaluated nothing real either, even though it is Applied over a real
// config and not the reasonNoControls empty-set case above. Its section
// prints the withheld line rather than a perfect 100/A grade.
func TestRenderPolicySections_Row45AllUnconfiguredPrintsWithheldLine(t *testing.T) {
	unconfigured := policyWithTree("Unconfigured", "pipelineMustNotEnableDebugTrace", `{"enabled":true}`)
	conf := confWithPolicies(t, unconfigured)
	runs := evaluatePlatformPolicies(testProvider(t), conf, debugTraceResult())

	out := captureStdoutAll(t, func() { renderPolicySections(testProvider(t), conf, runs, nil, nil) })

	assertContains(t, out, "== Policy: Unconfigured  [report]")
	assertContains(t, out, "Score withheld: no control was evaluated")
	if strings.Contains(out, "/ 100 pts") {
		t.Fatalf("must not print a graded letter-score badge, got:\n%s", out)
	}
}

// --no-controls is a request for NO verdict, and platform mode does not
// override it: the section prints no control blocks and no score banner, so
// no run that evaluated nothing is stamped with a grade (the safety chain
// documented on providerControlEntries).
func TestRenderPolicySections_NoControlsFlagWithholdsTheVerdict(t *testing.T) {
	a := policyWithTree("A", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig)
	conf := confWithPolicies(t, a)
	conf.NoControls = true
	runs := evaluatePlatformPolicies(testProvider(t), conf, debugTraceResult())

	out := captureStdoutAll(t, func() { renderPolicySections(testProvider(t), conf, runs, nil, nil) })

	assertContains(t, out, "== Policy: A  [report]")
	for _, forbidden := range []string{"Plumber Score", "Failed Controls", "Skipped Controls"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("--no-controls must not render %q, got:\n%s", forbidden, out)
		}
	}
}

// Policies sharing a configuration but differing in enforcement or
// min_points get their bracket per name: one bracket for the group would
// tell the reader the wrong enforcement for half of it.
func TestRenderPolicySections_DifferingEnforcementBracketsPerPolicy(t *testing.T) {
	a := policyWithTree("Soft", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig)
	b := policyWithTree("Hard", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig)
	b.Enforcement = platform.EnforcementBlock
	seventy := 70
	b.MinPoints = &seventy
	conf := confWithPolicies(t, a, b)
	runs := evaluatePlatformPolicies(testProvider(t), conf, debugTraceResult())

	out := captureStdoutAll(t, func() { renderPolicySections(testProvider(t), conf, runs, nil, nil) })

	assertContains(t, out, "== Policy: Soft [report], Hard [block, min_points 70]")
}

// A DEGRADED policy run with no findings: the section says controls could not
// be evaluated and prints NO issues table. An empty table there would read as
// a clean pipeline nobody actually evaluated (#220, the reason the guard on
// the table exists), and the not-evaluated warning is the only disclosure that
// the score below was computed over a subset of the controls.
func TestRenderPolicySections_DegradedRunWarnsAndPrintsNoEmptyIssuesTable(t *testing.T) {
	run := handMadePolicyRun(t, "A", debugTracePolicyYAML, nil)
	run.Result.DataCollectionDegraded = true
	run.Result.MarkNotEvaluable("pipelineMustNotEnableDebugTrace", "policy_lane_unavailable")

	out := captureStdoutAll(t, func() { renderPolicySections(testProvider(t), nil, []policyRun{run}, nil, nil) })

	assertContains(t, out, "control(s) could not be evaluated, the score below is computed over the rest")
	if strings.Contains(out, "none with open issues") {
		t.Fatalf("a degraded run with no findings must print no issues table at all:\n%s", out)
	}
	// The degraded filter drops every group with no findings, so the
	// per-control sections a degraded run cannot vouch for are not rendered as
	// verdicts: the warning above is what the reader gets instead.
	if strings.Contains(out, "Not Evaluated (") {
		t.Fatalf("a degraded run must not render per-control sections built on data it never collected:\n%s", out)
	}
	// #220: no letter grade over incomplete data.
	assertContains(t, out, "Score withheld")
}

// A degraded run WITH findings keeps its issues table: the findings are real,
// and suppressing them would hide what the run did see. Only the empty-table
// case above is suppressed.
func TestRenderPolicySections_DegradedRunWithFindingsKeepsTheIssuesTable(t *testing.T) {
	run := handMadePolicyRun(t, "A", debugTracePolicyYAML, []opaengine.Finding{debugTraceFinding()})
	run.Result.DataCollectionDegraded = true

	out := captureStdoutAll(t, func() { renderPolicySections(testProvider(t), nil, []policyRun{run}, nil, nil) })

	assertContains(t, out, "Failed Controls (1)")
	// The issues table's own header row, printed only when the table is.
	assertContains(t, out, "Codes")
	if strings.Contains(out, "none with open issues") {
		t.Fatalf("this run has findings, the table must list them:\n%s", out)
	}
	assertContains(t, out, "Score withheld")
}

// Spec s3: the verdict block is the platform's, one line per gated policy,
// then the platform's global score, then the exit line.
func TestRenderPlatformVerdict_BlockingAndGlobal(t *testing.T) {
	a := policyWithTree("A", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig)
	c := policyWithTree("Prod", "pipelineMustNotEnableDebugTrace", debugTraceControlConfigWide)
	c.Enforcement = platform.EnforcementBlock
	eighty := 80
	c.MinPoints = &eighty
	runs := evaluatePlatformPolicies(testProvider(t), confWithPolicies(t, a, c), debugTraceResult())
	v := &platformVerdict{
		Gate: &platformGate{Evaluated: true, Blocking: true, Policies: []platformGatePolicy{
			{ID: a.ID, Name: "A", Enforcement: "report", Blocking: false, LiveFailCount: 1},
			{ID: c.ID, Name: "Prod", Enforcement: "block", Blocking: true, LiveFailCount: 0},
		}},
		GlobalScore: &platformScore{Letter: "B", Points: 83},
	}
	gateErr := &PlatformGateError{Reason: "blocked", Policies: v.Gate.Policies[1:]}

	out := captureStdoutAll(t, func() { renderPlatformVerdict(runs, v, gateErr) })

	assertContains(t, out, "== Platform verdict")
	// The exact columns of "  %-*s   %-6s   %s" at width 4 ("Prod"). Prod's
	// own re-evaluated run scores 30 (one Critical, malus applied), which is
	// the figure its section printed: the reason line explains the
	// platform's verdict in the numbers the reader just saw.
	assertContains(t, out, "  A      report   not blocking\n")
	assertContains(t, out, "  Prod   block    BLOCKING (30 < min_points 80)\n")
	assertContains(t, out, "  Global score (platform): B  83 / 100 pts\n")
	assertContains(t, out, "  Exit 1: Prod blocks\n")
}

// A gate that blocks a policy with no min_points reports the platform's
// live-failure count instead of a threshold comparison.
func TestRenderPlatformVerdict_LiveFailuresReasonWithoutMinPoints(t *testing.T) {
	v := &platformVerdict{Gate: &platformGate{Evaluated: true, Blocking: true, Policies: []platformGatePolicy{
		{ID: "p1", Name: "Live", Enforcement: "block", Blocking: true, LiveFailCount: 3},
	}}}

	out := captureStdoutAll(t, func() { renderPlatformVerdict(nil, v, &PlatformGateError{Reason: "blocked"}) })

	assertContains(t, out, "  Live   block    BLOCKING (3 live failures)\n")
	assertContains(t, out, "  Exit 1: Live blocks\n")
}

// Nothing blocking: the block still prints, and it says exit 0 rather than
// leaving the reader to infer it.
func TestRenderPlatformVerdict_NoBlockExitZero(t *testing.T) {
	v := &platformVerdict{Gate: &platformGate{Evaluated: true, Policies: []platformGatePolicy{
		{ID: "p1", Name: "Only", Enforcement: "report"},
	}}}

	out := captureStdoutAll(t, func() { renderPlatformVerdict(nil, v, nil) })

	assertContains(t, out, "  Only   report   not blocking\n")
	assertContains(t, out, "  Exit 0\n")
}

// A gate that blocks the run without marking any single policy blocking (a
// run-level reason, or a shape this CLI predates) must still say WHY: the
// exit line falls back to the gate's own reason rather than printing
// "Exit 1:  blocks" with an empty name list. Same fallback chain the job-log
// line uses (platformGateDetail).
func TestRenderPlatformVerdict_BlockingWithNoBlockingPolicyFallsBackToTheReason(t *testing.T) {
	v := &platformVerdict{Gate: &platformGate{
		Evaluated: true,
		Blocking:  true,
		Reason:    "the project exceeded its live-failure budget",
		Policies:  []platformGatePolicy{{ID: "p1", Name: "Only", Enforcement: "report"}},
	}}

	out := captureStdoutAll(t, func() { renderPlatformVerdict(nil, v, &PlatformGateError{Reason: v.Gate.Reason}) })

	assertContains(t, out, "  Exit 1: the project exceeded its live-failure budget\n")
	if strings.Contains(out, "Exit 1:  blocks") {
		t.Fatal("an empty blocking-policy list must never render as a bare \"Exit 1:  blocks\"")
	}
}

// Invariant 5: no usable gate is fail-open, said in plain words, never a
// silent pass and never a fake verdict.
func TestRenderPlatformVerdict_Unavailable(t *testing.T) {
	out := captureStdoutAll(t, func() {
		renderPlatformVerdict(nil, &platformVerdict{Unavailable: "gate unavailable, letting through"}, nil)
	})

	assertContains(t, out, "Platform verdict: unavailable (gate unavailable, letting through), fail-open, exit 0")
}

// A nil verdict (no push at all) still prints the fail-open line.
func TestRenderPlatformVerdict_NilVerdictIsUnavailable(t *testing.T) {
	out := captureStdoutAll(t, func() { renderPlatformVerdict(nil, nil, nil) })

	assertContains(t, out, "Platform verdict: unavailable (no push), fail-open, exit 0")
}

// Spec s3: zero policies resolved is one honest line, not an empty report.
func TestRenderNothingEvaluated(t *testing.T) {
	rc := &platform.RunContext{
		Endpoint:    "https://platform.example.com",
		ProjectPath: "g/p",
		ContextErr:  errors.New("dial tcp: refused"),
	}

	out := captureStdoutAll(t, func() { renderNothingEvaluated(rc) })

	assertContains(t, out, "  linked to https://platform.example.com: no policy resolved for g/p (dial tcp: refused), nothing evaluated, exit 0")
}

// A reachable platform that assigned nothing is a different fact from an
// unreachable one, and the line must not claim an error that did not happen.
func TestRenderNothingEvaluated_NoAssignment(t *testing.T) {
	rc := &platform.RunContext{Endpoint: "https://platform.example.com", ProjectPath: "g/p"}

	out := captureStdoutAll(t, func() { renderNothingEvaluated(rc) })

	assertContains(t, out, "no policy resolved for g/p (no policy assigned), nothing evaluated, exit 0")
}

// A verdict that never arrived because the token failed is NOT a fail-open.
// maybePushPlatform returns a *PlatformTokenError there, classifyExecError
// exits 2 on it, and a line claiming "fail-open, exit 0" would contradict the
// process's own exit code in the very log the operator reads to diagnose it.
func TestRenderPlatformVerdict_TokenFailureIsNotFailOpen(t *testing.T) {
	out := captureStdoutAll(t, func() {
		renderPlatformVerdict(nil, nil, &PlatformTokenError{Reason: "no CI OIDC id-token available"})
	})

	assertContains(t, out, "Platform verdict: not obtained (platform push: no CI OIDC id-token available)")
	if strings.Contains(out, "fail-open") || strings.Contains(out, "exit 0") {
		t.Fatalf("a run that exits 2 on a token failure must not claim a fail-open exit 0:\n%s", out)
	}
}

// The fail-open line stays exactly as it was whenever nothing failed: an
// unreachable platform, or a 2xx that carried no gate, is the let-through
// invariant 5 requires, in the words the README tells operators to alert on.
func TestRenderPlatformVerdict_UnavailableWithoutAnErrorIsStillFailOpen(t *testing.T) {
	out := captureStdoutAll(t, func() {
		renderPlatformVerdict(nil, &platformVerdict{Unavailable: "gate unavailable, letting through"}, nil)
	})

	assertContains(t, out, "Platform verdict: unavailable (gate unavailable, letting through), fail-open, exit 0")
	if strings.Contains(out, "not obtained") {
		t.Fatalf("nothing failed here, the line must stay the fail-open one:\n%s", out)
	}
}
