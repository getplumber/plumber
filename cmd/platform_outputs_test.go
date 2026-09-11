package cmd

import (
	"reflect"
	"testing"

	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// twoPolicyRuns evaluates the same collected pipeline under two DIFFERENT
// control configurations that both catch the CI_DEBUG_TRACE job: two runs
// (distinct fingerprints, so no grouping) reporting one and the same finding.
// That overlap is what the union has to collapse.
func twoPolicyRuns(t *testing.T) []policyRun {
	t.Helper()
	a := policyWithTree("A", "pipelineMustNotEnableDebugTrace", `{"enabled":true,"forbiddenVariables":["CI_DEBUG_TRACE"]}`)
	b := policyWithTree("B", "pipelineMustNotEnableDebugTrace", `{"enabled":true,"forbiddenVariables":["CI_DEBUG_TRACE","OTHER"]}`)
	conf := confWithPolicies(t, a, b)
	runs := evaluatePlatformPolicies(testProvider(t), conf, debugTraceResult())
	if len(runs) != 2 {
		t.Fatalf("want two runs (two distinct control configurations), got %d", len(runs))
	}
	return runs
}

// Spec s5: the security reports of a platform-mode run carry the UNION of
// every applied run's findings, deduplicated by fingerprint. One alert per
// finding whatever number of policies cover it: a dashboard must not show the
// same finding twice because two policies enable the same control.
func TestPlatformUnionResult_DedupsByFingerprintAndNamesThePolicies(t *testing.T) {
	runs := twoPolicyRuns(t)
	base := debugTraceResult()
	base.Warnings = []string{"could not verify"}

	union := platformUnionResult(base, runs)

	if len(union.Findings) != 1 {
		t.Fatalf("the same finding under two policies is ONE union entry, got %d", len(union.Findings))
	}
	got := union.Findings[0].Policies
	if len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Fatalf("policies on the union finding = %#v, want [A B] in /context order", got)
	}
	if union.Findings[0].Fingerprint == "" {
		t.Error("the union is keyed on the fingerprint, so the entry must carry it")
	}
	// The run-level facts the writers report beside the findings (warnings,
	// degradation, the analyzed commit) are the run's, not a policy's.
	if len(union.Warnings) != 1 {
		t.Errorf("the union keeps the run's warnings, got %#v", union.Warnings)
	}
	// The collected result must not be mutated: it is what the JSON report
	// and the PBOM are still written from.
	if len(base.Findings) != 0 {
		t.Errorf("the collected result was mutated: %#v", base.Findings)
	}
}

// A finding no policy reported is not in the union: platform mode publishes
// what the platform's policies found, never a local-configuration finding.
func TestPlatformUnionResult_OnlyThePoliciesFindings(t *testing.T) {
	runs := twoPolicyRuns(t)
	base := debugTraceResult()
	base.Findings = []opaengine.Finding{{Code: "ISSUE-999", Message: "local only", Fingerprint: "local"}}

	union := platformUnionResult(base, runs)

	for _, f := range union.Findings {
		if f.Code == "ISSUE-999" {
			t.Fatalf("a local-configuration finding reached the platform-mode report: %#v", f)
		}
	}
}

// Spec s5 for SARIF: each result names the policies that reported it.
func TestBuildSARIF_PlatformMode_ResultCarriesPolicyNames(t *testing.T) {
	union := platformUnionResult(debugTraceResult(), twoPolicyRuns(t))

	doc := buildSARIF(union.Findings, ".plumber.yaml", "gitlab")

	if len(doc.Runs[0].Results) != 1 {
		t.Fatalf("results = %d, want 1", len(doc.Runs[0].Results))
	}
	got, _ := doc.Runs[0].Results[0].Properties["policies"].([]string)
	if len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Fatalf("properties.policies = %#v, want [A B]", doc.Runs[0].Results[0].Properties["policies"])
	}
}

// A standalone run's results carry no policies property: there are no
// policies, and an empty array would read as "no policy covers this".
func TestBuildSARIF_StandaloneCarriesNoPoliciesProperty(t *testing.T) {
	doc := buildSARIF([]opaengine.Finding{
		{Code: "ISSUE-701", Severity: "high", Message: "unpinned", File: "ci.yml", Line: 3},
	}, ".plumber.yaml", "github")

	if _, present := doc.Runs[0].Results[0].Properties["policies"]; present {
		t.Errorf("policies property present outside platform mode: %#v", doc.Runs[0].Results[0].Properties)
	}
}

// Spec s5 for the GitLab SAST report: the schema has no free-form per-finding
// bag, but `identifiers` is an open list, so each policy rides there as its
// own identifier. The primary identifier (the issue code, which GitLab dedups
// on) stays first and untouched.
func TestBuildGLSAST_PlatformMode_PolicyIdentifiers(t *testing.T) {
	union := platformUnionResult(debugTraceResult(), twoPolicyRuns(t))

	rep := buildGLSAST(union.Findings, "gitlab")

	if len(rep.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %d, want 1", len(rep.Vulnerabilities))
	}
	v := rep.Vulnerabilities[0]
	if v.Identifiers[0].Type != "plumber" {
		t.Fatalf("the primary identifier must stay the issue code: %#v", v.Identifiers[0])
	}
	var policies []string
	for _, id := range v.Identifiers {
		if id.Type == "plumber_policy" {
			policies = append(policies, id.Value)
		}
	}
	if len(policies) != 2 || policies[0] != "A" || policies[1] != "B" {
		t.Fatalf("plumber_policy identifiers = %#v, want [A B]", policies)
	}
}

// A standalone report gains no policy identifier.
func TestBuildGLSAST_StandaloneCarriesNoPolicyIdentifier(t *testing.T) {
	rep := buildGLSAST([]opaengine.Finding{
		{Code: "ISSUE-701", Severity: "high", Message: "x", File: "ci.yml", Line: 5},
	}, "github")

	for _, id := range rep.Vulnerabilities[0].Identifiers {
		if id.Type == "plumber_policy" {
			t.Errorf("policy identifier present outside platform mode: %#v", id)
		}
	}
}

// Review comment 3985437498: outputControlEntries keys its per-control
// policy map on e.ControlName and APPENDS every applied run's names to it, so
// a control two DIFFERENT runs both enable must end up naming both, in
// /context order, while a control only one of them enables names only that
// one. Every other test reaching this function used a single run; this pins
// the accumulation directly rather than through the OCSF/CSV writers.
func TestOutputControlEntries_TwoRunsShareOneControl(t *testing.T) {
	const debugTraceOnlyYAML = `version: "2.0"
gitlab:
  controls:
    pipelineMustNotEnableDebugTrace:
      enabled: true
      forbiddenVariables: ["CI_DEBUG_TRACE"]
`
	const debugTraceAndDinDYAML = `version: "2.0"
gitlab:
  controls:
    pipelineMustNotEnableDebugTrace:
      enabled: true
      forbiddenVariables: ["CI_DEBUG_TRACE"]
    pipelineMustNotUseDockerInDocker:
      enabled: true
`
	runA := handMadePolicyRun(t, "A", debugTraceOnlyYAML, nil)
	runB := handMadePolicyRun(t, "B", debugTraceAndDinDYAML, nil)

	_, policies := outputControlEntries(testProvider(t), nil, []policyRun{runA, runB})

	if got := policies["pipelineMustNotEnableDebugTrace"]; len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Fatalf("a control both runs enable must name both policies in /context order, got %#v", got)
	}
	if got := policies["pipelineMustNotUseDockerInDocker"]; len(got) != 1 || got[0] != "B" {
		t.Fatalf("a control only one run enables must name only that one, got %#v", got)
	}
}

// appendMissing is the primitive outputControlEntries and platformUnionResult
// both build their per-control/per-finding policy lists on: append the names
// not already present, dedup, and keep order.
func TestAppendMissing(t *testing.T) {
	if got := appendMissing([]string{"A"}, []string{"B", "A", "C"}); !reflect.DeepEqual(got, []string{"A", "B", "C"}) {
		t.Fatalf("appendMissing = %#v, want [A B C]", got)
	}
	if got := appendMissing(nil, []string{"X", "X"}); !reflect.DeepEqual(got, []string{"X"}) {
		t.Fatalf("appendMissing must dedup within the incoming names too, got %#v", got)
	}
	if got := appendMissing(nil, nil); len(got) != 0 {
		t.Fatalf("appendMissing(nil, nil) must stay empty, got %#v", got)
	}
}

// The union's NotEvaluable field directly: the collected result's local marks
// are replaced by the applied runs' own, one entry per marked control, and the
// first run to mark a control owns the reason (any run's mark is enough for
// the control never to read as a clean pass).
func TestPlatformUnionResult_NotEvaluableIsTheRunsOwnMarks(t *testing.T) {
	first := handMadePolicyRun(t, "A", debugTracePolicyYAML, nil)
	first.Result.MarkNotEvaluable("pipelineMustNotEnableDebugTrace", "policy_lane_unavailable")
	second := handMadePolicyRun(t, "B", dockerInDockerPolicyYAML, nil)
	second.Result.MarkNotEvaluable("pipelineMustNotEnableDebugTrace", "a_second_reason")
	skipped := handMadePolicyRun(t, "C", debugTracePolicyYAML, nil)
	skipped.Result.MarkNotEvaluable("neverAppliedControl", "an_un_applied_run_marks_nothing")
	skipped.Applied = false
	base := &control.AnalysisResult{CiValid: true}
	base.MarkNotEvaluable("pipelineMustNotUseDockerInDocker", "local_mark_must_not_appear")

	union := platformUnionResult(base, []policyRun{first, second, skipped})

	if _, leaked := union.NotEvaluable["pipelineMustNotUseDockerInDocker"]; leaked {
		t.Errorf("the collected result's LOCAL mark must not survive into the union: %#v", union.NotEvaluable)
	}
	if got := union.NotEvaluable["pipelineMustNotEnableDebugTrace"]; got != "policy_lane_unavailable" {
		t.Errorf("the first applied run to mark a control owns the reason, got %q", got)
	}
	if _, present := union.NotEvaluable["neverAppliedControl"]; present {
		t.Errorf("an un-applied run evaluated nothing and marks nothing: %#v", union.NotEvaluable)
	}
	// The collected result is copied, never mutated: it is still what the JSON
	// report and the PBOM are written from.
	if base.NotEvaluable["pipelineMustNotUseDockerInDocker"] != "local_mark_must_not_appear" {
		t.Errorf("the collected result was mutated: %#v", base.NotEvaluable)
	}
}
