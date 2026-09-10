package cmd

import (
	"testing"

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
