package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/internal/platform"
)

// debugTraceControlConfig is the debug-trace control as a policy declares it.
// The control is a no-op unless forbiddenVariables is populated (see
// policies/debug_trace.rego), and an enabled control with no substantive
// field is marked not_evaluable by MarkUnconfiguredControls - so "enabled"
// alone would evaluate to nothing and prove nothing here.
const debugTraceControlConfig = `{"enabled":true,"forbiddenVariables":["CI_DEBUG_TRACE"]}`

// policyWithTree builds a real resolved policy declaring exactly one control
// with the given stored config, the shape /context serves.
func policyWithTree(name, controlType, config string) platform.Policy {
	pol := treePolicy(name, platform.PolicyControl{
		ControlType: controlType,
		Config:      json.RawMessage(config),
	})
	// treePolicy stamps one shared id; distinct ids here keep the pushed
	// entries distinguishable when several policies are in play.
	pol.ID = "policy-" + name
	return pol
}

// derivedDefaultPolicy is the platform's derived "[Plumber default]"
// placeholder, exactly as /context serves it for an unassigned project: the
// nil uuid, report-only, and no control tree at all. internal/platform has no
// constructor for it - it is served, never built CLI-side - so the literal
// lives here, matching internal/platform's own contract fixtures.
func derivedDefaultPolicy() platform.Policy {
	return platform.Policy{ID: platform.NilUUID, Name: "[Plumber default]", Enforcement: platform.EnforcementReport}
}

// debugTraceResult is a collected GitLab run whose RETAINED IR carries one
// job setting CI_DEBUG_TRACE=true: re-evaluating it under a config that
// enables the debug-trace control produces a finding, and under one that does
// not, none. That contrast is what makes a per-policy verdict observable.
func debugTraceResult() *control.AnalysisResult {
	return &control.AnalysisResult{
		CiValid:     true,
		ProjectPath: "grp/app",
		Pipeline: &ir.NormalizedPipeline{
			Provider:      ir.ProviderGitLab,
			ProjectPath:   "grp/app",
			DefaultBranch: "main",
			Jobs: []ir.Job{{
				Name:       "build",
				OriginFile: ".gitlab-ci.yml",
				Variables:  map[string]string{"CI_DEBUG_TRACE": "true"},
			}},
		},
	}
}

// Two policies with byte-identical control trees share one evaluation and one
// section; a third with a different tree gets its own. Order follows /context.
func TestEvaluatePlatformPolicies_GroupsByFingerprintInContextOrder(t *testing.T) {
	a := policyWithTree("A", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig)
	b := policyWithTree("B", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig)
	c := policyWithTree("C", "pipelineMustNotUseDockerInDocker", `{"enabled":true}`)
	conf := confWithPolicies(t, a, b, c)
	result := debugTraceResult()

	runs := evaluatePlatformPolicies(testProvider(t), conf, result)

	if len(runs) != 2 {
		t.Fatalf("want 2 runs (A+B shared, C alone), got %d", len(runs))
	}
	if runs[0].Names() != "A, B" || runs[1].Names() != "C" {
		t.Fatalf("names: %q / %q", runs[0].Names(), runs[1].Names())
	}
	if !runs[0].Applied || runs[0].Score == nil || runs[0].Result == nil {
		t.Fatalf("shared run must be applied with a scoped result and score: %+v", runs[0])
	}
	if runs[0].Score.Score == "A" {
		t.Fatalf("A+B enable the debug-trace control and the IR carries a finding: score must not be A")
	}
	if runs[1].Score == nil || runs[1].Score.Score != "A" {
		t.Fatalf("C enables only docker-in-docker, no finding: want A, got %+v", runs[1].Score)
	}
}

// R2: a real policy declaring no controls evaluates an empty set: applied,
// zero findings, A/100, and says so.
func TestEvaluatePlatformPolicies_NoControlsDeclared_EvaluatesEmptySet(t *testing.T) {
	p := platform.Policy{ID: "11111111-1111-1111-1111-111111111111", Name: "Empty", Enforcement: platform.EnforcementReport}
	conf := confWithPolicies(t, p)

	runs := evaluatePlatformPolicies(testProvider(t), conf, debugTraceResult())

	if len(runs) != 1 || !runs[0].Applied || runs[0].Reason != reasonNoControls {
		t.Fatalf("want one applied run with the declares-no-controls reason, got %+v", runs)
	}
	if len(runs[0].Result.Findings) != 0 || runs[0].Score.Score != "A" {
		t.Fatalf("empty set must yield no findings and A, got %d findings, %s", len(runs[0].Result.Findings), runs[0].Score.Score)
	}
}

// R3: an unreadable tree is not applied, not scored, and not pushed.
func TestEvaluatePlatformPolicies_UnreadableTree_NotApplied(t *testing.T) {
	bad := policyWithTree("Bad", "pipelineMustNotEnableDebugTrace", `{"enabled": not-json`)
	conf := confWithPolicies(t, bad)

	runs := evaluatePlatformPolicies(testProvider(t), conf, debugTraceResult())

	if len(runs) != 1 || runs[0].Applied || runs[0].Score != nil {
		t.Fatalf("want one un-applied run, got %+v", runs)
	}
	if !strings.HasPrefix(runs[0].Reason, reasonTreeNotApplied) {
		t.Fatalf("reason: %q", runs[0].Reason)
	}
	entries := buildPolicyResults(runs, testProvider(t), conf)
	if len(entries) != 0 {
		t.Fatalf("an un-applied policy must not be pushed, got %d entries", len(entries))
	}
}

// R1: the derived placeholder evaluates the embedded default, never a local
// file.
func TestEvaluatePlatformPolicies_DerivedPlaceholder_UsesEmbeddedDefault(t *testing.T) {
	conf := confWithPolicies(t, derivedDefaultPolicy())
	// A local config that enables NOTHING must not influence the run.
	conf.PlumberConfig = &configuration.PlumberConfig{Version: "2.0"}

	runs := evaluatePlatformPolicies(testProvider(t), conf, debugTraceResult())

	if len(runs) != 1 || !runs[0].Applied || !runs[0].Derived {
		t.Fatalf("want one applied derived run, got %+v", runs)
	}
	if runs[0].Score.Score == "A" {
		t.Fatal("the embedded default enables the debug-trace control, so the finding must count: got A")
	}
}

// R6: no retained IR means nothing can be re-evaluated.
func TestEvaluatePlatformPolicies_NoRetainedPipeline_NotApplied(t *testing.T) {
	a := policyWithTree("A", "pipelineMustNotEnableDebugTrace", debugTraceControlConfig)
	conf := confWithPolicies(t, a)

	runs := evaluatePlatformPolicies(testProvider(t), conf, &control.AnalysisResult{CiValid: true})

	if len(runs) != 1 || runs[0].Applied || runs[0].Reason != reasonNoPipeline {
		t.Fatalf("got %+v", runs)
	}
}

// Standalone mode has no resolved policy set, so there is nothing to
// evaluate per policy: the push takes its own local route instead.
func TestEvaluatePlatformPolicies_StandaloneEvaluatesNothing(t *testing.T) {
	for name, conf := range map[string]*configuration.Configuration{
		"nil conf":        nil,
		"no platform run": {},
		"context fetch failed": {
			PlatformRun: &platform.RunContext{Endpoint: "https://p.example.com"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if runs := evaluatePlatformPolicies(testProvider(t), conf, debugTraceResult()); len(runs) != 0 {
				t.Fatalf("standalone must evaluate no policy run, got %+v", runs)
			}
		})
	}
}
