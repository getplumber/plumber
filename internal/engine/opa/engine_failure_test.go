package opa

import (
	"context"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

const healthyModule = `package healthy
import rego.v1
deny contains {"code": "ISSUE-101", "severity": "low", "message": "healthy finding", "job": "build"} if { true }
`

// conflictingModule trips eval_conflict_error: a complete function with two
// bodies producing different outputs for the same input, the shape #489
// hit in artipacked.
const conflictingModule = `package broken
import rego.v1
pick(x) := 1 if { x == x }
pick(x) := 2 if { x == x }
deny contains {"code": "ISSUE-102", "severity": "low", "message": "never", "job": "build"} if { pick(1) == 1 }
`

// TestEvaluateModules_IsolatesFailingModule is the #489 engine guard: one
// module that fails to evaluate must not take the findings of every other
// module with it. The healthy module's findings come back and the failure is
// reported by module name.
func TestEvaluateModules_IsolatesFailingModule(t *testing.T) {
	engine := New()
	engine.LoadModule("healthy", healthyModule)
	engine.LoadModule("broken", conflictingModule)
	pipeline := &ir.NormalizedPipeline{Jobs: []ir.Job{{Name: "build"}}}

	findings, failed, err := engine.EvaluateModules(context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("a module failure is not an engine error: %v", err)
	}
	if len(findings) != 1 || findings[0].Code != "ISSUE-101" {
		t.Fatalf("the healthy module's findings must survive, got %+v", findings)
	}
	if len(failed) != 1 || failed[0].Module != "broken" {
		t.Fatalf("want exactly the broken module reported, got %+v", failed)
	}
	if failed[0].Err == nil || !strings.Contains(failed[0].Err.Error(), "eval_conflict_error") {
		t.Fatalf("the failure must carry the engine's own error, got %v", failed[0].Err)
	}
}

// TestEvaluateStrict_FailsOnAnyModule pins the test suites' own contract:
// any module failure is an error naming the module, so a suite asserting a
// clean evaluation keeps catching a broken policy.
func TestEvaluateStrict_FailsOnAnyModule(t *testing.T) {
	engine := New()
	engine.LoadModule("healthy", healthyModule)
	engine.LoadModule("broken", conflictingModule)
	pipeline := &ir.NormalizedPipeline{Jobs: []ir.Job{{Name: "build"}}}

	if _, err := evaluateStrict(engine, context.Background(), pipeline, nil); err == nil || !strings.Contains(err.Error(), `module "broken"`) {
		t.Fatalf("evaluateStrict must fail naming the broken module, got %v", err)
	}
}
