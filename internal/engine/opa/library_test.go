package opa

import (
	"context"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// TestLibraryModulesAreCompiledWithTheRulesThatImportThem pins spec
// 2026-10-16 section 5: one shared provenance helper, importable by every
// rule, and a rule that does not import it still evaluates (it is compiled
// without the library).
func TestLibraryModulesAreCompiledWithTheRulesThatImportThem(t *testing.T) {
	e := New()
	e.LoadModule("plain", "package plain\n\nimport rego.v1\n\ndeny contains {\"code\": \"ISSUE-702\", \"message\": \"plain\"} if count(input.pipeline.jobs) > 0\n")
	e.LoadModule("libuser", "package libuser\n\nimport rego.v1\nimport data.lib.provenance\n\ndeny contains f if {\n\tsome job in input.pipeline.jobs\n\tsome use in job.uses\n\tf := object.union({\"code\": \"ISSUE-701\", \"message\": provenance.message(\"m \\u2014 fix\", use), \"job\": job.name}, provenance.fields(use))\n}\n")
	p := &ir.NormalizedPipeline{Jobs: []ir.Job{{Name: "ci/build", Uses: []ir.Action{
		{Uses: "a/b@v1", Line: 3},
		{Uses: "c/d@main", Line: 3, Nested: true, Via: []string{"a/b@v1"}, DefinedIn: "a/b@v1:action.yml:7"},
	}}}}
	fs, failed, err := e.EvaluateModules(context.Background(), p, nil)
	if err != nil || len(failed) != 0 {
		t.Fatalf("evaluate: %v %v", err, failed)
	}
	byMessage := map[string]Finding{}
	for _, f := range fs {
		byMessage[f.Message] = f
	}
	if _, ok := byMessage["m \u2014 fix"]; !ok {
		t.Errorf("a direct entry's message is unchanged, got %v", byMessage)
	}
	nested, ok := byMessage["m, pulled in via a/b@v1 \u2014 fix"]
	if !ok {
		t.Fatalf("the clause goes before the consequence dash, got %v", byMessage)
	}
	if nested.Data["definedIn"] != "a/b@v1:action.yml:7" || nested.Data["nested"] != true {
		t.Errorf("the nested finding carries its provenance, got %v", nested.Data)
	}
	if _, ok := byMessage["plain"]; !ok {
		t.Errorf("a rule that does not import the library still evaluates, got %v", byMessage)
	}
}

// TestCompiledQueriesFollowTheModuleSource pins that the compiled-query
// cache is keyed by the module source as well as its name: a module
// reloaded under the same name with another source answers with the new
// source, never a stale compile.
func TestCompiledQueriesFollowTheModuleSource(t *testing.T) {
	p := &ir.NormalizedPipeline{Jobs: []ir.Job{{Name: "ci/build"}}}
	for _, code := range []string{"ISSUE-101", "ISSUE-102"} {
		e := New()
		e.LoadModule("reloaded", "package reloaded\n\nimport rego.v1\n\ndeny contains {\"code\": \""+code+"\", \"message\": \"m\"} if count(input.pipeline.jobs) > 0\n")
		fs, failed, err := e.EvaluateModules(context.Background(), p, nil)
		if err != nil || len(failed) != 0 {
			t.Fatalf("evaluate: %v %v", err, failed)
		}
		if len(fs) != 1 || fs[0].Code != code {
			t.Errorf("the reloaded module answers with its own source %s, got %v", code, fs)
		}
	}
}
