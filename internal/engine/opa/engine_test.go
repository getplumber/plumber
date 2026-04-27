package opa

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/getplumber/plumber/internal/ir"
)

func TestEvaluateNoModules(t *testing.T) {
	engine := New()
	pipeline := &ir.NormalizedPipeline{Provider: ir.ProviderGitLab}

	findings, err := engine.Evaluate(context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestEvaluateToyPolicy(t *testing.T) {
	const module = `package toy

deny contains finding if {
	input.pipeline.provider == "gitlab"
	finding := {
		"code": "TOY-001",
		"severity": "low",
		"message": "gitlab pipeline detected",
	}
}`

	engine := New()
	engine.LoadModule("toy", module)

	pipeline := &ir.NormalizedPipeline{Provider: ir.ProviderGitLab}
	findings, err := engine.Evaluate(context.Background(), pipeline, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	got := findings[0]
	if got.Code != "TOY-001" {
		t.Fatalf("expected code TOY-001, got %q", got.Code)
	}
	if got.Severity != "low" {
		t.Fatalf("expected severity low, got %q", got.Severity)
	}
}

func TestEvaluateNilPipeline(t *testing.T) {
	engine := New()
	if _, err := engine.Evaluate(context.Background(), nil, nil); err == nil {
		t.Fatal("expected error for nil pipeline")
	}
}

func TestEvaluateConfigIsExposed(t *testing.T) {
	const module = `package cfgtest

deny contains finding if {
	input.config.threshold > 0
	finding := {
		"code":     "CFG-001",
		"severity": "low",
		"message":  sprintf("threshold is %d", [input.config.threshold]),
	}
}`

	engine := New()
	engine.LoadModule("cfgtest", module)

	pipeline := &ir.NormalizedPipeline{Provider: ir.ProviderGitLab}
	cfg := map[string]any{"threshold": 5}

	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Code != "CFG-001" {
		t.Fatalf("expected code CFG-001, got %q", findings[0].Code)
	}
}

func TestLoadFromFS(t *testing.T) {
	fsys := fstest.MapFS{
		"first.rego":  &fstest.MapFile{Data: []byte("package first")},
		"second.rego": &fstest.MapFile{Data: []byte("package second")},
		"ignored.txt": &fstest.MapFile{Data: []byte("should not be loaded")},
	}

	engine := New()
	if err := engine.LoadFromFS(fsys); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := engine.modules["first"]; !ok {
		t.Error("first.rego should be loaded as module \"first\"")
	}
	if _, ok := engine.modules["second"]; !ok {
		t.Error("second.rego should be loaded as module \"second\"")
	}
	if _, ok := engine.modules["ignored"]; ok {
		t.Error("non-.rego files must be skipped")
	}
	if len(engine.modules) != 2 {
		t.Errorf("expected exactly 2 modules, got %d", len(engine.modules))
	}
}
