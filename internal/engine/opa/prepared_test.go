package opa

import (
	"context"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// resetPreparedForTest empties the cache and the compile counter.
func resetPreparedForTest() {
	preparedQueries.Range(func(k, _ any) bool {
		preparedQueries.Delete(k)
		return true
	})
	preparedCompiles.Store(0)
}

// preparedCompilesForTest is the number of compilations since the last reset.
func preparedCompilesForTest() int64 { return preparedCompiles.Load() }

// A module's compiled query is prepared once per source and reused across
// evaluations: the second evaluation of the same module hits the cache, a
// different source of the same name does not, and both still evaluate right.
func TestPreparedQueriesAreReusedPerModuleSource(t *testing.T) {
	resetPreparedForTest()
	const name = "prepared_probe"
	src1 := "package prepared_probe\n\ndeny contains {\"code\": \"PROBE-1\", \"message\": \"one\", \"severity\": \"low\"} if {\n\tinput.pipeline.provider == \"github\"\n}\n"
	src2 := "package prepared_probe\n\ndeny contains {\"code\": \"PROBE-2\", \"message\": \"two\", \"severity\": \"low\"} if {\n\tinput.pipeline.provider == \"github\"\n}\n"
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub}
	input, err := buildInput(p, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	f1, err := evalModule(ctx, name, src1, input)
	if err != nil || len(f1) != 1 || f1[0].Code != "PROBE-1" {
		t.Fatalf("first eval: %v %+v", err, f1)
	}
	f2, err := evalModule(ctx, name, src1, input)
	if err != nil || len(f2) != 1 {
		t.Fatalf("second eval: %v %+v", err, f2)
	}
	if got := preparedCompilesForTest(); got != 1 {
		t.Fatalf("compiles after two evaluations of one source = %d, want 1", got)
	}
	f3, err := evalModule(ctx, name, src2, input)
	if err != nil || len(f3) != 1 || f3[0].Code != "PROBE-2" {
		t.Fatalf("eval of a changed source: %v %+v", err, f3)
	}
	if got := preparedCompilesForTest(); got != 2 {
		t.Fatalf("compiles after a changed source = %d, want 2", got)
	}
}
