package opa

import (
	"context"
	"fmt"

	"github.com/getplumber/plumber/internal/ir"
)

// evaluateStrict runs every policy and fails on ANY module failure, naming
// the first failing module: the contract a test suite wants, where a broken
// policy must fail loudly. The analysis itself uses EvaluateModules and
// degrades the failed policy's controls instead (#489).
func evaluateStrict(engine *Engine, ctx context.Context, pipeline *ir.NormalizedPipeline, config map[string]any) ([]Finding, error) {
	findings, failed, err := engine.EvaluateModules(ctx, pipeline, config)
	if err != nil {
		return nil, err
	}
	if len(failed) > 0 {
		return nil, fmt.Errorf("evaluate module %q: %w", failed[0].Module, failed[0].Err)
	}
	return findings, nil
}
