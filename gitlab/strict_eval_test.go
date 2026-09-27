package gitlab

import (
	"context"
	"fmt"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// evaluateStrict runs every policy and fails on ANY module failure, naming
// the first failing module: the contract a test suite wants, where a broken
// policy must fail loudly. The analysis itself uses EvaluateModules and
// degrades the failed policy's controls instead (#489).
func evaluateStrict(engine *opaengine.Engine, ctx context.Context, pipeline *ir.NormalizedPipeline, config map[string]any) ([]opaengine.Finding, error) {
	findings, failed, err := engine.EvaluateModules(ctx, pipeline, config)
	if err != nil {
		return nil, err
	}
	if len(failed) > 0 {
		return nil, fmt.Errorf("evaluate module %q: %w", failed[0].Module, failed[0].Err)
	}
	return findings, nil
}
