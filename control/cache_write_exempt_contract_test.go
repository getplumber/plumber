package control

import (
	"context"
	"slices"
	"testing"

	"github.com/getplumber/plumber/configuration"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// TestCacheWriteExemptConfigContract pins the yaml -> struct -> map -> rego
// chain for untrustedTriggersMustNotWriteCache's exemptions. The rego tests
// hand-build input.config, so a key the projection in buildEngineConfig
// spells differently from the rule ships silently; this runs the real
// projection through the embedded policies.
func TestCacheWriteExemptConfigContract(t *testing.T) {
	conf, _, _, err := configuration.LoadPlumberConfigFromBytes([]byte(`version: "2.0"
github:
  controls:
    untrustedTriggersMustNotWriteCache:
      enabled: true
      exemptWorkflows: [triage.yml]
      exemptJobs: [ci/warm]
`), "cache-write-contract")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	engineCfg := buildEngineConfig(conf.ControlsFor("github"), "")

	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	write := &ir.CacheModeDecl{Value: "write", Effective: "write", Line: 6, Level: "job"}
	pipeline := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{
		{Name: "triage/label", OriginFile: ".github/workflows/triage.yml", Triggers: []string{"issue_comment"}, CacheMode: write},
		{Name: "ci/warm", OriginFile: ".github/workflows/ci.yml", Triggers: []string{"pull_request_target"}, CacheMode: write},
		{Name: "ci/build", OriginFile: ".github/workflows/ci.yml", Triggers: []string{"pull_request_target"}, CacheMode: write},
	}}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, engineCfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	var jobs []string
	for _, f := range findings {
		if f.Code == "ISSUE-705" {
			jobs = append(jobs, f.Job)
		}
	}
	if !slices.Equal(jobs, []string{"ci/build"}) {
		t.Errorf("ISSUE-705 on %v, want [ci/build]", jobs)
	}
}
