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

// TestImageExemptConfigContract pins the yaml -> struct -> map -> rego chain
// for containerImageMustNotUseForbiddenTags.exemptImages. The rego tests
// hand-build input.config, so a key the projection in buildEngineConfig
// spells differently from the rules ships silently; this runs the real
// projection through the embedded policies. The digest check is off here,
// so the exemption has to reach the forbidden-tag rule on its own.
func TestImageExemptConfigContract(t *testing.T) {
	for _, digest := range []bool{false, true} {
		cfgYAML := `version: "2.0"
github:
  controls:
    containerImageMustNotUseForbiddenTags:
      enabled: true
      tags: [latest]
      exemptImages: [ghcr.io/my-org/report-tool]
`
		if digest {
			cfgYAML += "      containerImagesMustBePinnedByDigest: true\n"
		}
		conf, _, _, err := configuration.LoadPlumberConfigFromBytes([]byte(cfgYAML), "exempt-contract")
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		engineCfg := buildEngineConfig(conf.ControlsFor("github"), "")

		engine := opaengine.New()
		if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
			t.Fatalf("load policies: %v", err)
		}
		pipeline := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{
			{Name: "report", Image: &ir.Image{Name: "ghcr.io/my-org/report-tool", Tag: "latest"}},
			{Name: "deploy", Image: &ir.Image{Name: "alpine", Tag: "latest"}},
			// The exempt image on an allowed tag is not covered.
			{Name: "release", Image: &ir.Image{Name: "ghcr.io/my-org/report-tool", Tag: "v1.0.2"}},
		}}
		findings, err := evaluateStrict(engine, context.Background(), pipeline, engineCfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		got := map[string][]string{}
		for _, f := range findings {
			if f.Code == "ISSUE-102" || f.Code == "ISSUE-103" {
				got[f.Code] = append(got[f.Code], f.Job)
			}
		}
		if jobs := got["ISSUE-102"]; len(jobs) != 1 || jobs[0] != "deploy" {
			t.Errorf("digest=%v: ISSUE-102 on %v, want [deploy]", digest, jobs)
		}
		var want103 []string
		if digest {
			want103 = []string{"deploy", "release"}
		}
		jobs := got["ISSUE-103"]
		slices.Sort(jobs)
		if !slices.Equal(jobs, want103) {
			t.Errorf("digest=%v: ISSUE-103 on %v, want %v", digest, jobs, want103)
		}
	}
}
