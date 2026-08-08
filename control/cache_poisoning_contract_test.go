package control

import (
	"context"
	"testing"

	"github.com/getplumber/plumber/configuration"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
	"gopkg.in/yaml.v2"
)

// TestCachePoisoningConfigContract pins the yaml -> struct -> map -> rego chain
// for the cache-poisoning control. Every rego-only test hand-builds
// input.config, so a key mismatch between buildEngineConfig's map keys
// (task.go) and the rego's object.get keys ships silently. This runs the REAL
// buildEngineConfig projection of the EMBEDDED default config through the rego,
// so such a mismatch fails here.
func TestCachePoisoningConfigContract(t *testing.T) {
	var conf configuration.PlumberConfig
	if err := yaml.Unmarshal(defaultconfig.Get(), &conf); err != nil {
		t.Fatalf("unmarshal embedded default: %v", err)
	}
	engineCfg := buildEngineConfig(conf.ControlsFor("github"))
	if _, ok := engineCfg["cachePoisoning"]; !ok {
		t.Fatal("buildEngineConfig did not project a cachePoisoning block from the embedded default")
	}

	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	countISSUE705 := func(t *testing.T, p *ir.NormalizedPipeline) int {
		t.Helper()
		findings, err := engine.Evaluate(context.Background(), p, engineCfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		n := 0
		for _, f := range findings {
			if f.Code == "ISSUE-705" {
				n++
			}
		}
		return n
	}

	// setup-go with cache:false on a release job. The shipped default's
	// {mode:default, disableInput:cache, disableValue:false} must survive the
	// projection so no cache is restored. A typo'd disableInput/disableValue
	// key on either side flips this to a false positive.
	clean := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{{
		Name:     "publish",
		Triggers: []string{"release"},
		Uses:     []ir.Action{{Uses: "actions/setup-go@v5", With: map[string]any{"cache": false}}},
	}}}
	if n := countISSUE705(t, clean); n != 0 {
		t.Fatalf("clean (setup-go cache:false) through the real config projection: expected 0, got %d — the yaml->struct->map->rego contract is broken", n)
	}

	// actions/cache with an unscoped key on a release job: always-restore, not
	// release-scoped. Confirms the projection carries the control at all.
	viol := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{{
		Name:     "publish",
		Triggers: []string{"release"},
		Uses:     []ir.Action{{Uses: "actions/cache@v4", With: map[string]any{"key": "deps-abc", "path": "~/.npm"}}},
	}}}
	if n := countISSUE705(t, viol); n != 1 {
		t.Fatalf("violation (actions/cache unscoped) through the real config projection: expected 1, got %d", n)
	}
}
