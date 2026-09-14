package cmd

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
)

// TestApplyCollectionScope_Row62 covers applyCollectionScope: it fills
// Configuration.CollectionConfigs with one entry per resolved policy whose
// control tree could be assembled, in /context order, using the same
// assembler (configForPlatformPolicy) the evaluation itself uses (platform
// decision row 62).
func TestApplyCollectionScope_Row62(t *testing.T) {
	t.Run("nil PlatformRun leaves CollectionConfigs nil", func(t *testing.T) {
		conf := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{Version: "2.0"}}

		applyCollectionScope(testProvider(t), conf)

		if conf.CollectionConfigs != nil {
			t.Fatalf("want nil CollectionConfigs with no platform run, got %v", conf.CollectionConfigs)
		}
	})

	t.Run("two real policies with distinct trees yield two configs in order", func(t *testing.T) {
		a := policyWithTree("A", "branchMustBeProtected", `{"enabled":true,"minMergeAccessLevel":40}`)
		b := policyWithTree("B", "cicdVariablesMustBeMasked", `{"enabled":true}`)
		conf := confWithPolicies(t, a, b)

		applyCollectionScope(testProvider(t), conf)

		if len(conf.CollectionConfigs) != 2 {
			t.Fatalf("want 2 collection configs, got %d: %+v", len(conf.CollectionConfigs), conf.CollectionConfigs)
		}
		aCfg, bCfg := conf.CollectionConfigs[0], conf.CollectionConfigs[1]
		if aCfg.ControlsFor("gitlab").BranchMustBeProtected == nil {
			t.Fatal("first config must be A's tree (branchMustBeProtected)")
		}
		if bCfg.ControlsFor("gitlab").CicdVariablesMustBeMasked == nil {
			t.Fatal("second config must be B's tree (cicdVariablesMustBeMasked)")
		}
	})

	t.Run("a policy whose tree cannot be applied is skipped while its sibling survives", func(t *testing.T) {
		bad := policyWithTree("Bad", "pipelineMustNotEnableDebugTrace", `{"enabled": not-json`)
		good := policyWithTree("Good", "branchMustBeProtected", `{"enabled":true,"minMergeAccessLevel":40}`)
		conf := confWithPolicies(t, bad, good)

		applyCollectionScope(testProvider(t), conf)

		if len(conf.CollectionConfigs) != 1 {
			t.Fatalf("want 1 collection config (the unreadable tree contributes nothing), got %d: %+v",
				len(conf.CollectionConfigs), conf.CollectionConfigs)
		}
		if conf.CollectionConfigs[0].ControlsFor("gitlab").BranchMustBeProtected == nil {
			t.Fatal("the surviving config must be Good's tree (branchMustBeProtected)")
		}
	})

	t.Run("the derived placeholder yields the embedded default config", func(t *testing.T) {
		conf := confWithPolicies(t, derivedDefaultPolicy())
		// A local config that enables nothing must not influence the result:
		// the derived run is evaluated under the embedded default, never the
		// local file.
		conf.PlumberConfig = &configuration.PlumberConfig{Version: "2.0"}

		applyCollectionScope(testProvider(t), conf)

		if len(conf.CollectionConfigs) != 1 {
			t.Fatalf("want 1 collection config for the derived placeholder, got %d: %+v",
				len(conf.CollectionConfigs), conf.CollectionConfigs)
		}
		want, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "embedded default")
		if err != nil {
			t.Fatalf("load embedded default: %v", err)
		}
		got := conf.CollectionConfigs[0]
		if got.ControlsFor("gitlab").BranchMustBeProtected == nil != (want.ControlsFor("gitlab").BranchMustBeProtected == nil) {
			t.Fatalf("derived config must match the embedded default's branchMustBeProtected presence")
		}
	})
}
