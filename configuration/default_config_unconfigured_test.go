package configuration

import (
	"testing"

	defaultconfig "github.com/getplumber/plumber/defaultConfig"
)

// TestEmbeddedDefaultConfig_EnablesNoUnconfiguredControl pins #459 against the shipped default:
// the embedded .plumber.yaml (defaultConfig/.plumber.yaml, what a zero-config run and this repo's
// own dogfooding both extend) must never enable a RequiresConfig control without also setting one
// of its substantive fields. If it did, the control would silently turn not_evaluable on every
// default run and on Plumber's own 100/100 self-scan, exactly the vacuous-pass shape #459 exists
// to catch, just moved from "enabled but empty" to "enabled by the shipped baseline but empty".
func TestEmbeddedDefaultConfig_EnablesNoUnconfiguredControl(t *testing.T) {
	pc, _, _, err := LoadPlumberConfigFromBytes(defaultconfig.Get(), "default")
	if err != nil {
		t.Fatalf("loading the embedded default config: %v", err)
	}
	for _, e := range ControlsCatalog() {
		if !e.RequiresConfig {
			continue
		}
		for _, provider := range e.Providers {
			if IsUnconfigured(pc, provider, e.Name) {
				t.Errorf("#459: the embedded default config enables %s (%s) with no substantive field set; "+
					"a default run (and this repo's own 100/100 dogfooding) would silently report it not_evaluable",
					e.Name, provider)
			}
		}
	}
}
