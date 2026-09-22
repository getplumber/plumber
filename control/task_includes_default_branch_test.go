package control

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
)

// Ruling R6 of the 2026-09-22 issues-page review: the projection the engine
// evaluates carries the EFFECTIVE value of defaultBranchIsForbiddenVersion,
// so an operator who never wrote the key still has the default branch
// treated as a forbidden include version. The accessor decides it once
// (configuration.IncludesForbiddenVersionsControlConfig); this is the seam
// that puts it in front of the rule.
func TestBuildEngineConfig_DefaultBranchForbiddenWhenTheKeyIsUnset(t *testing.T) {
	no := false
	cases := []struct {
		name string
		cfg  *configuration.IncludesForbiddenVersionsControlConfig
		want bool
	}{
		{"key unset", &configuration.IncludesForbiddenVersionsControlConfig{}, true},
		{"operator opted out", &configuration.IncludesForbiddenVersionsControlConfig{DefaultBranchIsForbiddenVersion: &no}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := buildEngineConfig(&configuration.ControlsConfig{IncludesMustNotUseForbiddenVersions: tc.cfg})
			block, ok := cfg["includesForbiddenVersions"].(map[string]any)
			if !ok {
				t.Fatalf("no includesForbiddenVersions block in %#v", cfg)
			}
			if got := block["defaultBranchIsForbiddenVersion"]; got != tc.want {
				t.Errorf("defaultBranchIsForbiddenVersion = %#v, want %v", got, tc.want)
			}
		})
	}
}
