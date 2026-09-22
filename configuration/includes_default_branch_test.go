package configuration

import "testing"

// Ruling R6 of the 2026-09-22 issues-page review: an include pinned to the
// project's default branch is a forbidden version unless the operator says
// otherwise, so the unset key means true. The accessor is the one place
// that decides it; the shipped configs and the schema default only restate
// it for a reader.
func TestIsDefaultBranchForbidden_UnsetMeansTrue(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name string
		cfg  *IncludesForbiddenVersionsControlConfig
		want bool
	}{
		{"absent block", nil, true},
		{"key unset", &IncludesForbiddenVersionsControlConfig{}, true},
		{"explicit true", &IncludesForbiddenVersionsControlConfig{DefaultBranchIsForbiddenVersion: &yes}, true},
		{"explicit false", &IncludesForbiddenVersionsControlConfig{DefaultBranchIsForbiddenVersion: &no}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.IsDefaultBranchForbidden(); got != tc.want {
				t.Errorf("IsDefaultBranchForbidden() = %v, want %v", got, tc.want)
			}
		})
	}
}
