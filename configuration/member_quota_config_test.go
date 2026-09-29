package configuration

import (
	"strings"
	"testing"
)

func intp(i int) *int { return &i }

// Bounds are validated at config load (spec 4.2): a negative bound or a min
// above its max is a configuration error, not something the rule guesses at.
func TestProjectMemberQuotaValidateBounds(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *ProjectMemberQuotaControlConfig
		wantErr string
	}{
		{"nil block is fine", nil, ""},
		{"all unset is fine", &ProjectMemberQuotaControlConfig{}, ""},
		{"ordered bounds are fine", &ProjectMemberQuotaControlConfig{OwnerMin: intp(1), OwnerMax: intp(3), TotalMax: intp(0)}, ""},
		{"negative bound", &ProjectMemberQuotaControlConfig{MaintainerMax: intp(-1)}, "numberOfProjectMembersMustRespectQuota.maintainerMax: must be at least 0"},
		{"min above max", &ProjectMemberQuotaControlConfig{DeveloperMin: intp(5), DeveloperMax: intp(2)}, "numberOfProjectMembersMustRespectQuota: developerMin (5) exceeds developerMax (2)"},
		{"owner min above max", &ProjectMemberQuotaControlConfig{OwnerMin: intp(4), OwnerMax: intp(2)}, "numberOfProjectMembersMustRespectQuota: ownerMin (4) exceeds ownerMax (2)"},
		{"maintainer min above max", &ProjectMemberQuotaControlConfig{MaintainerMin: intp(6), MaintainerMax: intp(3)}, "numberOfProjectMembersMustRespectQuota: maintainerMin (6) exceeds maintainerMax (3)"},
		{"negative total bound", &ProjectMemberQuotaControlConfig{TotalMin: intp(-1)}, "numberOfProjectMembersMustRespectQuota.totalMin: must be at least 0"},
		{"total min above max", &ProjectMemberQuotaControlConfig{TotalMin: intp(9), TotalMax: intp(4)}, "numberOfProjectMembersMustRespectQuota: totalMin (9) exceeds totalMax (4)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validateBounds()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// The hook is reached from the loader: a file with inverted bounds must be
// refused by LoadPlumberConfigFromBytes, not only by a direct method call.
func TestProjectMemberQuotaBoundsRefusedAtLoad(t *testing.T) {
	const bad = `version: "2.0"
gitlab:
  controls:
    numberOfProjectMembersMustRespectQuota:
      enabled: true
      ownerMin: 4
      ownerMax: 2
`
	_, _, _, err := LoadPlumberConfigFromBytes([]byte(bad), "member-quota-test")
	if err == nil || !strings.Contains(err.Error(), "ownerMin (4) exceeds ownerMax (2)") {
		t.Fatalf("expected the loader to refuse inverted bounds, got %v", err)
	}
}

// Enabled with no bound set asserts nothing: IsUnconfigured must say so, so
// the run reports config_required rather than a vacuous pass (spec 4.2).
func TestProjectMemberQuotaEnabledWithoutBoundsIsUnconfigured(t *testing.T) {
	const bare = `version: "2.0"
gitlab:
  controls:
    numberOfProjectMembersMustRespectQuota:
      enabled: true
`
	pc, _, _, err := LoadPlumberConfigFromBytes([]byte(bare), "member-quota-test")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !IsUnconfigured(pc, ProviderGitLab, "numberOfProjectMembersMustRespectQuota") {
		t.Fatal("enabled with no bound must be unconfigured")
	}
	const one = `version: "2.0"
gitlab:
  controls:
    numberOfProjectMembersMustRespectQuota:
      enabled: true
      totalMax: 20
`
	pc, _, _, err = LoadPlumberConfigFromBytes([]byte(one), "member-quota-test")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if IsUnconfigured(pc, ProviderGitLab, "numberOfProjectMembersMustRespectQuota") {
		t.Fatal("one bound set is a configuration")
	}
	if got := pc.GetNumberOfProjectMembersMustRespectQuotaConfig(); got == nil || got.TotalMax == nil || *got.TotalMax != 20 {
		t.Fatalf("getter did not return the parsed block: %+v", got)
	}
}
