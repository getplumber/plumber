package control

import (
	"context"
	"testing"

	"github.com/getplumber/plumber/configuration"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// TestProjectMemberQuotaConfigContract pins the struct -> map -> rego chain for
// ISSUE-507: buildEngineConfig (task.go) emits
// cfg["numberOfProjectMembersMustRespectQuota"]["ownerMax"] and its seven
// siblings, and the rego reads exactly those keys. Every rego-only test
// hand-builds input.config, so a rename on either side would make the rule
// fall silent with all other tests green. Mirrors TestMRApprovalMinApprovalsConfigContract.
func TestProjectMemberQuotaConfigContract(t *testing.T) {
	intPtr := func(i int) *int { return &i }
	boolPtr := func(b bool) *bool { return &b }

	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	pipeline := &ir.NormalizedPipeline{
		Provider:            ir.ProviderGitLab,
		ProjectMembersKnown: true,
		ProjectMembers:      &ir.MemberCounts{Owners: 4, Maintainers: 0, Developers: 2, Total: 6},
	}
	roles := func(engineCfg map[string]any) map[string]bool {
		findings, err := evaluateStrict(engine, context.Background(), pipeline, engineCfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		out := map[string]bool{}
		for _, f := range findings {
			if f.Code == "ISSUE-507" {
				out[f.Data["role"].(string)] = true
			}
		}
		return out
	}

	// Every key through the REAL projection: each bound is set so that it is
	// violated, so a dropped or renamed key shows up as a missing role.
	cfg := buildEngineConfig(&configuration.ControlsConfig{
		NumberOfProjectMembersMustRespectQuota: &configuration.ProjectMemberQuotaControlConfig{
			Enabled:       boolPtr(true),
			OwnerMax:      intPtr(3),
			MaintainerMin: intPtr(1),
			DeveloperMin:  intPtr(3),
			TotalMax:      intPtr(5),
		},
	})
	block, ok := cfg["numberOfProjectMembersMustRespectQuota"].(map[string]any)
	if !ok {
		t.Fatal("buildEngineConfig did not project a numberOfProjectMembersMustRespectQuota block")
	}
	for _, key := range []string{"ownerMax", "maintainerMin", "developerMin", "totalMax"} {
		if _, has := block[key]; !has {
			t.Errorf("projection lacks %q", key)
		}
	}
	for _, key := range []string{"ownerMin", "maintainerMax", "developerMax", "totalMin"} {
		if _, has := block[key]; has {
			t.Errorf("projection carries unset key %q", key)
		}
	}
	got := roles(cfg)
	for _, role := range []string{"owner", "maintainer", "developer", "total"} {
		if !got[role] {
			t.Errorf("role %q did not fire through the real config projection: the struct->map->rego key contract is broken (%v)", role, got)
		}
	}

	// The other four keys, the mirror image.
	cfg = buildEngineConfig(&configuration.ControlsConfig{
		NumberOfProjectMembersMustRespectQuota: &configuration.ProjectMemberQuotaControlConfig{
			Enabled:       boolPtr(true),
			OwnerMin:      intPtr(5),
			MaintainerMax: intPtr(0),
			DeveloperMax:  intPtr(1),
			TotalMin:      intPtr(7),
		},
	})
	got = roles(cfg)
	for _, role := range []string{"owner", "developer", "total"} {
		if !got[role] {
			t.Errorf("role %q did not fire through ownerMin/developerMax/totalMin: %v", role, got)
		}
	}
	if got["maintainer"] {
		t.Errorf("maintainerMax 0 against 0 maintainers is compliant, got a finding: %v", got)
	}

	// Enabled with nothing set projects an empty block and fires nothing.
	cfg = buildEngineConfig(&configuration.ControlsConfig{
		NumberOfProjectMembersMustRespectQuota: &configuration.ProjectMemberQuotaControlConfig{Enabled: boolPtr(true)},
	})
	if n := len(roles(cfg)); n != 0 {
		t.Fatalf("no bound set: expected 0 findings, got %d", n)
	}
}
