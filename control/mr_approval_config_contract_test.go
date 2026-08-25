package control

import (
	"context"
	"testing"

	"github.com/getplumber/plumber/configuration"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// TestMRApprovalMinApprovalsConfigContract pins the struct -> map -> rego chain
// for ISSUE-502: buildEngineConfig (task.go) emits
// cfg["mergeRequestApprovalRulesMustRequireMinimumApprovals"]["minimumRequiredApprovals"],
// and the rego reads exactly those keys. Every rego-only test hand-builds
// input.config, so a rename on either side would silently make the rego fall
// back to a minimum of 0 — ISSUE-502 would never fire (a false pass) with all
// other tests still green. Mirrors TestCachePoisoningConfigContract.
func TestMRApprovalMinApprovalsConfigContract(t *testing.T) {
	intPtr := func(i int) *int { return &i }
	boolPtr := func(b bool) *bool { return &b }

	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	// A rule covering all protected branches, requiring only 1 approval.
	pipeline := &ir.NormalizedPipeline{
		Provider:             ir.ProviderGitLab,
		MRApprovalRulesKnown: true,
		MRApprovalRules: []ir.MRApprovalRule{
			{ID: "10", Name: "weak", ApprovalsRequired: 1, AppliesToAllProtectedBranches: true},
		},
	}
	count502 := func(engineCfg map[string]any) int {
		findings, err := engine.Evaluate(context.Background(), pipeline, engineCfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		n := 0
		for _, f := range findings {
			if f.Code == "ISSUE-502" {
				n++
			}
		}
		return n
	}

	// Minimum 2, via the REAL buildEngineConfig projection: the 1-approval rule
	// must fire exactly one ISSUE-502. A key rename on either side breaks this.
	cfg2 := buildEngineConfig(&configuration.ControlsConfig{
		MergeRequestApprovalRulesMustRequireMinimumApprovals: &configuration.MRApprovalRulesMinApprovalsControlConfig{
			Enabled:                  boolPtr(true),
			MinimumRequiredApprovals: intPtr(2),
		},
	})
	if _, ok := cfg2["mergeRequestApprovalRulesMustRequireMinimumApprovals"]; !ok {
		t.Fatal("buildEngineConfig did not project a mergeRequestApprovalRulesMustRequireMinimumApprovals block")
	}
	if n := count502(cfg2); n != 1 {
		t.Fatalf("min=2 through the real config projection: expected 1 ISSUE-502, got %d — the struct->map->rego key contract is broken", n)
	}

	// Minimum unset -> the rego's object.get defaults to 0 -> nothing is below 0,
	// so no finding. Pins the documented "treated as 0" behaviour end to end.
	cfgNil := buildEngineConfig(&configuration.ControlsConfig{
		MergeRequestApprovalRulesMustRequireMinimumApprovals: &configuration.MRApprovalRulesMinApprovalsControlConfig{
			Enabled: boolPtr(true),
		},
	})
	if n := count502(cfgNil); n != 0 {
		t.Fatalf("min unset (treated as 0): expected 0 ISSUE-502, got %d", n)
	}
}
