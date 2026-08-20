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

// TestMRApprovalSettingsConfigContract pins the same struct -> map -> rego
// chain for ISSUE-503. The stakes are higher here than for 502: every
// expectation is optional and the rego treats an absent key as "not checked",
// so a key rename on either side would not fail anything — it would read as
// "operator chose not to check this" and the control would silently assert
// nothing, forever, with every rego-only test (which hand-builds
// input.config) still green.
func TestMRApprovalSettingsConfigContract(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }
	strPtr := func(s string) *string { return &s }

	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	// A fully unlocked project: every expectation that reaches the rego
	// deviates, so the deviation list mirrors exactly which config keys
	// survived the projection.
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		MRApprovalSettings: &ir.MRApprovalSettings{
			BehaviorWhenCommitIsAdded: ir.MRApprovalBehaviorKeepApprovals,
		},
	}
	deviations503 := func(engineCfg map[string]any) []any {
		findings, err := engine.Evaluate(context.Background(), pipeline, engineCfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, f := range findings {
			if f.Code == "ISSUE-503" {
				devs, _ := f.Data["deviatingSettings"].([]any)
				return devs
			}
		}
		return nil
	}

	// All five expectations set, via the REAL buildEngineConfig projection:
	// all five must come back as deviations. Any dropped or renamed key
	// shrinks this list.
	cfgAll := buildEngineConfig(&configuration.ControlsConfig{
		MergeRequestApprovalSettingsMustBeCompliant: &configuration.MRApprovalSettingsControlConfig{
			Enabled:                         boolPtr(true),
			PreventApprovalByAuthor:         boolPtr(true),
			PreventApprovalsByCommitters:    boolPtr(true),
			PreventEditingApprovalRulesInMR: boolPtr(true),
			RequireReAuthToApprove:          boolPtr(true),
			BehaviorWhenCommitIsAdded:       strPtr(ir.MRApprovalBehaviorRemoveAllApprovals),
		},
	})
	if _, ok := cfgAll["mergeRequestApprovalSettingsMustBeCompliant"]; !ok {
		t.Fatal("buildEngineConfig did not project a mergeRequestApprovalSettingsMustBeCompliant block")
	}
	if devs := deviations503(cfgAll); len(devs) != 5 {
		t.Fatalf("all 5 expectations through the real config projection: expected 5 deviations, got %v — the struct->map->rego key contract is broken", devs)
	}

	// Only one expectation set -> exactly that one deviation: unset fields
	// must NOT be projected (the rego reads an absent key as "not checked").
	cfgOne := buildEngineConfig(&configuration.ControlsConfig{
		MergeRequestApprovalSettingsMustBeCompliant: &configuration.MRApprovalSettingsControlConfig{
			Enabled:                 boolPtr(true),
			PreventApprovalByAuthor: boolPtr(true),
		},
	})
	devs := deviations503(cfgOne)
	if len(devs) != 1 || devs[0] != "preventApprovalByAuthor" {
		t.Fatalf("one expectation set: expected exactly [preventApprovalByAuthor], got %v", devs)
	}
}

// TestMRSettingsConfigContract pins the struct -> map -> rego chain for
// ISSUE-506. Every expectation is optional and the rego reads an absent key as
// "not checked", so a key rename on either side would silently make the control
// assert nothing forever with the rego-only tests (which hand-build
// input.config) still green.
func TestMRSettingsConfigContract(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }
	strPtr := func(s string) *string { return &s }

	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	// A project whose every setting differs from the configured expectation, so
	// the deviation list mirrors exactly which config keys survived projection.
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		MRSettings: &ir.MRSettings{
			MergeMethod:                     "merge",
			SquashOption:                    "never",
			MergePipelinesEnabled:           false,
			MergeTrainsEnabled:              false,
			AllowMergeOnSkippedPipeline:     false,
			ResolveOutdatedDiffDiscussions:  false,
			PrintingMergeRequestLinkEnabled: false,
			RemoveSourceBranchAfterMerge:    false,
		},
	}
	deviations506 := func(engineCfg map[string]any) []any {
		findings, err := engine.Evaluate(context.Background(), pipeline, engineCfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, f := range findings {
			if f.Code == "ISSUE-506" {
				devs, _ := f.Data["deviatingSettings"].([]any)
				return devs
			}
		}
		return nil
	}

	// All eight expectations set (each the opposite of the pipeline's value),
	// via the REAL buildEngineConfig projection: all eight must deviate.
	cfgAll := buildEngineConfig(&configuration.ControlsConfig{
		MergeRequestSettingsMustBeCompliant: &configuration.MRSettingsControlConfig{
			Enabled:                         boolPtr(true),
			MergeMethod:                     strPtr("ff"),
			SquashOption:                    strPtr("always"),
			MergePipelinesEnabled:           boolPtr(true),
			MergeTrainsEnabled:              boolPtr(true),
			AllowMergeOnSkippedPipeline:     boolPtr(true),
			ResolveOutdatedDiffDiscussions:  boolPtr(true),
			PrintingMergeRequestLinkEnabled: boolPtr(true),
			RemoveSourceBranchAfterMerge:    boolPtr(true),
		},
	})
	if _, ok := cfgAll["mergeRequestSettingsMustBeCompliant"]; !ok {
		t.Fatal("buildEngineConfig did not project a mergeRequestSettingsMustBeCompliant block")
	}
	if devs := deviations506(cfgAll); len(devs) != 8 {
		t.Fatalf("all 8 expectations through the real config projection: expected 8 deviations, got %v — the struct->map->rego key contract is broken", devs)
	}

	// Only one expectation set -> exactly that one deviation: unset fields must
	// NOT be projected (the rego reads an absent key as "not checked").
	cfgOne := buildEngineConfig(&configuration.ControlsConfig{
		MergeRequestSettingsMustBeCompliant: &configuration.MRSettingsControlConfig{
			Enabled:     boolPtr(true),
			MergeMethod: strPtr("ff"),
		},
	})
	devs := deviations506(cfgOne)
	if len(devs) != 1 || devs[0] != "mergeMethod" {
		t.Fatalf("one expectation set: expected exactly [mergeMethod], got %v", devs)
	}
}
