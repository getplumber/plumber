package control

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// TestCollectionConfigs_Row62_FallsBackToTheRunsOwnConfig covers the empty
// CollectionConfigs case: collectionConfigs falls back to the run's own
// PlumberConfig, and a nil Configuration yields nil (platform decision row
// 62).
func TestCollectionConfigs_Row62_FallsBackToTheRunsOwnConfig(t *testing.T) {
	pc := &configuration.PlumberConfig{}
	conf := &configuration.Configuration{PlumberConfig: pc}

	got := collectionConfigs(conf)
	if len(got) != 1 || got[0] != pc {
		t.Fatalf("expected a one-element slice holding the run's own config, got %v", got)
	}

	if got := collectionConfigs(nil); got != nil {
		t.Fatalf("expected nil for a nil Configuration, got %v", got)
	}
}

// TestCollectionConfigs_Row62_PrefersTheResolvedPolicyConfigs covers the
// non-empty CollectionConfigs case: the returned slice is exactly the
// resolved policy configs, in order, and the run's own config is not
// included (platform decision row 62).
func TestCollectionConfigs_Row62_PrefersTheResolvedPolicyConfigs(t *testing.T) {
	own := &configuration.PlumberConfig{}
	first := &configuration.PlumberConfig{}
	second := &configuration.PlumberConfig{}
	conf := &configuration.Configuration{
		PlumberConfig:     own,
		CollectionConfigs: []*configuration.PlumberConfig{first, second},
	}

	got := collectionConfigs(conf)
	if len(got) != 2 || got[0] != first || got[1] != second {
		t.Fatalf("expected [first, second] in order, got %v", got)
	}
	for _, pc := range got {
		if pc == own {
			t.Fatal("expected the run's own config to be excluded when CollectionConfigs is set")
		}
	}
}

// TestAnyCollectionConfig_Row62_OrsTheGateOverEveryConfig covers the OR
// semantics: a control is collected when any resolved policy config enables
// it, even when the run's own config disables it, and the run's own
// SkipControlsFilter still applies to the scoped copy (platform decision row
// 62).
func TestAnyCollectionConfig_Row62_OrsTheGateOverEveryConfig(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }
	on := &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(true)}
	off := &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(false)}

	cfgWith := func(protected, masked *configuration.EnabledOnlyControlConfig) *configuration.PlumberConfig {
		return &configuration.PlumberConfig{
			GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
				CicdVariablesMustBeProtected: protected,
				CicdVariablesMustBeMasked:    masked,
			}},
		}
	}

	t.Run("run's own config disables both, a collection config enables one -> true", func(t *testing.T) {
		conf := &configuration.Configuration{
			PlumberConfig:     cfgWith(off, off),
			CollectionConfigs: []*configuration.PlumberConfig{cfgWith(on, off)},
		}
		if !anyCollectionConfig(conf, cicdVariableControlEnabled) {
			t.Fatal("expected true: one collection config enables a variable control")
		}
	})

	t.Run("every config disables both -> false", func(t *testing.T) {
		conf := &configuration.Configuration{
			PlumberConfig:     cfgWith(off, off),
			CollectionConfigs: []*configuration.PlumberConfig{cfgWith(off, off)},
		}
		if anyCollectionConfig(conf, cicdVariableControlEnabled) {
			t.Fatal("expected false: no config enables either variable control")
		}
	})

	t.Run("the run's own SkipControlsFilter still suppresses an enabling collection config", func(t *testing.T) {
		conf := &configuration.Configuration{
			PlumberConfig: cfgWith(off, off),
			SkipControlsFilter: []string{
				controlCicdVariablesMustBeProtected,
				controlCicdVariablesMustBeMasked,
			},
			CollectionConfigs: []*configuration.PlumberConfig{cfgWith(on, off)},
		}
		if anyCollectionConfig(conf, cicdVariableControlEnabled) {
			t.Fatal("expected false: the run's own SkipControlsFilter must still be honoured on the scoped copy")
		}
	})
}

// TestMarkLaneCollected_Row62_RecordsThelaneOnce covers markLaneCollected:
// nil-safe on a nil *AnalysisResult, creates the map on first use, and
// recording the same lane twice leaves exactly one entry (platform decision
// row 62).
func TestMarkLaneCollected_Row62_RecordsThelaneOnce(t *testing.T) {
	var nilResult *AnalysisResult
	nilResult.markLaneCollected(laneGitLabProtection)

	result := &AnalysisResult{}
	result.markLaneCollected(laneGitLabProtection)
	if !result.CollectedLanes[laneGitLabProtection] {
		t.Fatalf("expected the lane to be recorded, got %v", result.CollectedLanes)
	}

	result.markLaneCollected(laneGitLabProtection)
	if len(result.CollectedLanes) != 1 || !result.CollectedLanes[laneGitLabProtection] {
		t.Fatalf("expected exactly one recorded lane after calling twice, got %v", result.CollectedLanes)
	}
}

// TestGitLabCollectionGates_Row62_FireForAPolicyTheLocalConfigDisables pins
// the union at the gate level: a Configuration whose own PlumberConfig
// disables cicdVariablesMustBeProtected / cicdVariablesMustBeMasked,
// projectMustHaveSecurityPolicySource and every protection-lane control, but
// whose CollectionConfigs holds one config that enables each of them, still
// fires all three gates through anyCollectionConfig. With every config
// disabled, all three stay closed (platform decision row 62). The wiring in
// task.go that calls these gates is covered by the integration tier.
func TestGitLabCollectionGates_Row62_FireForAPolicyTheLocalConfigDisables(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }
	on := boolPtr(true)
	off := boolPtr(false)

	allControls := func(enabled *bool) configuration.ControlsConfig {
		return configuration.ControlsConfig{
			CicdVariablesMustBeProtected:                           &configuration.EnabledOnlyControlConfig{Enabled: enabled},
			CicdVariablesMustBeMasked:                              &configuration.EnabledOnlyControlConfig{Enabled: enabled},
			ProjectMustHaveSecurityPolicySource:                    &configuration.SecurityPolicyControlConfig{Enabled: enabled},
			BranchMustBeProtected:                                  &configuration.BranchProtectionControlConfig{Enabled: enabled},
			MergeRequestApprovalRulesMustRequireMinimumApprovals:   &configuration.MRApprovalRulesMinApprovalsControlConfig{Enabled: enabled},
			MergeRequestApprovalRulesMustCoverAllProtectedBranches: &configuration.EnabledOnlyControlConfig{Enabled: enabled},
			MergeRequestApprovalSettingsMustBeCompliant:            &configuration.MRApprovalSettingsControlConfig{Enabled: enabled},
			MergeRequestSettingsMustBeCompliant:                    &configuration.MRSettingsControlConfig{Enabled: enabled},
		}
	}

	localDisablesAll := &configuration.PlumberConfig{
		GitLab: &configuration.ProviderConfig{Controls: allControls(off)},
	}

	t.Run("a collection config that enables every gated control fires all three gates", func(t *testing.T) {
		conf := &configuration.Configuration{
			PlumberConfig: localDisablesAll,
			CollectionConfigs: []*configuration.PlumberConfig{
				{GitLab: &configuration.ProviderConfig{Controls: allControls(on)}},
			},
		}
		if !anyCollectionConfig(conf, cicdVariableControlEnabled) {
			t.Fatal("expected the cicd variable gate to fire from the collection config")
		}
		if !anyCollectionConfig(conf, securityPolicyControlEnabled) {
			t.Fatal("expected the security policy gate to fire from the collection config")
		}
		if !anyCollectionConfig(conf, protectionDataNeeded) {
			t.Fatal("expected the protection gate to fire from the collection config")
		}
	})

	t.Run("every config disabled leaves all three gates closed", func(t *testing.T) {
		conf := &configuration.Configuration{
			PlumberConfig: localDisablesAll,
			CollectionConfigs: []*configuration.PlumberConfig{
				{GitLab: &configuration.ProviderConfig{Controls: allControls(off)}},
			},
		}
		if anyCollectionConfig(conf, cicdVariableControlEnabled) {
			t.Fatal("expected the cicd variable gate to stay closed when every config disables it")
		}
		if anyCollectionConfig(conf, securityPolicyControlEnabled) {
			t.Fatal("expected the security policy gate to stay closed when every config disables it")
		}
		if anyCollectionConfig(conf, protectionDataNeeded) {
			t.Fatal("expected the protection gate to stay closed when every config disables it")
		}
	})
}

// TestCollectionBranchProtectionConfig_Row62 pins the one lane where a gate is
// not enough: the branch-protection fetch reads the control's own fields to
// decide WHICH branches to ask about, so the scopes of every collecting
// configuration have to be merged before the single fetch (platform decision
// row 62).
func TestCollectionBranchProtectionConfig_Row62(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }
	withBranchControl := func(cfg *configuration.BranchProtectionControlConfig) *configuration.PlumberConfig {
		return &configuration.PlumberConfig{
			Version: "2.0",
			GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
				BranchMustBeProtected: cfg,
			}},
		}
	}

	t.Run("a single collecting config is returned untouched", func(t *testing.T) {
		own := withBranchControl(&configuration.BranchProtectionControlConfig{
			Enabled:      boolPtr(true),
			NamePatterns: []string{"main"},
		})
		conf := &configuration.Configuration{PlumberConfig: own}

		if got := collectionBranchProtectionConfig(conf); got != own {
			t.Fatalf("want the one collecting config itself, no synthetic object, got %+v", got)
		}
	})

	t.Run("two enabling configs merge into one scope", func(t *testing.T) {
		first := withBranchControl(&configuration.BranchProtectionControlConfig{
			Enabled:                boolPtr(true),
			NamePatterns:           []string{"main"},
			DefaultMustBeProtected: boolPtr(false),
		})
		second := withBranchControl(&configuration.BranchProtectionControlConfig{
			Enabled:                boolPtr(true),
			NamePatterns:           []string{"release/*", "main"},
			DefaultMustBeProtected: boolPtr(true),
		})
		conf := &configuration.Configuration{
			PlumberConfig:     withBranchControl(nil),
			CollectionConfigs: []*configuration.PlumberConfig{first, second},
		}

		got := collectionBranchProtectionConfig(conf)
		if got == nil {
			t.Fatal("want a merged scope, got nil")
		}
		merged := got.ControlsFor(configuration.ProviderGitHub).BranchMustBeProtected
		if merged == nil || !merged.IsEnabled() {
			t.Fatalf("the merged scope must enable the control, got %+v", merged)
		}
		want := []string{"main", "release/*"}
		if len(merged.NamePatterns) != len(want) {
			t.Fatalf("namePatterns = %v, want %v (both patterns, each once)", merged.NamePatterns, want)
		}
		for i, p := range want {
			if merged.NamePatterns[i] != p {
				t.Fatalf("namePatterns = %v, want %v in first-seen order", merged.NamePatterns, want)
			}
		}
		if merged.DefaultMustBeProtected == nil || !*merged.DefaultMustBeProtected {
			t.Fatal("one config requiring the default branch makes the default branch part of the fetch scope")
		}
		// The inputs are the policies' own trees: merging must not write one
		// policy's patterns into another policy's configuration.
		if firstCfg := first.ControlsFor(configuration.ProviderGitHub).BranchMustBeProtected; len(firstCfg.NamePatterns) != 1 {
			t.Fatalf("the first config was mutated: namePatterns = %v", firstCfg.NamePatterns)
		}
	})

	t.Run("nothing requires the default branch, so it stays out of the scope", func(t *testing.T) {
		first := withBranchControl(&configuration.BranchProtectionControlConfig{
			Enabled:      boolPtr(true),
			NamePatterns: []string{"main"},
		})
		second := withBranchControl(&configuration.BranchProtectionControlConfig{
			Enabled:                boolPtr(true),
			NamePatterns:           []string{"release/*"},
			DefaultMustBeProtected: boolPtr(false),
		})
		conf := &configuration.Configuration{
			PlumberConfig:     withBranchControl(nil),
			CollectionConfigs: []*configuration.PlumberConfig{first, second},
		}

		merged := collectionBranchProtectionConfig(conf).ControlsFor(configuration.ProviderGitHub).BranchMustBeProtected
		if merged == nil {
			t.Fatal("want a merged scope, got none")
		}
		if merged.DefaultMustBeProtected == nil || *merged.DefaultMustBeProtected {
			t.Fatalf("defaultMustBeProtected = %v, want an explicit false: no policy asked for the default branch, "+
				"so the fetch must not pay for it", merged.DefaultMustBeProtected)
		}
	})

	t.Run("a disabled sibling contributes nothing to the merged scope", func(t *testing.T) {
		enabling := withBranchControl(&configuration.BranchProtectionControlConfig{
			Enabled:      boolPtr(true),
			NamePatterns: []string{"main"},
		})
		disabled := withBranchControl(&configuration.BranchProtectionControlConfig{
			Enabled:                boolPtr(false),
			NamePatterns:           []string{"legacy/*"},
			DefaultMustBeProtected: boolPtr(true),
		})
		conf := &configuration.Configuration{
			PlumberConfig:     withBranchControl(nil),
			CollectionConfigs: []*configuration.PlumberConfig{enabling, disabled},
		}

		merged := collectionBranchProtectionConfig(conf).ControlsFor(configuration.ProviderGitHub).BranchMustBeProtected
		if merged == nil {
			t.Fatal("want a merged scope, got none")
		}
		if len(merged.NamePatterns) != 1 || merged.NamePatterns[0] != "main" {
			t.Fatalf("namePatterns = %v, want only [main]: a policy that switched the control off asked for no branches",
				merged.NamePatterns)
		}
		if merged.DefaultMustBeProtected == nil || *merged.DefaultMustBeProtected {
			t.Fatal("a disabled control's defaultMustBeProtected must not widen the fetch scope")
		}
	})

	t.Run("every config disabling the control yields nil", func(t *testing.T) {
		off := &configuration.BranchProtectionControlConfig{Enabled: boolPtr(false), NamePatterns: []string{"main"}}
		conf := &configuration.Configuration{
			PlumberConfig: withBranchControl(off),
			CollectionConfigs: []*configuration.PlumberConfig{
				withBranchControl(off),
				withBranchControl(nil),
			},
		}

		if got := collectionBranchProtectionConfig(conf); got != nil {
			t.Fatalf("want nil so the enrichment no-ops on its own pc == nil guard, got %+v", got)
		}
	})
}

// TestShouldScanMutableExec_Row62_UnionedOverCollectionConfigs covers the
// action-source gate read through the union: the expensive per-action fetch is
// asked for when ANY collecting configuration enables
// actionsMustNotExecuteMutableRemoteCode, even when the run's own
// configuration switches it off (platform decision row 62).
func TestShouldScanMutableExec_Row62_UnionedOverCollectionConfigs(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }
	withMutableExec := func(enabled bool) *configuration.PlumberConfig {
		return &configuration.PlumberConfig{
			Version: "2.0",
			GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
				ActionsMustNotExecuteMutableRemoteCode: &configuration.EnabledOnlyControlConfig{Enabled: boolPtr(enabled)},
			}},
		}
	}

	conf := &configuration.Configuration{
		PlumberConfig:     withMutableExec(false),
		CollectionConfigs: []*configuration.PlumberConfig{withMutableExec(true)},
	}

	if shouldScanMutableExec(conf) {
		t.Fatal("the run's own configuration disables the control: the ungated gate must stay false")
	}
	if !anyCollectionConfig(conf, shouldScanMutableExec) {
		t.Fatal("a collecting configuration enables the control: the scan must be asked for")
	}
}

// TestBranchLaneCollected_Row62 pins which runs count as having collected the
// branch-protection lane: the scope handed to the collector must enable the
// control, since the single-config scope is that configuration itself and a
// disabled control does reach the collector, which no-ops (platform decision
// row 62).
func TestBranchLaneCollected_Row62(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }
	scope := func(enabled *bool) *configuration.PlumberConfig {
		var cfg *configuration.BranchProtectionControlConfig
		if enabled != nil {
			cfg = &configuration.BranchProtectionControlConfig{Enabled: enabled, NamePatterns: []string{"main"}}
		}
		return &configuration.PlumberConfig{
			Version: "2.0",
			GitHub:  &configuration.ProviderConfig{Controls: configuration.ControlsConfig{BranchMustBeProtected: cfg}},
		}
	}
	conf := &configuration.Configuration{PlumberConfig: scope(boolPtr(true))}

	if !branchLaneCollected(conf, "acme/app", scope(boolPtr(true))) {
		t.Fatal("an enabling scope collects the lane")
	}
	if branchLaneCollected(conf, "acme/app", scope(boolPtr(false))) {
		t.Fatal("a disabled control collects nothing: the collector no-ops on its own guard")
	}
	if branchLaneCollected(conf, "acme/app", scope(nil)) {
		t.Fatal("an absent control collects nothing")
	}
	if branchLaneCollected(conf, "acme/app", nil) {
		t.Fatal("a nil scope means no collecting configuration enables the control")
	}
	skipped := &configuration.Configuration{
		PlumberConfig:      scope(boolPtr(true)),
		SkipControlsFilter: []string{controlBranchMustBeProtected},
	}
	if branchLaneCollected(skipped, "acme/app", scope(boolPtr(true))) {
		t.Fatal("--skip-controls still removes the control, and with it its collection")
	}
	// The enrichment returns early on anything that is not owner/repo
	// shaped, so no fetch is attempted and the lane must not be recorded:
	// the guards here and there have to agree, or the run would claim data
	// nobody asked for.
	for _, bad := range []string{"", "acme", "acme/", "/app", "/"} {
		if branchLaneCollected(conf, bad, scope(boolPtr(true))) {
			t.Fatalf("project path %q is not owner/repo shaped: no fetch is attempted, so no lane is collected", bad)
		}
	}
}

// githubBranchPolicy returns a configuration whose GitHub
// branchMustBeProtected control is in the requested state, with a
// substantive field set so an enabled control is not ALSO unconfigured
// (#459): these cases are about a lane that never ran, and config_required
// would be a different, more specific reason.
func githubBranchPolicy(enabled bool) *configuration.PlumberConfig {
	return &configuration.PlumberConfig{
		Version: "2.0",
		GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			BranchMustBeProtected: &configuration.BranchProtectionControlConfig{
				Enabled:      &enabled,
				NamePatterns: []string{"main"},
			},
		}},
	}
}

// TestMarkUncollectedLanes_Row62_MarksAControlThePolicyEnablesOverAnUncollectedLane
// is the point of the marker: a control a policy enables whose gated
// collection did not run this run has nothing to report, so it must be
// not_evaluable rather than an empty findings list reading as a pass
// (platform decision row 62).
func TestMarkUncollectedLanes_Row62_MarksAControlThePolicyEnablesOverAnUncollectedLane(t *testing.T) {
	pc := githubBranchPolicy(true)
	entries := GitHubControls(pc)

	uncollected := &AnalysisResult{
		Findings: []opaengine.Finding{{Code: string(CodeBranchUnprotected)}},
	}
	MarkUncollectedLanes(uncollected, entries, configuration.ProviderGitHub)

	if reason := uncollected.NotEvaluable[controlBranchMustBeProtected]; reason != ReasonLaneNotCollected {
		t.Fatalf("reason = %q, want %q: nobody fetched the branch protections", reason, ReasonLaneNotCollected)
	}
	if len(uncollected.Findings) != 0 {
		t.Fatalf("a finding over a lane that never ran must be dropped, not merely relabelled; got %d", len(uncollected.Findings))
	}

	collected := &AnalysisResult{
		CollectedLanes: map[string]bool{laneGitHubBranches: true},
		Findings:       []opaengine.Finding{{Code: string(CodeBranchUnprotected)}},
	}
	MarkUncollectedLanes(collected, entries, configuration.ProviderGitHub)

	if reason, marked := collected.NotEvaluable[controlBranchMustBeProtected]; marked {
		t.Fatalf("the lane WAS collected: the control must keep its verdict, got reason %q", reason)
	}
	if len(collected.Findings) != 1 {
		t.Fatalf("a finding over a collected lane must survive; got %d", len(collected.Findings))
	}
}

// TestMarkUncollectedLanes_Row62_NeverCrossesProviders pins why the map is
// keyed by provider: branchMustBeProtected exists on both providers and
// reads a DIFFERENT lane on each, so the absence of the GitHub lane must
// never discredit a GitLab verdict (platform decision row 62).
func TestMarkUncollectedLanes_Row62_NeverCrossesProviders(t *testing.T) {
	enabled := true
	branchControl := func() *configuration.BranchProtectionControlConfig {
		return &configuration.BranchProtectionControlConfig{
			Enabled:      &enabled,
			NamePatterns: []string{"main"},
		}
	}
	pc := &configuration.PlumberConfig{
		Version: "2.0",
		GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			BranchMustBeProtected: branchControl(),
		}},
		GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
			BranchMustBeProtected: branchControl(),
		}},
	}
	lanes := map[string]bool{laneGitLabProtection: true}

	onGitLab := &AnalysisResult{CollectedLanes: lanes}
	MarkUncollectedLanes(onGitLab, GitLabControls(pc), configuration.ProviderGitLab)
	if reason, marked := onGitLab.NotEvaluable[controlBranchMustBeProtected]; marked {
		t.Fatalf("the GitLab protection lane ran: the GitLab verdict stands, got reason %q", reason)
	}

	// The same result, read as GitHub: that provider's lane is absent, so
	// the control there really has nothing to report.
	onGitHub := &AnalysisResult{CollectedLanes: lanes}
	MarkUncollectedLanes(onGitHub, GitHubControls(pc), configuration.ProviderGitHub)
	if reason := onGitHub.NotEvaluable[controlBranchMustBeProtected]; reason != ReasonLaneNotCollected {
		t.Fatalf("reason = %q, want %q: a GitLab lane is not the GitHub one", reason, ReasonLaneNotCollected)
	}
}

// TestMarkUncollectedLanes_Row62_SkipsDisabledControls: a control this
// policy switched off was not left unevaluated, it was turned off. Marking
// it would list a disabled control as something that went wrong and inflate
// every not-evaluated count (platform decision row 62).
func TestMarkUncollectedLanes_Row62_SkipsDisabledControls(t *testing.T) {
	result := &AnalysisResult{}
	MarkUncollectedLanes(result, GitHubControls(githubBranchPolicy(false)), configuration.ProviderGitHub)

	if reason, marked := result.NotEvaluable[controlBranchMustBeProtected]; marked {
		t.Fatalf("a disabled control must not be marked, got reason %q", reason)
	}
}

// TestMarkUncollectedLanes_Row62_KeepsTheMoreSpecificReason: this marker
// runs last, after the lane-gap and failed-collection markers, and
// MarkNotEvaluable is first-reason-wins. "The platform reported this lane
// degraded" names a cause an operator can act on; "the collection did not
// run" is the broader fallback and must not overwrite it (platform decision
// row 62).
func TestMarkUncollectedLanes_Row62_KeepsTheMoreSpecificReason(t *testing.T) {
	result := &AnalysisResult{}
	result.MarkNotEvaluable(controlBranchMustBeProtected, ReasonSnapshotLaneDegraded)
	MarkUncollectedLanes(result, GitHubControls(githubBranchPolicy(true)), configuration.ProviderGitHub)

	if reason := result.NotEvaluable[controlBranchMustBeProtected]; reason != ReasonSnapshotLaneDegraded {
		t.Fatalf("reason = %q, want the more specific %q", reason, ReasonSnapshotLaneDegraded)
	}
}

// TestMarkUncollectedLanes_Row62_AStandaloneRunMarksNothing pins that the
// marker is inert outside platform mode, and pins it from the data model
// rather than from a mode flag: a standalone run collects exactly what its
// OWN configuration gates, so every lane a control it enables reads was
// collected, and every lane that stayed closed belongs to controls the same
// configuration had disabled (their entries are Skipped). Both directions
// mark nothing, which is why the marker needs no special case for a run
// with no platform (platform decision row 62).
func TestMarkUncollectedLanes_Row62_AStandaloneRunMarksNothing(t *testing.T) {
	gatesByLane := map[string]func(*configuration.Configuration) bool{
		laneGitLabProtection:     protectionDataNeeded,
		laneGitLabVariables:      cicdVariableControlEnabled,
		laneGitLabSecurityPolicy: securityPolicyControlEnabled,
	}

	two := 2
	controlsWith := func(enabled *bool) configuration.ControlsConfig {
		return configuration.ControlsConfig{
			BranchMustBeProtected: &configuration.BranchProtectionControlConfig{
				Enabled:      enabled,
				NamePatterns: []string{"main"},
			},
			MergeRequestApprovalRulesMustRequireMinimumApprovals: &configuration.MRApprovalRulesMinApprovalsControlConfig{
				Enabled:                  enabled,
				MinimumRequiredApprovals: &two,
			},
			MergeRequestApprovalRulesMustCoverAllProtectedBranches: &configuration.EnabledOnlyControlConfig{Enabled: enabled},
			MergeRequestApprovalSettingsMustBeCompliant:            &configuration.MRApprovalSettingsControlConfig{Enabled: enabled},
			MergeRequestSettingsMustBeCompliant:                    &configuration.MRSettingsControlConfig{Enabled: enabled},
			CicdVariablesMustBeProtected:                           &configuration.EnabledOnlyControlConfig{Enabled: enabled},
			CicdVariablesMustBeMasked:                              &configuration.EnabledOnlyControlConfig{Enabled: enabled},
			ProjectMustHaveSecurityPolicySource:                    &configuration.SecurityPolicyControlConfig{Enabled: enabled},
		}
	}

	states := map[string]*bool{
		"every gated control enabled":  boolPtr(true),
		"every gated control disabled": boolPtr(false),
	}
	for name, enabled := range states {
		t.Run(name, func(t *testing.T) {
			pc := &configuration.PlumberConfig{
				Version: "2.0",
				GitLab:  &configuration.ProviderConfig{Controls: controlsWith(enabled)},
			}
			conf := &configuration.Configuration{PlumberConfig: pc}

			// The gates, exactly as RunAnalysis reads them on a run with no
			// collecting configuration of its own.
			result := &AnalysisResult{}
			for lane, gate := range gatesByLane {
				if anyCollectionConfig(conf, gate) {
					result.markLaneCollected(lane)
				}
			}

			MarkUncollectedLanes(result, GitLabControls(pc), configuration.ProviderGitLab)

			if len(result.NotEvaluable) != 0 {
				t.Fatalf("a standalone run has no uncollected lane to mark, got %v", result.NotEvaluable)
			}
		})
	}
}

// configurableControlsFor returns every control name this provider can have
// switched on in a configuration: the ControlsConfig fields (whose yaml tag
// IS the control name) that apply to the provider and are not benched in
// code. Derived from the struct rather than listed, so a control added to
// ControlsConfig is covered by the drift guard below without editing it.
func configurableControlsFor(provider string) []string {
	typ := reflect.TypeOf(configuration.ControlsConfig{})
	names := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		name, _, _ := strings.Cut(typ.Field(i).Tag.Get("yaml"), ",")
		if name == "" || !configuration.IsControlApplicableTo(name, provider) {
			continue
		}
		if configuration.IsBenched(provider, name) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// configEnablingOnly returns a Configuration for provider whose ONLY enabled
// control is name, so a gate evaluated over it answers about that one control
// and nothing else. The field is located by its yaml tag and filled through
// reflection for the same reason: no per-control literal to keep in step.
func configEnablingOnly(t *testing.T, provider, name string) *configuration.Configuration {
	t.Helper()
	var controls configuration.ControlsConfig
	v := reflect.ValueOf(&controls).Elem()
	typ := v.Type()
	for i := 0; i < typ.NumField(); i++ {
		if tag, _, _ := strings.Cut(typ.Field(i).Tag.Get("yaml"), ","); tag != name {
			continue
		}
		cfg := reflect.New(typ.Field(i).Type.Elem())
		enabled := cfg.Elem().FieldByName("Enabled")
		if !enabled.IsValid() || enabled.Kind() != reflect.Pointer || enabled.Type().Elem().Kind() != reflect.Bool {
			t.Fatalf("control %s: %s has no Enabled *bool field, so this helper cannot switch it on", name, typ.Field(i).Type)
		}
		on := true
		enabled.Set(reflect.ValueOf(&on))
		v.Field(i).Set(cfg)
		pc := &configuration.PlumberConfig{Version: "2.0"}
		switch provider {
		case configuration.ProviderGitLab:
			pc.GitLab = &configuration.ProviderConfig{Controls: controls}
		case configuration.ProviderGitHub:
			pc.GitHub = &configuration.ProviderConfig{Controls: controls}
		default:
			t.Fatalf("unknown provider %q", provider)
		}
		return &configuration.Configuration{PlumberConfig: pc}
	}
	t.Fatalf("control %s has no ControlsConfig field", name)
	return nil
}

// TestControlsByGatedLane_Row62_MirrorsTheGatesItStandsFor is the drift guard
// for the one coupling row 62 introduced: controlsByGatedLane restates, as a
// hand-written literal, a fact that already lives in the collection gates
// (protectionDataNeeded, cicdVariableControlEnabled,
// securityPolicyControlEnabled, branchLaneCollected, shouldScanMutableExec).
// Nothing else pins that the two keep agreeing, and they must: a control
// listed under a lane whose gate does not consider it is marked
// not_evaluable on every per-policy push even though its data WAS collected,
// and a control the gate considers but the table omits passes vacuously over
// a lane that never ran.
//
// The expectation is DERIVED rather than restated: for each lane, switch on
// exactly one control at a time and ask that lane's own gate whether it would
// collect. The controls whose enabling flips the gate are, by definition, the
// controls that have nothing to evaluate when the lane did not run, and that
// set must be exactly the table's row.
//
// The lane keys are compared both ways too, so a lane added to the table
// without its gate named here (the shape that forgets markLaneCollected) does
// not slip through silently (platform decision row 62).
func TestControlsByGatedLane_Row62_MirrorsTheGatesItStandsFor(t *testing.T) {
	gatesByProviderLane := map[string]map[string]func(*configuration.Configuration) bool{
		configuration.ProviderGitLab: {
			laneGitLabProtection:     protectionDataNeeded,
			laneGitLabVariables:      cicdVariableControlEnabled,
			laneGitLabSecurityPolicy: securityPolicyControlEnabled,
		},
		configuration.ProviderGitHub: {
			// The one lane whose gate needs the collector's own inputs: the
			// scope it is handed and the project path it addresses.
			laneGitHubBranches: func(conf *configuration.Configuration) bool {
				return branchLaneCollected(conf, "acme/app", collectionBranchProtectionConfig(conf))
			},
			laneGitHubActionSource: shouldScanMutableExec,
		},
	}

	for provider, gates := range gatesByProviderLane {
		t.Run(provider, func(t *testing.T) {
			table := controlsByGatedLane[provider]
			for lane := range table {
				if _, ok := gates[lane]; !ok {
					t.Fatalf("lane %q is in controlsByGatedLane but has no gate here: name the gate that records it, or the table cannot be checked against anything", lane)
				}
			}
			for lane, gate := range gates {
				if _, ok := table[lane]; !ok {
					t.Fatalf("lane %q has a gate but no controlsByGatedLane row: every gated collection owes its controls a reason", lane)
				}
				t.Run(lane, func(t *testing.T) {
					var derived []string
					for _, name := range configurableControlsFor(provider) {
						if gate(configEnablingOnly(t, provider, name)) {
							derived = append(derived, name)
						}
					}
					want := append([]string(nil), table[lane]...)
					sort.Strings(want)
					if len(derived) != len(want) {
						t.Fatalf("lane %q collects for %v, but the table lists %v", lane, derived, want)
					}
					for i := range want {
						if derived[i] != want[i] {
							t.Fatalf("lane %q collects for %v, but the table lists %v", lane, derived, want)
						}
					}
				})
			}
		})
	}
}
