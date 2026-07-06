package cmd

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/defaultconfig"
	"gopkg.in/yaml.v2"
)

// The wizard's default trusted-registry list must stay in lockstep with the
// curated .plumber.yaml list, so accepting init defaults reproduces the
// shipped authorized-sources policy rather than a lean subset.
func TestDefaultTrustedURLsMatchEmbeddedDefault(t *testing.T) {
	var cfg configuration.PlumberConfig
	if err := yaml.Unmarshal(defaultconfig.Get(), &cfg); err != nil {
		t.Fatalf("unmarshal embedded default: %v", err)
	}
	want := cfg.GitLab.Controls.ContainerImageMustComeFromAuthorizedSources.TrustedUrls
	got := defaultTrustedURLs()

	ws, gs := append([]string(nil), want...), append([]string(nil), got...)
	sort.Strings(ws)
	sort.Strings(gs)
	if strings.Join(ws, "\n") != strings.Join(gs, "\n") {
		t.Errorf("defaultTrustedURLs() drifted from embedded default:\nwant (%d): %v\ngot  (%d): %v", len(ws), ws, len(gs), gs)
	}
}

// enabledGitHubControlKeys parses a .plumber.yaml document and returns the
// set of github.controls.<name> keys whose block has enabled: true.
func enabledGitHubControlKeys(t *testing.T, doc []byte) map[string]bool {
	t.Helper()
	var root map[string]interface{}
	if err := yaml.Unmarshal(doc, &root); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out := map[string]bool{}
	gh, _ := root["github"].(map[interface{}]interface{})
	if gh == nil {
		return out
	}
	controls, _ := gh["controls"].(map[interface{}]interface{})
	for name, block := range controls {
		m, ok := block.(map[interface{}]interface{})
		if !ok {
			continue
		}
		if enabled, _ := m["enabled"].(bool); enabled {
			out[name.(string)] = true
		}
	}
	return out
}

// Every GitHub control enabled in the embedded default must also be emitted
// (and enabled) when the wizard defaults are accepted. This is the durable
// regression guard against `config init` drifting behind the shipped control
// set again. Opt-in controls disabled in the default (e.g.
// workflowMustIncludeRequiredActions) are intentionally not required here.
func TestStarterGitHubControlsMatchEmbeddedDefault(t *testing.T) {
	wantKeys := enabledGitHubControlKeys(t, defaultconfig.Get())
	if len(wantKeys) == 0 {
		t.Fatal("embedded default exposed no enabled github controls; test wiring is wrong")
	}
	starterBytes, err := yaml.Marshal(starterPlumberConfig())
	if err != nil {
		t.Fatalf("marshal starter: %v", err)
	}
	gotKeys := enabledGitHubControlKeys(t, starterBytes)
	for k := range wantKeys {
		if !gotKeys[k] {
			t.Errorf("config init starter omits github control %q that ships enabled in the embedded default", k)
		}
	}
}

func TestStarterPlumberConfigValidate(t *testing.T) {
	cfg := starterPlumberConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("starterPlumberConfig: %v", err)
	}
	if cfg.GitLab == nil {
		t.Fatal("starter config should populate the gitlab section")
	}
	if cfg.GitHub == nil {
		t.Fatal("starter config should populate the github section")
	}
}

func TestInitWizardStateEmptyCategories(t *testing.T) {
	st := &initWizardState{}
	cfg := st.toPlumberConfig()
	if cfg.Version != "2.0" {
		t.Fatalf("version: got %q", cfg.Version)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	// Empty Providers slice must fall back to GitLab-only (historical
	// contract preserved for callers that don't set Providers).
	if cfg.GitLab == nil {
		t.Fatal("empty providers should default to gitlab-only")
	}
	if cfg.GitHub != nil {
		t.Fatal("empty providers should not produce a github section")
	}
}

func TestToPlumberConfigRequiredInclusions(t *testing.T) {
	st := &initWizardState{
		Providers:              []string{"gitlab"},
		Categories:             []string{catComposition},
		CompositionChoices:     []string{compHardcoded},
		RequireComponents:      true,
		RequiredComponentsExpr: "components/sast/sast AND components/secret-detection/secret-detection",
		RequireTemplates:       true,
		RequiredTemplatesExpr:  "templates/security/sast",
	}
	cfg := st.toPlumberConfig()
	if cfg.GitLab.Controls.PipelineMustIncludeComponent == nil || cfg.GitLab.Controls.PipelineMustIncludeComponent.Required != st.RequiredComponentsExpr {
		t.Fatalf("component: %#v", cfg.GitLab.Controls.PipelineMustIncludeComponent)
	}
	if cfg.GitLab.Controls.PipelineMustIncludeTemplate == nil || cfg.GitLab.Controls.PipelineMustIncludeTemplate.Required != st.RequiredTemplatesExpr {
		t.Fatalf("template: %#v", cfg.GitLab.Controls.PipelineMustIncludeTemplate)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestToPlumberConfigRequiredSkippedWhenEmpty(t *testing.T) {
	st := &initWizardState{
		Providers:          []string{"gitlab"},
		Categories:         []string{catComposition},
		CompositionChoices: []string{compHardcoded},
		RequireComponents:  true,
	}
	cfg := st.toPlumberConfig()
	if cfg.GitLab.Controls.PipelineMustIncludeComponent != nil {
		t.Fatalf("expected nil, got %#v", cfg.GitLab.Controls.PipelineMustIncludeComponent)
	}
}

// GitHub-only flow: every shipping GitHub control writes only to the
// github section, the gitlab section stays nil, and GitLab-only
// controls (authorized sources, debug trace, …) don't leak in.
func TestInitWizardStateGitHubOnly(t *testing.T) {
	st := &initWizardState{
		Providers:  []string{"github"},
		Categories: []string{catImages, catComposition, catAccess},
		CompositionChoices: []string{
			compSecurity, compDinD,
			compActionPin, compDangerousTriggers, compDeclarePermissions,
			compReusableSecrets, compTemplateInjection,
		},
		ForbiddenTagsEnabled: true,
		ForbiddenTagsCSV:     "latest, dev",
		PinByDigest:          true,
		// Even though AuthorizedEnabled is true, the writer must
		// drop it (GitLab-only control) on a github-only run.
		AuthorizedEnabled:                  true,
		TrustedURLsText:                    "registry.example.com/*",
		ActionPinTrustedOwnersMultiline:    "actions\ngithub",
		SecurityJobPatternsGitHubMultiline: "*codeql*\n*trufflehog*",
		SecuritySubAllowFailure:            true,
		SecuritySubRules:                   true,
		SecuritySubWhenNotManual:           true,
		DinDDetectInsecureDaemon:           true,
		BranchEnabled:                      true,
		BranchPatterns:                     "main, release/*",
		BranchDefaultMustBeProtected:       true,
		BranchAllowForcePush:               false,
		BranchCodeOwnerApprovalRequired:    true,
		BranchMinMergeAccessLevel:          "30", // must be ignored on GH
		BranchMinPushAccessLevel:           "40", // must be ignored on GH
	}
	cfg := st.toPlumberConfig()
	if cfg.GitLab != nil {
		t.Fatalf("expected nil gitlab section for github-only, got %#v", cfg.GitLab)
	}
	if cfg.GitHub == nil {
		t.Fatal("expected github section to be populated")
	}
	gh := cfg.GitHub.Controls
	if gh.ContainerImageMustNotUseForbiddenTags == nil {
		t.Fatal("forbidden tags missing on github side")
	}
	if gh.ContainerImageMustComeFromAuthorizedSources != nil {
		t.Fatal("authorized-sources is GitLab-only; should be nil on github")
	}
	if gh.ActionsMustBePinnedByCommitSha == nil {
		t.Fatal("action pinning missing on github side")
	}
	if got := strings.Join(gh.ActionsMustBePinnedByCommitSha.TrustedOwners, ","); got != "actions,github" {
		t.Fatalf("trusted owners: %s", got)
	}
	if gh.WorkflowsMustDeclarePermissions == nil || !*gh.WorkflowsMustDeclarePermissions.Enabled {
		t.Fatal("permissions control not enabled")
	}
	if gh.WorkflowMustNotUseDangerousTriggers == nil || !*gh.WorkflowMustNotUseDangerousTriggers.Enabled {
		t.Fatal("dangerous triggers control not enabled")
	}
	if gh.ReusableWorkflowsMustNotInheritSecrets == nil || !*gh.ReusableWorkflowsMustNotInheritSecrets.Enabled {
		t.Fatal("reusable secrets control not enabled")
	}
	if gh.WorkflowMustNotInjectUserInputInScripts == nil || !*gh.WorkflowMustNotInjectUserInputInScripts.Enabled {
		t.Fatal("template injection control not enabled")
	}
	if gh.SecurityJobsMustNotBeWeakened == nil {
		t.Fatal("security jobs control missing")
	}
	if got := strings.Join(gh.SecurityJobsMustNotBeWeakened.SecurityJobPatterns, ","); got != "*codeql*,*trufflehog*" {
		t.Fatalf("github security patterns: %s", got)
	}
	if gh.PipelineMustNotUseDockerInDocker == nil {
		t.Fatal("dind control missing")
	}
	if gh.BranchMustBeProtected == nil {
		t.Fatal("branch protection missing")
	}
	// GitHub branch protection must NOT carry the GitLab access-level
	// ints — the GitHub rego rule doesn't read them and emitting them
	// would suggest a permission model that doesn't exist on GitHub.
	if gh.BranchMustBeProtected.MinMergeAccessLevel != nil {
		t.Fatal("min merge access level must not appear on github branch protection")
	}
	if gh.BranchMustBeProtected.MinPushAccessLevel != nil {
		t.Fatal("min push access level must not appear on github branch protection")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

// Both providers selected: cross-provider controls land in both
// sections (with provider-appropriate fields), provider-specific
// controls land only in their respective sections.
func TestInitWizardStateBothProviders(t *testing.T) {
	st := &initWizardState{
		Providers:  []string{"gitlab", "github"},
		Categories: []string{catImages, catComposition, catAccess, catVariables},
		CompositionChoices: []string{
			compHardcoded, compSecurity, compDinD,
			compActionPin, compDangerousTriggers,
		},
		ForbiddenTagsEnabled:               true,
		ForbiddenTagsCSV:                   "latest",
		AuthorizedEnabled:                  true,
		TrustedURLsText:                    "registry.example.com/*",
		TrustDockerHubOfficial:             true,
		ActionPinTrustedOwnersMultiline:    "actions",
		SecurityJobPatternsMultiline:       "*-sast",
		SecurityJobPatternsGitHubMultiline: "*codeql*",
		SecuritySubRules:                   true,
		SecuritySubWhenNotManual:           true,
		DinDDetectInsecureDaemon:           true,
		BranchEnabled:                      true,
		BranchPatterns:                     "main",
		BranchDefaultMustBeProtected:       true,
		BranchMinMergeAccessLevel:          "30",
		BranchMinPushAccessLevel:           "40",
		DebugTraceEnabled:                  true,
		DebugForbiddenVariablesMultiline:   "CI_DEBUG_TRACE",
	}
	cfg := st.toPlumberConfig()
	if cfg.GitLab == nil || cfg.GitHub == nil {
		t.Fatalf("both providers should produce both sections")
	}

	// Forbidden tags: cross-provider — both populated.
	if cfg.GitLab.Controls.ContainerImageMustNotUseForbiddenTags == nil ||
		cfg.GitHub.Controls.ContainerImageMustNotUseForbiddenTags == nil {
		t.Fatal("forbidden tags should write to both providers")
	}

	// Authorized sources: GitLab-only — github side nil.
	if cfg.GitLab.Controls.ContainerImageMustComeFromAuthorizedSources == nil {
		t.Fatal("authorized sources missing on gitlab side")
	}
	if cfg.GitHub.Controls.ContainerImageMustComeFromAuthorizedSources != nil {
		t.Fatal("authorized sources must not leak into github section")
	}

	// Security jobs: cross-provider but each side keeps its own pattern list.
	if cfg.GitLab.Controls.SecurityJobsMustNotBeWeakened == nil ||
		cfg.GitHub.Controls.SecurityJobsMustNotBeWeakened == nil {
		t.Fatal("security jobs should write to both providers")
	}
	if got := strings.Join(cfg.GitLab.Controls.SecurityJobsMustNotBeWeakened.SecurityJobPatterns, ","); got != "*-sast" {
		t.Fatalf("gitlab security pattern: %s", got)
	}
	if got := strings.Join(cfg.GitHub.Controls.SecurityJobsMustNotBeWeakened.SecurityJobPatterns, ","); got != "*codeql*" {
		t.Fatalf("github security pattern: %s", got)
	}

	// Action pinning: GitHub-only.
	if cfg.GitHub.Controls.ActionsMustBePinnedByCommitSha == nil {
		t.Fatal("action pinning missing on github side")
	}

	// Debug trace: GitLab-only — should only land on gitlab.
	if cfg.GitLab.Controls.PipelineMustNotEnableDebugTrace == nil {
		t.Fatal("debug trace missing on gitlab side")
	}

	// Branch protection: both populated; access levels only on GitLab.
	if cfg.GitLab.Controls.BranchMustBeProtected == nil || cfg.GitHub.Controls.BranchMustBeProtected == nil {
		t.Fatal("branch protection should write to both providers")
	}
	if cfg.GitLab.Controls.BranchMustBeProtected.MinMergeAccessLevel == nil {
		t.Fatal("gitlab branch protection should carry the access-level fields")
	}
	if cfg.GitHub.Controls.BranchMustBeProtected.MinMergeAccessLevel != nil {
		t.Fatal("github branch protection must not carry the gitlab access-level fields")
	}

	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

// Accepting the wizard defaults must reproduce the curated .plumber.yaml
// GitHub section: every shipping GitHub control present and set to its
// shipped value. This is the regression guard against config init drifting
// behind the embedded default again.
func TestStarterPlumberConfigGitHubMatchesCuratedDefaults(t *testing.T) {
	gh := starterPlumberConfig().GitHub.Controls

	if gh.WorkflowMustNotGrantPermissionsWriteAll == nil || !*gh.WorkflowMustNotGrantPermissionsWriteAll.Enabled {
		t.Error("write-all permissions control should be present and enabled")
	}
	if gh.ActionsMustNotBeArchived == nil || !*gh.ActionsMustNotBeArchived.Enabled {
		t.Error("archived-actions control should be present and enabled")
	}
	if gh.ActionsMustNotCarryKnownCVEs == nil || !*gh.ActionsMustNotCarryKnownCVEs.Enabled {
		t.Error("known-CVE control should be present and enabled")
	}
	if gh.PipelineMustNotEnableDebugTrace == nil || !*gh.PipelineMustNotEnableDebugTrace.Enabled {
		t.Fatal("github debug-trace control should be present and enabled")
	}
	if got := strings.Join(gh.PipelineMustNotEnableDebugTrace.ForbiddenVariables, ","); got != "ACTIONS_STEP_DEBUG,ACTIONS_RUNNER_DEBUG" {
		t.Errorf("github debug-trace forbidden vars: %s", got)
	}
	if gh.ContainerImageMustNotUseForbiddenTags == nil ||
		gh.ContainerImageMustNotUseForbiddenTags.ContainerImagesMustBePinnedByDigest == nil ||
		!*gh.ContainerImageMustNotUseForbiddenTags.ContainerImagesMustBePinnedByDigest {
		t.Error("github forbidden-tags should default to pin-by-digest true")
	}
	if sj := gh.SecurityJobsMustNotBeWeakened; sj == nil ||
		sj.AllowFailureMustBeFalse == nil || !*sj.AllowFailureMustBeFalse.Enabled {
		t.Error("github securityJobs.allowFailureMustBeFalse should default true")
	} else if !*sj.RulesMustNotBeRedefined.Enabled || !*sj.WhenMustNotBeManual.Enabled {
		t.Error("github securityJobs.rules/whenManual should default true")
	}
	if gh.BranchMustBeProtected == nil ||
		gh.BranchMustBeProtected.CodeOwnerApprovalRequired == nil ||
		!*gh.BranchMustBeProtected.CodeOwnerApprovalRequired {
		t.Error("github branch.codeOwnerApprovalRequired should default true")
	}
}

// The two toggles whose curated default differs per provider must keep
// the GitLab side at its (looser) shipped value when defaults are accepted.
func TestStarterPlumberConfigGitLabDefaultsUnchanged(t *testing.T) {
	gl := starterPlumberConfig().GitLab.Controls

	if gl.SecurityJobsMustNotBeWeakened == nil ||
		gl.SecurityJobsMustNotBeWeakened.AllowFailureMustBeFalse == nil ||
		*gl.SecurityJobsMustNotBeWeakened.AllowFailureMustBeFalse.Enabled {
		t.Error("gitlab securityJobs.allowFailureMustBeFalse should default false")
	}
	if gl.BranchMustBeProtected == nil ||
		gl.BranchMustBeProtected.CodeOwnerApprovalRequired == nil ||
		*gl.BranchMustBeProtected.CodeOwnerApprovalRequired {
		t.Error("gitlab branch.codeOwnerApprovalRequired should default false")
	}
	// GitLab ships all three security sub-toggles off (templates trip
	// them); the wizard must match rather than default rules/whenManual on.
	if sj := gl.SecurityJobsMustNotBeWeakened; sj == nil ||
		sj.RulesMustNotBeRedefined == nil || *sj.RulesMustNotBeRedefined.Enabled {
		t.Error("gitlab securityJobs.rulesMustNotBeRedefined should default false")
	} else if *sj.WhenMustNotBeManual.Enabled {
		t.Error("gitlab securityJobs.whenMustNotBeManual should default false")
	}
}

// workflowMustIncludeRequiredActions is opt-in: written only when the user
// supplies an expression, mirroring pipelineMustIncludeComponent on GitLab.
func TestToPlumberConfigRequiredActionsOptIn(t *testing.T) {
	base := func() *initWizardState {
		return &initWizardState{
			Providers:          []string{"github"},
			Categories:         []string{catComposition},
			CompositionChoices: []string{compActionPin},
		}
	}
	if cfg := base().toPlumberConfig(); cfg.GitHub.Controls.WorkflowMustIncludeRequiredActions != nil {
		t.Fatal("required actions must stay nil when no expression is provided")
	}

	st := base()
	st.RequiredActionsExpr = "myorg/sast-scan AND myorg/dependency-review"
	ra := st.toPlumberConfig().GitHub.Controls.WorkflowMustIncludeRequiredActions
	if ra == nil || !*ra.Enabled {
		t.Fatal("required actions should be enabled when an expression is provided")
	}
	if ra.Required != "myorg/sast-scan AND myorg/dependency-review" {
		t.Errorf("required actions expression: %q", ra.Required)
	}
}

// The provider auto-detection helper should map common remote URLs to
// the right default selection — saves the user a keystroke on the
// most common single-provider case.
func TestProvidersFromWizardLabels(t *testing.T) {
	got := providersFromWizardLabels([]string{provGitHub, provGitLab})
	if len(got) != 2 || got[0] != "github" || got[1] != "gitlab" {
		t.Fatalf("provider order/translation: %v", got)
	}
}

// TestProvidersFromProviderChoice guards the issue #256 fix: the single
// provider select must scope to exactly the chosen provider (picking
// GitHub must NOT leave GitLab in scope); "Both" is the explicit opt-in.
func TestProvidersFromProviderChoice(t *testing.T) {
	cases := []struct {
		choice string
		want   []string
	}{
		{provGitLab, []string{"gitlab"}},
		{provGitHub, []string{"github"}},
		{provBoth, []string{"gitlab", "github"}},
	}
	for _, c := range cases {
		got := providersFromProviderChoice(c.choice)
		if len(got) != len(c.want) {
			t.Fatalf("%q: got %v, want %v", c.choice, got, c.want)
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Fatalf("%q: got %v, want %v", c.choice, got, c.want)
			}
		}
	}
}

func TestWizardCategoriesForProviders(t *testing.T) {
	gitlab := wizardCategoriesForProviders([]string{"gitlab"})
	hasCatVariables := false
	for _, c := range gitlab {
		if c == catVariables {
			hasCatVariables = true
		}
	}
	if !hasCatVariables {
		t.Fatal("gitlab-only run should include catVariables")
	}
	github := wizardCategoriesForProviders([]string{"github"})
	for _, c := range github {
		if c == catVariables {
			t.Fatal("github-only run should NOT include catVariables (controls are benched)")
		}
	}
}

func TestHasCategory(t *testing.T) {
	st := &initWizardState{Categories: []string{catImages, catAccess}}
	if !st.hasCategory(catImages) {
		t.Fatal("hasCategory: expected true for catImages")
	}
	if st.hasCategory(catComposition) {
		t.Fatal("hasCategory: expected false for catComposition")
	}
	if st.hasCategory("") {
		t.Fatal("hasCategory: expected false for empty string")
	}
}

func TestHasProvider(t *testing.T) {
	st := &initWizardState{Providers: []string{"gitlab"}}
	if !hasProvider(st, "gitlab") {
		t.Fatal("hasProvider: expected true for gitlab")
	}
	if hasProvider(st, "github") {
		t.Fatal("hasProvider: expected false for github")
	}
}

func TestCompSelected(t *testing.T) {
	st := &initWizardState{CompositionChoices: []string{compSecurity, compDinD}}
	if !compSelected(st, compSecurity) {
		t.Fatal("compSelected: expected true for compSecurity")
	}
	if compSelected(st, compActionPin) {
		t.Fatal("compSelected: expected false for compActionPin")
	}
}

func TestCheckInitOverwrite_FileDoesNotExist(t *testing.T) {
	path := t.TempDir() + "/nonexistent.yaml"
	if err := checkInitOverwrite(path, false, false); err != nil {
		t.Fatalf("expected nil for non-existent file, got: %v", err)
	}
}

func TestCheckInitOverwrite_ForceAlwaysPasses(t *testing.T) {
	path := t.TempDir() + "/existing.yaml"
	if err := os.WriteFile(path, []byte("v: 1"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := checkInitOverwrite(path, true, false); err != nil {
		t.Fatalf("force=true: expected nil, got: %v", err)
	}
}

func TestCheckInitOverwrite_ExistsNoForceNoPrompt(t *testing.T) {
	path := t.TempDir() + "/existing.yaml"
	if err := os.WriteFile(path, []byte("v: 1"), 0644); err != nil {
		t.Fatal(err)
	}
	err := checkInitOverwrite(path, false, false)
	if err == nil {
		t.Fatal("expected error when file exists and no force/prompt")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCompositionOptionsForProviders(t *testing.T) {
	gitlab := compositionOptionsForProviders([]string{"gitlab"})
	for _, c := range gitlab {
		if c == compActionPin || c == compDangerousTriggers || c == compDeclarePermissions {
			t.Fatalf("github-only check %q leaked into gitlab-only composition menu", c)
		}
	}
	github := compositionOptionsForProviders([]string{"github"})
	for _, c := range github {
		if c == compHardcoded || c == compUpToDate || c == compForbidden || c == compScripts || c == compJobVars {
			t.Fatalf("gitlab-only check %q leaked into github-only composition menu", c)
		}
	}
	// Cross-provider checks must appear in both menus.
	gMenu := map[string]bool{}
	for _, c := range gitlab {
		gMenu[c] = true
	}
	hMenu := map[string]bool{}
	for _, c := range github {
		hMenu[c] = true
	}
	for _, c := range []string{compSecurity, compDinD, compLeaks} {
		if !gMenu[c] || !hMenu[c] {
			t.Fatalf("cross-provider check %q missing from one side (gitlab: %v, github: %v)", c, gMenu[c], hMenu[c])
		}
	}
}

// annotateGitleaksDisabled must mark every pipelineMustNotLeakSecretsInConfig
// block the wizard emitted with a note that secret scanning is temporarily
// disabled, must NOT advertise the gitleaksPath / gitleaksConfigPath overrides
// (gitleaksPath is the vector behind the resolved RCE — a generated config
// must never steer a user toward setting it), and must leave files that do not
// contain that block completely untouched.
func TestAnnotateGitleaksDisabled(t *testing.T) {
	const disabledNote = "temporarily disabled"

	t.Run("block present once -> disabled note inserted, no path knobs", func(t *testing.T) {
		in := []byte("gitlab:\n  controls:\n    pipelineMustNotLeakSecretsInConfig:\n      enabled: true\n    other:\n      enabled: true\n")
		got := string(annotateGitleaksDisabled(in))
		if !strings.Contains(got, disabledNote) {
			t.Fatalf("output missing temporarily-disabled note\n---\n%s", got)
		}
		// The former RCE knob must never be advertised in a generated config.
		for _, banned := range []string{"gitleaksPath", "gitleaksConfigPath"} {
			if strings.Contains(got, banned) {
				t.Fatalf("output must not advertise %q\n---\n%s", banned, got)
			}
		}
		// The note must come immediately after the enabled line, not somewhere else.
		if !strings.Contains(got, "      enabled: true\n      # "+"Secret scanning is temporarily disabled") {
			t.Fatalf("note not placed immediately after enabled line:\n%s", got)
		}
		// The other unrelated control must remain intact and unannotated.
		if !strings.Contains(got, "    other:\n      enabled: true\n") {
			t.Fatalf("unrelated control was modified:\n%s", got)
		}
	})

	t.Run("block present in both provider sections -> note in both", func(t *testing.T) {
		in := []byte(
			"gitlab:\n  controls:\n    pipelineMustNotLeakSecretsInConfig:\n      enabled: true\n" +
				"github:\n  controls:\n    pipelineMustNotLeakSecretsInConfig:\n      enabled: true\n",
		)
		got := string(annotateGitleaksDisabled(in))
		if c := strings.Count(got, disabledNote); c != 2 {
			t.Fatalf("expected exactly 2 disabled notes, got %d:\n%s", c, got)
		}
	})

	t.Run("block absent -> bytes unchanged", func(t *testing.T) {
		in := []byte("gitlab:\n  controls:\n    branchMustBeProtected:\n      enabled: true\n")
		got := annotateGitleaksDisabled(in)
		if string(got) != string(in) {
			t.Fatalf("expected unchanged output when no leak block present:\nin=%q\ngot=%q", in, got)
		}
	})

	t.Run("block present but disabled -> unchanged (helper keys off enabled: true)", func(t *testing.T) {
		// .plumber.yaml's shipped form has enabled: false. The helper keys
		// off `enabled: true` deliberately, so a disabled block is left as-is.
		in := []byte("gitlab:\n  controls:\n    pipelineMustNotLeakSecretsInConfig:\n      enabled: false\n")
		got := annotateGitleaksDisabled(in)
		if string(got) != string(in) {
			t.Fatalf("expected unchanged output for disabled leak block:\n%s", got)
		}
	})
}
