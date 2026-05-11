package cmd

import (
	"strings"
	"testing"
)

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

// The provider auto-detection helper should map common remote URLs to
// the right default selection — saves the user a keystroke on the
// most common single-provider case.
func TestProvidersFromWizardLabels(t *testing.T) {
	got := providersFromWizardLabels([]string{provGitHub, provGitLab})
	if len(got) != 2 || got[0] != "github" || got[1] != "gitlab" {
		t.Fatalf("provider order/translation: %v", got)
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
	for _, c := range []string{compSecurity, compDinD} {
		if !gMenu[c] || !hMenu[c] {
			t.Fatalf("cross-provider check %q missing from one side (gitlab: %v, github: %v)", c, gMenu[c], hMenu[c])
		}
	}
}
