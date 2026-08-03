package cmd

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/defaultconfig"
	"gopkg.in/yaml.v2"
)

// TestStarterCachePoisoningMatchesEmbeddedDefault deep-compares the wizard's
// cache-poisoning inventories against the shipped .plumber.yaml. The
// key-only TestStarterGitHubControlsMatchEmbeddedDefault does not catch
// list-content drift; this does, so `plumber init` never emits a weaker or
// noisier control than the embedded default.
func TestStarterCachePoisoningMatchesEmbeddedDefault(t *testing.T) {
	var embedded configuration.PlumberConfig
	if err := yaml.Unmarshal(defaultconfig.Get(), &embedded); err != nil {
		t.Fatalf("unmarshal embedded default: %v", err)
	}
	if embedded.GitHub == nil {
		t.Fatal("embedded default has no github section")
	}
	want := embedded.GitHub.Controls.ReleaseWorkflowsMustNotRestoreUntrustedCache
	if want == nil {
		t.Fatal("embedded default has no cache-poisoning control")
	}
	st := &initWizardState{
		Providers:          []string{"github"},
		Categories:         []string{catComposition},
		CompositionChoices: []string{compCachePoisoning},
	}
	got := st.toPlumberConfig().GitHub.Controls.ReleaseWorkflowsMustNotRestoreUntrustedCache
	if got == nil {
		t.Fatal("wizard did not emit the cache-poisoning control")
	}
	for _, c := range []struct {
		name      string
		want, got any
	}{
		{"publishActions", want.PublishActions, got.PublishActions},
		{"cacheActions", want.CacheActions, got.CacheActions},
		{"publishScriptPatterns", want.PublishScriptPatterns, got.PublishScriptPatterns},
		{"publishScriptExcludePatterns", want.PublishScriptExcludePatterns, got.PublishScriptExcludePatterns},
	} {
		if !reflect.DeepEqual(c.want, c.got) {
			t.Errorf("%s drift:\n  embedded (.plumber.yaml): %#v\n  wizard   (init.go):       %#v", c.name, c.want, c.got)
		}
	}
}

// The wizard now sources its authorized-source defaults directly from the
// embedded default (no hand-maintained copies), so lockstep drift is
// impossible by construction. This instead guards that those lists are
// actually populated in the embedded default — if the block were dropped the
// wizard would silently offer an empty allowlist.
func TestWizardDefaultsSourcedFromEmbeddedDefault(t *testing.T) {
	// Every list/string helper has an empty-value fallback for a missing block.
	// Guard them all: a renamed/dropped block in defaultConfig/.plumber.yaml must
	// fail here rather than silently degrade the wizard (e.g. an enabled control
	// with an empty pattern list that matches nothing).
	lists := map[string][]string{
		"defaultTrustedURLs":                            defaultTrustedURLs(),
		"defaultTrustedGithubActions":                   defaultTrustedGithubActions(),
		"defaultSecurityJobPatterns":                    defaultSecurityJobPatterns(),
		"defaultGitHubSecurityJobPatterns":              defaultGitHubSecurityJobPatterns(),
		"defaultDangerousVariables":                     defaultDangerousVariables(),
		"defaultJobOverrideVariables":                   defaultJobOverrideVariables(),
		"defaultForbiddenVersions":                      defaultForbiddenVersions(),
		"defaultGitHubDebugTraceVariables":              defaultGitHubDebugTraceVariables(),
		"defaultGitHubTrustedActionOwners":              defaultGitHubTrustedActionOwners(),
		"defaultCachePoisoningPublishActions":           defaultCachePoisoningPublishActions(),
		"defaultCachePoisoningPublishScriptPatterns":    defaultCachePoisoningPublishScriptPatterns(),
		"defaultCachePoisoningPublishScriptExcludePats": defaultCachePoisoningPublishScriptExcludePatterns(),
	}
	for name, got := range lists {
		if len(got) == 0 {
			t.Errorf("%s() is empty — its block is missing from the embedded default", name)
		}
	}
	strs := map[string]string{
		"defaultForbiddenTags":  defaultForbiddenTags(),
		"defaultBranchPatterns": defaultBranchPatterns(),
	}
	for name, got := range strs {
		if got == "" {
			t.Errorf("%s() is empty — its block is missing from the embedded default", name)
		}
	}
	if len(defaultCachePoisoningCacheActions()) == 0 {
		t.Error("defaultCachePoisoningCacheActions() is empty — its block is missing from the embedded default")
	}
	if defaultTrustedActionsMinimumStars() <= 0 {
		t.Errorf("defaultTrustedActionsMinimumStars() = %d, want > 0", defaultTrustedActionsMinimumStars())
	}
}

// When the wizard emits the authorized-actions control with the curated choice,
// the trustedGithubActions list and minimumStars it produces must match the
// shipped default exactly — the end-to-end guard that `init` (curated) and
// `generate` agree on this policy.
func TestWizardCuratedAuthorizedActionsMatchDefault(t *testing.T) {
	var cfg configuration.PlumberConfig
	if err := yaml.Unmarshal(defaultconfig.Get(), &cfg); err != nil {
		t.Fatalf("unmarshal embedded default: %v", err)
	}
	want := cfg.GitHub.Controls.GithubActionMustComeFromAuthorizedSources
	st := &initWizardState{
		Providers:                       []string{"github"},
		Categories:                      []string{catComposition},
		CompositionChoices:              []string{compAuthorizedActions},
		AuthorizedActionsUsePlumberList: true,
	}
	got := st.toPlumberConfig().GitHub.Controls.GithubActionMustComeFromAuthorizedSources
	if got == nil {
		t.Fatal("wizard did not emit the authorized-actions control")
	}
	if got.MinimumStars != want.MinimumStars {
		t.Errorf("minimumStars: wizard=%d default=%d", got.MinimumStars, want.MinimumStars)
	}
	if !reflect.DeepEqual(want.TrustedGithubActions, got.TrustedGithubActions) {
		t.Errorf("trustedGithubActions drift between wizard (curated) and default")
	}
}

// "From scratch" must leave the allowlist empty (and the star floor unset), so
// the choice is real and not silently overridden.
func TestWizardScratchAuthorizedActionsEmpty(t *testing.T) {
	st := &initWizardState{
		Providers:                       []string{"github"},
		Categories:                      []string{catComposition},
		CompositionChoices:              []string{compAuthorizedActions},
		AuthorizedActionsUsePlumberList: false,
	}
	got := st.toPlumberConfig().GitHub.Controls.GithubActionMustComeFromAuthorizedSources
	if got == nil {
		t.Fatal("wizard did not emit the authorized-actions control")
	}
	if len(got.TrustedGithubActions) != 0 || got.MinimumStars != 0 {
		t.Errorf("expected empty allowlist and no star floor, got list=%d stars=%d", len(got.TrustedGithubActions), got.MinimumStars)
	}
}

// The embedded default (defaultconfig.Get) must be byte-identical to the source
// defaultConfig/.plumber.yaml. Every build path regenerates the embed from the
// source (`make embed` / the CI+Docker `cp` step) before build/test; this
// asserts that link directly, so a stale or skipped regeneration — which would
// ship a drifted default to `config generate`, the init wizard, and zero-config
// analyze while every self-consistent test stays green — fails here instead.
func TestEmbeddedDefaultMatchesSource(t *testing.T) {
	src, err := os.ReadFile("../defaultConfig/.plumber.yaml")
	if err != nil {
		t.Fatalf("read source default: %v", err)
	}
	if !bytes.Equal(src, defaultconfig.Get()) {
		t.Errorf("embedded default (%d bytes) differs from defaultConfig/.plumber.yaml (%d bytes) — run `make embed` to regenerate the embed from source",
			len(defaultconfig.Get()), len(src))
	}
}

// `config generate` must write the embedded default verbatim, so the generated
// file and the shipped baseline can never diverge.
func TestConfigGenerateMatchesEmbeddedDefault(t *testing.T) {
	dir := t.TempDir()
	out := dir + "/gen.plumber.yaml"
	prevOut, prevForce := configGenerateOutput, configGenerateForce
	configGenerateOutput, configGenerateForce = out, true
	defer func() { configGenerateOutput, configGenerateForce = prevOut, prevForce }()

	if err := runConfigGenerate(nil, nil); err != nil {
		t.Fatalf("config generate: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read generated file: %v", err)
	}
	if !reflect.DeepEqual(got, defaultconfig.Get()) {
		t.Errorf("config generate output differs from embedded default (%d vs %d bytes)", len(got), len(defaultconfig.Get()))
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

// starterWizardConfig reproduces the "accept every wizard default" run:
// the initWizardState below mirrors the Default values of the survey
// prompts in init.go, then goes through the live toPlumberConfig mapping.
// It exists so the drift-guard tests compare wizard output against the
// embedded default via the same code path real wizard runs take.
func starterWizardConfig() *configuration.PlumberConfig {
	st := &initWizardState{
		Providers:                       []string{"gitlab", "github"},
		Categories:                      []string{catImages, catComposition, catAccess, catVariables},
		ForbiddenTagsEnabled:            true,
		ForbiddenTagsCSV:                defaultForbiddenTags(),
		PinByDigest:                     true,
		AuthorizedEnabled:               true,
		TrustDockerHubOfficial:          true,
		TrustedURLsText:                 strings.Join(defaultTrustedURLs(), "\n"),
		AuthorizedActionsUsePlumberList: true,
		CompositionChoices: []string{
			compHardcoded, compUpToDate, compForbidden, compRefCollision, compSecurity, compScripts, compJobVars, compDinD,
			compActionPin, compAuthorizedActions, compDangerousTriggers, compPRTargetHead, compDeclarePermissions, compReusableSecrets, compOverprovSecrets, compTemplateInjection,
			compEnvInjection, compWriteAllPerms, compRefConfusion, compArchivedActions, compKnownCVEs, compImpostorCommit, compMutableRemoteExec, compCachePoisoning, compDebugTraceGitHub,
		},
		ActionPinTrustedOwnersMultiline:        strings.Join(defaultGitHubTrustedActionOwners(), "\n"),
		SecurityJobPatternsGitHubMultiline:     strings.Join(defaultGitHubSecurityJobPatterns(), "\n"),
		ForbiddenVersionsMultiline:             strings.Join(defaultForbiddenVersions(), "\n"),
		DefaultBranchIsForbiddenVersion:        false,
		SecurityJobPatternsMultiline:           strings.Join(defaultSecurityJobPatterns(), "\n"),
		SecuritySubAllowFailure:                false,
		SecuritySubAllowFailureGitHub:          true,
		SecuritySubRules:                       true,
		SecuritySubRulesGitHub:                 true,
		SecuritySubWhenNotManual:               true,
		SecuritySubWhenNotManualGitHub:         true,
		DebugForbiddenVariablesGitHubMultiline: strings.Join(defaultGitHubDebugTraceVariables(), "\n"),
		JobOverrideVariablesMultiline:          strings.Join(defaultJobOverrideVariables(), "\n"),
		DinDDetectInsecureDaemon:               true,
		BranchEnabled:                          true,
		BranchPatterns:                         defaultBranchPatterns(),
		BranchDefaultMustBeProtected:           true,
		BranchAllowForcePush:                   false,
		BranchCodeOwnerApprovalRequired:        false,
		BranchCodeOwnerApprovalRequiredGitHub:  false,
		BranchMinMergeAccessLevel:              "30",
		BranchMinPushAccessLevel:               "40",
		DebugTraceEnabled:                      true,
		DebugForbiddenVariablesMultiline:       "CI_DEBUG_TRACE\nCI_DEBUG_SERVICES",
		UnsafeExpansionEnabled:                 true,
		DangerousVariablesMultiline:            strings.Join(defaultDangerousVariables(), "\n"),
		AllowedPatternsMultiline:               "",
	}
	return st.toPlumberConfig()
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
	starterBytes, err := yaml.Marshal(starterWizardConfig())
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
	cfg := starterWizardConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("starterWizardConfig: %v", err)
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
	gh := starterWizardConfig().GitHub.Controls

	if gh.WorkflowMustNotGrantPermissionsWriteAll == nil || !*gh.WorkflowMustNotGrantPermissionsWriteAll.Enabled {
		t.Error("write-all permissions control should be present and enabled")
	}
	if gh.ActionsMustNotBeArchived == nil || !*gh.ActionsMustNotBeArchived.Enabled {
		t.Error("archived-actions control should be present and enabled")
	}
	if gh.ActionsMustNotCarryKnownCVEs == nil || !*gh.ActionsMustNotCarryKnownCVEs.Enabled {
		t.Error("known-CVE control should be present and enabled")
	}
	if gh.ActionRefsMustExistUpstream == nil || !*gh.ActionRefsMustExistUpstream.Enabled {
		t.Error("impostor-commit control should be present and enabled")
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
		*gh.BranchMustBeProtected.CodeOwnerApprovalRequired {
		t.Error("github branch.codeOwnerApprovalRequired should default false (matches curated default; many first-run repos have no CODEOWNERS)")
	}

	if src := gh.GithubActionMustComeFromAuthorizedSources; src == nil {
		t.Error("authorized-actions control should be present")
	} else if src.MinimumStars != defaultTrustedActionsMinimumStars() || len(src.TrustedGithubActions) == 0 {
		t.Errorf("starter authorized-actions should ship the curated allowlist + star floor, got stars=%d list=%d", src.MinimumStars, len(src.TrustedGithubActions))
	}
}

// TestInitWizardEnablesImpostorCommit locks the compImpostorCommit ->
// ActionRefsMustExistUpstream mapping in toPlumberConfig: selecting the
// composition option must enable the control, and a run that does not
// select it must leave the control unset. Without this a mis-wired or
// dropped case in the wizard would silently stop enabling an ISSUE-707
// security control while the suite stayed green.
func TestInitWizardEnablesImpostorCommit(t *testing.T) {
	on := &initWizardState{
		Providers:          []string{"github"},
		Categories:         []string{catComposition},
		CompositionChoices: []string{compImpostorCommit},
	}
	if c := on.toPlumberConfig().GitHub.Controls.ActionRefsMustExistUpstream; c == nil || c.Enabled == nil || !*c.Enabled {
		t.Fatal("selecting compImpostorCommit must enable ActionRefsMustExistUpstream")
	}

	off := &initWizardState{
		Providers:          []string{"github"},
		Categories:         []string{catComposition},
		CompositionChoices: []string{compArchivedActions},
	}
	if c := off.toPlumberConfig().GitHub.Controls.ActionRefsMustExistUpstream; c != nil {
		t.Fatal("not selecting compImpostorCommit must leave ActionRefsMustExistUpstream unset")
	}
}

// The two toggles whose curated default differs per provider must keep
// the GitLab side at its (looser) shipped value when defaults are accepted.
func TestStarterPlumberConfigGitLabMatchesCuratedDefaults(t *testing.T) {
	gl := starterWizardConfig().GitLab.Controls

	// allow_failure stays off on GitLab: stock GitLab security templates ship
	// allow_failure: true, so flagging it would false-positive on every
	// template. The wizard must keep the curated default's looser value.
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
	// rules/when are ON in the curated GitLab default; the wizard must match
	// so zero-config and init users get the same GitLab security posture.
	if sj := gl.SecurityJobsMustNotBeWeakened; sj == nil ||
		sj.RulesMustNotBeRedefined == nil || !*sj.RulesMustNotBeRedefined.Enabled {
		t.Error("gitlab securityJobs.rulesMustNotBeRedefined should default true (matches curated default)")
	} else if !*sj.WhenMustNotBeManual.Enabled {
		t.Error("gitlab securityJobs.whenMustNotBeManual should default true (matches curated default)")
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
	for _, c := range []string{compSecurity, compDinD} {
		if !gMenu[c] || !hMenu[c] {
			t.Fatalf("cross-provider check %q missing from one side (gitlab: %v, github: %v)", c, gMenu[c], hMenu[c])
		}
	}
}
