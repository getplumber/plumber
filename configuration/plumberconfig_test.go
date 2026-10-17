package configuration

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"

	"github.com/getplumber/plumber/capability/capdecl"
	"github.com/getplumber/plumber/internal/ir"
)

// A missing config file must wrap ErrConfigNotFound so callers can detect the
// "no file" case with errors.Is and fall back to the embedded default. This
// locks the contract the zero-config fallback (analyze + config view) depends
// on: if the not-found path stops wrapping the sentinel, this test fails rather
// than the fallback silently regressing to an error.
func TestLoadPlumberConfig_MissingFileWrapsErrConfigNotFound(t *testing.T) {
	_, _, _, err := LoadPlumberConfig(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err == nil {
		t.Fatal("expected an error for a missing config file")
	}
	if !errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("missing file must wrap ErrConfigNotFound, got: %v", err)
	}
	// A parse/validation failure must NOT look like "not found".
	_, _, _, perr := LoadPlumberConfigFromBytes([]byte(":\tnot: valid: ["), "test")
	if perr == nil || errors.Is(perr, ErrConfigNotFound) {
		t.Fatalf("a parse error must not match ErrConfigNotFound, got: %v", perr)
	}
}

func TestLevenshteinDistance(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected int
	}{
		{
			name:     "identical strings",
			a:        "hello",
			b:        "hello",
			expected: 0,
		},
		{
			name:     "single character difference",
			a:        "hello",
			b:        "hallo",
			expected: 1,
		},
		{
			name:     "empty first string",
			a:        "",
			b:        "hello",
			expected: 5,
		},
		{
			name:     "empty second string",
			a:        "hello",
			b:        "",
			expected: 5,
		},
		{
			name:     "both empty",
			a:        "",
			b:        "",
			expected: 0,
		},
		{
			name:     "insertion",
			a:        "abc",
			b:        "abcd",
			expected: 1,
		},
		{
			name:     "deletion",
			a:        "abcd",
			b:        "abc",
			expected: 1,
		},
		{
			name:     "substitution",
			a:        "kitten",
			b:        "sitting",
			expected: 3,
		},
		{
			name:     "common typo - containerImage",
			a:        "containerImageMustNotUseForbiddenTags",
			b:        "containerImageMustNotUseForbiddenTag",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := levenshteinDistance(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("levenshteinDistance(%q, %q) = %d, want %d", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

func TestFindClosestMatch(t *testing.T) {
	validKeys := []string{
		"containerImageMustNotUseForbiddenTags",
		"containerImageMustComeFromAuthorizedSources",
		"branchMustBeProtected",
		"pipelineMustNotIncludeHardcodedJobs",
		"includesMustBeUpToDate",
		"includesMustNotUseForbiddenVersions",
		"pipelineMustIncludeComponent",
		"pipelineMustIncludeTemplate",
	}

	tests := []struct {
		name        string
		input       string
		expectMatch bool
		expectedKey string
	}{
		{
			name:        "exact match",
			input:       "containerImageMustNotUseForbiddenTags",
			expectMatch: true,
			expectedKey: "containerImageMustNotUseForbiddenTags",
		},
		{
			name:        "typo - missing 's' at end",
			input:       "containerImageMustNotUseForbiddenTag",
			expectMatch: true,
			expectedKey: "containerImageMustNotUseForbiddenTags",
		},
		{
			name:        "typo - wrong character",
			input:       "branchMustBeProtectod",
			expectMatch: true,
			expectedKey: "branchMustBeProtected",
		},
		{
			name:        "completely different string - no match",
			input:       "xyz123",
			expectMatch: false,
			expectedKey: "",
		},
		{
			name:        "similar but too different",
			input:       "containerMustNotUseTags",
			expectMatch: false,
			expectedKey: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindClosestMatch(tt.input, validKeys)
			if tt.expectMatch {
				if result != tt.expectedKey {
					t.Errorf("FindClosestMatch(%q) = %q, want %q", tt.input, result, tt.expectedKey)
				}
			} else {
				if result != "" {
					t.Errorf("FindClosestMatch(%q) = %q, want empty string", tt.input, result)
				}
			}
		})
	}
}

func TestValidateKnownKeys(t *testing.T) {
	tests := []struct {
		name           string
		yamlContent    string
		expectWarnings int
		wantContains   string
	}{
		{
			name: "valid config - no warnings",
			yamlContent: `
version: "1"
controls:
  containerImageMustNotUseForbiddenTags:
    enabled: true
  branchMustBeProtected:
    enabled: true
`,
			expectWarnings: 0,
		},
		{
			name: "unknown control key - typo missing 's'",
			yamlContent: `
version: "1"
controls:
  containerImageMustNotUseForbiddenTag:
    enabled: true
`,
			expectWarnings: 1,
			wantContains:   "containerImageMustNotUseForbiddenTags",
		},
		{
			name: "multiple unknown keys",
			yamlContent: `
version: "1"
controls:
  containerImageMustNotUseForbiddenTag:
    enabled: true
  branchMustBeProtectod:
    enabled: true
`,
			expectWarnings: 2,
		},
		{
			name: "completely unknown key",
			yamlContent: `
version: "1"
controls:
  someRandomControl:
    enabled: true
`,
			expectWarnings: 1,
		},
		{
			// pipelineMustNotLeakSecretsInConfig shipped until the
			// gitleaks integration was removed (#310). Configs that
			// still carry it must get the explicit "removed and
			// ignored" message, not the unknown-key suggestion path.
			name: "removed control key - explicit removal warning",
			yamlContent: `
version: "2.0"
gitlab:
  controls:
    pipelineMustNotLeakSecretsInConfig:
      enabled: true
`,
			expectWarnings: 1,
			wantContains:   "was removed and is now ignored",
		},
		{
			name: "unknown sub-key - tags typo",
			yamlContent: `
version: "1"
controls:
  containerImageMustNotUseForbiddenTags:
    enabled: true
    tag:
      - latest
`,
			expectWarnings: 1,
			wantContains:   "tags",
		},
		{
			name: "exemptImages sub-key - no warnings",
			yamlContent: `
version: "2.0"
github:
  controls:
    containerImageMustNotUseForbiddenTags:
      enabled: true
      tags: [latest]
      exemptImages:
        - ghcr.io/my-org/report-tool
`,
			expectWarnings: 0,
		},
		{
			name: "unknown sub-key - allowForcePush typo",
			yamlContent: `
version: "1"
controls:
  branchMustBeProtected:
    enabled: true
    allowForcePushes: false
`,
			expectWarnings: 1,
			wantContains:   "allowForcePush",
		},
		{
			name: "multiple sub-key typos in same control",
			yamlContent: `
version: "1"
controls:
  branchMustBeProtected:
    enabled: true
    namePattern:
      - main
    allowForcePushes: false
`,
			expectWarnings: 2,
		},
		{
			name: "typo at both control and sub-key level",
			yamlContent: `
version: "1"
controls:
  containerImageMustNotUseForbiddenTag:
    enabled: true
  branchMustBeProtected:
    enabled: true
    allowForcePushes: false
`,
			expectWarnings: 2,
		},
		{
			name: "valid sub-keys - no warnings",
			yamlContent: `
version: "1"
controls:
  branchMustBeProtected:
    enabled: true
    namePatterns:
      - main
    defaultMustBeProtected: true
    allowForcePush: false
    codeOwnerApprovalRequired: false
    minMergeAccessLevel: 30
    minPushAccessLevel: 40
`,
			expectWarnings: 0,
		},
		{
			name: "completely unknown sub-key",
			yamlContent: `
version: "1"
controls:
  includesMustBeUpToDate:
    enabled: true
    somethingTotallyRandom: true
`,
			expectWarnings: 1,
		},
		{
			name:           "invalid yaml - no warnings returned",
			yamlContent:    `{{{invalid yaml`,
			expectWarnings: 0,
		},
		{
			name: "empty controls section - no warnings",
			yamlContent: `
version: "1"
controls: {}
`,
			expectWarnings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := ValidateKnownKeys([]byte(tt.yamlContent))
			if len(warnings) != tt.expectWarnings {
				t.Errorf("ValidateKnownKeys() returned %d warnings, want %d. Warnings: %v",
					len(warnings), tt.expectWarnings, warnings)
			}
			if tt.wantContains != "" && len(warnings) > 0 {
				found := false
				for _, w := range warnings {
					if strings.Contains(w, tt.wantContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected warning to contain %q, but got: %v", tt.wantContains, warnings)
				}
			}
		})
	}
}

func TestValidControlNames(t *testing.T) {
	names := ValidControlNames()

	expected := []string{
		"actionRefsMustExistUpstream",
		"actionsMustBePinnedByCommitSha",
		"actionsMustNotBeArchived",
		"actionsMustNotCarryKnownCVEs",
		"actionsMustNotExecuteMutableRemoteCode",
		"branchMustBeProtected",
		"checkoutMustNotPersistCredentials",
		"cicdVariablesMustBeMasked",
		"cicdVariablesMustBeProtected",
		"componentMustComeFromAuthorizedSources",
		"containerImageMustComeFromAuthorizedSources",
		"containerImageMustNotUseForbiddenTags",
		"externalRefsMustNotCollide",
		"functionMustComeFromAuthorizedSources",
		"githubActionMustComeFromAuthorizedSources",
		"includesMustBeUpToDate",
		"includesMustNotUseForbiddenVersions",
		"mergeRequestApprovalRulesMustCoverAllProtectedBranches",
		"mergeRequestApprovalRulesMustRequireMinimumApprovals",
		"mergeRequestApprovalSettingsMustBeCompliant",
		"mergeRequestSettingsMustBeCompliant",
		"pipelineMustIncludeComponent",
		"pipelineMustIncludeTemplate",
		"pipelineMustNotEnableDebugTrace",
		"pipelineMustNotExecuteUnverifiedScripts",
		"pipelineMustNotIncludeHardcodedJobs",
		"pipelineMustNotOverrideJobVariables",
		"pipelineMustNotUseDockerInDocker",
		"pipelineMustNotUseUnsafeVariableExpansion",
		"projectMustHaveSecurityPolicySource",
		"pullRequestTargetMustNotCheckoutHead",
		"releaseWorkflowsMustNotRestoreUntrustedCache",
		"reusableWorkflowsMustNotInheritSecrets",
		"securityJobsMustNotBeWeakened",
		"workflowMustIncludeRequiredActions",
		"workflowMustNotExportEntireSecretsContext",
		"workflowMustNotGrantPermissionsWriteAll",
		"workflowMustNotInjectUserInputInScripts",
		"workflowMustNotUseDangerousTriggers",
		"workflowMustNotWriteUntrustedContentToGitHubEnv",
		"workflowsMustDeclarePermissions",
	}

	if len(names) != len(expected) {
		t.Fatalf("ValidControlNames() returned %d entries, want %d (%v)", len(names), len(expected), names)
	}

	for i := range expected {
		if names[i] != expected[i] {
			t.Fatalf("ValidControlNames()[%d] = %q, want %q", i, names[i], expected[i])
		}
	}
}

// behaviorWhenCommitIsAdded is validated AT CONFIG LOAD because the Rego rule
// looks the value up in a rank map: an unknown string would make the lookup
// undefined and silently disable the check, so a typo must fail loudly here
// instead.
func TestMRApprovalSettingsBehaviorValidation(t *testing.T) {
	valid := "remove_all_approvals"
	invalid := "keep-approvals" // dash, not underscore: the plausible typo
	enabled := true

	mk := func(behavior *string) *PlumberConfig {
		return &PlumberConfig{
			Version: "2.0",
			GitLab: &ProviderConfig{Controls: ControlsConfig{
				MergeRequestApprovalSettingsMustBeCompliant: &MRApprovalSettingsControlConfig{
					Enabled:                   &enabled,
					BehaviorWhenCommitIsAdded: behavior,
				},
			}},
		}
	}

	if err := mk(nil).Validate(); err != nil {
		t.Fatalf("unset behavior expectation must validate, got %v", err)
	}
	if err := mk(&valid).Validate(); err != nil {
		t.Fatalf("valid behavior expectation must validate, got %v", err)
	}
	err := mk(&invalid).Validate()
	if err == nil {
		t.Fatal("an unknown behaviorWhenCommitIsAdded value must fail config validation, not silently disable the check")
	}
	if !strings.Contains(err.Error(), invalid) || !strings.Contains(err.Error(), "remove_approvals_by_code_owners") {
		t.Fatalf("the error must name the bad value and the accepted ladder, got %v", err)
	}
}

// mergeMethod and squashOption are validated AT CONFIG LOAD because the Rego
// rule compares them for exact equality against GitLab's value: an unknown
// expectation would never equal a real setting and would flag every project, so
// a typo must fail loudly here instead.
func TestMRSettingsEnumValidation(t *testing.T) {
	enabled := true
	strPtr := func(s string) *string { return &s }
	mk := func(mutate func(*MRSettingsControlConfig)) *PlumberConfig {
		c := &MRSettingsControlConfig{Enabled: &enabled}
		mutate(c)
		return &PlumberConfig{Version: "2.0", GitLab: &ProviderConfig{Controls: ControlsConfig{
			MergeRequestSettingsMustBeCompliant: c,
		}}}
	}

	if err := mk(func(c *MRSettingsControlConfig) {}).Validate(); err != nil {
		t.Fatalf("unset enum expectations must validate, got %v", err)
	}
	if err := mk(func(c *MRSettingsControlConfig) {
		c.MergeMethod = strPtr("ff")
		c.SquashOption = strPtr("default_on")
	}).Validate(); err != nil {
		t.Fatalf("valid enum expectations must validate, got %v", err)
	}
	err := mk(func(c *MRSettingsControlConfig) { c.MergeMethod = strPtr("squash") }).Validate()
	if err == nil || !strings.Contains(err.Error(), "squash") || !strings.Contains(err.Error(), "rebase_merge") {
		t.Fatalf("an unknown mergeMethod must fail validation naming the bad value and the accepted set, got %v", err)
	}
	err = mk(func(c *MRSettingsControlConfig) { c.SquashOption = strPtr("sometimes") }).Validate()
	if err == nil || !strings.Contains(err.Error(), "sometimes") || !strings.Contains(err.Error(), "default_off") {
		t.Fatalf("an unknown squashOption must fail validation naming the bad value and the accepted set, got %v", err)
	}
}

// The configuration package validates behaviorWhenCommitIsAdded against its
// own list while the projection emits the ir.MRApprovalBehavior* constants;
// this pins the two so they cannot drift (a value the projection emits but
// validation rejects would make a correct config impossible to write).
func TestMRApprovalBehaviorValuesMatchIR(t *testing.T) {
	want := []string{
		ir.MRApprovalBehaviorKeepApprovals,
		ir.MRApprovalBehaviorRemoveCodeOwnerApprovals,
		ir.MRApprovalBehaviorRemoveAllApprovals,
	}
	if len(mrApprovalBehaviorValues) != len(want) {
		t.Fatalf("mrApprovalBehaviorValues has %d entries, want %d", len(mrApprovalBehaviorValues), len(want))
	}
	for i, v := range want {
		if mrApprovalBehaviorValues[i] != v {
			t.Fatalf("mrApprovalBehaviorValues[%d] = %q, want the IR constant %q (strictness order matters)", i, mrApprovalBehaviorValues[i], v)
		}
	}
}

func TestIsIncludePlumberDefaultsDefaultsTrue(t *testing.T) {
	var action *ActionAuthorizedSourcesControlConfig
	if !action.IsIncludePlumberDefaults() {
		t.Fatal("nil action config should default to true")
	}
	f := false
	action = &ActionAuthorizedSourcesControlConfig{IncludePlumberDefaults: &f}
	if action.IsIncludePlumberDefaults() {
		t.Fatal("explicit false should be false")
	}

	var image *ImageAuthorizedSourcesControlConfig
	if !image.IsIncludePlumberDefaults() {
		t.Fatal("nil image config should default to true")
	}
}

func TestIncludePlumberDefaultsIsAKnownSubKey(t *testing.T) {
	cfg := []byte(`github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      enabled: true
      includePlumberDefaults: false
      trustedGithubActions:
        - myorg
`)
	warnings := ValidateKnownKeys(cfg)
	for _, w := range warnings {
		if strings.Contains(w, "includePlumberDefaults") {
			t.Fatalf("includePlumberDefaults flagged as unknown: %q", w)
		}
	}
}

// exemptImages loads on both providers as written: a plain user list,
// with no curated base to union it with.
func TestLoadPlumberConfigFromBytes_ExemptImages(t *testing.T) {
	data := []byte(`version: "2.0"
gitlab:
  controls:
    containerImageMustNotUseForbiddenTags:
      enabled: true
      exemptImages: [registry.example.com/team/tool]
github:
  controls:
    containerImageMustNotUseForbiddenTags:
      enabled: true
      exemptImages: [ghcr.io/my-org/report-tool, debian]
`)
	cfg, _, warnings, err := LoadPlumberConfigFromBytes(data, "exempt-images")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if got := cfg.ControlsFor("gitlab").ContainerImageMustNotUseForbiddenTags.ExemptImages; strings.Join(got, ",") != "registry.example.com/team/tool" {
		t.Errorf("gitlab exemptImages = %v", got)
	}
	if got := cfg.ControlsFor("github").ContainerImageMustNotUseForbiddenTags.ExemptImages; strings.Join(got, ",") != "ghcr.io/my-org/report-tool,debian" {
		t.Errorf("github exemptImages = %v", got)
	}
}

// Spec 4.2/4.6: .plumber.yaml carries the same capabilities schema as the org setting; a
// well-formed capabilities key loads into PlumberConfig.Capabilities.
func TestLoadPlumberConfigFromBytes_Capabilities(t *testing.T) {
	data := []byte(`version: "2.0"
capabilities:
  - name: secret_detection
    recognizers:
      - tool: gitleaks
        images: ["*gitleaks*"]
        commands: ["*gitleaks*"]
`)
	cfg, _, warnings, err := LoadPlumberConfigFromBytes(data, "capabilities")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	decls := decodedCapabilities(t, cfg)
	if len(decls) != 1 || decls[0].Name != "secret_detection" ||
		len(decls[0].Recognizers) != 1 || decls[0].Recognizers[0].Tool != "gitleaks" {
		t.Fatalf("Capabilities = %+v", decls)
	}
}

// decodedCapabilities re-encodes the raw capabilities value the load kept and decodes it
// strictly, the way provider.CapabilitiesOf does.
func decodedCapabilities(t *testing.T, cfg *PlumberConfig) []capdecl.Declaration {
	t.Helper()
	data, err := yaml.Marshal(map[string]interface{}{"capabilities": cfg.Capabilities})
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	decls, err := capdecl.DecodeYAML(data)
	if err != nil {
		t.Fatalf("strict decode: %v", err)
	}
	return decls
}

// Spec 4.2 and 7: the load keeps the capabilities key raw, so a malformed key (a typo, a
// wrong type, a map instead of a list) never fails the configuration load, in either mode;
// the strict decode and its one warning happen when the effective list is built.
func TestLoadPlumberConfigFromBytes_MalformedCapabilitiesNeverFailTheLoad(t *testing.T) {
	for name, text := range map[string]string{
		"typo key":          "capabilities:\n  - name: secret_detection\n    recognizers:\n      - image: [\"*gitleaks*\"]\n",
		"wrong-typed field": "capabilities:\n  - name: secret_detection\n    recognizers:\n      - images: \"*foo*\"\n",
		"a map, not a list": "capabilities:\n  name: secret_detection\n",
		"a scalar":          "capabilities: yes\n",
	} {
		cfg, _, _, err := LoadPlumberConfigFromBytes([]byte("version: \"2.0\"\n"+text), name)
		if err != nil || cfg == nil || cfg.Capabilities == nil {
			t.Errorf("%s: load = %v, %v; want the key kept raw and no error", name, cfg, err)
		}
	}
}

// A file without the capabilities key leaves PlumberConfig.Capabilities nil (the CLI fills
// in the built-in list itself, spec 4.2; the field is not defaulted here).
func TestLoadPlumberConfigFromBytes_NoCapabilitiesKeyLeavesNil(t *testing.T) {
	cfg, _, _, err := LoadPlumberConfigFromBytes([]byte(`version: "2.0"`), "no-capabilities")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Capabilities != nil {
		t.Fatalf("Capabilities = %+v, want nil", cfg.Capabilities)
	}
}

// ValidateKnownKeys no longer walks the capabilities key: the strict decode when the
// effective list is built names an unknown key in its one warning (provider.CapabilitiesOf),
// so a load-time walk would warn twice for one typo.
func TestValidateKnownKeys_CapabilitiesLeftToTheStrictDecode(t *testing.T) {
	cfg := []byte(`capabilities:
  - name: secret_detection
    recognisers:
      - tool: gitleaks
        image: ["*gitleaks*"]
`)
	for _, w := range ValidateKnownKeys(cfg) {
		if strings.Contains(w, "capabilities") {
			t.Fatalf("unexpected load-time capabilities warning %q", w)
		}
	}
}

// The extends overlay (deepMergeYAML) replaces lists wholesale, so the capabilities key
// needs no special merge code: the overlay's own list, not a union with the base, is what
// the user gets (spec 4.2, configuration/merge.go).
func TestLoadPlumberConfigFromBytes_CapabilitiesOverlayReplacesWholesale(t *testing.T) {
	data := []byte(`version: "2.0"
extends: plumber:default
capabilities:
  - name: sast
    recognizers:
      - tool: semgrep
        commands: ["*semgrep*"]
`)
	cfg, _, _, err := LoadPlumberConfigFromBytes(data, "capabilities-overlay")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if decls := decodedCapabilities(t, cfg); len(decls) != 1 || decls[0].Name != "sast" {
		t.Fatalf("Capabilities = %+v, want exactly the overlay's own [sast]", decls)
	}
}
