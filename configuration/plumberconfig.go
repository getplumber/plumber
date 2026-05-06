package configuration

import (
	"fmt"
	"os"
	"sort"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// validControlSchema maps each known control name to its valid sub-keys.
// When adding a new control, add its entry here to enable validation.
var validControlSchema = map[string][]string{
	"containerImageMustNotUseForbiddenTags": {
		"enabled", "tags", "containerImagesMustBePinnedByDigest",
	},
	"containerImageMustComeFromAuthorizedSources": {
		"enabled", "trustedUrls", "trustDockerHubOfficialImages",
	},
	"branchMustBeProtected": {
		"enabled", "namePatterns", "defaultMustBeProtected",
		"allowForcePush", "codeOwnerApprovalRequired",
		"minMergeAccessLevel", "minPushAccessLevel",
	},
	"pipelineMustNotIncludeHardcodedJobs": {
		"enabled",
	},
	"includesMustBeUpToDate": {
		"enabled",
	},
	"includesMustNotUseForbiddenVersions": {
		"enabled", "forbiddenVersions", "defaultBranchIsForbiddenVersion",
	},
	"pipelineMustIncludeComponent": {
		"enabled", "required", "requiredGroups",
	},
	"pipelineMustIncludeTemplate": {
		"enabled", "required", "requiredGroups",
	},
	"pipelineMustNotEnableDebugTrace": {
		"enabled", "forbiddenVariables",
	},
	"pipelineMustNotUseUnsafeVariableExpansion": {
		"enabled", "dangerousVariables", "allowedPatterns",
	},
	"securityJobsMustNotBeWeakened": {
		"enabled", "securityJobPatterns",
		"allowFailureMustBeFalse", "rulesMustNotBeRedefined", "whenMustNotBeManual",
	},
	"pipelineMustNotExecuteUnverifiedScripts": {
		"enabled", "trustedUrls",
	},
	"pipelineMustNotOverrideJobVariables": {
		"enabled", "variables",
	},
	"pipelineMustNotUseDockerInDocker": {
		"enabled", "detectInsecureDaemon",
	},
	"actionsMustBePinnedByCommitSha": {
		"enabled", "trustedOwners",
	},
	"workflowMustNotInjectUserInputInScripts": {
		"enabled",
	},
	"workflowMustNotUseDangerousTriggers": {
		"enabled",
	},
	"workflowsMustDeclarePermissions": {
		"enabled",
	},
	"reusableWorkflowsMustNotInheritSecrets": {
		"enabled",
	},
}

// validControlKeys returns the list of known control names.
func validControlNames() []string {
	keys := make([]string, 0, len(validControlSchema))
	for k := range validControlSchema {
		keys = append(keys, k)
	}
	return keys
}

// ValidControlNames returns all known control names from the configuration schema.
func ValidControlNames() []string {
	names := validControlNames()
	sort.Strings(names)
	return names
}

// ValidFlatKeys returns every valid flattened key path recognized by the
// schema, e.g. "controls.branchMustBeProtected.enabled". This includes
// keys that may be commented out in the default config file.
func ValidFlatKeys() map[string]struct{} {
	keys := make(map[string]struct{})
	for control, subKeys := range validControlSchema {
		for _, sub := range subKeys {
			keys["controls."+control+"."+sub] = struct{}{}
		}
	}
	return keys
}

// PlumberConfig represents the .plumber.yaml configuration file structure.
//
// Schema versions:
//   - "2.0" — current per-provider schema (gitlab.controls, github.controls).
//   - "1.0" — legacy flat schema (top-level controls). Auto-converted in
//     memory at load time with a deprecation warning. Run
//     `plumber config migrate` to upgrade the file on disk.
//
// The legacy v1 fields (Controls) remain on the struct so the loader can
// detect a v1 file, parse it, and convert it via convertV1ToV2. After a
// v2 load — or after conversion — Controls is the zero value and
// downstream code reads from GitLab.Controls / GitHub.Controls.
type PlumberConfig struct {
	// Version of the config file format.
	// "2.0" = current per-provider schema. "1.0" = legacy flat schema.
	// Missing version is tolerated and treated as legacy.
	Version string `yaml:"version,omitempty"`

	// GitLab provider section (v2 schema). Holds GitLab-specific auth,
	// the enabledControls allowlist, and the per-control configuration map.
	GitLab *ProviderConfig `yaml:"gitlab,omitempty"`

	// GitHub provider section (v2 schema). Same shape as GitLab.
	GitHub *ProviderConfig `yaml:"github,omitempty"`

	// Controls configuration (legacy v1 schema, top-level).
	// After a v2 load this is the zero value; after a v1 load convertV1ToV2
	// moves these into GitLab.Controls and clears this field.
	Controls ControlsConfig `yaml:"controls,omitempty"`
}

// ProviderConfig is the per-provider configuration block introduced in
// schema v2. One instance per provider section in .plumber.yaml.
//
// Toggle semantics mirror the GitLab side: a control absent from
// `controls:` is treated as enabled at the filter level; a control
// present with `enabled: false` is dropped. The dev-side `bench` set
// in control/registry.go suppresses non-production controls
// regardless of YAML state — see that file for how to promote a
// benched control out of bench.
type ProviderConfig struct {
	// Auth holds provider-specific authentication knobs. Optional.
	// Today only GitHub uses this (RequireAuth). Reserved for future
	// per-provider auth options on GitLab if needed.
	Auth *AuthConfig `yaml:"auth,omitempty"`

	// Controls holds per-control configuration. Same struct types as
	// the legacy top-level ControlsConfig — only the YAML location and
	// the values differ between providers.
	Controls ControlsConfig `yaml:"controls,omitempty"`
}

// AuthConfig holds per-provider authentication knobs. Currently only
// GitHub uses this; the type is provider-agnostic so GitLab can adopt
// it later without a schema change.
type AuthConfig struct {
	// RequireAuth, when true, makes the analyze command exit non-zero
	// if no provider credentials are available. Default false on GitHub
	// (soft-degrade with visible banner, matching `gh` CLI ergonomics).
	// Has no effect on GitLab today (GitLab already hard-fails without
	// a token via CLI flag / env).
	RequireAuth *bool `yaml:"requireAuth,omitempty"`
}

// IsRequireAuth returns whether requireAuth is set to true.
// Defaults to false when the section, the field, or the auth block is nil.
func (a *AuthConfig) IsRequireAuth() bool {
	if a == nil || a.RequireAuth == nil {
		return false
	}
	return *a.RequireAuth
}

// ControlsConfig holds configuration for all controls
type ControlsConfig struct {
	// ContainerImageMustNotUseForbiddenTags control configuration
	ContainerImageMustNotUseForbiddenTags *ImageForbiddenTagsControlConfig `yaml:"containerImageMustNotUseForbiddenTags,omitempty"`

	// ContainerImageMustComeFromAuthorizedSources control configuration
	ContainerImageMustComeFromAuthorizedSources *ImageAuthorizedSourcesControlConfig `yaml:"containerImageMustComeFromAuthorizedSources,omitempty"`

	// BranchMustBeProtected control configuration
	BranchMustBeProtected *BranchProtectionControlConfig `yaml:"branchMustBeProtected,omitempty"`

	// PipelineMustNotIncludeHardcodedJobs control configuration
	PipelineMustNotIncludeHardcodedJobs *HardcodedJobsControlConfig `yaml:"pipelineMustNotIncludeHardcodedJobs,omitempty"`

	// IncludesMustBeUpToDate control configuration
	IncludesMustBeUpToDate *IncludesUpToDateControlConfig `yaml:"includesMustBeUpToDate,omitempty"`

	// IncludesMustNotUseForbiddenVersions control configuration
	IncludesMustNotUseForbiddenVersions *IncludesForbiddenVersionsControlConfig `yaml:"includesMustNotUseForbiddenVersions,omitempty"`

	// PipelineMustIncludeComponent control configuration
	PipelineMustIncludeComponent *RequiredComponentsControlConfig `yaml:"pipelineMustIncludeComponent,omitempty"`

	// PipelineMustIncludeTemplate control configuration
	PipelineMustIncludeTemplate *RequiredTemplatesControlConfig `yaml:"pipelineMustIncludeTemplate,omitempty"`

	// PipelineMustNotEnableDebugTrace control configuration
	PipelineMustNotEnableDebugTrace *DebugTraceControlConfig `yaml:"pipelineMustNotEnableDebugTrace,omitempty"`

	// PipelineMustNotUseUnsafeVariableExpansion control configuration
	PipelineMustNotUseUnsafeVariableExpansion *VariableInjectionControlConfig `yaml:"pipelineMustNotUseUnsafeVariableExpansion,omitempty"`

	// SecurityJobsMustNotBeWeakened control configuration
	SecurityJobsMustNotBeWeakened *SecurityJobsWeakenedControlConfig `yaml:"securityJobsMustNotBeWeakened,omitempty"`

	// PipelineMustNotExecuteUnverifiedScripts control configuration
	PipelineMustNotExecuteUnverifiedScripts *UnverifiedScriptsControlConfig `yaml:"pipelineMustNotExecuteUnverifiedScripts,omitempty"`

	// PipelineMustNotOverrideJobVariables control configuration
	PipelineMustNotOverrideJobVariables *JobVariablesOverrideControlConfig `yaml:"pipelineMustNotOverrideJobVariables,omitempty"`

	// PipelineMustNotUseDockerInDocker control configuration
	PipelineMustNotUseDockerInDocker *DockerInDockerControlConfig `yaml:"pipelineMustNotUseDockerInDocker,omitempty"`

	// ActionsMustBePinnedByCommitSha control configuration (GitHub Actions only)
	ActionsMustBePinnedByCommitSha *ActionsPinnedByShaControlConfig `yaml:"actionsMustBePinnedByCommitSha,omitempty"`

	// WorkflowMustNotInjectUserInputInScripts control configuration (GitHub Actions only).
	// Config-free; toggle via `enabled`.
	WorkflowMustNotInjectUserInputInScripts *EnabledOnlyControlConfig `yaml:"workflowMustNotInjectUserInputInScripts,omitempty"`

	// WorkflowMustNotUseDangerousTriggers control configuration (GitHub Actions only).
	// Config-free; toggle via `enabled`.
	WorkflowMustNotUseDangerousTriggers *EnabledOnlyControlConfig `yaml:"workflowMustNotUseDangerousTriggers,omitempty"`

	// WorkflowsMustDeclarePermissions control configuration (GitHub Actions only).
	// Config-free; toggle via `enabled`.
	WorkflowsMustDeclarePermissions *EnabledOnlyControlConfig `yaml:"workflowsMustDeclarePermissions,omitempty"`

	// ReusableWorkflowsMustNotInheritSecrets control configuration (GitHub Actions only).
	// Config-free; toggle via `enabled`.
	ReusableWorkflowsMustNotInheritSecrets *EnabledOnlyControlConfig `yaml:"reusableWorkflowsMustNotInheritSecrets,omitempty"`
}

// EnabledOnlyControlConfig is the shape used for controls that have no
// configurable behaviour beyond on/off. The Rego rule for these controls
// reads no `input.config.<name>` keys; toggling enabled to false simply
// drops their findings via FilterFindingsByEnabledControls.
type EnabledOnlyControlConfig struct {
	Enabled *bool `yaml:"enabled,omitempty"`
}

// IsEnabled reports whether the control is enabled. Returns false when
// the wrapper or the field is nil — same convention as every other
// IsEnabled() in this package.
func (c *EnabledOnlyControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// ActionsPinnedByShaControlConfig configures the GitHub Actions supply-
// chain pinning check (ISSUE-104). Only meaningful on GitHub workflows.
type ActionsPinnedByShaControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// TrustedOwners lists action-owner prefixes that are exempt from the
	// pin-by-SHA requirement. Only owners inside the workflow's existing
	// trust boundary should be listed here — "actions" and "github"
	// cover the first-party GitHub-owned actions the runtime trusts
	// implicitly. Adding a third-party owner here re-opens the exact
	// supply-chain risk the check exists to close.
	TrustedOwners []string `yaml:"trustedOwners,omitempty"`
}

// IsEnabled returns whether the control is enabled
func (c *ActionsPinnedByShaControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// ImageForbiddenTagsControlConfig configuration for the forbidden image tags control
type ImageForbiddenTagsControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// Tags is a list of forbidden tags (e.g., latest, dev)
	Tags []string `yaml:"tags,omitempty"`

	// ContainerImagesMustBePinnedByDigest when true, ALL images must use immutable digest references.
	// Takes precedence over the forbidden tags list — any image not pinned by digest is flagged.
	ContainerImagesMustBePinnedByDigest *bool `yaml:"containerImagesMustBePinnedByDigest,omitempty"`
}

// IsPinnedByDigestRequired returns whether all images must be pinned by digest
func (c *ImageForbiddenTagsControlConfig) IsPinnedByDigestRequired() bool {
	if c == nil || c.ContainerImagesMustBePinnedByDigest == nil {
		return false
	}
	return *c.ContainerImagesMustBePinnedByDigest
}

// ImageAuthorizedSourcesControlConfig configuration for the authorized image sources control
type ImageAuthorizedSourcesControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// TrustedUrls is a list of trusted registry URLs/patterns (supports wildcards)
	TrustedUrls []string `yaml:"trustedUrls,omitempty"`

	// TrustDockerHubOfficialImages trusts official Docker Hub images (e.g., nginx, alpine)
	TrustDockerHubOfficialImages *bool `yaml:"trustDockerHubOfficialImages,omitempty"`
}

// BranchProtectionControlConfig configuration for the branch protection control
type BranchProtectionControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// NamePatterns is a list of branch name patterns that must be protected (supports wildcards)
	NamePatterns []string `yaml:"namePatterns,omitempty"`

	// DefaultMustBeProtected requires the default branch to be protected
	DefaultMustBeProtected *bool `yaml:"defaultMustBeProtected,omitempty"`

	// AllowForcePush when false, force push must be disabled on protected branches
	AllowForcePush *bool `yaml:"allowForcePush,omitempty"`

	// CodeOwnerApprovalRequired when true, code owner approval is required
	CodeOwnerApprovalRequired *bool `yaml:"codeOwnerApprovalRequired,omitempty"`

	// MinMergeAccessLevel minimum access level required to merge (0=No one, 30=Developer, 40=Maintainer)
	MinMergeAccessLevel *int `yaml:"minMergeAccessLevel,omitempty"`

	// MinPushAccessLevel minimum access level required to push (0=No one, 30=Developer, 40=Maintainer)
	MinPushAccessLevel *int `yaml:"minPushAccessLevel,omitempty"`
}

// HardcodedJobsControlConfig configuration for the hardcoded jobs control
type HardcodedJobsControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`
}

// IncludesUpToDateControlConfig configuration for the includes up-to-date control
type IncludesUpToDateControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`
}

// IncludesForbiddenVersionsControlConfig configuration for the forbidden versions control
type IncludesForbiddenVersionsControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// ForbiddenVersions is a list of version patterns considered forbidden (e.g., latest, main, HEAD)
	ForbiddenVersions []string `yaml:"forbiddenVersions,omitempty"`

	// DefaultBranchIsForbiddenVersion when true, adds the project's default branch to forbidden versions
	DefaultBranchIsForbiddenVersion *bool `yaml:"defaultBranchIsForbiddenVersion,omitempty"`
}

// RequiredComponentsControlConfig configuration for the required components control
type RequiredComponentsControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// Required is a human-readable boolean expression defining required components.
	// Supports AND, OR operators and parentheses for grouping.
	// AND has higher precedence than OR.
	//
	// Examples:
	//   "components/sast/sast AND components/secret-detection/secret-detection"
	//   "(components/sast/sast AND components/secret-detection/secret-detection) OR your-org/full-security/full-security"
	Required string `yaml:"required,omitempty"`

	// RequiredGroups uses DNF (Disjunctive Normal Form) format:
	// Outer array = OR (at least one group must be satisfied)
	// Inner array = AND (all components in group must be present)
	// Example: [["comp-a", "comp-b"], ["comp-c"]] means:
	//   "must have (comp-a AND comp-b) OR (comp-c)"
	//
	// Cannot be used together with 'required'.
	RequiredGroups [][]string `yaml:"requiredGroups,omitempty"`
}

// GetResolvedRequiredGroups returns the effective required groups by resolving
// either the 'required' expression or the 'requiredGroups' field.
// Returns an error if both are set or if the expression is invalid.
func (c *RequiredComponentsControlConfig) GetResolvedRequiredGroups() ([][]string, error) {
	if c == nil {
		return nil, nil
	}
	hasExpression := c.Required != ""
	hasGroups := len(c.RequiredGroups) > 0

	if hasExpression && hasGroups {
		return nil, fmt.Errorf("pipelineMustIncludeComponent: cannot use both 'required' and 'requiredGroups' — use only one")
	}
	if hasExpression {
		groups, err := ParseRequiredExpression(c.Required)
		if err != nil {
			return nil, fmt.Errorf("pipelineMustIncludeComponent: %w", err)
		}
		return groups, nil
	}
	return c.RequiredGroups, nil
}

// DebugTraceControlConfig configuration for the debug trace detection control
type DebugTraceControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// ForbiddenVariables is a list of CI/CD variable names that must not be set to "true"
	// Defaults: CI_DEBUG_TRACE, CI_DEBUG_SERVICES
	ForbiddenVariables []string `yaml:"forbiddenVariables,omitempty"`
}

// VariableInjectionControlConfig configuration for the unsafe variable expansion control
type VariableInjectionControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// DangerousVariables is a list of CI/CD variable names whose values come from user input
	// and should not appear in script blocks where shell injection is possible
	DangerousVariables []string `yaml:"dangerousVariables,omitempty"`

	// AllowedPatterns is a list of regex patterns. Script lines matching any of these
	// patterns will not be flagged even if they contain a dangerous variable.
	AllowedPatterns []string `yaml:"allowedPatterns,omitempty"`
}

// SecurityJobsWeakenedControlConfig configuration for the security jobs weakening control
type SecurityJobsWeakenedControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// SecurityJobPatterns is a list of job name patterns considered "security jobs" (supports wildcards)
	SecurityJobPatterns []string `yaml:"securityJobPatterns,omitempty"`

	// Sub-control toggles (sit directly under the control, no wrapper)
	AllowFailureMustBeFalse *SecurityJobsSubControlToggle `yaml:"allowFailureMustBeFalse,omitempty"`
	RulesMustNotBeRedefined *SecurityJobsSubControlToggle `yaml:"rulesMustNotBeRedefined,omitempty"`
	WhenMustNotBeManual     *SecurityJobsSubControlToggle `yaml:"whenMustNotBeManual,omitempty"`
}

// SecurityJobsSubControlToggle is a simple enabled/disabled toggle for a sub-control
type SecurityJobsSubControlToggle struct {
	Enabled *bool `yaml:"enabled,omitempty"`
}

// IsEnabled returns whether the sub-control toggle is enabled.
// Returns the provided default if the toggle or its Enabled field is nil.
func (t *SecurityJobsSubControlToggle) IsEnabled(defaultVal bool) bool {
	if t == nil || t.Enabled == nil {
		return defaultVal
	}
	return *t.Enabled
}

// UnverifiedScriptsControlConfig configuration for the unverified script execution control
type UnverifiedScriptsControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// TrustedUrls is a list of URL patterns that should not trigger findings.
	// Supports wildcards (e.g., "https://internal-artifacts.example.com/*").
	TrustedUrls []string `yaml:"trustedUrls,omitempty"`
}

// JobVariablesOverrideControlConfig configuration for the job variable override control
type JobVariablesOverrideControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// Variables is a list of CI/CD variable names that must not be defined
	// in the pipeline configuration file. They should only be set via
	// GitLab CI/CD Settings > Variables.
	Variables []string `yaml:"variables,omitempty"`
}

// DockerInDockerControlConfig configuration for the Docker-in-Docker detection control
type DockerInDockerControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// DetectInsecureDaemon when true, also flags insecure daemon configuration
	// (DOCKER_TLS_CERTDIR="" or DOCKER_HOST pointing to non-TLS port 2375)
	// in jobs that use a DinD service.
	DetectInsecureDaemon *bool `yaml:"detectInsecureDaemon,omitempty"`
}

// RequiredTemplatesControlConfig configuration for the required templates control
type RequiredTemplatesControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// Required is a human-readable boolean expression defining required templates.
	// Supports AND, OR operators and parentheses for grouping.
	// AND has higher precedence than OR.
	//
	// Examples:
	//   "templates/go/go AND templates/trivy/trivy"
	//   "(templates/go/go AND templates/trivy/trivy) OR templates/full-go-pipeline"
	Required string `yaml:"required,omitempty"`

	// RequiredGroups uses DNF (Disjunctive Normal Form) format:
	// Outer array = OR (at least one group must be satisfied)
	// Inner array = AND (all templates in group must be present)
	// Example: [["go", "helm"], ["go_helm_unified"]] means:
	//   "must have (go AND helm) OR (go_helm_unified)"
	//
	// Cannot be used together with 'required'.
	RequiredGroups [][]string `yaml:"requiredGroups,omitempty"`
}

// GetResolvedRequiredGroups returns the effective required groups by resolving
// either the 'required' expression or the 'requiredGroups' field.
// Returns an error if both are set or if the expression is invalid.
func (c *RequiredTemplatesControlConfig) GetResolvedRequiredGroups() ([][]string, error) {
	if c == nil {
		return nil, nil
	}
	hasExpression := c.Required != ""
	hasGroups := len(c.RequiredGroups) > 0

	if hasExpression && hasGroups {
		return nil, fmt.Errorf("pipelineMustIncludeTemplate: cannot use both 'required' and 'requiredGroups' — use only one")
	}
	if hasExpression {
		groups, err := ParseRequiredExpression(c.Required)
		if err != nil {
			return nil, fmt.Errorf("pipelineMustIncludeTemplate: %w", err)
		}
		return groups, nil
	}
	return c.RequiredGroups, nil
}

// LoadPlumberConfig loads configuration from a file path.
// It reads the file once, validates for unknown keys, parses
// the YAML into the config struct, detects whether the file uses
// the legacy v1 schema (top-level `controls:`/`engine:`) or the
// current v2 schema (per-provider `gitlab.controls:` /
// `github.controls:`), and converts v1 in-memory to v2.
// Returns the parsed config, the resolved path, any warnings
// (unknown-key + deprecation), and an error if loading or
// validation failed.
func LoadPlumberConfig(configPath string) (*PlumberConfig, string, []string, error) {
	l := logrus.WithField("action", "LoadPlumberConfig")

	if configPath == "" {
		return nil, "", nil, fmt.Errorf("config file path is required")
	}

	l = l.WithField("configPath", configPath)
	l.Info("Loading configuration from file")

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, configPath, nil, fmt.Errorf("config file not found: %s", configPath)
		}
		l.WithError(err).Error("Failed to read config file")
		return nil, configPath, nil, err
	}

	warnings := ValidateKnownKeys(data)

	config := &PlumberConfig{}
	if err := yaml.Unmarshal(data, config); err != nil {
		l.WithError(err).Error("Failed to parse config file")
		return nil, configPath, warnings, err
	}

	// Reject explicitly-set unsupported versions early. Empty version is
	// allowed (legacy default behaviour) and gets a deprecation warning
	// from convertV1ToV2. "1.0" is the legacy schema; "2.0" is current.
	if config.Version != "" && config.Version != "1.0" && config.Version != "2.0" {
		return nil, configPath, warnings, fmt.Errorf(
			"unsupported config version %q; supported: [\"1.0\" (legacy), \"2.0\" (current)]", config.Version)
	}

	// Detect a top-level `engine:` block in the raw YAML and emit a
	// deprecation warning. The block is no longer parsed into a Go
	// field — yaml.v2 silently ignores it — so this is the only place
	// the user gets feedback that their config has dead bytes.
	if rawHasTopLevelKey(data, "engine") {
		warnings = append(warnings,
			"engine.enabled has been removed in schema v1.0 and is now ignored. "+
				"Delete the 'engine' block from your .plumber.yaml.")
	}

	// Schema detection: presence of any provider section means the file is
	// v2-shaped. Otherwise it's legacy v1 — run the converter to promote
	// top-level controls under gitlab.controls. Mixed files (top-level
	// controls AND a provider section) also go through the converter,
	// where v2 wins for keys present on both sides.
	if config.GitLab == nil && config.GitHub == nil {
		warnings = append(warnings, convertV1ToV2(config)...)
	} else if !controlsConfigIsZero(config.Controls) {
		warnings = append(warnings, convertV1ToV2(config)...)
	}
	// At this point the in-memory config is v2-shaped. If the file did
	// not declare a version, or declared the legacy "1.0", normalise to
	// "2.0" so downstream consumers and re-emitters see the current value.
	if config.Version == "" || config.Version == "1.0" {
		config.Version = "2.0"
	}

	if err := config.validate(); err != nil {
		return nil, configPath, warnings, fmt.Errorf("configuration validation error: %w", err)
	}

	l.WithField("config", config).Debug("Configuration loaded successfully")
	return config, configPath, warnings, nil
}

// validate checks for configuration errors, including expression syntax
// and mutual exclusivity of 'required' vs 'requiredGroups'.
// In v2 (post-LoadPlumberConfig) the legacy top-level Controls is empty
// and provider sections carry the data; we still walk the legacy field
// defensively to cover code paths that build a PlumberConfig in-process
// without going through the loader.
func (c *PlumberConfig) validate() error {
	if c == nil {
		return nil
	}

	if err := validateControlsConfig(&c.Controls); err != nil {
		return err
	}
	if c.GitLab != nil {
		if err := validateControlsConfig(&c.GitLab.Controls); err != nil {
			return err
		}
	}
	if c.GitHub != nil {
		if err := validateControlsConfig(&c.GitHub.Controls); err != nil {
			return err
		}
	}
	return nil
}

// validateControlsConfig runs structural checks for any control whose
// configuration has cross-field constraints (e.g. mutual exclusivity).
// Provider-agnostic: same rules apply wherever the controls live.
func validateControlsConfig(c *ControlsConfig) error {
	if c == nil {
		return nil
	}
	if comp := c.PipelineMustIncludeComponent; comp != nil {
		if _, err := comp.GetResolvedRequiredGroups(); err != nil {
			return err
		}
	}
	if tmpl := c.PipelineMustIncludeTemplate; tmpl != nil {
		if _, err := tmpl.GetResolvedRequiredGroups(); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks structural consistency (required component/template expressions, etc.).
func (c *PlumberConfig) Validate() error {
	return c.validate()
}

// GetContainerImageMustNotUseForbiddenTagsConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetContainerImageMustNotUseForbiddenTagsConfig() *ImageForbiddenTagsControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").ContainerImageMustNotUseForbiddenTags
}

// GetContainerImageMustComeFromAuthorizedSourcesConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetContainerImageMustComeFromAuthorizedSourcesConfig() *ImageAuthorizedSourcesControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").ContainerImageMustComeFromAuthorizedSources
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *ImageForbiddenTagsControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *ImageAuthorizedSourcesControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetBranchMustBeProtectedConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetBranchMustBeProtectedConfig() *BranchProtectionControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").BranchMustBeProtected
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *BranchProtectionControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetPipelineMustNotIncludeHardcodedJobsConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetPipelineMustNotIncludeHardcodedJobsConfig() *HardcodedJobsControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").PipelineMustNotIncludeHardcodedJobs
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *HardcodedJobsControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetIncludesMustBeUpToDateConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetIncludesMustBeUpToDateConfig() *IncludesUpToDateControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").IncludesMustBeUpToDate
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *IncludesUpToDateControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetIncludesMustNotUseForbiddenVersionsConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetIncludesMustNotUseForbiddenVersionsConfig() *IncludesForbiddenVersionsControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").IncludesMustNotUseForbiddenVersions
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *IncludesForbiddenVersionsControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetPipelineMustIncludeComponentConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetPipelineMustIncludeComponentConfig() *RequiredComponentsControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").PipelineMustIncludeComponent
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *RequiredComponentsControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetPipelineMustIncludeTemplateConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetPipelineMustIncludeTemplateConfig() *RequiredTemplatesControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").PipelineMustIncludeTemplate
}

// GetPipelineMustNotEnableDebugTraceConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetPipelineMustNotEnableDebugTraceConfig() *DebugTraceControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").PipelineMustNotEnableDebugTrace
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *DebugTraceControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetPipelineMustNotUseUnsafeVariableExpansionConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetPipelineMustNotUseUnsafeVariableExpansionConfig() *VariableInjectionControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").PipelineMustNotUseUnsafeVariableExpansion
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *VariableInjectionControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetSecurityJobsMustNotBeWeakenedConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetSecurityJobsMustNotBeWeakenedConfig() *SecurityJobsWeakenedControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").SecurityJobsMustNotBeWeakened
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *SecurityJobsWeakenedControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetPipelineMustNotExecuteUnverifiedScriptsConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetPipelineMustNotExecuteUnverifiedScriptsConfig() *UnverifiedScriptsControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").PipelineMustNotExecuteUnverifiedScripts
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *UnverifiedScriptsControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetPipelineMustNotOverrideJobVariablesConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetPipelineMustNotOverrideJobVariablesConfig() *JobVariablesOverrideControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").PipelineMustNotOverrideJobVariables
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *JobVariablesOverrideControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetPipelineMustNotUseDockerInDockerConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetPipelineMustNotUseDockerInDockerConfig() *DockerInDockerControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").PipelineMustNotUseDockerInDocker
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *DockerInDockerControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// IsDetectInsecureDaemonEnabled returns whether insecure daemon detection is enabled.
// Defaults to true when the field is nil.
func (c *DockerInDockerControlConfig) IsDetectInsecureDaemonEnabled() bool {
	if c == nil || c.DetectInsecureDaemon == nil {
		return true
	}
	return *c.DetectInsecureDaemon
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *RequiredTemplatesControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// levenshteinDistance calculates the Levenshtein distance between two strings
func levenshteinDistance(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	// Create matrix
	matrix := make([][]int, len(a)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(b)+1)
	}

	// Initialize first column
	for i := 0; i <= len(a); i++ {
		matrix[i][0] = i
	}

	// Initialize first row
	for j := 0; j <= len(b); j++ {
		matrix[0][j] = j
	}

	// Fill in the rest
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(a)][len(b)]
}

func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// FindClosestMatch finds the closest matching valid key using Levenshtein distance.
// Returns an empty string if no reasonable match is found.
func FindClosestMatch(unknownKey string, validKeys []string) string {
	if len(validKeys) == 0 {
		return ""
	}

	type match struct {
		key      string
		distance int
	}

	matches := make([]match, len(validKeys))
	for i, key := range validKeys {
		matches[i] = match{key: key, distance: levenshteinDistance(unknownKey, key)}
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].distance < matches[j].distance
	})

	// Only suggest if distance is reasonable (less than half the key length)
	if matches[0].distance < len(unknownKey)/2+2 {
		return matches[0].key
	}
	return ""
}

// contains checks if a string is in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// rawHasTopLevelKey reports whether the raw YAML data has the named
// key at top level. Used to detect deprecated keys (e.g. "engine") that
// no longer have a Go-side struct field, so they would otherwise be
// silently dropped by yaml.Unmarshal.
func rawHasTopLevelKey(data []byte, name string) bool {
	var raw map[interface{}]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return false
	}
	_, ok := raw[name]
	return ok
}

// ValidateKnownKeys checks for unknown configuration keys in .plumber.yaml
// at both the control level and the sub-key level. It accepts both the
// legacy v1 schema (top-level `controls:`) and the v2 schema (provider-
// nested `gitlab.controls:` / `github.controls:`). Returns a list of
// warning messages for unknown keys, with suggestions where a close
// known key exists.
func ValidateKnownKeys(data []byte) []string {
	var raw map[interface{}]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil
	}

	var warnings []string

	// v1: top-level `controls:`.
	if controlsRaw, ok := raw["controls"]; ok {
		warnings = append(warnings, validateControlsBlock(controlsRaw, "controls")...)
	}

	// v2: per-provider nested `controls:`.
	for _, provider := range []string{"gitlab", "github"} {
		provRaw, ok := raw[provider]
		if !ok {
			continue
		}
		provMap, ok := provRaw.(map[interface{}]interface{})
		if !ok {
			continue
		}
		if controlsRaw, ok := provMap["controls"]; ok {
			prefix := provider + ".controls"
			warnings = append(warnings, validateControlsBlock(controlsRaw, prefix)...)
			warnings = append(warnings, validateControlsBlockProvider(controlsRaw, provider)...)
		}
	}

	return warnings
}

// validateControlsBlockProvider warns when a control listed under
// `gitlab.controls:` or `github.controls:` is not registered for that
// provider in controlsMeta. Catches typos like putting a GitHub-only
// control under gitlab.controls.
func validateControlsBlockProvider(controlsRaw interface{}, provider string) []string {
	controls, ok := controlsRaw.(map[interface{}]interface{})
	if !ok {
		return nil
	}
	var warnings []string
	for keyRaw := range controls {
		controlName, ok := keyRaw.(string)
		if !ok {
			continue
		}
		meta, known := controlsMeta[controlName]
		if !known {
			// validateControlsBlock already covers unknown names.
			continue
		}
		applies := false
		for _, p := range meta.Providers {
			if p == provider {
				applies = true
				break
			}
		}
		if !applies {
			warnings = append(warnings, fmt.Sprintf(
				"Control %q is not applicable to %s; valid providers: %v",
				controlName, provider, meta.Providers))
		}
	}
	return warnings
}

// validateControlsBlock validates an unmarshalled `controls:` block
// (whether at v1 root or under a v2 provider section). The pathPrefix
// is used in warning messages to point the user at the right YAML
// location, e.g. "controls" or "gitlab.controls".
func validateControlsBlock(controlsRaw interface{}, pathPrefix string) []string {
	controls, ok := controlsRaw.(map[interface{}]interface{})
	if !ok {
		return nil
	}

	var warnings []string
	knownNames := validControlNames()

	for keyRaw, valueRaw := range controls {
		controlName, ok := keyRaw.(string)
		if !ok {
			continue
		}

		if !contains(knownNames, controlName) {
			suggestion := FindClosestMatch(controlName, knownNames)
			if suggestion != "" {
				warnings = append(warnings,
					fmt.Sprintf("Unknown control in %s: %q. Did you mean %q?", pathPrefix, controlName, suggestion))
			} else {
				warnings = append(warnings,
					fmt.Sprintf("Unknown control in %s: %q", pathPrefix, controlName))
			}
			continue
		}

		subMap, ok := valueRaw.(map[interface{}]interface{})
		if !ok {
			continue
		}
		validSubKeys := validControlSchema[controlName]

		for subKeyRaw := range subMap {
			subKey, ok := subKeyRaw.(string)
			if !ok {
				continue
			}
			if !contains(validSubKeys, subKey) {
				suggestion := FindClosestMatch(subKey, validSubKeys)
				if suggestion != "" {
					warnings = append(warnings,
						fmt.Sprintf("Unknown key %q in control %q (%s). Did you mean %q?", subKey, controlName, pathPrefix, suggestion))
				} else {
					warnings = append(warnings,
						fmt.Sprintf("Unknown key %q in control %q (%s)", subKey, controlName, pathPrefix))
				}
			}
		}
	}

	return warnings
}
