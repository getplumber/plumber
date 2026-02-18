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
}

// validControlKeys returns the list of known control names.
func validControlNames() []string {
	keys := make([]string, 0, len(validControlSchema))
	for k := range validControlSchema {
		keys = append(keys, k)
	}
	return keys
}

// PlumberConfig represents the .plumber.yaml configuration file structure
type PlumberConfig struct {
	// Version of the config file format
	Version string `yaml:"version"`

	// Controls configuration
	Controls ControlsConfig `yaml:"controls"`
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

// LoadPlumberConfig loads configuration from a file path
// The config file path is required - returns error if empty or not found
func LoadPlumberConfig(configPath string) (*PlumberConfig, string, error) {
	l := logrus.WithField("action", "LoadPlumberConfig")

	if configPath == "" {
		return nil, "", fmt.Errorf("config file path is required")
	}

	l = l.WithField("configPath", configPath)
	l.Info("Loading configuration from file")

	// Read the file
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, configPath, fmt.Errorf("config file not found: %s", configPath)
		}
		l.WithError(err).Error("Failed to read config file")
		return nil, configPath, err
	}

	// Parse YAML
	config := &PlumberConfig{}
	if err := yaml.Unmarshal(data, config); err != nil {
		l.WithError(err).Error("Failed to parse config file")
		return nil, configPath, err
	}

	// Validate expression fields early to catch syntax errors at load time
	if err := config.validate(); err != nil {
		return nil, configPath, fmt.Errorf("configuration validation error: %w", err)
	}

	l.WithField("config", config).Debug("Configuration loaded successfully")
	return config, configPath, nil
}

// validate checks for configuration errors, including expression syntax
// and mutual exclusivity of 'required' vs 'requiredGroups'.
func (c *PlumberConfig) validate() error {
	if c == nil {
		return nil
	}

	// Validate pipelineMustIncludeComponent
	if comp := c.Controls.PipelineMustIncludeComponent; comp != nil {
		if _, err := comp.GetResolvedRequiredGroups(); err != nil {
			return err
		}
	}

	// Validate pipelineMustIncludeTemplate
	if tmpl := c.Controls.PipelineMustIncludeTemplate; tmpl != nil {
		if _, err := tmpl.GetResolvedRequiredGroups(); err != nil {
			return err
		}
	}

	return nil
}

// GetContainerImageMustNotUseForbiddenTagsConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetContainerImageMustNotUseForbiddenTagsConfig() *ImageForbiddenTagsControlConfig {
	if c == nil {
		return nil
	}
	return c.Controls.ContainerImageMustNotUseForbiddenTags
}

// GetContainerImageMustComeFromAuthorizedSourcesConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetContainerImageMustComeFromAuthorizedSourcesConfig() *ImageAuthorizedSourcesControlConfig {
	if c == nil {
		return nil
	}
	return c.Controls.ContainerImageMustComeFromAuthorizedSources
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
	return c.Controls.BranchMustBeProtected
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
	return c.Controls.PipelineMustNotIncludeHardcodedJobs
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
	return c.Controls.IncludesMustBeUpToDate
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
	return c.Controls.IncludesMustNotUseForbiddenVersions
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
	return c.Controls.PipelineMustIncludeComponent
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
	return c.Controls.PipelineMustIncludeTemplate
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

// findClosestMatch finds the closest matching valid key using Levenshtein distance
func findClosestMatch(unknownKey string, validKeys []string) string {
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

// ValidateKnownKeys checks for unknown configuration keys in .plumber.yaml
// at both the control level and the sub-key level.
// Returns a list of warning messages for unknown keys.
func ValidateKnownKeys(data []byte) []string {
	var raw map[interface{}]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil
	}

	var warnings []string

	controlsRaw, exists := raw["controls"]
	if !exists {
		return warnings
	}

	controls, ok := controlsRaw.(map[interface{}]interface{})
	if !ok {
		return warnings
	}

	knownNames := validControlNames()

	for keyRaw, valueRaw := range controls {
		controlName, ok := keyRaw.(string)
		if !ok {
			continue
		}

		// Check control name
		if !contains(knownNames, controlName) {
			suggestion := findClosestMatch(controlName, knownNames)
			if suggestion != "" {
				warnings = append(warnings,
					fmt.Sprintf("Unknown control in .plumber.yaml: %q. Did you mean %q?", controlName, suggestion))
			} else {
				warnings = append(warnings,
					fmt.Sprintf("Unknown control in .plumber.yaml: %q", controlName))
			}
			continue
		}

		// Check sub-keys within this control
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
				suggestion := findClosestMatch(subKey, validSubKeys)
				if suggestion != "" {
					warnings = append(warnings,
						fmt.Sprintf("Unknown key %q in control %q. Did you mean %q?", subKey, controlName, suggestion))
				} else {
					warnings = append(warnings,
						fmt.Sprintf("Unknown key %q in control %q", subKey, controlName))
				}
			}
		}
	}

	return warnings
}
