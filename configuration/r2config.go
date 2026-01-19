package configuration

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// R2Config represents the .r2 configuration file structure
type R2Config struct {
	// Version of the config file format
	Version string `yaml:"version"`

	// Controls configuration
	Controls ControlsConfig `yaml:"controls"`
}

// ControlsConfig holds configuration for all controls
type ControlsConfig struct {
	// ImageMutable control configuration
	ImageMutable *ImageMutableControlConfig `yaml:"imageMutable,omitempty"`

	// ImageUntrusted control configuration
	ImageUntrusted *ImageUntrustedControlConfig `yaml:"imageUntrusted,omitempty"`

	// BranchProtection control configuration
	BranchProtection *BranchProtectionControlConfig `yaml:"branchProtection,omitempty"`
}

// ImageMutableControlConfig configuration for the mutable image tag control
type ImageMutableControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// MutableTags is a list of tags considered mutable
	MutableTags []string `yaml:"mutableTags,omitempty"`
}

// ImageUntrustedControlConfig configuration for the untrusted image control
type ImageUntrustedControlConfig struct {
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

// LoadR2Config loads configuration from a file path
// The config file is REQUIRED - returns error if not found
// If configPath is empty, looks for .r2 or .r2.yaml in current directory
func LoadR2Config(configPath string) (*R2Config, string, error) {
	l := logrus.WithField("action", "LoadR2Config")

	// If no path specified, try to find .r2 or .r2.yaml in current directory
	if configPath == "" {
		cwd, err := os.Getwd()
		if err != nil {
			l.WithError(err).Error("Unable to get current directory")
			return nil, "", err
		}

		// Try different file names
		possiblePaths := []string{
			filepath.Join(cwd, ".r2"),
			filepath.Join(cwd, ".r2.yaml"),
			filepath.Join(cwd, ".r2.yml"),
			filepath.Join(cwd, "r2.yaml"),
			filepath.Join(cwd, "r2.yml"),
		}

		for _, path := range possiblePaths {
			if _, err := os.Stat(path); err == nil {
				configPath = path
				break
			}
		}
	}

	// Config file is required
	if configPath == "" {
		return nil, "", fmt.Errorf("no .r2 config file found. Please provide a config file with --config flag")
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
	config := &R2Config{}
	if err := yaml.Unmarshal(data, config); err != nil {
		l.WithError(err).Error("Failed to parse config file")
		return nil, configPath, err
	}

	l.WithField("config", config).Debug("Configuration loaded successfully")
	return config, configPath, nil
}

// GetImageMutableConfig returns the ImageMutable control configuration
// Returns nil if not configured
func (c *R2Config) GetImageMutableConfig() *ImageMutableControlConfig {
	if c == nil {
		return nil
	}
	return c.Controls.ImageMutable
}

// GetImageUntrustedConfig returns the ImageUntrusted control configuration
// Returns nil if not configured
func (c *R2Config) GetImageUntrustedConfig() *ImageUntrustedControlConfig {
	if c == nil {
		return nil
	}
	return c.Controls.ImageUntrusted
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *ImageMutableControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *ImageUntrustedControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetBranchProtectionConfig returns the BranchProtection control configuration
// Returns nil if not configured
func (c *R2Config) GetBranchProtectionConfig() *BranchProtectionControlConfig {
	if c == nil {
		return nil
	}
	return c.Controls.BranchProtection
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *BranchProtectionControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}
