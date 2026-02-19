package configuration

import (
	"time"

	"github.com/sirupsen/logrus"
)

// Configuration represents the simplified CLI configuration options
type Configuration struct {
	// GitLab connection settings
	GitlabURL   string // URL of the GitLab instance (e.g., https://gitlab.com)
	GitlabToken string // GitLab API token

	// Project settings
	ProjectPath string // Full path of the project (e.g., group/project)
	ProjectID   int    // Project ID on GitLab
	Branch      string // Branch to analyze (from --branch flag, defaults to project's default branch)

	// HTTP client settings
	HTTPClientTimeout time.Duration // Timeout for HTTP clients (REST and GraphQL)

	// GitLab API retry configuration
	GitlabRetryMaxRetries     int           // Maximum number of retries for GitLab API requests
	GitlabRetryInitialBackoff time.Duration // Initial backoff time for GitLab API retries
	GitlabRetryMaxBackoff     time.Duration // Maximum backoff time for GitLab API retries
	GitlabRetryBackoffFactor  float64       // Backoff multiplication factor for exponential backoff

	// Local CI configuration (from local filesystem)
	LocalCIConfigContent []byte // Content of local .gitlab-ci.yml (nil if using remote)
	UsingLocalCIConfig   bool   // True when using local CI config file
	GitRepoRoot          string // Root of the git repository (empty if not in a git repo)
	IsLocalProject       bool   // True when the local git repo matches the project being analyzed

	// Logging
	LogLevel logrus.Level

	// Version info
	Version string

	// Plumber Configuration (from .plumber.yaml file)
	PlumberConfig *PlumberConfig

	// Values must match .plumber.yaml control keys
	// ControlsFilter runs only the listed controls when set;
	ControlsFilter []string
	// SkipControlsFilter skips the listed controls when set;
	SkipControlsFilter []string
}

// NewDefaultConfiguration creates a Configuration with sensible defaults
func NewDefaultConfiguration() *Configuration {
	return &Configuration{
		GitlabURL:                 "https://gitlab.com",
		HTTPClientTimeout:         30 * time.Second,
		GitlabRetryMaxRetries:     3,
		GitlabRetryInitialBackoff: 1 * time.Second,
		GitlabRetryMaxBackoff:     30 * time.Second,
		GitlabRetryBackoffFactor:  2.0,
		LogLevel:                  logrus.WarnLevel,
		Version:                   "0.1.0",
	}
}
