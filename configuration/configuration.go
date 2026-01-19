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
	ProjectPath   string // Full path of the project (e.g., group/project)
	ProjectID     int    // Project ID on GitLab
	DefaultBranch string // Default branch of the project

	// HTTP client settings
	HTTPClientTimeout time.Duration // Timeout for HTTP clients (REST and GraphQL)

	// GitLab API retry configuration
	GitlabRetryMaxRetries     int           // Maximum number of retries for GitLab API requests
	GitlabRetryInitialBackoff time.Duration // Initial backoff time for GitLab API retries
	GitlabRetryMaxBackoff     time.Duration // Maximum backoff time for GitLab API retries
	GitlabRetryBackoffFactor  float64       // Backoff multiplication factor for exponential backoff

	// Logging
	LogLevel logrus.Level

	// Version info
	Version string

	// R2 Configuration (from .r2 file)
	R2Config *R2Config
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
		LogLevel:                  logrus.InfoLevel,
		Version:                   "0.1.0",
	}
}
