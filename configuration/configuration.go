package configuration

import (
	"net/http"
	"time"
)

// Configuration represents the simplified CLI configuration options
type Configuration struct {
	// GitLab connection settings
	GitlabURL   string // URL of the GitLab instance (e.g., https://gitlab.com)
	GitlabToken string // GitLab API token

	// GitHub connection settings
	// GithubAPIHost is the GitHub API host. Empty means default
	// (api.github.com). Set to a GitHub Enterprise Server host
	// (e.g. "ghes.example.com" or "ghes.example.com/api/v3") to
	// target a self-hosted instance. Auth is provided via the same
	// resolution chain as default github.com (GH_TOKEN /
	// GH_ENTERPRISE_TOKEN / GITHUB_TOKEN / gh auth).
	GithubAPIHost string

	// Project settings
	ProjectPath string // Full path of the project (e.g., group/project)
	ProjectID   int    // Project ID on GitLab
	Branch      string // Branch to analyze (from --branch flag, defaults to project's default branch)

	// HTTP client settings
	HTTPClientTimeout time.Duration // Timeout for HTTP clients (REST and GraphQL)

	// HTTPClient, when non-nil, is used verbatim by the GitLab REST/GraphQL/HTTP
	// client constructors instead of building the default retry-wrapped client.
	// It exists so an EMBEDDING host (the Plumber platform, ADR-0021) can inject
	// its single, shared, rate-limited/cached client per (provider, instance)
	// (INVARIANTS rule J). The CLI's own runs leave this nil and get the default
	// client unchanged — this field is purely additive and transparent.
	HTTPClient *http.Client

	// GitLab API retry configuration
	GitlabRetryMaxRetries     int           // Maximum number of retries for GitLab API requests
	GitlabRetryInitialBackoff time.Duration // Initial backoff time for GitLab API retries
	GitlabRetryMaxBackoff     time.Duration // Maximum backoff time for GitLab API retries
	GitlabRetryBackoffFactor  float64       // Backoff multiplication factor for exponential backoff

	// CI configuration path override (from --ci-config-path flag)
	CIConfigPathOverride string // When set, overrides the project's CI config file path (e.g., "my-custom-ci.yml")

	// Local CI configuration (from local filesystem)
	LocalCIConfigContent []byte // Content of local .gitlab-ci.yml (nil if using remote)
	UsingLocalCIConfig   bool   // True when using local CI config file
	GitRepoRoot          string // Root of the git repository (empty if not in a git repo)
	IsLocalProject       bool   // True when the local git repo matches the project being analyzed

	// Version info
	Version string

	// Plumber Configuration (from .plumber.yaml file)
	PlumberConfig *PlumberConfig
	// ConfigFilePath is the path the Plumber config was loaded from, shown
	// in the run header.
	ConfigFilePath string

	// Values must match .plumber.yaml control keys
	// ControlsFilter runs only the listed controls when set;
	ControlsFilter []string
	// SkipControlsFilter skips the listed controls when set;
	SkipControlsFilter []string
	// NoControls turns off control evaluation entirely for this run
	// (--no-controls). It is a command-line override that wins over the
	// config: the controls enabled in .plumber.yaml are ignored, no policy
	// is evaluated, and with nothing evaluated there is no score and no
	// gate to fail. Collectors still run, because the PBOM and the JSON
	// report are built from the same collected data.
	NoControls bool

	// ProgressFunc is an optional callback invoked during analysis to report progress.
	// step: current step number (1-based), total: total number of steps, message: description.
	ProgressFunc func(step int, total int, message string)
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
		Version:                   "0.1.0",
	}
}
