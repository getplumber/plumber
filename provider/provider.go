// Package provider defines the Provider interface that every CI platform
// must implement, along with a global registry so the analyze command can
// dispatch to the right implementation without hard-coded if/switch chains.
//
// Adding a new provider requires:
//  1. Implement Provider in a new file (e.g. provider/bitbucket.go)
//  2. Call Register(&BitbucketProvider{}) in an init() function
//  3. Declare applicable controls in configuration/registry.go
//  4. Add a Controls() implementation in control/catalog.go
//  5. Add a ProviderConfig field in configuration/plumberconfig.go
package provider

import (
	"errors"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/pbom"
	"github.com/spf13/cobra"
)

// StatsBuilder computes the stat lines displayed above the findings block for
// a single control. It is registered separately from the Provider interface
// because the implementation often depends on cmd-internal helpers that would
// create import cycles if embedded in the interface. cmd/ registers the builder
// via RegisterStatsBuilder during init.
type StatsBuilder func(controlName string, result *control.AnalysisResult, pc *configuration.PlumberConfig, findings []opaengine.Finding) []control.StatLine

var statsBuilders = map[string]StatsBuilder{}

// RegisterStatsBuilder associates a StatsBuilder with a provider name. It is
// called from cmd/ init functions to avoid import cycles.
func RegisterStatsBuilder(providerName string, b StatsBuilder) {
	statsBuilders[providerName] = b
}

// BuildControlStats invokes the registered StatsBuilder for providerName.
// Returns nil when no builder is registered.
func BuildControlStats(providerName, controlName string, result *control.AnalysisResult, pc *configuration.PlumberConfig, findings []opaengine.Finding) []control.StatLine {
	if b, ok := statsBuilders[providerName]; ok {
		return b(controlName, result, pc, findings)
	}
	return nil
}

// ErrNoRemote is returned by RunRemote when a provider only supports local
// analysis (e.g. GitLab, which always fetches via its own API).
var ErrNoRemote = errors.New("provider does not support remote analysis")

// CIEnvMapping describes the CI environment variables a provider sets so
// the location linker can build stable source links anchored to the commit
// that triggered the analysis.
type CIEnvMapping struct {
	// ServerURL is the env var that holds the base URL of the forge server
	// (e.g. "CI_SERVER_URL" for GitLab, "GITHUB_SERVER_URL" for GitHub).
	ServerURL string
	// RepoPath is the env var that holds the project path (e.g.
	// "CI_PROJECT_PATH" / "GITHUB_REPOSITORY").
	RepoPath string
	// CommitSHA is the env var that holds the commit SHA (e.g.
	// "CI_COMMIT_SHA" / "GITHUB_SHA").
	CommitSHA string
	// RefName is the env var that holds the analyzed branch or tag name
	// (e.g. "CI_COMMIT_REF_NAME" / "GITHUB_REF_NAME"). It is the
	// authoritative ref in CI, preferred over the resolved default branch.
	RefName string
}

// PostActionSummary bundles the gate outcome needed by PostAnalysisActions
// to avoid exceeding the parameter count limit. Passed is the active gate's
// verdict; GateLine is its human-readable rendering for the MR comment.
//
// Platform is set only in platform mode (spec
// 2026-09-10-cli-platform-mode-policies-only s5) and is then what the badge
// and the merge-request comment report: Score is nil there by construction,
// because the run has no run-level grade and a locally computed one would be
// the figure that contradicts the platform's.
type PostActionSummary struct {
	Passed     bool
	GateLine   string
	Score      *control.PlumberScoreResult
	ScoreMode  bool
	ScorePoint bool
	Platform   *PlatformPostSummary
}

// PlatformPostSummary and PlatformPolicyLine are control's types, re-exported
// under this package's names because the post actions are named from here.
// They live in control/ because that is where the badge and the comment that
// render them live, and control cannot import provider.
type (
	PlatformPostSummary = control.PlatformPostSummary
	PlatformPolicyLine  = control.PlatformPolicyLine
)

// Provider is the contract every CI platform must satisfy. The analyze
// command resolves the active provider via Get() and delegates all
// provider-specific logic through this interface, keeping the shared
// pipeline (compliance calculation, output rendering, artifact writing)
// provider-agnostic.
type Provider interface {
	// Name returns the canonical provider identifier ("gitlab", "github", …).
	Name() string

	// Controls returns the ordered catalog of controls for this provider.
	// The returned entries drive the compliance table and the per-control
	// rendering sections.
	Controls(pc *configuration.PlumberConfig) []control.ControlEntry

	// ComputeCompliance derives the overall compliance percentage and the
	// number of non-skipped controls that were evaluated from result.
	ComputeCompliance(result *control.AnalysisResult, conf *configuration.Configuration) (compliance float64, controlCount int)

	// Run executes the analysis for this provider using the local clone or
	// the provider's API, depending on conf.
	Run(conf *configuration.Configuration) (*control.AnalysisResult, error)

	// RunRemote fetches the pipeline from a remote API and runs analysis.
	// Returns ErrNoRemote when the provider does not support this mode.
	RunRemote(conf *configuration.Configuration) (*control.AnalysisResult, error)

	// WritePBOM writes a Pipeline Bill of Materials to filePath in the
	// provider's native PBOM format. platform is the platform-mode score
	// block (per-policy verdicts plus the platform's global score), nil on
	// every other run.
	WritePBOM(result *control.AnalysisResult, conf *configuration.Configuration, filePath string, score *control.PlumberScoreResult, scoreMode bool, platform *pbom.PlatformSummary) error

	// WritePBOMCycloneDX writes the PBOM in CycloneDX format.
	WritePBOMCycloneDX(result *control.AnalysisResult, conf *configuration.Configuration, filePath string, score *control.PlumberScoreResult, scoreMode bool, platform *pbom.PlatformSummary) error

	// PostAnalysisActions runs provider-specific post-analysis side-effects
	// such as posting MR comments or updating the project badge. Providers
	// that have no post-analysis actions return nil.
	PostAnalysisActions(cmd *cobra.Command, result *control.AnalysisResult, conf *configuration.Configuration, s PostActionSummary) error

	// BlobURLInfix returns the URL segment between the repository base URL
	// and the file path when building clickable source links.
	// Example: GitLab "/-/blob/", GitHub "/blob/".
	BlobURLInfix() string

	// CIEnvVars returns the mapping of CI environment variables used to
	// build stable source links when running inside a CI pipeline.
	CIEnvVars() CIEnvMapping
}

// registry holds the registered providers, keyed by their canonical name.
var registry = map[string]Provider{}

// Register adds p to the global registry. It is typically called from
// an init() function in the provider's implementation file.
// Panics if a provider with the same name is already registered.
func Register(p Provider) {
	if _, exists := registry[p.Name()]; exists {
		panic("provider: duplicate registration for " + p.Name())
	}
	registry[p.Name()] = p
}

// Get returns the provider registered under name and whether it was found.
func Get(name string) (Provider, bool) {
	p, ok := registry[name]
	return p, ok
}
