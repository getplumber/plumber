// Package pbom provides Pipeline Bill of Materials (PBOM) generation.
//
// A PBOM is an inventory of all dependencies used in a CI/CD pipeline,
// including container images and includes (components, templates, remote files).
// Unlike an SBOM (Software Bill of Materials) which tracks application dependencies,
// a PBOM tracks pipeline infrastructure dependencies.
package pbom

import (
	"time"

	"github.com/getplumber/plumber/utils"
)

// Version is the current PBOM specification version
const Version = "1.0.0"

// PBOM represents a Pipeline Bill of Materials - an inventory of all
// dependencies used in a CI/CD pipeline.
// JSON field order follows encode/json struct order: version stamp, project
// context, aggregate summary, score, then inventories (read top-to-bottom).
type PBOM struct {
	PBOMVersion string    `json:"pbomVersion"`
	GeneratedAt time.Time `json:"generatedAt"`

	Project ProjectInfo `json:"project"`

	Summary Summary `json:"summary"`

	PlumberScore *PlumberScoreSummary `json:"plumberScore,omitempty"`

	ContainerImages []ContainerImage `json:"containerImages"`
	Includes        []Include        `json:"includes"`
}

// PlumberScoreSummary mirrors control.PlumberScoreResult for JSON consumers (PBOM / SBOM).
type PlumberScoreSummary struct {
	ProfileID            string             `json:"profileId"`
	RawPoints            float64            `json:"rawPoints"`
	FinalPoints          float64            `json:"finalPoints"`
	Score                string             `json:"score,omitempty"`
	CriticalMalusApplied bool               `json:"criticalMalusApplied,omitempty"`
	CriticalMalusMax     float64            `json:"criticalMalusMax,omitempty"`
	Counts               PlumberScoreCounts `json:"counts"`
}

// PlumberScoreCounts is the number of issues per severity bucket.
type PlumberScoreCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// ProjectInfo contains information about the analyzed project.
// Provider names which CI platform produced this PBOM ("gitlab" or
// "github"). URL is the platform host used by the analysis (full
// URL on GitLab, host or host/api/v3 on GitHub). GitLabURL is kept
// for backward compatibility with v0.2.x consumers that key on it;
// new readers should prefer Provider + URL.
type ProjectInfo struct {
	Path      string `json:"path"`
	ID        int    `json:"id,omitempty"`
	Provider  string `json:"provider,omitempty"`
	URL       string `json:"url,omitempty"`
	GitLabURL string `json:"gitlabUrl,omitempty"`
	Branch    string `json:"branch,omitempty"`
}

// ContainerImage represents a container image used in the pipeline
type ContainerImage struct {
	// Full image reference (e.g., "docker.io/library/golang:1.22-alpine")
	Image string `json:"image"`

	// Parsed components
	Registry string `json:"registry"`
	Name     string `json:"name"`
	Tag      string `json:"tag,omitempty"`

	// Usage context
	Jobs []string `json:"jobs"`

	// Compliance status (from analysis, if available)
	Authorized   *bool `json:"authorized,omitempty"`
	ForbiddenTag *bool `json:"forbiddenTag,omitempty"`
}

// Include represents an include/component/template used in the
// pipeline. On GitHub, the analogue of GitLab's "include" types are:
//   - "action"           — third-party `uses: owner/repo@ref` step
//   - "reusableWorkflow" — `uses:` at the job level pointing at a
//                           reusable-workflow file
type Include struct {
	// Type of include: "component", "project", "local", "remote",
	// "template" (GitLab) or "action", "reusableWorkflow" (GitHub).
	Type string `json:"type"`

	// Location/path of the include
	Location string `json:"location"`

	// For project includes
	Project string `json:"project,omitempty"`

	// Version information
	Version       string `json:"version,omitempty"`
	LatestVersion string `json:"latestVersion,omitempty"`
	UpToDate      *bool  `json:"upToDate,omitempty"`

	// For components from GitLab CI/CD Catalog
	ComponentName string `json:"componentName,omitempty"`
	FromCatalog   bool   `json:"fromCatalog,omitempty"`

	// Whether this is a nested include (included by another include)
	Nested bool `json:"nested,omitempty"`

	// Override information (populated from control results)
	Overridden     bool                        `json:"overridden,omitempty"`
	OverriddenJobs []utils.OverriddenJobDetail `json:"overriddenJobs,omitempty"`

	// GitHub-only compliance enrichments populated from GitHubComplianceData.
	// Archived is true when the action's upstream repository is archived
	// (ISSUE-702). HasCVE is true when the action's upstream carries at
	// least one published GitHub Advisory (ISSUE-703). Advisories is the
	// list of GHSA IDs that triggered HasCVE.
	Archived   *bool    `json:"archived,omitempty"`
	HasCVE     *bool    `json:"hasCve,omitempty"`
	Advisories []string `json:"advisories,omitempty"`
}

// Summary provides aggregate statistics about the pipeline dependencies
type Summary struct {
	// Image counts
	TotalImages      int `json:"totalImages"`
	UniqueRegistries int `json:"uniqueRegistries"`

	// Include counts
	TotalIncludes   int `json:"totalIncludes"`
	Components      int `json:"components"`
	ProjectIncludes int `json:"projectIncludes"`
	LocalIncludes   int `json:"localIncludes"`
	RemoteIncludes  int `json:"remoteIncludes"`
	Templates       int `json:"templates"`

	// GitHub-specific include counts. Always emitted (matches the
	// pattern the GitLab-side counters above use — zero is meaningful
	// and gets serialised as `0`, not dropped).
	Actions           int `json:"actions"`
	ReusableWorkflows int `json:"reusableWorkflows"`
}
