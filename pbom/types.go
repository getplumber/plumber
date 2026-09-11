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

	// Policies and PlatformGlobalScore are the platform-mode score block
	// (spec 2026-09-10-cli-platform-mode-policies-only s5). In that mode
	// there is no run-level score to put in PlumberScore: every verdict
	// belongs to one of the platform's policies, and the single global
	// figure is the platform's own, present only when the push returned one.
	// Both are absent from a standalone PBOM.
	Policies            []PolicyScore        `json:"policies,omitempty"`
	PlatformGlobalScore *PlatformGlobalScore `json:"platformGlobalScore,omitempty"`

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

// PolicyScore is one resolved platform policy's own verdict over its own
// control set. Score and FinalPoints are omitted for a policy the CLI could
// not evaluate (Applied false, Reason says why): a letter-less zero would
// read as a policy that scored badly rather than one that ran nothing.
type PolicyScore struct {
	Name        string `json:"name"`
	Enforcement string `json:"enforcement"`
	Score       string `json:"score,omitempty"`
	FinalPoints *int   `json:"finalPoints,omitempty"`
	Applied     bool   `json:"applied"`
	Reason      string `json:"reason,omitempty"`
}

// PlatformGlobalScore is the platform's own displayed score for the run, as
// the push response returned it. It is never computed CLI-side.
type PlatformGlobalScore struct {
	Letter string `json:"letter,omitempty"`
	Points int    `json:"points"`
}

// PlatformSummary is what a platform-mode run hands the PBOM writers: the
// per-policy verdicts and the platform's global score (nil when the push
// returned none). nil itself outside platform mode.
//
// ImageControlsEvaluated is false when no resolved policy enables the image
// controls. The per-image ForbiddenTag / Authorized booleans are a POSITIVE
// claim - an image no finding names is published as authorized - so with no
// policy asking for those controls the writers drop them entirely and the
// image is reported as inventory alone. Both fields are already *bool, so
// dropping them is the existing tri-state, not a schema change.
type PlatformSummary struct {
	Policies               []PolicyScore
	GlobalScore            *PlatformGlobalScore
	ImageControlsEvaluated bool
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
	// CommitSHA and Ref are the analyzed commit and its branch/tag (#443).
	// Empty when the commit could not be resolved.
	CommitSHA string `json:"commitSHA,omitempty"`
	Ref       string `json:"ref,omitempty"`
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
//     reusable-workflow file
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
