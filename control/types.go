package control

import (
	"github.com/getplumber/plumber/collector"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/sirupsen/logrus"
)

var l = logrus.WithField("context", "control")

// AnalysisResult holds the complete result of a pipeline analysis
type AnalysisResult struct {
	// Project information
	ProjectPath   string `json:"projectPath"`
	ProjectID     int    `json:"projectId"`
	DefaultBranch string `json:"defaultBranch"`

	// CI configuration status
	CiValid        bool     `json:"ciValid"`
	CiMissing      bool     `json:"ciMissing"`
	CiErrors       []string `json:"ciErrors,omitempty"`  // Specific CI config errors from GitLab
	CIConfigSource string   `json:"ciConfigSource"`      // "local" or "remote"

	// Pipeline origin data
	PipelineOriginMetrics *PipelineOriginMetricsSummary `json:"pipelineOriginMetrics,omitempty"`

	// Pipeline image data
	PipelineImageMetrics *PipelineImageMetricsSummary `json:"pipelineImageMetrics,omitempty"`

	// Findings from the Rego/OPA rule engine. Single source of truth
	// for compliance results since all legacy Go controls were retired
	// (see docs/REFACTOR_MULTI_PROVIDER.md §8 Phase A).
	Findings []opaengine.Finding `json:"findings,omitempty"`

	// Raw collected data (not included in JSON output, used for PBOM generation
	// and for the per-control aggregated stats block printed under each
	// control header in the terminal output).
	PipelineImageData  *collector.GitlabPipelineImageData    `json:"-"`
	PipelineOriginData *collector.GitlabPipelineOriginData   `json:"-"`
	ProtectionData     *collector.GitlabProtectionAnalysisData `json:"-"`

	// GitHubStats holds per-control denominators computed from the
	// GitHub IR after a GitHub analysis. Used by the GitHub renderer
	// to produce per-control stats blocks ("Total Images: 19,
	// Pinned By Digest: 1, …") and per-control compliance
	// percentages, matching the GitLab output structure. Nil on the
	// GitLab path.
	GitHubStats *GitHubAnalysisStats `json:"-"`
}

// GitHubAnalysisStats holds per-control aggregations computed by
// AggregateGitHubStats from the normalized pipeline IR. Each field
// corresponds to a denominator/numerator pair used by the renderer
// to display "(X.X% compliant)" headers and stats blocks like the
// GitLab side. All fields are pre-aggregated counts — the renderer
// does not walk the IR again.
type GitHubAnalysisStats struct {
	// Actions pinning (ISSUE-104).
	ActionRefsTotal     int
	ActionRefsUnpinned  int
	ActionRefsExempt    int

	// Container images (ISSUE-102 / ISSUE-103).
	ImagesTotal           int
	ImagesPinnedByDigest  int
	ImagesUsingForbidden  int

	// Docker-in-Docker (ISSUE-412 / ISSUE-413).
	JobsTotal              int
	JobsWithDinD           int
	JobsWithInsecureDaemon int

	// Reusable workflow secrets (ISSUE-302).
	ReusableCalls               int
	ReusableCallsSecretsInherit int

	// Security jobs (ISSUE-410).
	SecurityJobsTotal    int
	SecurityJobsWeakened int

	// Workflow content scanned for template injection (ISSUE-206).
	ScriptLinesTotal int

	// Workflows + properties (ISSUE-414, ISSUE-304).
	WorkflowsTotal               int
	WorkflowsWithDangerousTrigger int
	WorkflowsMissingPermissions  int
}

// PipelineOriginMetricsSummary is a simplified version of origin metrics for output
type PipelineOriginMetricsSummary struct {
	JobTotal            uint `json:"jobTotal"`
	JobHardcoded        uint `json:"jobHardcoded"`
	OriginTotal         uint `json:"originTotal"`
	OriginComponent     uint `json:"originComponent"`
	OriginLocal         uint `json:"originLocal"`
	OriginProject       uint `json:"originProject"`
	OriginRemote        uint `json:"originRemote"`
	OriginTemplate      uint `json:"originTemplate"`
	OriginGitLabCatalog uint `json:"originGitLabCatalog"`
	OriginOutdated      uint `json:"originOutdated"`
}

// PipelineImageMetricsSummary is a simplified version of image metrics for output
type PipelineImageMetricsSummary struct {
	Total uint `json:"total"`
}
