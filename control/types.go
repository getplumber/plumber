package control

import (
	"github.com/getplumber/plumber/collector"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/sirupsen/logrus"
)

var l = logrus.WithField("context", "control")

// AnalysisResult holds the complete result of a pipeline analysis
type AnalysisResult struct {
	// Project information
	ProjectPath   string `json:"projectPath"`
	ProjectID     int    `json:"projectId"`
	DefaultBranch string `json:"defaultBranch"`
	// AnalyzeBranch is the branch the analysis actually ran against
	// (--branch or the project's default). May differ from DefaultBranch.
	AnalyzeBranch string `json:"analyzeBranch,omitempty"`
	// HeadCommitSha is the head SHA of the analyzed branch, when known.
	// Used to build stable remote source links so that, even if the
	// branch moves later, links in the artifact still point at the
	// exact code that produced the finding. Empty when the SHA could
	// not be resolved (e.g. local-only runs without a fetched HEAD).
	HeadCommitSha string `json:"headCommitSha,omitempty"`

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

	// GitHubPipeline is the normalized IR produced by the GitHub
	// collector, retained on the result so legacy JSON / PBOM /
	// CycloneDX builders can read images, action references, and
	// per-branch protection details without re-running the collector.
	// Nil on the GitLab path.
	GitHubPipeline *ir.NormalizedPipeline `json:"-"`
}

// GitHubAnalysisStats holds per-control aggregations computed by
// AggregateGitHubStats from the normalized pipeline IR. Each field
// corresponds to a denominator/numerator pair used by the renderer
// to display "(X.X% compliant)" headers and stats blocks like the
// GitLab side. All fields are pre-aggregated counts — the renderer
// does not walk the IR again.
type GitHubAnalysisStats struct {
	// Actions pinning (ISSUE-701).
	ActionRefsTotal     int
	ActionRefsUnpinned  int
	ActionRefsExempt    int

	// Actions supply-chain (ISSUE-702, ISSUE-703). Counted across
	// every `uses:` entry that has API metadata, regardless of the
	// pin-by-SHA trusted-owner exemption — the rules themselves do
	// not exempt. In practice trusted-owner refs have nil metadata
	// (enrichment skips them) and won't add to either count.
	ActionRefsArchived   int
	ActionRefsVulnerable int

	// Container images (ISSUE-102 / ISSUE-103).
	ImagesTotal           int
	ImagesPinnedByDigest  int
	ImagesUsingForbidden  int

	// Docker-in-Docker (ISSUE-412 / ISSUE-413).
	JobsTotal              int
	JobsWithDinD           int
	JobsWithInsecureDaemon int

	// Excessive permissions (ISSUE-803). Counts jobs whose effective
	// `permissions:` is the literal `write-all` shortcut (workflow-
	// level grants are propagated per-job by the collector, so the
	// per-job count is the right denominator either way).
	JobsWithWriteAll int

	// Debug trace (ISSUE-203, GitHub side). VariableBindingsTotal is
	// the env-var denominator displayed by the stats block; mirrors
	// the GitLab side's "Variables Checked". DebugTraceFound counts
	// (job, var) pairs where the variable name matches a configured
	// forbidden entry case-insensitively and the value is truthy.
	VariableBindingsTotal int
	DebugTraceFound       int

	// Reusable workflow secrets (ISSUE-302).
	ReusableCalls               int
	ReusableCallsSecretsInherit int

	// Security jobs (ISSUE-410).
	SecurityJobsTotal    int
	SecurityJobsWeakened int

	// Workflow content scanned for template injection (ISSUE-207).
	ScriptLinesTotal int

	// Unverified script execution (ISSUE-411).
	UnverifiedScriptsFound int

	// Workflows + properties (ISSUE-802, ISSUE-801).
	WorkflowsTotal               int
	WorkflowsWithDangerousTrigger int
	WorkflowsMissingPermissions  int

	// Branch protection (ISSUE-501 / ISSUE-505).
	BranchesTotal     int
	BranchesProtected int
	BranchesMatched   int // matched a configured namePattern
	// BranchesProtectionDetailsUnknown counts in-scope branches whose
	// protection-detail fetch did not yield authoritative data
	// (typically: GitHub /branches/{name}/protection 403/404 because
	// the token lacks Administration:Read). The branch_non_compliant
	// rule (ISSUE-505) abstains on such branches; this counter exists
	// so the renderer can surface a "we couldn't fully evaluate this"
	// caveat instead of a misleading 100% compliant.
	BranchesProtectionDetailsUnknown int
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
