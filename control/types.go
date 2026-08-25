package control

import (
	"github.com/getplumber/plumber/gitlab"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/sirupsen/logrus"
)

var l = logrus.WithField("context", "control")

// StatLine is a single labelled metric rendered above a control's findings
// block in the terminal output. Label is the display name; Value is a
// pre-formatted string (plain int, percentage, …).
type StatLine struct {
	Label string
	Value string
}

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
	CiErrors       []string `json:"ciErrors,omitempty"` // Specific CI config errors from GitLab
	CIConfigSource string   `json:"ciConfigSource"`     // "local" or "remote"

	// Pipeline origin data
	PipelineOriginMetrics *PipelineOriginMetricsSummary `json:"pipelineOriginMetrics,omitempty"`

	// Pipeline image data
	PipelineImageMetrics *PipelineImageMetricsSummary `json:"pipelineImageMetrics,omitempty"`

	// Findings from the Rego/OPA rule engine. Single source of truth
	// for compliance results since all legacy Go controls were retired.
	Findings []opaengine.Finding `json:"findings,omitempty"`

	// Raw collected data (not included in JSON output, used for PBOM generation
	// and for the per-control aggregated stats block printed under each
	// control header in the terminal output).
	PipelineImageData  *gitlab.GitlabPipelineImageData      `json:"-"`
	PipelineOriginData *gitlab.GitlabPipelineOriginData     `json:"-"`
	ProtectionData     *gitlab.GitlabProtectionAnalysisData `json:"-"`
	// VariablesData records the settings-variable collection for the
	// cicdVariablesMustBe* controls. Set only after the collection ran;
	// nil (never ran) or Known=false (401/403) makes those controls
	// report not-evaluable rather than a false pass (see StatusFor).
	VariablesData *gitlab.GitlabVariablesAnalysisData `json:"-"`

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
	// per-branch protection details without re-running the gitlab.
	// Nil on the GitLab path.
	GitHubPipeline *ir.NormalizedPipeline `json:"-"`

	// Warnings holds non-fatal "could not verify" messages from the run,
	// e.g. a known-CVE check skipped because an action's pinned commit
	// could not be resolved to a version (tag list blocked by an org IP
	// allow list, rate limit, or network). Surfaced in the terminal,
	// JSON, SARIF and GLSAST output, and gated by --fail-warnings (exit
	// 3) so a degraded check is visible instead of silently passing.
	Warnings []string `json:"warnings,omitempty"`

	// ApprovalRulesTierCaveat is set when an MR approval-rule control ran but
	// the GitLab approvals API returned zero rules — the ambiguous case where
	// the project is either on GitLab Free (feature unavailable, API returns an
	// empty list) or on Premium/Ultimate with no rules configured. The API
	// gives no tier signal to tell them apart, so renderers surface a
	// Premium/Ultimate caveat next to ISSUE-502/504 rather than presenting the
	// result as authoritative.
	ApprovalRulesTierCaveat bool `json:"-"`

	// DataCollectionDegraded is set when a collection or enrichment step
	// failed mid-run, so the analysis ran on incomplete data: a GitLab
	// merged-CI fetch that timed out (empty pipeline), or a GitHub run
	// where some workflow files or the branch-protection fetch could not
	// be retrieved. When true the renderer withholds the letter-score
	// banner and marks the un-collected controls "not evaluated" instead
	// of presenting missing data as 100% compliant (#220). Distinct from
	// CiMissing, which is the legitimate "this project has no CI config"
	// state and is not degraded.
	DataCollectionDegraded bool `json:"dataCollectionDegraded,omitempty"`

	// DegradedReasons lists the human-readable collection/enrichment
	// failures behind DataCollectionDegraded (e.g. "3 workflow file(s)
	// could not be fetched", "branch protection could not be fetched").
	// Surfaced as a caveat in the terminal. Empty when not degraded.
	DegradedReasons []string `json:"degradedReasons,omitempty"`
}

// GitHubAnalysisStats holds per-control aggregations computed by
// AggregateGitHubStats from the normalized pipeline IR. Each field
// corresponds to a denominator/numerator pair used by the renderer
// to display "(X.X% compliant)" headers and stats blocks like the
// GitLab side. All fields are pre-aggregated counts — the renderer
// does not walk the IR again.
type GitHubAnalysisStats struct {
	// Actions pinning (ISSUE-701).
	ActionRefsTotal    int
	ActionRefsUnpinned int
	ActionRefsExempt   int

	// Actions supply-chain (ISSUE-702, ISSUE-703, ISSUE-402). Counted
	// across every `uses:` entry that has API metadata, regardless of
	// the pin-by-SHA trusted-owner exemption — the rules themselves do
	// not exempt. In practice trusted-owner refs have nil metadata
	// (enrichment skips them) and won't add to either count.
	ActionRefsArchived   int
	ActionRefsVulnerable int
	ActionRefsAmbiguous  int
	// ActionRefsAbsentUpstream (ISSUE-707) counts SHA-pinned refs the
	// upstream repo confirmed do not exist. Guarded on isShaPinned so it
	// stays aligned with the impostor-commit rego, which only fires on a
	// 40-char SHA.
	ActionRefsAbsentUpstream int

	// Container images (ISSUE-102 / ISSUE-103).
	ImagesTotal          int
	ImagesPinnedByDigest int
	ImagesUsingForbidden int

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
	WorkflowsTotal                int
	WorkflowsWithDangerousTrigger int
	WorkflowsMissingPermissions   int

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
