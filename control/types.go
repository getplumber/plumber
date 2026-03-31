package control

import (
	"github.com/getplumber/plumber/collector"
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

	// Control results
	ImageForbiddenTagsResult        *GitlabImageForbiddenTagsResult               `json:"imageForbiddenTagsResult,omitempty"`
	ImageAuthorizedSourcesResult    *GitlabImageAuthorizedSourcesResult           `json:"imageAuthorizedSourcesResult,omitempty"`
	BranchProtectionResult          *GitlabBranchProtectionResult                 `json:"branchProtectionResult,omitempty"`
	HardcodedJobsResult             *GitlabPipelineHardcodedJobsResult            `json:"hardcodedJobsResult,omitempty"`
	OutdatedIncludesResult          *GitlabPipelineIncludesOutdatedResult         `json:"outdatedIncludesResult,omitempty"`
	ForbiddenVersionsIncludesResult *GitlabPipelineIncludesForbiddenVersionResult `json:"forbiddenVersionsIncludesResult,omitempty"`
	RequiredComponentsResult        *GitlabPipelineRequiredComponentsResult       `json:"requiredComponentsResult,omitempty"`
	RequiredTemplatesResult         *GitlabPipelineRequiredTemplatesResult        `json:"requiredTemplatesResult,omitempty"`
	DebugTraceResult                *GitlabPipelineDebugTraceResult              `json:"debugTraceResult,omitempty"`
	VariableInjectionResult         *GitlabPipelineVariableInjectionResult       `json:"variableInjectionResult,omitempty"`
	SecurityJobsWeakenedResult      *GitlabSecurityJobsWeakenedResult            `json:"securityJobsWeakenedResult,omitempty"`
	UnverifiedScriptsResult         *GitlabPipelineUnverifiedScriptsResult       `json:"unverifiedScriptsResult,omitempty"`
	JobVariablesOverrideResult      *GitlabPipelineJobVariablesOverrideResult    `json:"jobVariablesOverrideResult,omitempty"`

	// Raw collected data (not included in JSON output, used for PBOM generation)
	PipelineImageData  *collector.GitlabPipelineImageData  `json:"-"`
	PipelineOriginData *collector.GitlabPipelineOriginData `json:"-"`
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
