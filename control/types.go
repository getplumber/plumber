package control

import "github.com/sirupsen/logrus"

var l = logrus.WithField("context", "control")

// AnalysisResult holds the complete result of a pipeline analysis
type AnalysisResult struct {
	// Project information
	ProjectPath string `json:"projectPath"`
	ProjectID   int    `json:"projectId"`

	// CI configuration status
	CiValid   bool `json:"ciValid"`
	CiMissing bool `json:"ciMissing"`

	// Pipeline origin data
	PipelineOriginMetrics *PipelineOriginMetricsSummary `json:"pipelineOriginMetrics,omitempty"`

	// Pipeline image data
	PipelineImageMetrics *PipelineImageMetricsSummary `json:"pipelineImageMetrics,omitempty"`

	// Control results
	ImageMutableResult     *GitlabImageMutableResult     `json:"imageMutableResult,omitempty"`
	ImageUntrustedResult   *GitlabImageUntrustedResult   `json:"imageUntrustedResult,omitempty"`
	BranchProtectionResult *GitlabBranchProtectionResult `json:"branchProtectionResult,omitempty"`
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

// GitlabBranchProtectionResult holds the result of the branch protection control
type GitlabBranchProtectionResult struct {
	Enabled    bool                     `json:"enabled"`
	Skipped    bool                     `json:"skipped,omitempty"`
	Compliance float64                  `json:"compliance"`
	Version    string                   `json:"version"`
	Data       []BranchProtectionData   `json:"data,omitempty"`
	Metrics    *BranchProtectionMetrics `json:"metrics,omitempty"`
	Issues     []BranchProtectionIssue  `json:"issues,omitempty"`
	Error      string                   `json:"error,omitempty"`
}

// BranchProtectionData holds information about a branch's protection status
type BranchProtectionData struct {
	BranchName                    string `json:"branchName"`
	Default                       bool   `json:"default"`
	Protected                     bool   `json:"protected"`
	AllowForcePush                bool   `json:"allowForcePush,omitempty"`
	CodeOwnerApprovalRequired     bool   `json:"codeOwnerApprovalRequired,omitempty"`
	MinMergeAccessLevel           int    `json:"minMergeAccessLevel,omitempty"`
	MinPushAccessLevel            int    `json:"minPushAccessLevel,omitempty"`
	AuthorizedMinMergeAccessLevel int    `json:"authorizedMinMergeAccessLevel,omitempty"`
	AuthorizedMinPushAccessLevel  int    `json:"authorizedMinPushAccessLevel,omitempty"`
}

// BranchProtectionMetrics holds metrics for the branch protection control
type BranchProtectionMetrics struct {
	Branches                   int `json:"branches"`
	BranchesToProtect          int `json:"branchesToProtect"`
	UnprotectedBranches        int `json:"unprotectedBranches"`
	NonCompliantBranches       int `json:"nonCompliantBranches"`
	TotalProtectedBranches     int `json:"totalProtectedBranches"`
	ProjectsCorrectlyProtected int `json:"projectsCorrectlyProtected"`
}

// BranchProtectionIssue represents an issue found by the branch protection control
type BranchProtectionIssue struct {
	Type                             string `json:"type"` // "unprotected" or "non_compliant"
	BranchName                       string `json:"branchName"`
	AllowForcePush                   bool   `json:"allowForcePush,omitempty"`
	AllowForcePushDisplay            bool   `json:"allowForcePushDisplay,omitempty"`
	CodeOwnerApprovalRequired        bool   `json:"codeOwnerApprovalRequired,omitempty"`
	CodeOwnerApprovalRequiredDisplay bool   `json:"codeOwnerApprovalRequiredDisplay,omitempty"`
	MinMergeAccessLevel              int    `json:"minMergeAccessLevel,omitempty"`
	MinMergeAccessLevelDisplay       bool   `json:"minMergeAccessLevelDisplay,omitempty"`
	AuthorizedMinMergeAccessLevel    int    `json:"authorizedMinMergeAccessLevel,omitempty"`
	MinPushAccessLevel               int    `json:"minPushAccessLevel,omitempty"`
	MinPushAccessLevelDisplay        bool   `json:"minPushAccessLevelDisplay,omitempty"`
	AuthorizedMinPushAccessLevel     int    `json:"authorizedMinPushAccessLevel,omitempty"`
}
