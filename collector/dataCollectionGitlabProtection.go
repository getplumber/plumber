package collector

import (
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	"github.com/sirupsen/logrus"
	glab "gitlab.com/gitlab-org/api/client-go"
)

const (
	DataCollectionTypeGitlabProtectionVersion = "0.2.0"
)

// Behavior when commit is added constants
const (
	BehaviorWhenCommitIsAddedKeepApprovalsId = iota + 1
	BehaviorWhenCommitIsAddedRemoveCodeOwnerApprovalsId
	BehaviorWhenCommitIsAddedRemoveApprovalsId
)

// Behavior when commit is added text values
const (
	BehaviorWhenCommitIsAddedKeepApprovalsText   = "Keep approvals"
	BehaviorWhenCommitIsAddedRemoveCodeOwnerText = "Remove approvals by Code Owners if their files changed"
	BehaviorWhenCommitIsAddedRemoveApprovalsText = "Remove all approvals"
)

// GitLab squash option constants
const (
	SquashOptionNever      = "never"       // Never squash
	SquashOptionAlways     = "always"      // Always squash
	SquashOptionDefaultOn  = "default_on"  // Squash by default (can be turned off)
	SquashOptionDefaultOff = "default_off" // Don't squash by default (can be turned on)
)

// GitlabProtectionDataCollection handles protection data collection
type GitlabProtectionDataCollection struct{}

// GitlabProtectionData holds the collected protection data
type GitlabProtectionData struct {
	Branches []*GitlabProtectionDataBranch `json:"branches"`
}

// GitlabProtectionMetrics holds metrics about protection data
type GitlabProtectionMetrics struct {
	Branches int `json:"branches"`
}

// GitlabProtectionDataBranch holds branch information
type GitlabProtectionDataBranch struct {
	BranchName string `json:"branchName"`
	Default    bool   `json:"default"`
}

// GitlabProtectionAnalysisData holds all the data needed by protection controls
type GitlabProtectionAnalysisData struct {
	Branches           []string                    `json:"branches"`
	BranchProtections  []gitlab.BranchProtection   `json:"branchProtections"`
	MRApprovalRules    []*glab.ProjectApprovalRule `json:"mrApprovalRules"`
	MRApprovalSettings *glab.ProjectApprovals      `json:"mrApprovalSettings"`
	MRSettings         *glab.Project               `json:"mrSettings"`
	ProjectMembers     []gitlab.GitlabMemberInfo   `json:"projectMembers"`
}

// Run fetches all GitLab protection data needed by the controls
func (dc *GitlabProtectionDataCollection) Run(
	project *gitlab.ProjectInfo,
	token string,
	conf *configuration.Configuration,
) (*GitlabProtectionAnalysisData, *GitlabProtectionMetrics, error) {

	l := l.WithFields(logrus.Fields{
		"dataCollection":        "GitlabProtection",
		"dataCollectionVersion": DataCollectionTypeGitlabProtectionVersion,
		"project":               project.Path,
	})
	l.Info("Start data collection")

	returnedData := &GitlabProtectionAnalysisData{}
	metrics := &GitlabProtectionMetrics{}

	// Get project branches and branch protections together
	branches, branchProtections, err := gitlab.FetchProjectBranchData(project.Path, token, conf.GitlabURL, conf)
	if err != nil {
		l.WithError(err).Error("Failed to fetch project branch data")
		return nil, metrics, err
	}
	returnedData.Branches = branches
	returnedData.BranchProtections = branchProtections
	metrics.Branches = len(branches)

	// Get project MR approval rules (may fail with 403/404 on non-premium GitLab)
	approvalRules, err := gitlab.FetchProjectMRApprovalRules(project.ID, token, conf.GitlabURL, conf)
	if err != nil {
		errStr := err.Error()
		if !strings.Contains(errStr, "403") && !strings.Contains(errStr, "404") {
			l.WithError(err).Error("Failed to fetch MR approval rules")
			return nil, metrics, err
		}
		l.WithError(err).Warn("MR approval rules not available (may require premium)")
		// If 403/404 error, MRApprovalRules will be nil which controls can handle
	} else {
		returnedData.MRApprovalRules = approvalRules
	}

	// Get project MR approval settings (may fail with 403/404 on non-premium GitLab)
	approvalSettings, err := gitlab.FetchProjectMRApprovalSettings(project.ID, token, conf.GitlabURL, conf)
	if err != nil {
		errStr := err.Error()
		if !strings.Contains(errStr, "403") && !strings.Contains(errStr, "404") {
			l.WithError(err).Error("Failed to fetch MR approval settings")
			return nil, metrics, err
		}
		l.WithError(err).Warn("MR approval settings not available (may require premium)")
		// If 403/404 error, MRApprovalSettings will be nil which controls can handle
	} else {
		returnedData.MRApprovalSettings = approvalSettings
	}

	// Get project settings (includes MR settings like squash, merge method)
	projectSettings, _, err := gitlab.FetchGitlabProject(project.ID, token, conf.GitlabURL, conf)
	if err != nil {
		l.WithError(err).Error("Failed to fetch project settings")
		return nil, metrics, err
	}
	returnedData.MRSettings = projectSettings

	// Get project members
	members, err := gitlab.FetchProjectMembers(project.ID, token, conf.GitlabURL, conf)
	if err != nil {
		l.WithError(err).Warn("Failed to fetch project members")
		// Continue without members
	} else {
		returnedData.ProjectMembers = members
	}

	l.WithFields(logrus.Fields{
		"branchCount":           len(returnedData.Branches),
		"branchProtectionCount": len(returnedData.BranchProtections),
		"memberCount":           len(returnedData.ProjectMembers),
	}).Info("Protection data collection completed")

	return returnedData, metrics, nil
}
