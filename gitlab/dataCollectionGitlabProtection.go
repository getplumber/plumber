package gitlab

import (
	"net/http"

	"github.com/getplumber/plumber/configuration"
	"github.com/sirupsen/logrus"
	glab "gitlab.com/gitlab-org/api/client-go"
)

// isPremiumFeatureUnavailable reports whether an approval-rules/settings fetch
// failed with a 403/404 — the "feature unavailable / token lacks scope" signal
// that leaves the listing not-evaluable (never a false pass). It reads the
// typed HTTP status the fetch surfaces, not a substring of the error string,
// which embeds the request URL and could carry "403"/"404" spuriously (e.g. a
// project id), so a hard 500 on such a project is not misread as premium-missing.
func isPremiumFeatureUnavailable(status int) bool {
	return status == http.StatusForbidden || status == http.StatusNotFound
}

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
	Branches          []string                    `json:"branches"`
	BranchProtections []BranchProtection          `json:"branchProtections"`
	MRApprovalRules   []*glab.ProjectApprovalRule `json:"mrApprovalRules"`
	// MRApprovalRulesKnown records whether the approval-rules listing was
	// read authoritatively. It stays false on a 403/404 (non-premium
	// GitLab, or a token without scope), so the approval-rule controls
	// (ISSUE-502/504) report not-evaluable rather than a false pass: an
	// unreadable listing must not make a project look compliant.
	MRApprovalRulesKnown bool                   `json:"mrApprovalRulesKnown"`
	MRApprovalSettings   *glab.ProjectApprovals `json:"mrApprovalSettings"`
	MRSettings           *glab.Project          `json:"mrSettings"`
	ProjectMembers       []GitlabMemberInfo     `json:"projectMembers"`

	// SecurityPolicyKnown is true when the security policy project linkage was
	// read authoritatively (a successful GraphQL read; nil linkage then means
	// "none linked"). False when the linkage could not be read (auth error, or
	// the field is unavailable) so ISSUE-601 reports not-evaluable, not a pass.
	SecurityPolicyKnown bool `json:"securityPolicyKnown"`
	// SecurityPolicyProject is the linked GitLab security policy project, or nil
	// when none is linked. Only meaningful when SecurityPolicyKnown is true.
	SecurityPolicyProject *SecurityPolicyProjectLink `json:"securityPolicyProject"`
}

// Run fetches all GitLab protection data needed by the controls
func (dc *GitlabProtectionDataCollection) Run(
	project *ProjectInfo,
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
	branches, branchProtections, err := FetchProjectBranchData(project.Path, token, conf.GitlabURL, conf)
	if err != nil {
		l.WithError(err).Error("Failed to fetch project branch data")
		return nil, metrics, err
	}
	returnedData.Branches = branches
	returnedData.BranchProtections = branchProtections
	metrics.Branches = len(branches)

	// Get project MR approval rules (may 403/404 when the token cannot read them; GitLab Free returns 200 with an empty list)
	approvalRules, rulesStatus, err := FetchProjectMRApprovalRules(project.ID, token, conf.GitlabURL, conf)
	if err != nil {
		if !isPremiumFeatureUnavailable(rulesStatus) {
			l.WithError(err).Error("Failed to fetch MR approval rules")
			return nil, metrics, err
		}
		l.WithError(err).Warn("MR approval rules not available (may require premium)")
		// If 403/404 error, MRApprovalRules stays nil and MRApprovalRulesKnown
		// stays false, so ISSUE-502/504 report not-evaluable, not a false pass.
	} else {
		returnedData.MRApprovalRules = approvalRules
		returnedData.MRApprovalRulesKnown = true
	}

	// Get project MR approval settings (may 403/404 when the token cannot read them; GitLab Free returns 200 with an empty list)
	approvalSettings, settingsStatus, err := FetchProjectMRApprovalSettings(project.ID, token, conf.GitlabURL, conf)
	if err != nil {
		if !isPremiumFeatureUnavailable(settingsStatus) {
			l.WithError(err).Error("Failed to fetch MR approval settings")
			return nil, metrics, err
		}
		l.WithError(err).Warn("MR approval settings not available (may require premium)")
		// If 403/404 error, MRApprovalSettings stays nil, so ISSUE-503 reports
		// not-evaluable, not a false pass (the nil pointer is the Known signal).
	} else {
		returnedData.MRApprovalSettings = approvalSettings
	}

	// Get project settings (includes MR settings like squash, merge method)
	projectSettings, _, err := FetchGitlabProject(project.ID, token, conf.GitlabURL, conf)
	if err != nil {
		l.WithError(err).Error("Failed to fetch project settings")
		return nil, metrics, err
	}
	returnedData.MRSettings = projectSettings

	// Get project members
	members, err := FetchProjectMembers(project.ID, token, conf.GitlabURL, conf)
	if err != nil {
		l.WithError(err).Warn("Failed to fetch project members")
		// Continue without members
	} else {
		returnedData.ProjectMembers = members
	}

	// Get the linked security policy project (GraphQL; GitLab Ultimate). Fetched
	// only when the control is enabled — it is a separate API surface, so a
	// disabled control pays no cost. A read failure is never fatal: it leaves
	// SecurityPolicyKnown false, so ISSUE-601 reports not-evaluable.
	if spc := conf.PlumberConfig.GetProjectMustHaveSecurityPolicySourceConfig(); spc != nil && spc.IsEnabled() {
		link, known, spErr := GetSecurityPolicyProject(project.Path, token, conf.GitlabURL, conf)
		if spErr != nil {
			l.WithError(spErr).Warn("Failed to fetch security policy project; ISSUE-601 will report not-evaluable")
		}
		returnedData.SecurityPolicyKnown = known
		returnedData.SecurityPolicyProject = link
	}

	l.WithFields(logrus.Fields{
		"branchCount":           len(returnedData.Branches),
		"branchProtectionCount": len(returnedData.BranchProtections),
		"memberCount":           len(returnedData.ProjectMembers),
	}).Info("Protection data collection completed")

	return returnedData, metrics, nil
}
