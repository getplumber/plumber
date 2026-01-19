package control

import (
	wildcard "github.com/IGLOU-EU/go-wildcard/v2"
	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	"github.com/sirupsen/logrus"
)

const ControlTypeGitlabProtectionBranchProtectionNotCompliantVersion = "0.2.0"

//////////////////////////
// Control configuration //
//////////////////////////

// GitlabBranchProtectionControl handles branch protection compliance checking
type GitlabBranchProtectionControl struct {
	config *configuration.BranchProtectionControlConfig
}

// NewGitlabBranchProtectionControl creates a new branch protection control instance
func NewGitlabBranchProtectionControl(config *configuration.BranchProtectionControlConfig) *GitlabBranchProtectionControl {
	return &GitlabBranchProtectionControl{
		config: config,
	}
}

// BranchProtectionCompliance holds information about a branch's protection compliance
type BranchProtectionCompliance struct {
	BranchName                string
	Default                   bool
	Protected                 bool
	AllowForcePush            bool
	CodeOwnerApprovalRequired bool
	MinPushAccessLevel        int
	MinMergeAccessLevel       int
	ProtectionPattern         string
	PushAccessLevels          []gitlab.BranchProtectionAccessLevel
	MergeAccessLevels         []gitlab.BranchProtectionAccessLevel
}

///////////////////
// Control run  //
///////////////////

// Run executes the branch protection compliance check
func (c *GitlabBranchProtectionControl) Run(
	protectionData *collector.GitlabProtectionAnalysisData,
	project *gitlab.ProjectInfo,
) *GitlabBranchProtectionResult {

	// Set logging
	logger := l.WithFields(logrus.Fields{
		"control":   "GitlabBranchProtectionNotCompliant",
		"project":   project.Path,
		"projectId": project.ID,
	})

	// Check if control is enabled
	if c.config == nil || !c.config.IsEnabled() {
		logger.Info("Branch protection control is disabled or not configured")
		return &GitlabBranchProtectionResult{
			Enabled:    false,
			Skipped:    true,
			Compliance: 100.0,
			Version:    ControlTypeGitlabProtectionBranchProtectionNotCompliantVersion,
		}
	}

	// Log the control start
	logger.Info("Start branch protection control")

	data := []BranchProtectionData{}
	issues := []BranchProtectionIssue{}
	metrics := &BranchProtectionMetrics{}
	compliance := 0.0

	// Check which branches should be protected based on configuration
	branchesToProtect := map[string]*BranchProtectionCompliance{}
	if len(protectionData.Branches) != 0 {
		branchesToProtect = c.checkBranches(
			protectionData.Branches,
			protectionData.BranchProtections,
			project.DefaultBranch,
		)
	}

	nonCompliantCount := 0
	unprotectedCount := 0
	totalProtectedBranches := 0

	// Get config values with defaults
	allowForcePush := false
	if c.config.AllowForcePush != nil {
		allowForcePush = *c.config.AllowForcePush
	}

	codeOwnerApprovalRequired := false
	if c.config.CodeOwnerApprovalRequired != nil {
		codeOwnerApprovalRequired = *c.config.CodeOwnerApprovalRequired
	}

	minMergeAccessLevel := 0
	if c.config.MinMergeAccessLevel != nil {
		minMergeAccessLevel = *c.config.MinMergeAccessLevel
	}

	minPushAccessLevel := 0
	if c.config.MinPushAccessLevel != nil {
		minPushAccessLevel = *c.config.MinPushAccessLevel
	}

	defaultMustBeProtected := false
	if c.config.DefaultMustBeProtected != nil {
		defaultMustBeProtected = *c.config.DefaultMustBeProtected
	}

	// Process each branch that should be protected
	for _, branch := range branchesToProtect {
		// Add branch data for all branches that should be protected
		branchData := BranchProtectionData{
			BranchName: branch.BranchName,
			Default:    branch.Default,
			Protected:  branch.Protected,
		}

		// Handle unprotected branches
		if !branch.Protected {
			unprotectedCount++

			// Create issue for unprotected branch
			issue := BranchProtectionIssue{
				Type:       "unprotected",
				BranchName: branch.BranchName,
			}
			issues = append(issues, issue)
			data = append(data, branchData)
			continue
		}

		totalProtectedBranches++

		// Skip if this branch doesn't match any pattern in this configuration
		matchesPattern := false
		for _, pattern := range c.config.NamePatterns {
			if wildcard.Match(pattern, branch.BranchName) {
				matchesPattern = true
				break
			}
		}
		if !matchesPattern && !(defaultMustBeProtected && branch.Default) {
			continue
		}

		// Check compliance issues
		issueData := BranchProtectionIssue{
			Type:                          "non_compliant",
			BranchName:                    branch.BranchName,
			AllowForcePush:                branch.AllowForcePush,
			CodeOwnerApprovalRequired:     branch.CodeOwnerApprovalRequired,
			MinMergeAccessLevel:           branch.MinMergeAccessLevel,
			AuthorizedMinMergeAccessLevel: minMergeAccessLevel,
			MinPushAccessLevel:            branch.MinPushAccessLevel,
			AuthorizedMinPushAccessLevel:  minPushAccessLevel,
		}

		hasIssue := false

		// Check if forcePushAllowed is not respected
		if !allowForcePush && branch.AllowForcePush {
			issueData.AllowForcePushDisplay = true
			hasIssue = true
		}

		// Check if codeOwnerApprovalRequired is not respected
		if codeOwnerApprovalRequired && !branch.CodeOwnerApprovalRequired {
			issueData.CodeOwnerApprovalRequiredDisplay = true
			hasIssue = true
		}

		// Check if min access level is not respected for merge
		if branch.MinMergeAccessLevel != 0 && (minMergeAccessLevel == 0 || minMergeAccessLevel > branch.MinMergeAccessLevel) {
			issueData.MinMergeAccessLevelDisplay = true
			hasIssue = true
		}

		// Check if min access level is not respected for push
		if branch.MinPushAccessLevel != 0 && (minPushAccessLevel == 0 || minPushAccessLevel > branch.MinPushAccessLevel) {
			issueData.MinPushAccessLevelDisplay = true
			hasIssue = true
		}

		// Create issue if needed
		if hasIssue {
			nonCompliantCount++

			// Add data with compliance details
			branchData.AllowForcePush = issueData.AllowForcePush
			branchData.CodeOwnerApprovalRequired = issueData.CodeOwnerApprovalRequired
			branchData.MinMergeAccessLevel = issueData.MinMergeAccessLevel
			branchData.MinPushAccessLevel = issueData.MinPushAccessLevel
			branchData.AuthorizedMinMergeAccessLevel = issueData.AuthorizedMinMergeAccessLevel
			branchData.AuthorizedMinPushAccessLevel = issueData.AuthorizedMinPushAccessLevel

			issues = append(issues, issueData)
		}

		// Always add data for protected branches, even if compliant
		if hasIssue || len(data) == 0 || data[len(data)-1].BranchName != branchData.BranchName {
			data = append(data, branchData)
		}
	}

	// Calculate metrics
	metrics.Branches = len(protectionData.Branches)
	metrics.BranchesToProtect = len(branchesToProtect)
	metrics.UnprotectedBranches = unprotectedCount
	metrics.NonCompliantBranches = nonCompliantCount
	metrics.TotalProtectedBranches = totalProtectedBranches
	if unprotectedCount == 0 && nonCompliantCount == 0 && len(branchesToProtect) > 0 {
		metrics.ProjectsCorrectlyProtected = 1
	}

	// Calculate compliance
	if len(issues) == 0 {
		compliance = 100.0
	} else {
		logger.WithField("issueCount", len(issues)).Debug("Issues found, compliance is 0")
	}

	return &GitlabBranchProtectionResult{
		Enabled:    true,
		Compliance: compliance,
		Version:    ControlTypeGitlabProtectionBranchProtectionNotCompliantVersion,
		Data:       data,
		Metrics:    metrics,
		Issues:     issues,
	}
}

// checkBranches determines which branches need protection and their current protection status
func (c *GitlabBranchProtectionControl) checkBranches(
	branches []string,
	branchProtections []gitlab.BranchProtection,
	defaultBranch string,
) map[string]*BranchProtectionCompliance {

	// Get config values
	defaultMustBeProtected := false
	if c.config.DefaultMustBeProtected != nil {
		defaultMustBeProtected = *c.config.DefaultMustBeProtected
	}

	// Filter repo branches by patterns
	branchesToProtect := map[string]*BranchProtectionCompliance{}

	// First, collect all branches that need protection based on configuration
	if defaultMustBeProtected {
		branchesToProtect[defaultBranch] = &BranchProtectionCompliance{
			BranchName: defaultBranch,
			Default:    true,
			Protected:  false,
		}
	}

	for _, branch := range branches {
		for _, pattern := range c.config.NamePatterns {
			if wildcard.Match(pattern, branch) {
				if _, exists := branchesToProtect[branch]; !exists {
					branchesToProtect[branch] = &BranchProtectionCompliance{
						BranchName: branch,
						Default:    branch == defaultBranch,
						Protected:  false,
					}
				}
			}
		}
	}

	// Set all branches to protect with the least permissive protection
	// configuration to simplify the check in the next loop while keeping the
	// most permissive rule in case of multiple match
	for _, branch := range branchesToProtect {
		branch.AllowForcePush = false
		branch.CodeOwnerApprovalRequired = true
		branch.MinMergeAccessLevel = gitlab.AccessLevelNo
		branch.MinPushAccessLevel = gitlab.AccessLevelNo
		branch.PushAccessLevels = []gitlab.BranchProtectionAccessLevel{}
		branch.MergeAccessLevels = []gitlab.BranchProtectionAccessLevel{}
	}

	// For each branch to protect: loop over all protection patterns and try
	// to match following GitLab pattern matching rules:
	// - Only wildcard "*" can be used
	// - Matching is case-sensitive

	// NOTE: here, we use the wildcard lib matching (*, ?, .) pattern which is
	// not the same as GitLab. It can produce wrong results in case of
	// interrogation mark or dots present in protection name pattern (they are
	// not interpreted by GitLab but we interpret them)

	// NOTE: if a branch matches 2 protection rules, the most permissive is
	// applied (see
	// https://docs.gitlab.com/ee/user/project/repository/branches/protected.html#when-a-branch-matches-multiple-rules)

	for _, branch := range branchesToProtect {
		for _, branchProtection := range branchProtections {

			// If protection does not match with branch, continue
			if !wildcard.Match(branchProtection.ProtectionPattern, branch.BranchName) {
				continue
			}

			// Add protection data
			branch.Protected = true

			// NOTE: if several protection patterns match for the same branch,
			// this field will be overridden
			branch.ProtectionPattern = branchProtection.ProtectionPattern

			// Add protection rules while always keeping the most permissive

			// If allow force push currently set in the branch is false, it
			// means that it's not to the most permissive state, so we can
			// apply current protection
			if !branch.AllowForcePush {
				branch.AllowForcePush = branchProtection.AllowForcePush
			}

			// If code owner approval required currently set in the branch is
			// true, it means that it's not to the most permissive state, so we
			// can apply current protection
			if branch.CodeOwnerApprovalRequired {
				branch.CodeOwnerApprovalRequired = branchProtection.CodeOwnerApprovalRequired
			}

			// Merge access level
			for _, mergeAccessLevel := range branchProtection.MergeAccessLevels {

				// Add it to branch for data
				branch.MergeAccessLevels = append(branch.MergeAccessLevels, mergeAccessLevel)

				// If merge access level from the protection rule is different
				// than 0 (No one) and smaller than the minimum currently set
				// in branch, we take it as min access level as it's equal or
				// more permissive to the current min
				if branch.MinMergeAccessLevel == 0 || ((mergeAccessLevel.AccessLevel != gitlab.AccessLevelNo) && (mergeAccessLevel.AccessLevel < branch.MinMergeAccessLevel)) {
					branch.MinMergeAccessLevel = mergeAccessLevel.AccessLevel
				}
			}

			// Push access level
			for _, pushAccessLevel := range branchProtection.PushAccessLevels {

				// Add it to branch for data
				branch.PushAccessLevels = append(branch.PushAccessLevels, pushAccessLevel)

				// If push access level from the protection rule is different than
				// 0 (No one) and smaller than the minimum currently set in branch,
				// we apply it as min access level as it's equal or more permissive
				// to the current min
				if branch.MinPushAccessLevel == 0 || ((pushAccessLevel.AccessLevel != gitlab.AccessLevelNo) && (pushAccessLevel.AccessLevel < branch.MinMergeAccessLevel)) {
					branch.MinPushAccessLevel = pushAccessLevel.AccessLevel
				}
			}
		}
	}

	return branchesToProtect
}
