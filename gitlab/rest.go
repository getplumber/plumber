package gitlab

import (
	"strconv"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/sirupsen/logrus"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// GetFullPathAndName returns the full path and full name of a project using its ID
func GetFullPathAndName(id int, token string, instanceUrl string, conf *configuration.Configuration) (string, string, error) {
	l := logger.WithFields(logrus.Fields{
		"projectID": id,
		"action":    "GetFullPathAndName",
	})

	glab, err := GetNewGitlabClient(token, instanceUrl, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return "", "", err
	}

	options := &gitlab.GetProjectOptions{
		License:              new(bool),
		Statistics:           new(bool),
		WithCustomAttributes: new(bool),
	}

	project, _, err := glab.Projects.GetProject(id, options)
	if err != nil {
		l.WithError(err).Error("Error when trying to get project")
		return "", "", err
	}

	return project.PathWithNamespace, project.NameWithNamespace, nil
}

// FetchGitlabProject retrieves a project from GitLab using its ID
func FetchGitlabProject(id int, token string, APIURL string, conf *configuration.Configuration) (*gitlab.Project, error, error) {
	l := logger.WithFields(logrus.Fields{
		"action":          "FetchGitlabProject",
		"GitlabProjectID": id,
		"APIURL":          APIURL,
	})

	glab, err := GetNewGitlabClient(token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return nil, nil, err
	}

	project, _, err := glab.Projects.GetProject(id, &gitlab.GetProjectOptions{
		License:              new(bool),
		Statistics:           new(bool),
		WithCustomAttributes: new(bool),
	})

	if err != nil {
		l.WithError(err).Warning("Unable to get project from GitLab API")
		return project, err, nil
	}

	l.WithField("projectPath", project.PathWithNamespace).Info("Fetch project from GitLab API")
	return project, nil, nil
}

// FetchGitlabFile retrieves a file from a GitLab project using its path
func FetchGitlabFile(projectPath string, filePath string, ref string, token string, APIURL string, conf *configuration.Configuration) ([]byte, error, error) {
	l := logger.WithFields(logrus.Fields{
		"action":            "FetchGitlabFile",
		"GitlabProjectPath": projectPath,
		"filePath":          filePath,
		"ref":               ref,
		"APIURL":            APIURL,
	})

	glab, err := GetNewGitlabClient(token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return []byte{}, nil, err
	}

	options := &gitlab.GetRawFileOptions{}
	if ref != "" {
		options.Ref = &ref
	}

	file, _, err := glab.RepositoryFiles.GetRawFile(projectPath, filePath, options)
	if err != nil {
		l.WithError(err).Info("Unable to get file from GitLab API")
		return []byte{}, err, nil
	}

	l.Debug("Fetched file from GitLab API")
	return file, nil, nil
}

// SearchTags gets all tags of a project
func SearchTags(projectPath string, token string, APIURL string, conf *configuration.Configuration) ([]string, error, error) {
	l := logger.WithFields(logrus.Fields{
		"action":            "SearchTags",
		"GitlabProjectPath": projectPath,
		"APIURL":            APIURL,
	})

	gTags := []*gitlab.Tag{}

	glab, err := GetNewGitlabClient(token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return []string{}, nil, err
	}

	var perPage int64 = 100
	orderBy := "updated"
	sort := "desc"
	options := &gitlab.ListTagsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: perPage,
		},
		OrderBy: &orderBy,
		Sort:    &sort,
	}

	for page := int64(1); true; page++ {
		options.ListOptions.Page = page

		tags, _, err := glab.Tags.ListTags(projectPath, options)
		if err != nil {
			l.WithError(err).Warning("Failed to retreive tags from GitLab API")
			return []string{}, err, nil
		} else {
			gTags = append(gTags, tags...)
			if int64(len(tags)) < perPage {
				break
			}
		}
	}
	l.Debug("Fetched tags from GitLab API")

	allTags := make([]string, len(gTags))
	for i, tag := range gTags {
		allTags[i] = tag.Name
	}

	return allTags, nil, nil
}

// FetchProjectBranches retrieves all branches for a project
func FetchProjectBranches(projectID int, token string, APIURL string, conf *configuration.Configuration) ([]string, error) {
	l := logger.WithFields(logrus.Fields{
		"action":    "FetchProjectBranches",
		"projectID": projectID,
		"APIURL":    APIURL,
	})

	glab, err := GetNewGitlabClient(token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return nil, err
	}

	var allBranches []string
	var perPage int64 = 100
	options := &gitlab.ListBranchesOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: perPage,
		},
	}

	for page := int64(1); ; page++ {
		options.Page = page
		branches, _, err := glab.Branches.ListBranches(projectID, options)
		if err != nil {
			l.WithError(err).Error("Failed to fetch branches")
			return nil, err
		}

		for _, branch := range branches {
			allBranches = append(allBranches, branch.Name)
		}

		if int64(len(branches)) < perPage {
			break
		}
	}

	l.WithField("branchCount", len(allBranches)).Debug("Fetched branches")
	return allBranches, nil
}

// FetchBranchProtections retrieves branch protection settings for a project
func FetchBranchProtections(projectID int, token string, APIURL string, conf *configuration.Configuration) ([]BranchProtection, error) {
	l := logger.WithFields(logrus.Fields{
		"action":    "FetchBranchProtections",
		"projectID": projectID,
		"APIURL":    APIURL,
	})

	glab, err := GetNewGitlabClient(token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return nil, err
	}

	var allProtections []BranchProtection
	var perPage int64 = 100
	options := &gitlab.ListProtectedBranchesOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: perPage,
		},
	}

	for page := int64(1); ; page++ {
		options.Page = page
		protections, _, err := glab.ProtectedBranches.ListProtectedBranches(projectID, options)
		if err != nil {
			l.WithError(err).Warning("Failed to fetch branch protections")
			return nil, err
		}

		for _, p := range protections {
			bp := BranchProtection{
				ProtectionPattern:         p.Name,
				AllowForcePush:            p.AllowForcePush,
				CodeOwnerApprovalRequired: p.CodeOwnerApprovalRequired,
			}

			// Extract access levels
			for _, level := range p.PushAccessLevels {
				bp.PushAccessLevels = append(bp.PushAccessLevels, BranchProtectionAccessLevel{
					AccessLevel:            int(level.AccessLevel),
					AccessLevelDescription: level.AccessLevelDescription,
				})
			}
			for _, level := range p.MergeAccessLevels {
				bp.MergeAccessLevels = append(bp.MergeAccessLevels, BranchProtectionAccessLevel{
					AccessLevel:            int(level.AccessLevel),
					AccessLevelDescription: level.AccessLevelDescription,
				})
			}

			allProtections = append(allProtections, bp)
		}

		if int64(len(protections)) < perPage {
			break
		}
	}

	l.WithField("protectionCount", len(allProtections)).Debug("Fetched branch protections")
	return allProtections, nil
}

// FetchProjectMRApprovalRules retrieves MR approval rules for a project
func FetchProjectMRApprovalRules(projectID int, token string, APIURL string, conf *configuration.Configuration) ([]*gitlab.ProjectApprovalRule, error) {
	l := logger.WithFields(logrus.Fields{
		"action":    "FetchProjectMRApprovalRules",
		"projectID": projectID,
		"APIURL":    APIURL,
	})

	glab, err := GetNewGitlabClient(token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return nil, err
	}

	rules, _, err := glab.Projects.GetProjectApprovalRules(projectID, nil)
	if err != nil {
		l.WithError(err).Warning("Failed to fetch MR approval rules")
		return nil, err
	}

	l.WithField("ruleCount", len(rules)).Debug("Fetched MR approval rules")
	return rules, nil
}

// FetchProjectMRApprovalSettings retrieves MR approval settings for a project
func FetchProjectMRApprovalSettings(projectID int, token string, APIURL string, conf *configuration.Configuration) (*gitlab.ProjectApprovals, error) {
	l := logger.WithFields(logrus.Fields{
		"action":    "FetchProjectMRApprovalSettings",
		"projectID": projectID,
		"APIURL":    APIURL,
	})

	glab, err := GetNewGitlabClient(token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return nil, err
	}

	settings, _, err := glab.Projects.GetApprovalConfiguration(projectID)
	if err != nil {
		l.WithError(err).Warning("Failed to fetch MR approval settings")
		return nil, err
	}

	l.Debug("Fetched MR approval settings")
	return settings, nil
}

// FetchProjectMembers retrieves all members of a project
func FetchProjectMembers(projectID int, token string, APIURL string, conf *configuration.Configuration) ([]GitlabMemberInfo, error) {
	l := logger.WithFields(logrus.Fields{
		"action":    "FetchProjectMembers",
		"projectID": projectID,
		"APIURL":    APIURL,
	})

	glab, err := GetNewGitlabClient(token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return nil, err
	}

	var allMembers []GitlabMemberInfo
	var perPage int64 = 100
	options := &gitlab.ListProjectMembersOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: perPage,
		},
	}

	for page := int64(1); ; page++ {
		options.Page = page
		members, _, err := glab.ProjectMembers.ListAllProjectMembers(projectID, options)
		if err != nil {
			l.WithError(err).Warning("Failed to fetch project members")
			return nil, err
		}

		for _, m := range members {
			// Skip bot users
			if strings.Contains(m.Username, "_bot_") {
				l.WithField("botUsername", m.Username).Debug("Skipping bot user")
				continue
			}

			member := GitlabMemberInfo{
				ID:            int(m.ID),
				Name:          m.Username,
				DisplayedName: m.Name,
				Email:         m.Email,
				AvatarURL:     m.AvatarURL,
				AccessLevel:   int(m.AccessLevel),
			}
			allMembers = append(allMembers, member)
		}

		if int64(len(members)) < perPage {
			break
		}
	}

	l.WithField("memberCount", len(allMembers)).Debug("Fetched project members")
	return allMembers, nil
}

// FetchGroupMembers retrieves all members of a group
func FetchGroupMembers(groupID int, token string, APIURL string, conf *configuration.Configuration) ([]GitlabMemberInfo, error) {
	l := logger.WithFields(logrus.Fields{
		"action":  "FetchGroupMembers",
		"groupID": groupID,
		"APIURL":  APIURL,
	})

	glab, err := GetNewGitlabClient(token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return nil, err
	}

	var allMembers []GitlabMemberInfo
	var perPage int64 = 100
	options := &gitlab.ListGroupMembersOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: perPage,
		},
	}

	for page := int64(1); ; page++ {
		options.Page = page
		members, _, err := glab.Groups.ListAllGroupMembers(groupID, options)
		if err != nil {
			l.WithError(err).Warning("Failed to fetch group members")
			return nil, err
		}

		for _, m := range members {
			// Skip bot users
			if strings.Contains(m.Username, "_bot_") {
				l.WithField("botUsername", m.Username).Debug("Skipping bot user")
				continue
			}

			member := GitlabMemberInfo{
				ID:            int(m.ID),
				Name:          m.Username,
				DisplayedName: m.Name,
				Email:         m.Email,
				AvatarURL:     m.AvatarURL,
				AccessLevel:   int(m.AccessLevel),
			}
			allMembers = append(allMembers, member)
		}

		if int64(len(members)) < perPage {
			break
		}
	}

	l.WithField("memberCount", len(allMembers)).Debug("Fetched group members")
	return allMembers, nil
}

// FetchProjectBranchData fetches branches and their protection settings
func FetchProjectBranchData(projectPath string, token string, APIURL string, conf *configuration.Configuration) ([]string, []BranchProtection, error) {
	l := logger.WithFields(logrus.Fields{
		"action":      "FetchProjectBranchData",
		"projectPath": projectPath,
		"APIURL":      APIURL,
	})

	glab, err := GetNewGitlabClient(token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return nil, nil, err
	}

	// Fetch branches
	var allBranches []string
	var perPage int64 = 100
	branchOptions := &gitlab.ListBranchesOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: perPage,
		},
	}

	for page := int64(1); ; page++ {
		branchOptions.Page = page
		branches, _, err := glab.Branches.ListBranches(projectPath, branchOptions)
		if err != nil {
			l.WithError(err).Error("Failed to fetch branches")
			return nil, nil, err
		}

		for _, branch := range branches {
			allBranches = append(allBranches, branch.Name)
		}

		if int64(len(branches)) < perPage {
			break
		}
	}

	// Fetch branch protections
	var allProtections []BranchProtection
	protOptions := &gitlab.ListProtectedBranchesOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: perPage,
		},
	}

	for page := int64(1); ; page++ {
		protOptions.Page = page
		protections, _, err := glab.ProtectedBranches.ListProtectedBranches(projectPath, protOptions)
		if err != nil {
			l.WithError(err).Warning("Failed to fetch branch protections (may require premium)")
			// Return branches without protections
			return allBranches, nil, nil
		}

		for _, p := range protections {
			bp := BranchProtection{
				ProtectionPattern:         p.Name,
				AllowForcePush:            p.AllowForcePush,
				CodeOwnerApprovalRequired: p.CodeOwnerApprovalRequired,
			}

			for _, level := range p.PushAccessLevels {
				bp.PushAccessLevels = append(bp.PushAccessLevels, BranchProtectionAccessLevel{
					AccessLevel:            int(level.AccessLevel),
					AccessLevelDescription: level.AccessLevelDescription,
				})
			}
			for _, level := range p.MergeAccessLevels {
				bp.MergeAccessLevels = append(bp.MergeAccessLevels, BranchProtectionAccessLevel{
					AccessLevel:            int(level.AccessLevel),
					AccessLevelDescription: level.AccessLevelDescription,
				})
			}

			allProtections = append(allProtections, bp)
		}

		if int64(len(protections)) < perPage {
			break
		}
	}

	l.WithFields(logrus.Fields{
		"branchCount":     len(allBranches),
		"protectionCount": len(allProtections),
	}).Debug("Fetched branch data")

	return allBranches, allProtections, nil
}

// GetGroupFullPath returns gitlab group fullPath from id
func GetGroupFullPath(groupID int, token string, APIURL string, conf *configuration.Configuration) (string, error) {
	l := logrus.WithFields(logrus.Fields{
		"groupID": groupID,
		"APIURL":  APIURL,
		"action":  "GetGroupFullPath",
	})

	var path string

	glab, err := GetNewGitlabClient(token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return path, err
	}

	group, _, err := glab.Groups.GetGroup(groupID,
		&gitlab.GetGroupOptions{
			WithCustomAttributes: new(bool), // false
		})

	if err != nil {
		l.WithError(err).Warning("Unable to get group from GitLab API")
		return path, err
	}

	l.WithField("groupPath", group.FullPath).Info("Fetch group from GitLab API")
	path = group.FullPath

	return path, nil
}

// FetchGitlabGroup retrieves a group from GitLab using its ID
// The first error returned is error from GitLab API response if any
func FetchGitlabGroup(id int, token string, APIURL string, conf *configuration.Configuration) (*gitlab.Group, error, error) {
	l := logger.WithFields(logrus.Fields{
		"action":        "FetchGitlabGroup",
		"GitlabGroupID": id,
		"APIURL":        APIURL,
	})

	glab, err := GetNewGitlabClient(token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return nil, nil, err
	}

	group, _, err := glab.Groups.GetGroup(id,
		&gitlab.GetGroupOptions{
			WithCustomAttributes: new(bool), // false
			WithProjects:         new(bool), // false
		})

	if err != nil {
		l.WithError(err).Warning("Unable to get group from GitLab API")
		return group, err, nil
	}

	l.WithField("groupPath", group.FullPath).Info("Fetch group from GitLab API")
	return group, nil, nil
}

// RepoHasFolder tests if a folder exists in a gitlab repository
func RepoHasFolder(projectPath string, folderPath string, token string, APIURL string, conf *configuration.Configuration) bool {
	l := logger.WithFields(logrus.Fields{
		"action":            "RepoHasFolder",
		"GitlabProjectPath": projectPath,
		"folderPath":        folderPath,
		"APIURL":            APIURL,
	})

	glab, err := GetNewGitlabClient(token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return false
	}

	tree, _, err := glab.Repositories.ListTree(
		projectPath,
		&gitlab.ListTreeOptions{Path: &folderPath},
	)

	return err == nil && len(tree) > 0
}

// FetchRepositoryBranches fetches all branches from a repository, respecting a maxPage limit
func FetchRepositoryBranches(client *gitlab.Client, projectID string, maxPage int) ([]*gitlab.Branch, error) {
	l := logrus.WithFields(logrus.Fields{
		"action":    "FetchRepositoryBranches",
		"projectID": projectID,
		"maxPage":   maxPage,
	})

	var allBranches []*gitlab.Branch
	page := int64(1)

	for int(page) <= maxPage {
		options := &gitlab.ListBranchesOptions{}
		options.Page = page
		options.PerPage = 100

		l.WithField("page", page).Debug("Fetching branches from GitLab")

		branches, resp, err := client.Branches.ListBranches(projectID, options)
		if err != nil {
			l.WithError(err).Error("Failed to fetch branches from GitLab")
			return nil, err
		}

		allBranches = append(allBranches, branches...)

		// Break if no more pages are available
		if resp.NextPage == 0 {
			break
		}

		page = resp.NextPage
	}

	l.WithField("totalBranchCount", len(allBranches)).Debug("Fetched all branches successfully")
	return allBranches, nil
}

// IsGitlabInstanceEnterprise checks if the GitLab instance is enterprise edition
func IsGitlabInstanceEnterprise(token, APIURL string, conf *configuration.Configuration) (bool, error) {
	l := logger.WithFields(logrus.Fields{
		"action": "IsGitlabInstanceEnterprise",
	})

	glab, err := GetNewGitlabClient(token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Failed to create GitLab client")
		return false, err
	}

	metadata, _, apiErr := glab.Metadata.GetMetadata()
	if apiErr != nil {
		l.WithError(apiErr).Error("Failed to fetch instance metadata")
		return false, apiErr
	}

	return metadata.Enterprise, nil
}

// GetGitlabInstanceVersion fetches the GitLab instance version
func GetGitlabInstanceVersion(token, APIURL string, conf *configuration.Configuration) (string, error) {
	l := logrus.WithFields(logrus.Fields{
		"action": "GetGitlabInstanceVersion",
		"APIURL": APIURL,
	})

	glab, err := GetNewGitlabClient(token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Failed to create GitLab client")
		return "", err
	}

	metadata, _, apiErr := glab.Metadata.GetMetadata()
	if apiErr != nil {
		l.WithError(apiErr).Error("Failed to fetch instance metadata")
		return "", apiErr
	}

	l.WithField("version", metadata.Version).Debug("Retrieved GitLab instance version")
	return metadata.Version, nil
}

// IsVersionGreaterOrEqual compares GitLab version strings
// Returns true if the given version is greater than or equal to the required version
func IsVersionGreaterOrEqual(version, requiredVersion string) bool {
	l := logrus.WithFields(logrus.Fields{
		"action":          "IsVersionGreaterOrEqual",
		"version":         version,
		"requiredVersion": requiredVersion,
	})

	// Remove any suffix (like "-ee" in "17.6.0-ee")
	version = strings.Split(version, "-")[0]
	requiredVersion = strings.Split(requiredVersion, "-")[0]

	// Split version strings into components
	vParts := strings.Split(version, ".")
	reqParts := strings.Split(requiredVersion, ".")

	// Parse up to 3 components (major.minor.patch)
	// Fill with zeros if missing
	vComponents := make([]int, 3)
	reqComponents := make([]int, 3)

	// Parse current version components
	for i := 0; i < len(vParts) && i < 3; i++ {
		num, err := strconv.Atoi(vParts[i])
		if err != nil {
			l.WithError(err).WithField("component", vParts[i]).Warning("Failed to parse version component")
			return false
		}
		vComponents[i] = num
	}

	// Parse required version components
	for i := 0; i < len(reqParts) && i < 3; i++ {
		num, err := strconv.Atoi(reqParts[i])
		if err != nil {
			l.WithError(err).WithField("component", reqParts[i]).Warning("Failed to parse required version component")
			return false
		}
		reqComponents[i] = num
	}

	// Compare major.minor.patch in sequence
	for i := 0; i < 3; i++ {
		if vComponents[i] > reqComponents[i] {
			return true
		}
		if vComponents[i] < reqComponents[i] {
			return false
		}
	}

	// All components are equal
	return true
}
