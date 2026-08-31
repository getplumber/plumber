package gitlab

import (
	"net/http"

	"github.com/getplumber/plumber/configuration"
	"github.com/sirupsen/logrus"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

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
		l.WithError(err).Warn("Unable to get project from GitLab API")
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
		options.Page = page

		tags, _, err := glab.Tags.ListTags(projectPath, options)
		if err != nil {
			l.WithError(err).Warn("Failed to retreive tags from GitLab API")
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

// BranchExists reports whether the given branch (or tag/ref) exists in the
// project. A 404 from the API means it does not exist and is returned as
// (false, nil); any other failure (auth, network) is a real error. Used to
// tell a non-existent --branch apart from a branch that simply has no
// .gitlab-ci.yml, so the former fails loudly instead of rendering a
// confusing limited report (#222).
func BranchExists(projectID int, branch string, token string, APIURL string, conf *configuration.Configuration) (bool, error) {
	l := logger.WithFields(logrus.Fields{
		"action":    "BranchExists",
		"projectID": projectID,
		"branch":    branch,
	})

	glab, err := GetNewGitlabClient(token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return false, err
	}

	_, resp, err := glab.Branches.GetBranch(projectID, branch)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return false, nil
		}
		l.WithError(err).Error("Failed to check whether branch exists")
		return false, err
	}
	return true, nil
}

// RefResolvesAsTagAndBranch probes whether ref exists in projectPath as a
// tag and/or as a branch. go-gitlab accepts a "group/project" path as the
// project identifier, so callers pass the include's resolved project path
// directly. A 404 means "not that kind of ref" (false); any other error is
// returned so the caller abstains rather than guessing. ref-confusion
// (ISSUE-402) fires only on a confirmed tag-AND-branch collision, so an
// indeterminate probe (auth, network, rate limit) must never assert
// ambiguity — the error path leaves both false and surfaces err.
func RefResolvesAsTagAndBranch(projectPath string, ref string, token string, APIURL string, conf *configuration.Configuration) (tagExists bool, branchExists bool, err error) {
	l := logger.WithFields(logrus.Fields{
		"action":      "RefResolvesAsTagAndBranch",
		"projectPath": projectPath,
		"ref":         ref,
	})

	glab, err := GetNewGitlabClient(token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return false, false, err
	}

	if _, resp, e := glab.Tags.GetTag(projectPath, ref); e != nil {
		if resp == nil || resp.StatusCode != http.StatusNotFound {
			l.WithError(e).Error("Failed to check whether tag exists")
			return false, false, e
		}
	} else {
		tagExists = true
	}

	if _, resp, e := glab.Branches.GetBranch(projectPath, ref); e != nil {
		if resp == nil || resp.StatusCode != http.StatusNotFound {
			l.WithError(e).Error("Failed to check whether branch exists")
			return tagExists, false, e
		}
	} else {
		branchExists = true
	}

	return tagExists, branchExists, nil
}

// FetchProjectMRApprovalRules retrieves MR approval rules for a project. The
// second return is the HTTP status of a failed request (0 when there was no
// response), so the caller can classify a 403/404 (feature unavailable / token
// scope → not-evaluable) apart from a hard failure on the typed status rather
// than substring-matching the error string.
func FetchProjectMRApprovalRules(projectID int, token string, APIURL string, conf *configuration.Configuration) ([]*gitlab.ProjectApprovalRule, int, error) {
	l := logger.WithFields(logrus.Fields{
		"action":    "FetchProjectMRApprovalRules",
		"projectID": projectID,
		"APIURL":    APIURL,
	})

	glab, err := GetNewGitlabClient(token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return nil, 0, err
	}

	// Paginate: GET /projects/:id/approval_rules defaults to per_page 20, so a
	// project with more rules than one page would otherwise be silently
	// truncated — and the caller marks the listing authoritative
	// (MRApprovalRulesKnown=true), which would turn a missed weak rule into a
	// false pass for ISSUE-502. Mirrors FetchProjectMembers / FetchProjectBranchData.
	var allRules []*gitlab.ProjectApprovalRule
	options := &gitlab.GetProjectApprovalRulesListsOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100},
	}
	for page := int64(1); ; page++ {
		options.Page = page
		rules, resp, err := glab.Projects.GetProjectApprovalRules(projectID, options)
		if err != nil {
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			l.WithError(err).Warn("Failed to fetch MR approval rules")
			return nil, status, err
		}
		allRules = append(allRules, rules...)
		if resp == nil || resp.NextPage == 0 {
			break
		}
	}

	l.WithField("ruleCount", len(allRules)).Debug("Fetched MR approval rules")
	return allRules, http.StatusOK, nil
}

// FetchProjectMRApprovalSettings retrieves MR approval settings for a project.
// The second return is the HTTP status of a failed request (0 when there was no
// response), so the caller classifies a 403/404 apart from a hard failure on
// the typed status.
func FetchProjectMRApprovalSettings(projectID int, token string, APIURL string, conf *configuration.Configuration) (*gitlab.ProjectApprovals, int, error) {
	l := logger.WithFields(logrus.Fields{
		"action":    "FetchProjectMRApprovalSettings",
		"projectID": projectID,
		"APIURL":    APIURL,
	})

	glab, err := GetNewGitlabClient(token, APIURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a Gitlab client")
		return nil, 0, err
	}

	settings, resp, err := glab.Projects.GetApprovalConfiguration(projectID)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		l.WithError(err).Warn("Failed to fetch MR approval settings")
		return nil, status, err
	}

	l.Debug("Fetched MR approval settings")
	return settings, http.StatusOK, nil
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
			// Return the error rather than an empty list. "This project has
			// no protected branches" is the exact violation
			// branchMustBeProtected exists to catch, so a read that FAILED
			// must not arrive looking like one - a token without the scope,
			// or a 403, would otherwise be reported as every branch being
			// unprotected.
			//
			// The branches collected so far are still returned: the caller
			// can tell "which branches exist" from "how they are protected",
			// and the first question is still answered. Callers that cannot
			// use a partial answer check err and ignore the rest.
			l.WithError(err).Warn("Failed to fetch branch protections; the protection detail is unknown, not empty")
			return allBranches, nil, err
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
