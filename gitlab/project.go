package gitlab

import (
	"fmt"

	"github.com/getplumber/plumber/configuration"
	"github.com/sirupsen/logrus"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// FetchProjectDetails fetches complete project information from GitLab API
// and returns a Project struct populated with all available data
func FetchProjectDetails(projectPath string, token string, instanceURL string, conf *configuration.Configuration) (*Project, error) {
	l := logger.WithFields(logrus.Fields{
		"action":      "FetchProjectDetails",
		"projectPath": projectPath,
		"instanceURL": instanceURL,
	})

	project := &Project{
		Path:       projectPath,
		CiConfPath: ".gitlab-ci.yml", // Default CI config path
	}

	// First, try to get project info via REST API
	glab, err := GetNewGitlabClient(token, instanceURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a GitLab client")
		return nil, err
	}

	// Get project by path
	gitlabProject, resp, err := glab.Projects.GetProject(projectPath, &gitlab.GetProjectOptions{
		License:              new(bool),
		Statistics:           new(bool),
		WithCustomAttributes: new(bool),
	})

	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			l.Info("Project not found on GitLab")
			// Return a minimal project indicating not found
			return nil, fmt.Errorf("project not found: %s", projectPath)
		}
		l.WithError(err).Error("Unable to fetch project from GitLab API")
		return nil, err
	}

	// Populate project info from REST API response
	project.IdOnPlatform = int(gitlabProject.ID)
	project.Name = gitlabProject.Name
	project.Path = gitlabProject.PathWithNamespace
	project.DefaultBranch = gitlabProject.DefaultBranch
	project.Visibility = string(gitlabProject.Visibility)
	project.Archived = gitlabProject.Archived
	if gitlabProject.LastActivityAt != nil {
		project.LastActivityAt = *gitlabProject.LastActivityAt
	}
	if gitlabProject.CreatedAt != nil {
		project.CreatedAt = *gitlabProject.CreatedAt
	}

	// Get CI config path if custom
	if gitlabProject.CIConfigPath != "" {
		project.CiConfPath = gitlabProject.CIConfigPath
	}

	// The merge-request settings ISSUE-506 reads. Already in this response;
	// projecting them here is what lets an embedding host serve them without
	// a second call to the same endpoint (#368 ask 4).
	project.MergeMethod = string(gitlabProject.MergeMethod)
	project.SquashOption = string(gitlabProject.SquashOption)
	project.MergePipelinesEnabled = gitlabProject.MergePipelinesEnabled
	project.MergeTrainsEnabled = gitlabProject.MergeTrainsEnabled
	project.AllowMergeOnSkippedPipeline = gitlabProject.AllowMergeOnSkippedPipeline
	project.ResolveOutdatedDiffDiscussions = gitlabProject.ResolveOutdatedDiffDiscussions
	project.PrintingMergeRequestLinkEnabled = gitlabProject.PrintingMergeRequestLinkEnabled
	project.RemoveSourceBranchAfterMerge = gitlabProject.RemoveSourceBranchAfterMerge

	// Determine group ID if project is in a group
	if gitlabProject.Namespace != nil && gitlabProject.Namespace.Kind == "group" {
		project.GroupIdOnPlatform = int(gitlabProject.Namespace.ID)
	}

	// Get the latest commit SHA for the default branch
	latestSha, err := fetchLatestCommitSha(glab, projectPath, project.DefaultBranch, l)
	if err != nil {
		l.WithError(err).Warn("Unable to fetch latest commit SHA, using HEAD")
		project.LatestHeadCommitSha = "HEAD"
	} else {
		project.LatestHeadCommitSha = latestSha
	}

	l.WithFields(logrus.Fields{
		"projectID":       project.IdOnPlatform,
		"projectName":     project.Name,
		"defaultBranch":   project.DefaultBranch,
		"ciConfigPath":    project.CiConfPath,
		"latestCommitSha": project.LatestHeadCommitSha,
	}).Info("Project info fetched successfully")

	return project, nil
}

// fetchLatestCommitSha gets the latest commit SHA for a branch
func fetchLatestCommitSha(glab *gitlab.Client, projectPath string, branch string, l *logrus.Entry) (string, error) {
	if branch == "" {
		branch = "main"
	}

	commits, _, err := glab.Commits.ListCommits(projectPath, &gitlab.ListCommitsOptions{
		RefName: &branch,
		ListOptions: gitlab.ListOptions{
			PerPage: 1,
			Page:    1,
		},
	})

	if err != nil {
		return "", err
	}

	if len(commits) > 0 {
		return commits[0].ID, nil
	}

	return "HEAD", nil
}

// FetchLatestCommitSha gets the latest commit SHA for a given branch.
// Exported wrapper around fetchLatestCommitSha for use outside the gitlab package.
func FetchLatestCommitSha(token, instanceURL, projectPath, branch string, conf *configuration.Configuration) (string, error) {
	l := logger.WithFields(logrus.Fields{
		"action": "FetchLatestCommitSha",
		"branch": branch,
	})

	glab, err := GetNewGitlabClient(token, instanceURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a GitLab client")
		return "", err
	}

	return fetchLatestCommitSha(glab, projectPath, branch, l)
}

// ToProjectInfo converts Project to the simpler ProjectInfo struct used by collectors
func (p *Project) ToProjectInfo() *ProjectInfo {
	return &ProjectInfo{
		ID:                  p.IdOnPlatform,
		Path:                p.Path,
		CiConfPath:          p.CiConfPath,
		DefaultBranch:       p.DefaultBranch,
		AnalyzeBranch:       p.DefaultBranch, // Defaults to DefaultBranch, can be overridden
		LatestHeadCommitSha: p.LatestHeadCommitSha,
		Archived:            p.Archived,
		NotFound:            false, // If we have a Project struct, it was found
		IsGroup:             p.GroupIdOnPlatform > 0,
	}
}
