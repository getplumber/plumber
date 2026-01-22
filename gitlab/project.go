package gitlab

import (
	"context"
	"fmt"

	"github.com/getplumber/plumber/configuration"
	"github.com/machinebox/graphql"
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

// FetchProjectByID fetches project information using its GitLab ID
func FetchProjectByID(projectID int, token string, instanceURL string, conf *configuration.Configuration) (*Project, error) {
	l := logger.WithFields(logrus.Fields{
		"action":      "FetchProjectByID",
		"projectID":   projectID,
		"instanceURL": instanceURL,
	})

	// Get project by ID using REST API
	glab, err := GetNewGitlabClient(token, instanceURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to get a GitLab client")
		return nil, err
	}

	gitlabProject, resp, err := glab.Projects.GetProject(projectID, &gitlab.GetProjectOptions{
		License:              new(bool),
		Statistics:           new(bool),
		WithCustomAttributes: new(bool),
	})

	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			l.Info("Project not found on GitLab")
			return nil, fmt.Errorf("project not found: %d", projectID)
		}
		l.WithError(err).Error("Unable to fetch project from GitLab API")
		return nil, err
	}

	// Now call FetchProjectDetails with the path to get full details
	return FetchProjectDetails(gitlabProject.PathWithNamespace, token, instanceURL, conf)
}

// EnhanceProjectWithGraphQL adds additional data from GraphQL API
// This can get information not available via REST
func EnhanceProjectWithGraphQL(project *Project, token string, instanceURL string, conf *configuration.Configuration) error {
	l := logger.WithFields(logrus.Fields{
		"action":      "EnhanceProjectWithGraphQL",
		"projectPath": project.Path,
		"instanceURL": instanceURL,
	})

	query := `
		query getProject($fullPath: ID!) {
			project(fullPath: $fullPath) {
				id
				name
				fullPath
				archived
				visibility
				repository {
					rootRef
				}
				ciConfigPathOrDefault
				group {
					fullPath
				}
			}
		}
	`

	type graphqlResponse struct {
		Project struct {
			ID                    string `json:"id"`
			Name                  string `json:"name"`
			FullPath              string `json:"fullPath"`
			Archived              bool   `json:"archived"`
			Visibility            string `json:"visibility"`
			CiConfigPathOrDefault string `json:"ciConfigPathOrDefault"`
			Repository            struct {
				RootRef string `json:"rootRef"`
			} `json:"repository"`
			Group *struct {
				FullPath string `json:"fullPath"`
			} `json:"group"`
		} `json:"project"`
	}

	client := GetGraphQLClient(instanceURL, conf)
	req := graphql.NewRequest(query)
	req.Var("fullPath", project.Path)
	req.Header.Add("Authorization", "Bearer "+token)

	var resp graphqlResponse
	if err := client.Run(context.Background(), req, &resp); err != nil {
		l.WithError(err).Warn("GraphQL query failed")
		return err
	}

	// Update with GraphQL data if available
	if resp.Project.CiConfigPathOrDefault != "" {
		project.CiConfPath = resp.Project.CiConfigPathOrDefault
	}

	l.Info("Project info enhanced with GraphQL data")
	return nil
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

// GetCIPredefinedVariables returns CI predefined variables based on project info
// These would normally be available in GitLab CI jobs
func (p *Project) GetCIPredefinedVariables() map[string]string {
	vars := make(map[string]string)

	vars["CI_PROJECT_ID"] = fmt.Sprintf("%d", p.IdOnPlatform)
	vars["CI_PROJECT_NAME"] = p.Name
	vars["CI_PROJECT_PATH"] = p.Path
	vars["CI_PROJECT_PATH_SLUG"] = p.Path // Could be slugified
	vars["CI_COMMIT_REF_NAME"] = p.DefaultBranch
	vars["CI_COMMIT_SHA"] = p.LatestHeadCommitSha
	vars["CI_PROJECT_VISIBILITY"] = p.Visibility

	return vars
}
