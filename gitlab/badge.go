package gitlab

import (
	"github.com/getplumber/plumber/configuration"
	"github.com/sirupsen/logrus"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

const (
	// PlumberBadgeName is the name used for Plumber project badges
	PlumberBadgeName = "Plumber"
	// UnableToGetGitlabClient is the error message for when a Gitlab client cannot be created
	UnableToGetGitlabClient = "Unable to get a Gitlab client"
)

// ListProjectBadges retrieves all badges for a project
func ListProjectBadges(projectID int, token string, instanceURL string, conf *configuration.Configuration) ([]*gitlab.ProjectBadge, error) {
	l := logger.WithFields(logrus.Fields{
		"action":    "ListProjectBadges",
		"projectID": projectID,
	})

	glab, err := GetNewGitlabClient(token, instanceURL, conf)
	if err != nil {
		l.WithError(err).Error()
		return nil, err
	}

	badges, _, err := glab.ProjectBadges.ListProjectBadges(projectID, &gitlab.ListProjectBadgesOptions{})
	if err != nil {
		l.WithError(err).Error("Failed to list project badges")
		return nil, err
	}

	l.WithField("badgeCount", len(badges)).Debug("Fetched project badges")
	return badges, nil
}

// CreateProjectBadge creates a new badge on a project
func CreateProjectBadge(projectID int, name, imageURL, linkURL, token, instanceURL string, conf *configuration.Configuration) (*gitlab.ProjectBadge, error) {
	l := logger.WithFields(logrus.Fields{
		"action":    "CreateProjectBadge",
		"projectID": projectID,
		"name":      name,
	})

	glab, err := GetNewGitlabClient(token, instanceURL, conf)
	if err != nil {
		l.WithError(err).Error(UnableToGetGitlabClient)
		return nil, err
	}

	badge, _, err := glab.ProjectBadges.AddProjectBadge(projectID, &gitlab.AddProjectBadgeOptions{
		Name:     &name,
		ImageURL: &imageURL,
		LinkURL:  &linkURL,
	})
	if err != nil {
		l.WithError(err).Error("Failed to create project badge")
		return nil, err
	}

	l.WithField("badgeID", badge.ID).Debug("Created project badge")
	return badge, nil
}

// UpdateProjectBadge updates an existing badge on a project
func UpdateProjectBadge(projectID int, badgeID int, name, imageURL, linkURL, token, instanceURL string, conf *configuration.Configuration) (*gitlab.ProjectBadge, error) {
	l := logger.WithFields(logrus.Fields{
		"action":    "UpdateProjectBadge",
		"projectID": projectID,
		"badgeID":   badgeID,
		"name":      name,
	})

	glab, err := GetNewGitlabClient(token, instanceURL, conf)
	if err != nil {
		l.WithError(err).Error(UnableToGetGitlabClient)
		return nil, err
	}

	badge, _, err := glab.ProjectBadges.EditProjectBadge(projectID, int64(badgeID), &gitlab.EditProjectBadgeOptions{
		Name:     &name,
		ImageURL: &imageURL,
		LinkURL:  &linkURL,
	})
	if err != nil {
		l.WithError(err).Error("Failed to update project badge")
		return nil, err
	}

	l.WithField("badgeID", badge.ID).Debug("Updated project badge")
	return badge, nil
}
