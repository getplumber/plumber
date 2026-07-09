package control

import (
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	"github.com/sirupsen/logrus"
)

// ManageProjectBadge creates or updates the Plumber badge on the project.
// The badge shows the Plumber letter score (A–E, see ScoreBadgeURL) and links
// to the score documentation. No-op when no score is available.
func ManageProjectBadge(
	projectID int,
	conf *configuration.Configuration,
	ps *PlumberScoreResult,
) error {
	if ps == nil {
		return nil
	}
	l := logrus.WithFields(logrus.Fields{
		"action":    "ManageProjectBadge",
		"projectID": projectID,
		"score":     ps.Score,
	})

	// Generate badge image URL
	badgeImageURL := ScoreBadgeURL(ps.Score)
	badgeLinkURL := PlumberScoreDocURL

	// List existing badges to find Plumber badge
	badges, err := gitlab.ListProjectBadges(projectID, conf.GitlabToken, conf.GitlabURL, conf)
	if err != nil {
		l.WithError(err).Error("Unable to list project badges")
		return err
	}

	// Look for existing Plumber badge by name or by shields.io URL pattern
	// Use pointer to differentiate "not found" from "found"
	// Name match takes precedence over URL pattern match
	var existingBadgeID *int
	for _, badge := range badges {
		// Check for exact name match first (takes precedence)
		if badge.Name == gitlab.PlumberBadgeName {
			id := int(badge.ID)
			existingBadgeID = &id
			break // Name match is definitive
		}
		// Also match by image URL pattern (for badges created before name was set)
		// Only store if we haven't found a better match yet
		if existingBadgeID == nil && strings.Contains(badge.ImageURL, "shields.io") && strings.Contains(badge.ImageURL, "Plumber") {
			id := int(badge.ID)
			existingBadgeID = &id
			// Don't break - continue looking for a name match which takes precedence
		}
	}

	if existingBadgeID != nil {
		// Update existing badge
		l.WithField("badgeID", *existingBadgeID).Debug("Found existing Plumber badge, updating")
		_, err = gitlab.UpdateProjectBadge(
			projectID,
			*existingBadgeID,
			gitlab.PlumberBadgeName,
			badgeImageURL,
			badgeLinkURL,
			conf.GitlabToken,
			conf.GitlabURL,
			conf,
		)
		if err != nil {
			l.WithError(err).Error("Failed to update project badge")
			return err
		}
		l.Info("Updated Plumber badge on project")
	} else {
		// Create new badge
		l.Debug("No existing Plumber badge found, creating new one")
		_, err = gitlab.CreateProjectBadge(
			projectID,
			gitlab.PlumberBadgeName,
			badgeImageURL,
			badgeLinkURL,
			conf.GitlabToken,
			conf.GitlabURL,
			conf,
		)
		if err != nil {
			l.WithError(err).Error("Failed to create project badge")
			return err
		}
		l.Info("Created Plumber badge on project")
	}

	return nil
}
