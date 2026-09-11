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
	return manageProjectBadgeLetter(projectID, conf, ps.Score)
}

// ManageProjectBadgePlatform is the platform-mode badge (spec s5): the letter
// is the platform's own global score. When the push returned none, or one
// that is not a Plumber Score letter (see hasPublishableGlobal), the badge is
// NOT updated - it keeps its last good value rather than being overwritten
// with a blank, with something that is not a grade, or with a locally
// computed letter the platform never agreed to.
func ManageProjectBadgePlatform(
	projectID int,
	conf *configuration.Configuration,
	s *PlatformPostSummary,
) error {
	if !s.hasPublishableGlobal() {
		return nil
	}
	return manageProjectBadgeLetter(projectID, conf, s.GlobalLetter)
}

// manageProjectBadgeLetter is the shared badge write: both entry points
// resolve to a letter and then run exactly the same create-or-update, so the
// two modes cannot drift on how the badge is matched or named.
func manageProjectBadgeLetter(
	projectID int,
	conf *configuration.Configuration,
	letter string,
) error {
	l := logrus.WithFields(logrus.Fields{
		"action":    "ManageProjectBadge",
		"projectID": projectID,
		"score":     letter,
	})

	// Generate badge image URL
	badgeImageURL := ScoreBadgeURL(letter)
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
