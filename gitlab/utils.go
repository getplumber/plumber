package gitlab

import (
	"errors"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/IGLOU-EU/go-wildcard/v2"
	gover "github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
)

var logger = logrus.WithField("context", "platform/gitlab")

// ParseGitLab GraphQL ID string
func ParseGitlabID(idString string) (int, error) {

	// Set logging
	l := logrus.WithFields(logrus.Fields{
		"idString": idString,
		"action":   "ParseGitlabID",
	})

	splitted := strings.Split(idString, "/")

	if len(splitted) != 5 {
		err := errors.New("wrong GitLab global id format")
		l.WithError(err).Error("Unable to parse the GitLab GraphQL global ID")
		return 0, err
	}

	id, err := strconv.Atoi(splitted[len(splitted)-1])
	if err != nil {
		l.WithError(err).Error("Unable to parse the GitLab GraphQL global ID")
		return 0, err
	}

	return id, nil
}

// Build gitLab GraphQL ID string
func BuildGitlabID(id int, idType string) string {

	result := "gid://gitlab/" + idType + "/" + strconv.Itoa(id)
	return result
}

// RemoveGitRefFromURL removes git refs (commits, branches, tags) from a URL
func RemoveGitRefFromURL(rawURL string) (string, error) {
	// Parse the URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, err
	}

	// Common patterns for git refs in URLs
	// GitLab/GitHub: /blob/{ref}/... or /-/raw/{ref}/...
	patterns := []string{
		`/blob/[^/]+/`,
		`/-/raw/[^/]+/`,
		`/-/blob/[^/]+/`,
		`/raw/[^/]+/`,
	}

	path := parsedURL.Path
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(path) {
			// Replace the ref part with a generic placeholder or remove it
			path = re.ReplaceAllString(path, "/blob/")
		}
	}

	parsedURL.Path = path
	return parsedURL.String(), nil
}

// Return an uniq id for a template data
func RemoveVersionInRawLink(raw string) string {

	// Initialize logger
	l := logrus.WithFields(logrus.Fields{
		"action": "RemoveVersionInRawLink",
	})

	// Sanitize the raw link by removing all versions

	// 1. Remove the version of old remote include links
	rawWithoutVersion := strings.Split(raw, "@")[0]

	// 2. Remove the git ref
	var err error
	rawWithoutVersion, err = RemoveGitRefFromURL(rawWithoutVersion)
	if err != nil {
		l.WithError(err).Error("Unable to remove the version from the raw link")
	}

	// Return raw without version
	return rawWithoutVersion
}

// Return if a template is up to date
func IsUpToDate(version, latestVersion string, latestRefs []string) bool {

	// Initialize logger
	l := logrus.WithFields(logrus.Fields{
		"action":         "IsUpToDate",
		"versionToCheck": version,
		"latestVersion":  latestVersion,
		"latestRefs":     latestRefs,
	})

	if latestVersion == "" || version == "" {
		l.Warn("Checking latest of an empty version or empty latestVersion")
		return false
	}

	// If exact match, return true
	if version == latestVersion {
		l.Debug("Match with latestVersion")
		return true
	}

	// Check all "latest" refs (like HEAD, main, master, etc.)
	for _, ref := range latestRefs {
		if version == ref {
			l.Debug("Match with a latestRef")
			return true
		}
	}

	// Try to parse as semantic versions and compare
	v1, err1 := gover.NewVersion(version)
	v2, err2 := gover.NewVersion(latestVersion)

	// If both are valid semantic versions, compare them properly
	if err1 == nil && err2 == nil {
		l.WithFields(logrus.Fields{
			"parsedVersion":       v1.String(),
			"parsedLatestVersion": v2.String(),
		}).Debug("Both versions parsed as semantic versions")

		// If version is greater than or equal to latest version, it's up to date
		if v1.GreaterThanOrEqual(v2) {
			l.Debug("Version is greater than or equal to latest version")
			return true
		}
	} else {
		l.WithFields(logrus.Fields{
			"versionParseError":       err1,
			"latestVersionParseError": err2,
		}).Debug("Could not parse versions as semantic versions, falling back to string comparison")
	}

	l.Debug("No match with any ref. Not up to date")
	return false
}

// Return if a template is using a latest ref
func IsUsingLatest(version string, latestRefs []string) bool {

	// Initialize logger
	l := logrus.WithFields(logrus.Fields{
		"action":         "IsUsingLatest",
		"versionToCheck": version,
		"latestRefs":     latestRefs,
	})

	if version == "" {
		l.Warn("Checking latest of an empty version")
		return false
	}

	// Check all "latest" refs
	for _, ref := range latestRefs {
		if version == ref {
			l.Debug("Match with a latestRef")
			return true
		}
	}

	l.Debug("No match with any ref. Not up to date")
	return false
}

func BuildVariableSafeConfID(protected, masked bool, ids ...string) string {

	fullID := ""
	for _, id := range ids {
		fullID += id + "|"
	}

	return fullID + strconv.FormatBool(protected) + strconv.FormatBool(masked)

}

func ConvertCICDVariableToMap(variables []CICDVariable) map[string]string {

	result := make(map[string]string, len(variables))
	for _, variable := range variables {
		result[variable.Name] = variable.Value
	}
	return result
}

// BranchMatchesPattern checks if a branch name matches a pattern using wildcard matching
// Supports * wildcard for pattern matching (e.g., "*production*", "release/*")
func BranchMatchesPattern(pattern, branchName string) bool {
	matched, _ := filepath.Match(pattern, branchName)
	return matched
}

// CheckItemMatchToPatterns detects if a string matches at least one of the patterns
// using wildcard lib (not regex)
// Examples: "3.2*" matches "3.2-rc-buster", "3.22"
//
//	"*-dev" matches "1.0-dev", "feature-dev"
func CheckItemMatchToPatterns(item string, patterns []string) bool {
	// If patterns is empty, return false
	if len(patterns) == 0 {
		return false
	}

	// Iterate through patterns sequentially
	for _, pattern := range patterns {
		if wildcard.Match(pattern, item) {
			return true
		}
	}

	return false
}
