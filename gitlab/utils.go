package gitlab

import (
	"path/filepath"

	gover "github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
)

var logger = logrus.WithField("context", "platform/gitlab")

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
