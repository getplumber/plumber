package gitlab

import (
	"path/filepath"

	"github.com/getplumber/plumber/configuration"
	gover "github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
)

var logger = logrus.WithField("context", "platform/gitlab")

// IsUpToDate reports whether a template version is the latest one.
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

// ConvertCICDVariableToMap turns an API variable listing into the name to
// value map image-reference resolution expands from. It keeps only the
// variables whose value a job on the analysed ref would actually hold, by
// the same rule the platform path applies (variableExpandable): a file
// variable resolves to a temporary path, a masked or hidden one is never
// rendered anywhere, a protected one is withheld when the analysed ref is
// not protected (refProtected), and an environment-scoped one differs per
// job. A defined-but-empty value is skipped too, as on the job-environment
// path: substituting "" turns `$REGISTRY/app` into `/app`, a reference that
// looks resolved and is not the one the job uses. Everything skipped keeps
// its placeholder, so the reference is marked unresolved and the image
// rules abstain instead of judging a reference the job never runs.
func ConvertCICDVariableToMap(variables []CICDVariable, refProtected bool) map[string]string {
	result := make(map[string]string, len(variables))
	for _, variable := range variables {
		if variable.Value == "" {
			continue
		}
		if !variableExpandable(variable.Type, variable.Masked, variable.Hidden, variable.Protected, variable.Environment, refProtected) {
			continue
		}
		result[variable.Name] = variable.Value
	}
	return result
}

// analysedBranchIsProtected answers over the API the question GitLab answers
// inside a pipeline with CI_COMMIT_REF_PROTECTED: is the branch under
// analysis (the requested one, else the project's default branch) a
// protected branch. GitLab's single-branch endpoint carries its own
// `protected` verdict, so no pattern matching is redone here. When the
// branch cannot be read it counts as unprotected, so protected variables
// keep their placeholder and the image rules abstain.
func analysedBranchIsProtected(project *ProjectInfo, token string, conf *configuration.Configuration) bool {
	if project == nil || conf == nil {
		return false
	}
	branch := conf.Branch
	if branch == "" {
		branch = project.DefaultBranch
	}
	if branch == "" {
		return false
	}
	glab, err := GetNewGitlabClient(token, conf.GitlabURL, conf)
	if err != nil {
		logger.WithError(err).WithField("branch", branch).Debug("branch protection unavailable; protected variables keep their placeholder")
		return false
	}
	b, _, err := glab.Branches.GetBranch(project.Path, branch)
	if err != nil || b == nil {
		logger.WithError(err).WithField("branch", branch).Debug("branch protection unavailable; protected variables keep their placeholder")
		return false
	}
	return b.Protected
}

// BranchMatchesPattern checks if a branch name matches a pattern using wildcard matching
// Supports * wildcard for pattern matching (e.g., "*production*", "release/*")
func BranchMatchesPattern(pattern, branchName string) bool {
	matched, _ := filepath.Match(pattern, branchName)
	return matched
}
