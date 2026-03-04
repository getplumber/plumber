package control

import (
	"strings"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	"github.com/sirupsen/logrus"
)

const ControlTypeGitlabPipelineOriginVersionVersion = "0.1.0"

// originHardcoded is the constant for hardcoded origin type
const originHardcoded = "hardcoded"

//////////////////
// Control conf //
//////////////////

// GitlabPipelineIncludesForbiddenVersionConf holds the configuration for forbidden version detection
type GitlabPipelineIncludesForbiddenVersionConf struct {
	// Enabled controls whether this check runs
	Enabled bool `json:"enabled"`

	// ForbiddenVersions is a list of version patterns considered forbidden (e.g., latest, main, HEAD)
	ForbiddenVersions []string `json:"forbiddenVersions"`

	// DefaultBranchIsForbiddenVersion when true, adds the project's default branch to forbidden versions
	DefaultBranchIsForbiddenVersion bool `json:"defaultBranchIsForbiddenVersion"`
}

// GetConf loads configuration from PlumberConfig
func (p *GitlabPipelineIncludesForbiddenVersionConf) GetConf(plumberConfig *configuration.PlumberConfig) error {
	if plumberConfig == nil {
		p.Enabled = false
		return nil
	}

	versionConfig := plumberConfig.GetIncludesMustNotUseForbiddenVersionsConfig()
	if versionConfig == nil {
		p.Enabled = false
		return nil
	}

	p.Enabled = versionConfig.IsEnabled()
	p.ForbiddenVersions = versionConfig.ForbiddenVersions
	if versionConfig.DefaultBranchIsForbiddenVersion != nil {
		p.DefaultBranchIsForbiddenVersion = *versionConfig.DefaultBranchIsForbiddenVersion
	}

	l.WithFields(logrus.Fields{
		"enabled":                         p.Enabled,
		"forbiddenVersions":               p.ForbiddenVersions,
		"defaultBranchIsForbiddenVersion": p.DefaultBranchIsForbiddenVersion,
	}).Debug("includesMustNotUseForbiddenVersions control configuration loaded from .plumber.yaml file")

	return nil
}

////////////////////////////
// Control data & metrics //
////////////////////////////

// GitlabPipelineIncludesForbiddenVersionMetrics holds metrics about forbidden version usage
type GitlabPipelineIncludesForbiddenVersionMetrics struct {
	Total                  uint `json:"total"`
	UsingForbiddenVersion  uint `json:"usingForbiddenVersion"`
	UsingAuthorizedVersion uint `json:"usingAuthorizedVersion"`
}

// GitlabPipelineIncludesForbiddenVersionResult holds the result of the forbidden version control
type GitlabPipelineIncludesForbiddenVersionResult struct {
	Issues     []GitlabPipelineIncludesForbiddenVersionIssue `json:"issues"`
	Metrics    GitlabPipelineIncludesForbiddenVersionMetrics `json:"metrics"`
	Compliance float64                                       `json:"compliance"`
	Version    string                                        `json:"version"`
	CiValid    bool                                          `json:"ciValid"`
	CiMissing  bool                                          `json:"ciMissing"`
	Skipped    bool                                          `json:"skipped"`
	Error      string                                        `json:"error,omitempty"`
}

////////////////////
// Control issues //
////////////////////

// GitlabPipelineIncludesForbiddenVersionIssue represents an issue with a forbidden version
// Issue data for mutable version usage - PolicyIssueTypeId = [11]
type GitlabPipelineIncludesForbiddenVersionIssue struct {
	Code                  ErrorCode `json:"code"`
	DocURL                string    `json:"docUrl"`
	Version               string    `json:"version"`
	LatestVersion         string    `json:"latestVersion,omitempty"`
	PlumberOriginPath     string    `json:"plumberOriginPath,omitempty"`
	GitlabIncludeLocation string    `json:"gitlabIncludeLocation"`
	GitlabIncludeType     string    `json:"gitlabIncludeType"`
	GitlabIncludeProject  string    `json:"gitlabIncludeProject,omitempty"`
	Nested                bool      `json:"nested"`
	ComponentName         string    `json:"componentName,omitempty"`
	PlumberTemplateName   string    `json:"plumberTemplateName,omitempty"`
	OriginHash            uint64    `json:"originHash"`
}

///////////////////////
// Control functions //
///////////////////////

// Run executes the forbidden version detection control
func (p *GitlabPipelineIncludesForbiddenVersionConf) Run(pipelineOriginData *collector.GitlabPipelineOriginData, projectDefaultBranch string) *GitlabPipelineIncludesForbiddenVersionResult {
	l := l.WithFields(logrus.Fields{
		"control":        "GitlabPipelineIncludesForbiddenVersion",
		"controlVersion": ControlTypeGitlabPipelineOriginVersionVersion,
	})
	l.Info("Start forbidden version control")

	result := &GitlabPipelineIncludesForbiddenVersionResult{
		Issues:     []GitlabPipelineIncludesForbiddenVersionIssue{},
		Metrics:    GitlabPipelineIncludesForbiddenVersionMetrics{},
		Compliance: 100.0, // Start with 100%, will be set to 0 if any forbidden version found
		Version:    ControlTypeGitlabPipelineOriginVersionVersion,
		CiValid:    pipelineOriginData.CiValid,
		CiMissing:  pipelineOriginData.CiMissing,
		Skipped:    false,
	}

	if !p.Enabled {
		l.Info("Forbidden version control is disabled, skipping")
		result.Skipped = true
		return result
	}

	metrics := GitlabPipelineIncludesForbiddenVersionMetrics{}

	///////////////////////////////////////
	// Check for forbidden version usage //
	///////////////////////////////////////

	// Check all origins found in the data collection
	for _, origin := range pipelineOriginData.Origins {

		// Skip hardcoded origins and origins without versions
		if origin.OriginType == originHardcoded || origin.Version == "" {
			continue
		}

		lOrigin := l.WithFields(logrus.Fields{
			"originType":        origin.OriginType,
			"version":           origin.Version,
			"location":          origin.GitlabIncludeOrigin.Location,
			"fromPlumber":       origin.FromPlumber,
			"fromGitlabCatalog": origin.FromGitlabCatalog,
		})
		lOrigin.Debug("Origin version control in progress")

		// Create a copy of forbidden versions to avoid modifying the original
		forbiddenVersions := make([]string, len(p.ForbiddenVersions))
		copy(forbiddenVersions, p.ForbiddenVersions)

		// Add default branch if configured and available
		// TODO: default branch is not detected for GitLab catalog components yet
		originDefaultBranch := ""
		if origin.FromPlumber {
			// For Plumber templates, get the default branch from template.Repo.DefaultBranch
			originDefaultBranch = origin.PlumberOrigin.RepoDefaultBranch
		} else {
			// Fallback to analyzed project default
			originDefaultBranch = projectDefaultBranch
		}

		if p.DefaultBranchIsForbiddenVersion && originDefaultBranch != "" {
			forbiddenVersions = append(forbiddenVersions, originDefaultBranch)
		}

		// Check if the version matches any forbidden version pattern
		isForbiddenVersion := gitlab.CheckItemMatchToPatterns(origin.Version, forbiddenVersions)

		if isForbiddenVersion {
			// Determine the appropriate latest version based on origin type
			latestVersion := ""
			plumberOriginPath := ""
			plumberTemplateName := ""

			if origin.FromPlumber {
				latestVersion = origin.PlumberOrigin.LatestVersion
				plumberOriginPath = origin.PlumberOrigin.Path
				plumberTemplateName = origin.PlumberOrigin.Path
			} else if origin.FromGitlabCatalog {
				latestVersion = origin.GitlabComponent.ComponentLatestVersion
			}

			// Extract template name from the path (just the last part after the last "/")
			templateName := plumberTemplateName
			if plumberTemplateName != "" && strings.Contains(plumberTemplateName, "/") {
				templateName = plumberTemplateName[strings.LastIndex(plumberTemplateName, "/")+1:]
			}

			// Extract component name from gitlabIncludeLocation if it's a component and componentName is empty
			componentName := origin.GitlabComponent.ComponentName
			if origin.GitlabIncludeOrigin.Type == "component" && componentName == "" && origin.GitlabIncludeOrigin.Location != "" {
				if strings.Contains(origin.GitlabIncludeOrigin.Location, "/") {
					componentName = origin.GitlabIncludeOrigin.Location[strings.LastIndex(origin.GitlabIncludeOrigin.Location, "/")+1:]
				}
			}

			// Create issue for forbidden version
			issue := GitlabPipelineIncludesForbiddenVersionIssue{
				Code:                  CodeIncludeForbiddenVersion,
				DocURL:                CodeIncludeForbiddenVersion.DocURL(),
				Version:               origin.Version,
				LatestVersion:         latestVersion,
				PlumberOriginPath:     plumberOriginPath,
				GitlabIncludeLocation: origin.GitlabIncludeOrigin.Location,
				GitlabIncludeType:     origin.GitlabIncludeOrigin.Type,
				GitlabIncludeProject:  origin.GitlabIncludeOrigin.Project,
				Nested:                origin.Nested,
				ComponentName:         componentName,
				PlumberTemplateName:   templateName,
				OriginHash:            origin.OriginHash,
			}

			result.Issues = append(result.Issues, issue)
			metrics.UsingForbiddenVersion++

			lOrigin.WithField("forbiddenVersions", forbiddenVersions).Info("Forbidden version detected")
		} else {
			// Update metrics for valid versions
			metrics.UsingAuthorizedVersion++
		}
	}

	// Calculate total metrics
	metrics.Total = metrics.UsingForbiddenVersion + metrics.UsingAuthorizedVersion

	// Set compliance: 0% if any forbidden version found, 100% otherwise
	if len(result.Issues) > 0 {
		result.Compliance = 0.0
	} else {
		result.Compliance = 100.0
	}

	// Update result with final metrics
	result.Metrics = metrics

	l.WithFields(logrus.Fields{
		"totalOrigins":            metrics.Total,
		"forbiddenVersionOrigins": metrics.UsingForbiddenVersion,
		"compliance":              result.Compliance,
	}).Info("Forbidden version control completed")

	return result
}
