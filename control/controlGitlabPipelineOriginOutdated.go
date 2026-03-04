package control

import (
	"strings"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/sirupsen/logrus"
)

const ControlTypeGitlabPipelineOriginOutdatedVersion = "0.1.0"

//////////////////
// Control conf //
//////////////////

// GitlabPipelineIncludesOutdatedConf holds the configuration for outdated includes detection
// No specific configuration needed for outdated detection
// The logic uses the UpToDate field from the analysis data
type GitlabPipelineIncludesOutdatedConf struct {
	// Enabled controls whether this check runs
	Enabled bool `json:"enabled"`
}

// GetConf loads configuration from PlumberConfig
func (p *GitlabPipelineIncludesOutdatedConf) GetConf(plumberConfig *configuration.PlumberConfig) error {
	if plumberConfig == nil {
		p.Enabled = false
		return nil
	}

	outdatedConfig := plumberConfig.GetIncludesMustBeUpToDateConfig()
	if outdatedConfig == nil {
		p.Enabled = false
		return nil
	}

	p.Enabled = outdatedConfig.IsEnabled()

	l.WithFields(logrus.Fields{
		"enabled": p.Enabled,
	}).Debug("includesMustBeUpToDate control configuration loaded from .plumber.yaml file")

	return nil
}

////////////////////////////
// Control data & metrics //
////////////////////////////

// GitlabPipelineIncludesOutdatedMetrics holds metrics about outdated includes
type GitlabPipelineIncludesOutdatedMetrics struct {
	Total          uint `json:"total"`
	OriginOutdated uint `json:"originOutdated"`
	CiInvalid      uint `json:"ciInvalid"`
	CiMissing      uint `json:"ciMissing"`
}

// GitlabPipelineIncludesOutdatedResult holds the result of the outdated control
type GitlabPipelineIncludesOutdatedResult struct {
	Issues     []GitlabPipelineIncludesOutdatedIssue `json:"issues"`
	Metrics    GitlabPipelineIncludesOutdatedMetrics `json:"metrics"`
	Compliance float64                               `json:"compliance"`
	Version    string                                `json:"version"`
	CiValid    bool                                  `json:"ciValid"`
	CiMissing  bool                                  `json:"ciMissing"`
	Skipped    bool                                  `json:"skipped"`
	Error      string                                `json:"error,omitempty"`
}

////////////////////
// Control issues //
////////////////////

// GitlabPipelineIncludesOutdatedIssue represents an issue with an outdated include
// Issue data for outdated origin - PolicyIssueTypeId = [10]
type GitlabPipelineIncludesOutdatedIssue struct {
	Code                  ErrorCode `json:"code"`
	DocURL                string    `json:"docUrl"`
	Version               string    `json:"version"`
	LatestVersion         string    `json:"latestVersion"`
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

// Run executes the outdated includes detection control
func (p *GitlabPipelineIncludesOutdatedConf) Run(pipelineOriginData *collector.GitlabPipelineOriginData) *GitlabPipelineIncludesOutdatedResult {
	l := l.WithFields(logrus.Fields{
		"control":        "GitlabPipelineIncludesOutdated",
		"controlVersion": ControlTypeGitlabPipelineOriginOutdatedVersion,
	})
	l.Info("Start outdated includes control")

	result := &GitlabPipelineIncludesOutdatedResult{
		Issues:     []GitlabPipelineIncludesOutdatedIssue{},
		Metrics:    GitlabPipelineIncludesOutdatedMetrics{},
		Compliance: 0.0, // Start with 0%, will be set to 100 if no outdated origins found
		Version:    ControlTypeGitlabPipelineOriginOutdatedVersion,
		CiValid:    pipelineOriginData.CiValid,
		CiMissing:  pipelineOriginData.CiMissing,
		Skipped:    false,
	}

	if !p.Enabled {
		l.Info("Outdated includes control is disabled, skipping")
		result.Skipped = true
		result.Compliance = 100.0
		return result
	}

	// Initialize metrics
	metrics := GitlabPipelineIncludesOutdatedMetrics{}

	// Count CI status (max 1 as it's only one asset)
	if !pipelineOriginData.CiValid {
		metrics.CiInvalid = 1
	}
	if pipelineOriginData.CiMissing {
		metrics.CiMissing = 1
	}

	//////////////////////////////////
	// Check for outdated origins //
	//////////////////////////////////

	// Check all origins for outdated versions
	for _, origin := range pipelineOriginData.Origins {

		// Skip hardcoded origins - they are not "includes"
		if origin.OriginType == "hardcoded" {
			continue
		}

		// Count all non-hardcoded origins as includes
		metrics.Total++

		lOrigin := l.WithFields(logrus.Fields{
			"originType":        origin.OriginType,
			"version":           origin.Version,
			"location":          origin.GitlabIncludeOrigin.Location,
			"upToDate":          origin.UpToDate,
			"fromPlumber":       origin.FromPlumber,
			"fromGitlabCatalog": origin.FromGitlabCatalog,
		})
		lOrigin.Debug("Checking origin for outdated version")

		// Check if origin is outdated (only for Plumber or GitLab catalog origins)
		if (origin.FromPlumber || origin.FromGitlabCatalog) && !origin.UpToDate {

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

			// Create issue for outdated origin
			issue := GitlabPipelineIncludesOutdatedIssue{
				Code:                  CodeIncludeOutdated,
				DocURL:                CodeIncludeOutdated.DocURL(),
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
			metrics.OriginOutdated++

			lOrigin.Info("Outdated origin detected")
		}
	}

	// Set compliance: 100% if no outdated origins found, 0% otherwise
	if len(result.Issues) == 0 {
		result.Compliance = 100.0
	} else {
		result.Compliance = 0.0
	}

	// Update result with final metrics
	result.Metrics = metrics

	l.WithFields(logrus.Fields{
		"totalOrigins":    metrics.Total,
		"outdatedOrigins": metrics.OriginOutdated,
		"compliance":      result.Compliance,
	}).Info("Outdated includes control completed")

	return result
}
