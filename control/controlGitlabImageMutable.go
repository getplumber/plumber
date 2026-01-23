package control

import (
	"fmt"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	"github.com/sirupsen/logrus"
)

const ControlTypeGitlabImageForbiddenTagsVersion = "0.2.0"

// GitlabImageForbiddenTagsConf holds the configuration for forbidden tag detection
type GitlabImageForbiddenTagsConf struct {
	// Enabled controls whether this check runs
	Enabled bool `json:"enabled"`

	// ForbiddenTags is a list of tags considered forbidden (e.g., latest, dev)
	ForbiddenTags []string `json:"forbiddenTags"`
}

// GetConf loads configuration from PlumberConfig
// Returns error if config is missing or incomplete
func (p *GitlabImageForbiddenTagsConf) GetConf(plumberConfig *configuration.PlumberConfig) error {
	// Plumber config is required
	if plumberConfig == nil {
		return fmt.Errorf("Plumber config is required but not provided")
	}

	// Get control config from PlumberConfig
	imgConfig := plumberConfig.GetContainerImageMustNotUseForbiddenTagsConfig()
	if imgConfig == nil {
		return fmt.Errorf("containerImageMustNotUseForbiddenTags control configuration is missing from .plumber.yaml config file")
	}

	// Check if enabled field is set
	if imgConfig.Enabled == nil {
		return fmt.Errorf("containerImageMustNotUseForbiddenTags.enabled field is required in .plumber.yaml config file")
	}

	// Check if tags field is set
	if imgConfig.Tags == nil {
		return fmt.Errorf("containerImageMustNotUseForbiddenTags.tags field is required in .plumber.yaml config file")
	}

	// Apply configuration
	p.Enabled = imgConfig.IsEnabled()
	p.ForbiddenTags = imgConfig.Tags

	l.WithFields(logrus.Fields{
		"enabled":       p.Enabled,
		"forbiddenTags": p.ForbiddenTags,
	}).Debug("containerImageMustNotUseForbiddenTags control configuration loaded from .plumber.yaml file")

	return nil
}

// GitlabImageForbiddenTagsMetrics holds metrics about forbidden image tags
type GitlabImageForbiddenTagsMetrics struct {
	Total              uint `json:"total"`
	UsingForbiddenTags uint `json:"usingForbiddenTags"`
	CiInvalid          uint `json:"ciInvalid"`
	CiMissing          uint `json:"ciMissing"`
}

// GitlabImageForbiddenTagsResult holds the result of the forbidden tags control
type GitlabImageForbiddenTagsResult struct {
	Issues     []GitlabPipelineImageIssueTag   `json:"issues"`
	Metrics    GitlabImageForbiddenTagsMetrics `json:"metrics"`
	Compliance float64                         `json:"compliance"`
	Version    string                          `json:"version"`
	CiValid    bool                            `json:"ciValid"`
	CiMissing  bool                            `json:"ciMissing"`
	Skipped    bool                            `json:"skipped"`         // True if control was disabled
	Error      string                          `json:"error,omitempty"` // Error message if data collection failed
}

////////////////////
// Control issues //
////////////////////

// GitlabPipelineImageIssueTag represents an issue with an image using a mutable tag
type GitlabPipelineImageIssueTag struct {
	Link string `json:"link"`
	Tag  string `json:"tag"`
	Job  string `json:"job"`
}

///////////////////////
// Control functions //
///////////////////////

// Run executes the forbidden tag detection control
func (p *GitlabImageForbiddenTagsConf) Run(pipelineImageData *collector.GitlabPipelineImageData) *GitlabImageForbiddenTagsResult {
	l := l.WithFields(logrus.Fields{
		"control":        "GitlabImageForbiddenTags",
		"controlVersion": ControlTypeGitlabImageForbiddenTagsVersion,
	})
	l.Info("Start forbidden image tag control")

	result := &GitlabImageForbiddenTagsResult{
		Issues:     []GitlabPipelineImageIssueTag{},
		Metrics:    GitlabImageForbiddenTagsMetrics{},
		Compliance: 100.0,
		Version:    ControlTypeGitlabImageForbiddenTagsVersion,
		CiValid:    pipelineImageData.CiValid,
		CiMissing:  pipelineImageData.CiMissing,
		Skipped:    false,
	}

	// Check if control is enabled
	if !p.Enabled {
		l.Info("Forbidden image tag control is disabled, skipping")
		result.Skipped = true
		return result
	}

	// If CI is invalid or missing, return early
	if !pipelineImageData.CiValid || pipelineImageData.CiMissing {
		result.Compliance = 0.0
		if !pipelineImageData.CiValid {
			result.Metrics.CiInvalid = 1
		}
		if pipelineImageData.CiMissing {
			result.Metrics.CiMissing = 1
		}
		return result
	}

	// Loop over all images to check for forbidden tags
	for _, image := range pipelineImageData.Images {
		// Check tag against forbidden patterns
		isForbiddenTag := gitlab.CheckItemMatchToPatterns(image.Tag, p.ForbiddenTags)

		if isForbiddenTag {
			issue := GitlabPipelineImageIssueTag{
				Link: image.Link,
				Tag:  image.Tag,
				Job:  image.Job,
			}
			result.Issues = append(result.Issues, issue)
			result.Metrics.UsingForbiddenTags++
		}
	}

	// Calculate compliance based on issues
	if len(result.Issues) > 0 {
		result.Compliance = 0.0
		l.WithField("issuesCount", len(result.Issues)).Debug("Found issues, setting compliance to 0")
	}

	// Set metrics
	result.Metrics.Total = uint(len(pipelineImageData.Images))

	l.WithFields(logrus.Fields{
		"totalImages":       result.Metrics.Total,
		"forbiddenTagCount": result.Metrics.UsingForbiddenTags,
		"compliance":        result.Compliance,
	}).Info("Forbidden image tag control completed")

	return result
}
