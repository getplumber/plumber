package control

import (
	"fmt"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	"github.com/sirupsen/logrus"
)

const ControlTypeGitlabImageMutableVersion = "0.2.0"

// GitlabImageMutableConf holds the configuration for mutable tag detection
type GitlabImageMutableConf struct {
	// Enabled controls whether this check runs
	Enabled bool `json:"enabled"`

	// MutableTags is a list of tags considered mutable
	MutableTags []string `json:"mutableTags"`
}

// GetConf loads configuration from PBConfig
// Returns error if config is missing or incomplete
func (p *GitlabImageMutableConf) GetConf(pbConfig *configuration.PBConfig) error {
	// PB config is required
	if pbConfig == nil {
		return fmt.Errorf("PB config is required but not provided")
	}

	// Get ImageMutable config from PBConfig
	imgConfig := pbConfig.GetImageMutableConfig()
	if imgConfig == nil {
		return fmt.Errorf("imageMutable control configuration is missing from conf.pb.yaml config file")
	}

	// Check if enabled field is set
	if imgConfig.Enabled == nil {
		return fmt.Errorf("imageMutable.enabled field is required in conf.pb.yaml config file")
	}

	// Check if mutableTags field is set
	if imgConfig.MutableTags == nil {
		return fmt.Errorf("imageMutable.mutableTags field is required in conf.pb.yaml config file")
	}

	// Apply configuration
	p.Enabled = imgConfig.IsEnabled()
	p.MutableTags = imgConfig.MutableTags

	l.WithFields(logrus.Fields{
		"enabled":     p.Enabled,
		"mutableTags": p.MutableTags,
	}).Debug("ImageMutable control configuration loaded from conf.pb.yaml file")

	return nil
}

// GitlabImageMutableMetrics holds metrics about mutable image tags
type GitlabImageMutableMetrics struct {
	Total           uint `json:"total"`
	UsingMutableTag uint `json:"usingMutableTag"`
	CiInvalid       uint `json:"ciInvalid"`
	CiMissing       uint `json:"ciMissing"`
}

// GitlabImageMutableResult holds the result of the mutable tag control
type GitlabImageMutableResult struct {
	Issues     []GitlabPipelineImageIssueTag `json:"issues"`
	Metrics    GitlabImageMutableMetrics     `json:"metrics"`
	Compliance float64                       `json:"compliance"`
	Version    string                        `json:"version"`
	CiValid    bool                          `json:"ciValid"`
	CiMissing  bool                          `json:"ciMissing"`
	Skipped    bool                          `json:"skipped"`         // True if control was disabled
	Error      string                        `json:"error,omitempty"` // Error message if data collection failed
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

// Run executes the mutable tag detection control
func (p *GitlabImageMutableConf) Run(pipelineImageData *collector.GitlabPipelineImageData) *GitlabImageMutableResult {
	l := l.WithFields(logrus.Fields{
		"control":        "GitlabImageMutable",
		"controlVersion": ControlTypeGitlabImageMutableVersion,
	})
	l.Info("Start mutable image tag control")

	result := &GitlabImageMutableResult{
		Issues:     []GitlabPipelineImageIssueTag{},
		Metrics:    GitlabImageMutableMetrics{},
		Compliance: 100.0,
		Version:    ControlTypeGitlabImageMutableVersion,
		CiValid:    pipelineImageData.CiValid,
		CiMissing:  pipelineImageData.CiMissing,
		Skipped:    false,
	}

	// Check if control is enabled
	if !p.Enabled {
		l.Info("Mutable image tag control is disabled, skipping")
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

	// Loop over all images to check for mutable tags
	for _, image := range pipelineImageData.Images {
		// Check tag mutability using configuration patterns
		isMutableTag := gitlab.CheckItemMatchToPatterns(image.Tag, p.MutableTags)

		if isMutableTag {
			issue := GitlabPipelineImageIssueTag{
				Link: image.Link,
				Tag:  image.Tag,
				Job:  image.Job,
			}
			result.Issues = append(result.Issues, issue)
			result.Metrics.UsingMutableTag++
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
		"totalImages":     result.Metrics.Total,
		"mutableTagCount": result.Metrics.UsingMutableTag,
		"compliance":      result.Compliance,
	}).Info("Mutable image tag control completed")

	return result
}
