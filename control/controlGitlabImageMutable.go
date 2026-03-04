package control

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	"github.com/sirupsen/logrus"
)

const ControlTypeGitlabImageForbiddenTagsVersion = "0.3.0"

// GitlabImageForbiddenTagsConf holds the configuration for forbidden tag detection
type GitlabImageForbiddenTagsConf struct {
	// Enabled controls whether this check runs
	Enabled bool `json:"enabled"`

	// ForbiddenTags is a list of tags considered forbidden (e.g., latest, dev)
	ForbiddenTags []string `json:"forbiddenTags"`

	// MustBePinnedByDigest when true, ALL images must use immutable digest references.
	// Takes precedence over the forbidden tags list.
	MustBePinnedByDigest bool `json:"mustBePinnedByDigest"`
}

// GetConf loads configuration from PlumberConfig
// If config is nil or the control section is missing, the control is disabled (skipped).
func (p *GitlabImageForbiddenTagsConf) GetConf(plumberConfig *configuration.PlumberConfig) error {
	// Plumber config is required
	if plumberConfig == nil {
		p.Enabled = false
		return nil
	}

	// Get control config from PlumberConfig
	imgConfig := plumberConfig.GetContainerImageMustNotUseForbiddenTagsConfig()
	if imgConfig == nil {
		// Control not configured - disable it
		l.Debug("containerImageMustNotUseForbiddenTags control configuration is missing from .plumber.yaml file, skipping")
		p.Enabled = false
		return nil
	}

	// Check if enabled field is set
	if imgConfig.Enabled == nil {
		return fmt.Errorf("containerImageMustNotUseForbiddenTags.enabled field is required in .plumber.yaml config file")
	}

	// Check if tags field is set (required unless mustBePinnedByDigest takes over)
	if imgConfig.Tags == nil && !imgConfig.IsPinnedByDigestRequired() {
		return fmt.Errorf("containerImageMustNotUseForbiddenTags.tags field is required in .plumber.yaml config file")
	}

	// Apply configuration
	p.Enabled = imgConfig.IsEnabled()
	p.ForbiddenTags = imgConfig.Tags
	p.MustBePinnedByDigest = imgConfig.IsPinnedByDigestRequired()

	l.WithFields(logrus.Fields{
		"enabled":              p.Enabled,
		"forbiddenTags":        p.ForbiddenTags,
		"mustBePinnedByDigest": p.MustBePinnedByDigest,
	}).Debug("containerImageMustNotUseForbiddenTags control configuration loaded from .plumber.yaml file")

	return nil
}

// GitlabImageForbiddenTagsMetrics holds metrics about forbidden image tags
type GitlabImageForbiddenTagsMetrics struct {
	Total              uint `json:"total"`
	UsingForbiddenTags uint `json:"usingForbiddenTags"`
	NotPinnedByDigest  uint `json:"notPinnedByDigest,omitempty"`
	PinnedByDigest     uint `json:"pinnedByDigest,omitempty"`
	CiInvalid          uint `json:"ciInvalid"`
	CiMissing          uint `json:"ciMissing"`
}

// GitlabImageForbiddenTagsResult holds the result of the forbidden tags control
type GitlabImageForbiddenTagsResult struct {
	Issues               []GitlabPipelineImageIssueTag   `json:"issues"`
	Metrics              GitlabImageForbiddenTagsMetrics `json:"metrics"`
	Compliance           float64                         `json:"compliance"`
	Version              string                          `json:"version"`
	CiValid              bool                            `json:"ciValid"`
	CiMissing            bool                            `json:"ciMissing"`
	Skipped              bool                            `json:"skipped"`              // True if control was disabled
	MustBePinnedByDigest bool                            `json:"mustBePinnedByDigest"` // True if digest pinning mode was active
	Error                string                          `json:"error,omitempty"`      // Error message if data collection failed
}

////////////////////
// Control issues //
////////////////////

// GitlabPipelineImageIssueTag represents an issue with an image using a mutable tag
type GitlabPipelineImageIssueTag struct {
	Code   ErrorCode `json:"code"`
	DocURL string    `json:"docUrl"`
	Link   string    `json:"link"`
	Tag    string    `json:"tag"`
	Job    string    `json:"job"`
}

///////////////////////
// Control functions //
///////////////////////

// Run executes the forbidden tag detection control
func (p *GitlabImageForbiddenTagsConf) Run(pipelineImageData *collector.GitlabPipelineImageData) *GitlabImageForbiddenTagsResult {
	l := l.WithFields(logrus.Fields{
		"control":              "GitlabImageForbiddenTags",
		"controlVersion":       ControlTypeGitlabImageForbiddenTagsVersion,
		"mustBePinnedByDigest": p.MustBePinnedByDigest,
	})
	l.Info("Start forbidden image tag control")

	result := &GitlabImageForbiddenTagsResult{
		Issues:               []GitlabPipelineImageIssueTag{},
		Metrics:              GitlabImageForbiddenTagsMetrics{},
		Compliance:           100.0,
		Version:              ControlTypeGitlabImageForbiddenTagsVersion,
		CiValid:              pipelineImageData.CiValid,
		CiMissing:            pipelineImageData.CiMissing,
		Skipped:              false,
		MustBePinnedByDigest: p.MustBePinnedByDigest,
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

	// Loop over all images
	for _, image := range pipelineImageData.Images {

		// If mustBePinnedByDigest is enabled, check digest pinning first (takes precedence)
		if p.MustBePinnedByDigest {
			if isImagePinnedByDigest(image.Link) {
				result.Metrics.PinnedByDigest++
				continue
			}

			// Not pinned by digest — flag it
			issue := GitlabPipelineImageIssueTag{
				Code:   CodeImageNotPinnedByDigest,
				DocURL: CodeImageNotPinnedByDigest.DocURL(),
				Link:   image.Link,
				Tag:    image.Tag,
				Job:    image.Job,
			}
			result.Issues = append(result.Issues, issue)
			result.Metrics.NotPinnedByDigest++
			continue
		}

		// Standard mode: check tag against forbidden patterns
		isForbiddenTag := gitlab.CheckItemMatchToPatterns(image.Tag, p.ForbiddenTags)

		if isForbiddenTag {
			issue := GitlabPipelineImageIssueTag{
				Code:   CodeImageForbiddenTag,
				DocURL: CodeImageForbiddenTag.DocURL(),
				Link:   image.Link,
				Tag:    image.Tag,
				Job:    image.Job,
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
		"notPinnedByDigest": result.Metrics.NotPinnedByDigest,
		"pinnedByDigest":    result.Metrics.PinnedByDigest,
		"compliance":        result.Compliance,
	}).Info("Forbidden image tag control completed")

	return result
}

/////////////////////////////////
// Digest pinning utility      //
/////////////////////////////////

// imageDigestPattern matches a valid content digest (e.g., sha256:<hex>, sha512:<hex>).
var imageDigestPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(?:[+._-][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,}$`)

// isImagePinnedByDigest checks whether an image reference contains an immutable digest.
// Returns true for references like "alpine@sha256:abc123..." and false for tag-only
// references like "alpine:3.19" or "alpine".
func isImagePinnedByDigest(imageLink string) bool {
	link := strings.TrimSpace(imageLink)
	if link == "" {
		return false
	}

	lastAt := strings.LastIndex(link, "@")
	if lastAt <= 0 || lastAt >= len(link)-1 {
		return false
	}

	digest := link[lastAt+1:]
	return imageDigestPattern.MatchString(digest)
}
