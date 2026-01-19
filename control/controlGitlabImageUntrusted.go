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

const ControlTypeGitlabImageUntrustedVersion = "0.1.0"

// Constants for image registry and trust status
const (
	dockerHubDomain     = "docker.io"
	unknownRegistry     = "unknown"
	trustedSourceType   = "trusted"
	untrustedSourceType = "untrusted"
)

// GitlabImageUntrustedConf holds the configuration for untrusted image detection
type GitlabImageUntrustedConf struct {
	// Enabled controls whether this check runs
	Enabled bool `json:"enabled"`

	// TrustedUrls is a list of trusted registry URLs/patterns
	TrustedUrls []string `json:"trustedUrls"`

	// TrustDockerHubOfficialImages trusts official Docker Hub images (e.g., nginx, alpine)
	TrustDockerHubOfficialImages bool `json:"trustDockerHubOfficialImages"`
}

// GetConf loads configuration from R2Config
// Returns error if config is missing or incomplete
func (p *GitlabImageUntrustedConf) GetConf(r2Config *configuration.R2Config) error {
	// R2 config is required
	if r2Config == nil {
		return fmt.Errorf("R2 config is required but not provided")
	}

	// Get ImageUntrusted config from R2Config
	imgConfig := r2Config.GetImageUntrustedConfig()
	if imgConfig == nil {
		return fmt.Errorf("imageUntrusted control configuration is missing from .r2 config file")
	}

	// Check if enabled field is set
	if imgConfig.Enabled == nil {
		return fmt.Errorf("imageUntrusted.enabled field is required in .r2 config file")
	}

	// Apply configuration
	p.Enabled = imgConfig.IsEnabled()
	p.TrustedUrls = imgConfig.TrustedUrls
	if imgConfig.TrustDockerHubOfficialImages != nil {
		p.TrustDockerHubOfficialImages = *imgConfig.TrustDockerHubOfficialImages
	}

	l.WithFields(logrus.Fields{
		"enabled":                      p.Enabled,
		"trustedUrls":                  p.TrustedUrls,
		"trustDockerHubOfficialImages": p.TrustDockerHubOfficialImages,
	}).Debug("ImageUntrusted control configuration loaded from .r2 file")

	return nil
}

// GitlabImageUntrustedMetrics holds metrics about untrusted images
type GitlabImageUntrustedMetrics struct {
	Total     uint `json:"total"`
	Trusted   uint `json:"trusted"`
	Untrusted uint `json:"untrusted"`
	CiInvalid uint `json:"ciInvalid"`
	CiMissing uint `json:"ciMissing"`
}

// GitlabImageUntrustedResult holds the result of the untrusted image control
type GitlabImageUntrustedResult struct {
	Issues     []GitlabPipelineImageIssueUntrusted `json:"issues"`
	Metrics    GitlabImageUntrustedMetrics         `json:"metrics"`
	Compliance float64                             `json:"compliance"`
	Version    string                              `json:"version"`
	CiValid    bool                                `json:"ciValid"`
	CiMissing  bool                                `json:"ciMissing"`
	Skipped    bool                                `json:"skipped"`         // True if control was disabled
	Error      string                              `json:"error,omitempty"` // Error message if data collection failed
}

////////////////////
// Control issues //
////////////////////

// GitlabPipelineImageIssueUntrusted represents an issue with an untrusted image
type GitlabPipelineImageIssueUntrusted struct {
	Link   string `json:"link"`
	Status string `json:"status"`
	Job    string `json:"job"`
}

///////////////////////
// Control functions //
///////////////////////

// checkImageTrustStatus checks if an image is from a trusted source
func checkImageTrustStatus(image *collector.GitlabPipelineImageInfo, trustedUrls []string, trustDockerHubOfficialImages bool) string {
	// Check if Docker Hub options are enabled
	isDockerHubOfficial := false
	if trustDockerHubOfficialImages && image.Registry == dockerHubDomain {
		// Check if it's a Docker Hub official image (no username in path)
		// Official images have a single element path (e.g., docker.io/nginx)
		if !strings.Contains(image.Name, "/") {
			isDockerHubOfficial = true
		}
	}

	// If no trusted urls in the conf and Docker Hub options don't apply: image status is untrusted
	if len(trustedUrls) == 0 && !isDockerHubOfficial {
		return untrustedSourceType
	}

	// Check if the image url is trusted
	imageUrl := ""
	if image.Registry == unknownRegistry {
		imageUrl = image.Name
	} else {
		imageUrl = image.Registry + "/" + image.Name
	}

	// Include tag in the URL for pattern matching (if tag is present)
	if image.Tag != "" {
		imageUrl = imageUrl + ":" + image.Tag
	}

	imageUrlSanitized := strings.Trim(imageUrl, "/")
	if imageUrlSanitized == "" {
		return untrustedSourceType
	}

	l.WithFields(logrus.Fields{
		"imageUrlSanitized": imageUrlSanitized,
		"name":              image.Name,
		"tag":               image.Tag,
		"registry":          image.Registry,
		"link":              image.Link,
	}).Debug("Checking trust status of image")

	// Normalize variable notations in both the image URL and the trusted URL patterns
	normalizeVarNotation := func(s string) string {
		re := regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)
		return re.ReplaceAllString(s, `$$$1`)
	}
	imageUrlNormalized := normalizeVarNotation(imageUrlSanitized)
	trustedNormalized := make([]string, 0, len(trustedUrls))
	for _, p := range trustedUrls {
		trustedNormalized = append(trustedNormalized, normalizeVarNotation(p))
	}

	// Check if the image is in the trusted URLs list
	if gitlab.CheckItemMatchToPatterns(imageUrlNormalized, trustedNormalized) {
		return trustedSourceType
	}

	// If the image is a Docker Hub official image, mark it as trusted
	if isDockerHubOfficial {
		l.WithField("image", image.Name).Debug("Docker Hub official image considered trusted")
		return trustedSourceType
	}

	return untrustedSourceType
}

// Run executes the untrusted image detection control
func (p *GitlabImageUntrustedConf) Run(pipelineImageData *collector.GitlabPipelineImageData) *GitlabImageUntrustedResult {
	l := l.WithFields(logrus.Fields{
		"control":        "GitlabImageUntrusted",
		"controlVersion": ControlTypeGitlabImageUntrustedVersion,
	})
	l.Info("Start untrusted image control")

	result := &GitlabImageUntrustedResult{
		Issues:     []GitlabPipelineImageIssueUntrusted{},
		Metrics:    GitlabImageUntrustedMetrics{},
		Compliance: 100.0,
		Version:    ControlTypeGitlabImageUntrustedVersion,
		CiValid:    pipelineImageData.CiValid,
		CiMissing:  pipelineImageData.CiMissing,
		Skipped:    false,
	}

	// Check if control is enabled
	if !p.Enabled {
		l.Info("Untrusted image control is disabled, skipping")
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

	// Loop over all images to check trust status
	for _, image := range pipelineImageData.Images {
		status := checkImageTrustStatus(&image, p.TrustedUrls, p.TrustDockerHubOfficialImages)

		// Update metrics
		switch status {
		case trustedSourceType:
			result.Metrics.Trusted++
		case untrustedSourceType:
			result.Metrics.Untrusted++
			// Add issue for untrusted images
			issue := GitlabPipelineImageIssueUntrusted{
				Link:   image.Link,
				Status: status,
				Job:    image.Job,
			}
			result.Issues = append(result.Issues, issue)
		}
	}

	// Calculate compliance based on issues
	if len(result.Issues) > 0 {
		result.Compliance = 0.0
		l.WithField("issuesCount", len(result.Issues)).Debug("Found untrusted images, setting compliance to 0")
	}

	// Set total metrics
	result.Metrics.Total = uint(len(pipelineImageData.Images))

	l.WithFields(logrus.Fields{
		"totalImages":    result.Metrics.Total,
		"trustedCount":   result.Metrics.Trusted,
		"untrustedCount": result.Metrics.Untrusted,
		"compliance":     result.Compliance,
	}).Info("Untrusted image control completed")

	return result
}
