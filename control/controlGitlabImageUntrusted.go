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

const ControlTypeGitlabImageAuthorizedSourcesVersion = "0.1.0"

// Constants for image registry and trust status
const (
	dockerHubDomain    = "docker.io"
	unknownRegistry    = "unknown"
	authorizedStatus   = "authorized"
	unauthorizedStatus = "unauthorized"
)

// GitlabImageAuthorizedSourcesConf holds the configuration for image source authorization
type GitlabImageAuthorizedSourcesConf struct {
	// Enabled controls whether this check runs
	Enabled bool `json:"enabled"`

	// TrustedUrls is a list of authorized registry URLs/patterns
	TrustedUrls []string `json:"trustedUrls"`

	// TrustDockerHubOfficialImages trusts official Docker Hub images (e.g., nginx, alpine)
	TrustDockerHubOfficialImages bool `json:"trustDockerHubOfficialImages"`
}

// GetConf loads configuration from PlumberConfig
// Returns error if config is missing or incomplete
func (p *GitlabImageAuthorizedSourcesConf) GetConf(plumberConfig *configuration.PlumberConfig) error {
	// Plumber config is required
	if plumberConfig == nil {
		return fmt.Errorf("Plumber config is required but not provided")
	}

	// Get control config from PlumberConfig
	imgConfig := plumberConfig.GetContainerImageMustComeFromAuthorizedSourcesConfig()
	if imgConfig == nil {
		return fmt.Errorf("containerImageMustComeFromAuthorizedSources control configuration is missing from .plumber.yaml config file")
	}

	// Check if enabled field is set
	if imgConfig.Enabled == nil {
		return fmt.Errorf("containerImageMustComeFromAuthorizedSources.enabled field is required in .plumber.yaml config file")
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
	}).Debug("containerImageMustComeFromAuthorizedSources control configuration loaded from .plumber.yaml file")

	return nil
}

// GitlabImageAuthorizedSourcesMetrics holds metrics about image source authorization
type GitlabImageAuthorizedSourcesMetrics struct {
	Total        uint `json:"total"`
	Authorized   uint `json:"authorized"`
	Unauthorized uint `json:"unauthorized"`
	CiInvalid    uint `json:"ciInvalid"`
	CiMissing    uint `json:"ciMissing"`
}

// GitlabImageAuthorizedSourcesResult holds the result of the image authorized sources control
type GitlabImageAuthorizedSourcesResult struct {
	Issues     []GitlabPipelineImageIssueUnauthorized `json:"issues"`
	Metrics    GitlabImageAuthorizedSourcesMetrics    `json:"metrics"`
	Compliance float64                                `json:"compliance"`
	Version    string                                 `json:"version"`
	CiValid    bool                                   `json:"ciValid"`
	CiMissing  bool                                   `json:"ciMissing"`
	Skipped    bool                                   `json:"skipped"`         // True if control was disabled
	Error      string                                 `json:"error,omitempty"` // Error message if data collection failed
}

////////////////////
// Control issues //
////////////////////

// GitlabPipelineImageIssueUnauthorized represents an issue with an unauthorized image source
type GitlabPipelineImageIssueUnauthorized struct {
	Link   string `json:"link"`
	Status string `json:"status"`
	Job    string `json:"job"`
}

///////////////////////
// Control functions //
///////////////////////

// checkImageAuthorizationStatus checks if an image is from an authorized source
func checkImageAuthorizationStatus(image *collector.GitlabPipelineImageInfo, trustedUrls []string, trustDockerHubOfficialImages bool) string {
	// Check if Docker Hub options are enabled
	isDockerHubOfficial := false
	if trustDockerHubOfficialImages && image.Registry == dockerHubDomain {
		// Check if it's a Docker Hub official image (no username in path)
		// Official images have a single element path (e.g., docker.io/nginx)
		if !strings.Contains(image.Name, "/") {
			isDockerHubOfficial = true
		}
	}

	// If no trusted urls in the conf and Docker Hub options don't apply: image is unauthorized
	if len(trustedUrls) == 0 && !isDockerHubOfficial {
		return unauthorizedStatus
	}

	// Check if the image url is authorized
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
		return unauthorizedStatus
	}

	l.WithFields(logrus.Fields{
		"imageUrlSanitized": imageUrlSanitized,
		"name":              image.Name,
		"tag":               image.Tag,
		"registry":          image.Registry,
		"link":              image.Link,
	}).Debug("Checking authorization status of image")

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

	// Check if the image is in the authorized URLs list
	if gitlab.CheckItemMatchToPatterns(imageUrlNormalized, trustedNormalized) {
		return authorizedStatus
	}

	// If the image is a Docker Hub official image, mark it as authorized
	if isDockerHubOfficial {
		l.WithField("image", image.Name).Debug("Docker Hub official image considered authorized")
		return authorizedStatus
	}

	return unauthorizedStatus
}

// Run executes the image authorized sources control
func (p *GitlabImageAuthorizedSourcesConf) Run(pipelineImageData *collector.GitlabPipelineImageData) *GitlabImageAuthorizedSourcesResult {
	l := l.WithFields(logrus.Fields{
		"control":        "GitlabImageAuthorizedSources",
		"controlVersion": ControlTypeGitlabImageAuthorizedSourcesVersion,
	})
	l.Info("Start image authorized sources control")

	result := &GitlabImageAuthorizedSourcesResult{
		Issues:     []GitlabPipelineImageIssueUnauthorized{},
		Metrics:    GitlabImageAuthorizedSourcesMetrics{},
		Compliance: 100.0,
		Version:    ControlTypeGitlabImageAuthorizedSourcesVersion,
		CiValid:    pipelineImageData.CiValid,
		CiMissing:  pipelineImageData.CiMissing,
		Skipped:    false,
	}

	// Check if control is enabled
	if !p.Enabled {
		l.Info("Image authorized sources control is disabled, skipping")
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

	// Loop over all images to check authorization status
	for _, image := range pipelineImageData.Images {
		status := checkImageAuthorizationStatus(&image, p.TrustedUrls, p.TrustDockerHubOfficialImages)

		// Update metrics
		switch status {
		case authorizedStatus:
			result.Metrics.Authorized++
		case unauthorizedStatus:
			result.Metrics.Unauthorized++
			// Add issue for unauthorized images
			issue := GitlabPipelineImageIssueUnauthorized{
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
		l.WithField("issuesCount", len(result.Issues)).Debug("Found unauthorized images, setting compliance to 0")
	}

	// Set total metrics
	result.Metrics.Total = uint(len(pipelineImageData.Images))

	l.WithFields(logrus.Fields{
		"totalImages":       result.Metrics.Total,
		"authorizedCount":   result.Metrics.Authorized,
		"unauthorizedCount": result.Metrics.Unauthorized,
		"compliance":        result.Compliance,
	}).Info("Image authorized sources control completed")

	return result
}
