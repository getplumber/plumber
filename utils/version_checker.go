package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/go-version"
)

const (
	githubReleasesURL = "https://api.github.com/repos/getplumber/plumber/releases/latest"
	timeoutSeconds    = 3
)

// ReleaseInfo represents GitHub release API response
type ReleaseInfo struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

// VersionChecker handles version checking functionality
type VersionChecker struct {
	currentVersion string
	httpClient     *http.Client
}

// NewVersionChecker creates a new version checker
func NewVersionChecker(currentVersion string) *VersionChecker {
	return &VersionChecker{
		currentVersion: currentVersion,
		httpClient: &http.Client{
			Timeout: timeoutSeconds * time.Second,
		},
	}
}

// CheckForUpdate checks if a newer version is available
// Returns the latest version and whether an update is available
// Returns empty strings if check fails (fail-fast behavior)
func (vc *VersionChecker) CheckForUpdate() (latestVersion string, updateAvailable bool, err error) {
	// Skip version check in CI environments
	if isCIEnvironment() {
		return "", false, nil
	}

	// Skip for dev builds
	if vc.currentVersion == "dev" || vc.currentVersion == "" {
		return "", false, nil
	}

	// Fetch latest release from GitHub
	release, err := vc.fetchLatestRelease()
	if err != nil {
		// Fail fast: return error without blocking
		return "", false, err
	}

	// Parse versions
	current, err := version.NewVersion(vc.currentVersion)
	if err != nil {
		return "", false, fmt.Errorf("invalid current version: %w", err)
	}

	latest, err := version.NewVersion(cleanVersion(release.TagName))
	if err != nil {
		return "", false, fmt.Errorf("invalid latest version: %w", err)
	}

	// Compare versions
	if latest.GreaterThan(current) {
		return release.TagName, true, nil
	}

	return release.TagName, false, nil
}

// fetchLatestRelease fetches the latest release from GitHub API
func (vc *VersionChecker) fetchLatestRelease() (*ReleaseInfo, error) {
	req, err := http.NewRequest("GET", githubReleasesURL, nil)
	if err != nil {
		return nil, err
	}

	// Add headers to avoid rate limiting
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "plumber-cli")

	resp, err := vc.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github API returned status %d", resp.StatusCode)
	}

	var release ReleaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	return &release, nil
}

// isCIEnvironment checks if running in a CI environment
func isCIEnvironment() bool {
	// Check common CI environment variables
	ciVars := []string{
		"CI",
		"GITLAB_CI",
		"GITHUB_ACTIONS",
		"JENKINS_URL",
		"TRAVIS",
		"CIRCLECI",
		"DRONE",
		"BUILDKITE",
	}

	for _, v := range ciVars {
		if os.Getenv(v) != "" {
			return true
		}
	}

	return false
}

// cleanVersion removes 'v' prefix from version string
func cleanVersion(v string) string {
	if len(v) > 0 && v[0] == 'v' {
		return v[1:]
	}
	return v
}

// PrintUpdateMessage prints update notification to stderr
func PrintUpdateMessage(currentVersion, latestVersion string) {
	fmt.Fprintf(os.Stderr, "\n📦 A new version of plumber is available!\n")
	fmt.Fprintf(os.Stderr, "   Current:  %s\n", currentVersion)
	fmt.Fprintf(os.Stderr, "   Latest:   %s\n", latestVersion)
	fmt.Fprintf(os.Stderr, "   Install:  https://github.com/getplumber/plumber#installation\n\n")
}
