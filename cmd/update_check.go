package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	goversion "github.com/hashicorp/go-version"
	glabCI "github.com/getplumber/plumber/gitlab"
	"github.com/sirupsen/logrus"
)

const (
	githubLatestReleaseURL = "https://api.github.com/repos/getplumber/plumber/releases/latest"
	upgradeDocsURL         = "https://github.com/getplumber/plumber#-installation"
	versionCheckTimeout    = 3 * time.Second
)

type githubRelease struct {
	TagName string `json:"tag_name"`
}

// checkForNewerVersion fetches the latest plumber release from GitHub and
// prints a notice if a newer version is available. It is intentionally
// fail-fast: network errors, timeouts, or parse failures are silently
// ignored so that users are never blocked by the check.
//
// The check is skipped:
//   - in CI environments (GITLAB_CI / CI env vars are set)
//   - when the binary was built without a real version tag (Version == "dev")
func checkForNewerVersion() {
	// Skip in CI: Docker images embed plumber and the check adds no value there.
	if glabCI.IsRunningInCI() {
		logrus.Debug("version check: skipping in CI environment")
		return
	}

	// Skip for dev builds where there is no meaningful version to compare.
	if Version == "dev" || Version == "" {
		logrus.Debug("version check: skipping for dev build")
		return
	}

	client := &http.Client{Timeout: versionCheckTimeout}
	resp, err := client.Get(githubLatestReleaseURL)
	if err != nil {
		logrus.Debugf("version check: request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logrus.Debugf("version check: unexpected HTTP status %d", resp.StatusCode)
		return
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		logrus.Debugf("version check: could not decode response: %v", err)
		return
	}

	checkVersionNotice(Version, release.TagName, "")
}

// checkVersionNotice compares currentVer against latestTag and prints an
// upgrade notice to stderr when a newer version is available.
// releaseURL is used in tests to override the real GitHub URL (pass "" to use default).
func checkVersionNotice(currentVer, latestTag, _ string) {
	current, err := goversion.NewVersion(currentVer)
	if err != nil {
		logrus.Debugf("version check: could not parse current version %q: %v", currentVer, err)
		return
	}

	latest, err := goversion.NewVersion(latestTag)
	if err != nil {
		logrus.Debugf("version check: could not parse latest version %q: %v", latestTag, err)
		return
	}

	if latest.GreaterThan(current) {
		fmt.Fprintf(os.Stderr, "\nA newer version of plumber is available: %s (you have %s)\n", latestTag, currentVer)
		fmt.Fprintf(os.Stderr, "Upgrade instructions: %s\n\n", upgradeDocsURL)
	}
}
