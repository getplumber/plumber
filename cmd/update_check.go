package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	glabCI "github.com/getplumber/plumber/gitlab"
	goversion "github.com/hashicorp/go-version"
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
// sends an upgrade notice to ch when a newer version is available.
// It always sends exactly one value (possibly empty) so the receiver
// never blocks indefinitely. Network errors, timeouts, or parse failures
// result in an empty send so that users are never blocked by the check.
//
// The check is skipped:
//   - in CI environments (GITLAB_CI / CI env vars are set)
//   - when the binary was built without a real version tag (Version == "dev")
func checkForNewerVersion(ch chan<- string) {
	var msg string
	defer func() { ch <- msg }()

	if glabCI.IsRunningInCI() {
		logrus.Debug("version check: skipping in CI environment")
		return
	}

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

	msg = buildUpdateNotice(Version, release.TagName)
}

// buildUpdateNotice compares currentVer against latestTag and returns an
// upgrade notice when a newer version is available, or "" if up-to-date.
func buildUpdateNotice(currentVer, latestTag string) string {
	current, err := goversion.NewVersion(currentVer)
	if err != nil {
		logrus.Debugf("version check: could not parse current version %q: %v", currentVer, err)
		return ""
	}

	latest, err := goversion.NewVersion(latestTag)
	if err != nil {
		logrus.Debugf("version check: could not parse latest version %q: %v", latestTag, err)
		return ""
	}

	if latest.GreaterThan(current) {
		return fmt.Sprintf("\nA newer version of plumber is available: %s (you have %s)\nUpgrade instructions: %s\nTo disable this check: export PLUMBER_NO_UPDATE_CHECK=1\n\n", latestTag, currentVer, upgradeDocsURL)
	}
	return ""
}
