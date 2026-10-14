package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		logrus.Debugf("version check: unexpected HTTP status %d", resp.StatusCode)
		return
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		logrus.Debugf("version check: could not decode response: %v", err)
		return
	}

	msg = buildUpdateNotice(Version, release.TagName, detectInstallChannel())
}

// channel is the way the running binary was installed, as far as its path
// on disk tells. It decides which upgrade command the notice prints: a
// `mise use` install pins the version resolved at install time and never
// re-resolves it, so a user who installed months ago keeps running that
// version until told the one command that moves it.
type channel string

const (
	channelUnknown   channel = ""
	channelMise      channel = "mise"
	channelBrew      channel = "brew"
	channelGoInstall channel = "go"
)

// upgradeHint is what the notice prints after the arrow: the channel's own
// upgrade command, or the generic install docs when the channel is unknown.
func (c channel) upgradeHint() string {
	switch c {
	case channelMise:
		return "mise upgrade github:getplumber/plumber"
	case channelBrew:
		return "brew upgrade plumber"
	case channelGoInstall:
		return "go install github.com/getplumber/plumber@latest"
	default:
		return upgradeDocsURL
	}
}

// installChannel classifies a resolved binary path. It is a pure function of
// the path (and optional extra Go bin dirs taken from the environment) so
// every path shape can be unit-tested with literals.
//
//   - mise keeps every tool under <data dir>/installs/<tool>/<version>/, so
//     "/mise/installs/" is present whatever the data dir and whether the
//     version segment is a number or "latest".
//   - Homebrew puts formulae in <prefix>/Cellar/<formula>/<version>/; the
//     prefix patterns cover a bare prefix path too (bin symlinks that did
//     not resolve, or a non-Cellar layout).
//   - go install drops the binary in GOBIN or GOPATH/bin, which is
//     $HOME/go/bin by default; a custom GOPATH is only known from the
//     environment, hence goBinDirs.
func installChannel(path string, goBinDirs ...string) channel {
	if path == "" {
		return channelUnknown
	}
	path = filepath.ToSlash(path)

	if strings.Contains(path, "/mise/installs/") {
		return channelMise
	}

	brewMarkers := []string{"/Cellar/plumber/", "/opt/homebrew/", "/usr/local/Homebrew/", "/home/linuxbrew/.linuxbrew/"}
	for _, m := range brewMarkers {
		if strings.Contains(path, m) {
			return channelBrew
		}
	}

	if strings.Contains(path, "/go/bin/") {
		return channelGoInstall
	}
	for _, dir := range goBinDirs {
		if dir == "" {
			continue
		}
		dir = filepath.ToSlash(filepath.Clean(dir))
		if strings.HasPrefix(path, dir+"/") {
			return channelGoInstall
		}
	}

	return channelUnknown
}

// detectInstallChannel resolves the running executable (following symlinks:
// mise and Homebrew both expose the binary through one) and classifies it.
// Any failure yields channelUnknown, which keeps the generic notice.
func detectInstallChannel() channel {
	exe, err := os.Executable()
	if err != nil {
		logrus.Debugf("version check: could not locate the running binary: %v", err)
		return channelUnknown
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	var goBinDirs []string
	if gobin := os.Getenv("GOBIN"); gobin != "" {
		goBinDirs = append(goBinDirs, gobin)
	}
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		for _, p := range filepath.SplitList(gopath) {
			goBinDirs = append(goBinDirs, filepath.Join(p, "bin"))
		}
	}
	return installChannel(exe, goBinDirs...)
}

// buildUpdateNotice compares currentVer against latestTag and returns an
// upgrade notice when a newer version is available, or "" if up-to-date.
// The notice ends with the upgrade command of the detected install channel,
// or the install docs URL when the channel is unknown.
func buildUpdateNotice(currentVer, latestTag string, ch channel) string {
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
		// Keep this to a single short line: it prints at the end of every run,
		// so anything bigger drowns out the actual results.
		return fmt.Sprintf("\nplumber %s is available (you have %s) → %s\n", latestTag, currentVer, ch.upgradeHint())
	}
	return ""
}
