package cmd

import (
	"strings"
	"testing"
)

func TestCheckForNewerVersion_SkipsDevBuild(t *testing.T) {
	Version = "dev"
	ch := make(chan string, 1)
	checkForNewerVersion(ch)
	if msg := <-ch; msg != "" {
		t.Errorf("expected empty message for dev build, got: %q", msg)
	}
}

func TestCheckForNewerVersion_SkipsInCI(t *testing.T) {
	t.Setenv("CI", "true")
	Version = "0.1.0"
	ch := make(chan string, 1)
	checkForNewerVersion(ch)
	if msg := <-ch; msg != "" {
		t.Errorf("expected empty message in CI, got: %q", msg)
	}
}

func TestBuildUpdateNotice_PrintsUpgradeNotice(t *testing.T) {
	msg := buildUpdateNotice("0.1.0", "v0.2.0", channelUnknown)

	if !strings.Contains(msg, "v0.2.0") {
		t.Errorf("expected upgrade notice mentioning v0.2.0, got: %q", msg)
	}
	if !strings.Contains(msg, "0.1.0") {
		t.Errorf("expected current version 0.1.0 in notice, got: %q", msg)
	}
	if !strings.Contains(msg, upgradeDocsURL) {
		t.Errorf("expected upgrade docs URL in notice, got: %q", msg)
	}
}

func TestBuildUpdateNotice_SilentWhenUpToDate(t *testing.T) {
	msg := buildUpdateNotice("0.2.0", "v0.2.0", channelUnknown)
	if msg != "" {
		t.Errorf("expected no message when versions match, got: %q", msg)
	}
}

func TestBuildUpdateNotice_SilentWhenNewer(t *testing.T) {
	msg := buildUpdateNotice("0.3.0", "v0.2.0", channelUnknown)
	if msg != "" {
		t.Errorf("expected no message when current is newer, got: %q", msg)
	}
}

func TestBuildUpdateNotice_InvalidVersionsAreSilent(t *testing.T) {
	msg1 := buildUpdateNotice("not-a-version", "v0.2.0", channelUnknown)
	msg2 := buildUpdateNotice("0.1.0", "not-a-version", channelUnknown)
	if msg1 != "" || msg2 != "" {
		t.Errorf("expected no message for invalid versions, got: %q, %q", msg1, msg2)
	}
}

func TestInstallChannel_DetectsWhereTheBinaryLives(t *testing.T) {
	cases := []struct {
		name string
		path string
		want channel
	}{
		{"mise linux pinned version", "/home/u/.local/share/mise/installs/github-getplumber-plumber/0.3.27/plumber", channelMise},
		{"mise macos latest", "/Users/u/.local/share/mise/installs/github-getplumber-plumber/latest/plumber", channelMise},
		{"mise custom data dir", "/opt/tools/mise/installs/github-getplumber-plumber/0.6.1/bin/plumber", channelMise},
		{"brew macos apple silicon", "/opt/homebrew/Cellar/plumber/0.6.1/bin/plumber", channelBrew},
		{"brew macos intel", "/usr/local/Cellar/plumber/0.6.1/bin/plumber", channelBrew},
		{"brew macos intel prefix", "/usr/local/Homebrew/bin/plumber", channelBrew},
		{"brew linux", "/home/linuxbrew/.linuxbrew/Cellar/plumber/0.6.1/bin/plumber", channelBrew},
		// The prefix markers alone, for a brew binary whose symlink did not resolve.
		{"brew apple silicon prefix", "/opt/homebrew/bin/plumber", channelBrew},
		{"brew linux prefix", "/home/linuxbrew/.linuxbrew/bin/plumber", channelBrew},
		{"go install default gopath", "/home/u/go/bin/plumber", channelGoInstall},
		{"go install root gopath", "/root/go/bin/plumber", channelGoInstall},
		{"manual binary", "/usr/local/bin/plumber", channelUnknown},
		{"docker image", "/plumber", channelUnknown},
		{"empty path", "", channelUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := installChannel(tc.path); got != tc.want {
				t.Errorf("installChannel(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestInstallChannel_CustomGoBinDir(t *testing.T) {
	if got := installChannel("/data/gopath/bin/plumber", "/data/gopath/bin"); got != channelGoInstall {
		t.Errorf("expected go install channel for a binary under GOPATH/bin, got %q", got)
	}
	if got := installChannel("/data/gopath/bin/plumber"); got != channelUnknown {
		t.Errorf("expected unknown channel without the GOPATH hint, got %q", got)
	}
}

func TestBuildUpdateNotice_ChannelCommandReplacesDocsURL(t *testing.T) {
	cases := []struct {
		ch   channel
		want string
	}{
		{channelMise, "mise upgrade github:getplumber/plumber"},
		{channelBrew, "brew upgrade plumber"},
		{channelGoInstall, "go install github.com/getplumber/plumber@latest"},
	}
	for _, tc := range cases {
		msg := buildUpdateNotice("0.3.27", "v0.6.1", tc.ch)
		if !strings.Contains(msg, "v0.6.1") || !strings.Contains(msg, "0.3.27") {
			t.Errorf("%s: expected both versions in notice, got: %q", tc.ch, msg)
		}
		if !strings.Contains(msg, tc.want) {
			t.Errorf("%s: expected upgrade command %q in notice, got: %q", tc.ch, tc.want, msg)
		}
		if strings.Contains(msg, upgradeDocsURL) {
			t.Errorf("%s: the channel command must replace the docs URL, got: %q", tc.ch, msg)
		}
	}
}

func TestBuildUpdateNotice_UnknownChannelKeepsDocsURL(t *testing.T) {
	msg := buildUpdateNotice("0.3.27", "v0.6.1", channelUnknown)
	if !strings.Contains(msg, upgradeDocsURL) {
		t.Errorf("expected the generic docs URL for an unknown channel, got: %q", msg)
	}
}

// A go install build carries the module version stamped in its build info:
// the tag of a release, or a pseudo-version for a commit between two
// releases. Both go through the notice builder as a current version, and
// the hint names the go install channel.
func TestBuildUpdateNotice_GoInstallBuildVersions(t *testing.T) {
	msg := buildUpdateNotice("0.6.2-0.20261001120000-abcdef123456", "v0.6.2", channelGoInstall)
	if !strings.Contains(msg, "v0.6.2") || !strings.Contains(msg, "0.6.2-0.20261001120000-abcdef123456") {
		t.Errorf("a pseudo-version before the release must get the notice, got: %q", msg)
	}
	if !strings.Contains(msg, "go install github.com/getplumber/plumber@latest") {
		t.Errorf("the notice must name the go install channel, got: %q", msg)
	}
	if msg := buildUpdateNotice("0.6.2", "v0.6.2", channelGoInstall); msg != "" {
		t.Errorf("a build at the released tag is up to date, got: %q", msg)
	}
	if msg := buildUpdateNotice("0.6.3-0.20261020120000-0123456789ab", "v0.6.2", channelGoInstall); msg != "" {
		t.Errorf("a pseudo-version after the latest release is newer, got: %q", msg)
	}
}
