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
	msg := buildUpdateNotice("0.1.0", "v0.2.0")

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
	msg := buildUpdateNotice("0.2.0", "v0.2.0")
	if msg != "" {
		t.Errorf("expected no message when versions match, got: %q", msg)
	}
}

func TestBuildUpdateNotice_SilentWhenNewer(t *testing.T) {
	msg := buildUpdateNotice("0.3.0", "v0.2.0")
	if msg != "" {
		t.Errorf("expected no message when current is newer, got: %q", msg)
	}
}

func TestBuildUpdateNotice_InvalidVersionsAreSilent(t *testing.T) {
	msg1 := buildUpdateNotice("not-a-version", "v0.2.0")
	msg2 := buildUpdateNotice("0.1.0", "not-a-version")
	if msg1 != "" || msg2 != "" {
		t.Errorf("expected no message for invalid versions, got: %q, %q", msg1, msg2)
	}
}
