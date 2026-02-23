package cmd

import (
	"os"
	"strings"
	"testing"
)

func captureStderr(f func()) string {
	r, w, _ := os.Pipe()
	oldStderr := os.Stderr
	os.Stderr = w
	f()
	w.Close()
	os.Stderr = oldStderr
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	return string(buf[:n])
}

func TestCheckForNewerVersion_SkipsDevBuild(t *testing.T) {
	// checkForNewerVersion must not make network calls for dev builds
	Version = "dev"
	// If the guard fails, the real GitHub URL would be called in tests.
	// The test simply verifies it returns without panicking or blocking.
	checkForNewerVersion()
}

func TestCheckForNewerVersion_SkipsInCI(t *testing.T) {
	t.Setenv("CI", "true")
	Version = "0.1.0"
	checkForNewerVersion() // should return immediately due to CI guard
}

func TestCheckVersionNotice_PrintsUpgradeNotice(t *testing.T) {
	output := captureStderr(func() {
		checkVersionNotice("0.1.0", "v0.2.0", "")
	})

	if !strings.Contains(output, "v0.2.0") {
		t.Errorf("expected upgrade notice mentioning v0.2.0, got: %q", output)
	}
	if !strings.Contains(output, "0.1.0") {
		t.Errorf("expected current version 0.1.0 in notice, got: %q", output)
	}
	if !strings.Contains(output, upgradeDocsURL) {
		t.Errorf("expected upgrade docs URL in notice, got: %q", output)
	}
}

func TestCheckVersionNotice_SilentWhenUpToDate(t *testing.T) {
	output := captureStderr(func() {
		checkVersionNotice("0.2.0", "v0.2.0", "")
	})
	if output != "" {
		t.Errorf("expected no output when versions match, got: %q", output)
	}
}

func TestCheckVersionNotice_SilentWhenNewer(t *testing.T) {
	// User is on a newer version than the release (e.g., dev/pre-release builds)
	output := captureStderr(func() {
		checkVersionNotice("0.3.0", "v0.2.0", "")
	})
	if output != "" {
		t.Errorf("expected no output when current is newer, got: %q", output)
	}
}

func TestCheckVersionNotice_InvalidVersionsAreSilent(t *testing.T) {
	// Malformed version strings must not panic
	output := captureStderr(func() {
		checkVersionNotice("not-a-version", "v0.2.0", "")
		checkVersionNotice("0.1.0", "not-a-version", "")
	})
	if output != "" {
		t.Errorf("expected no output for invalid versions, got: %q", output)
	}
}
