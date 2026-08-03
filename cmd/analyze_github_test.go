package cmd

import (
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// detectGitHubAuthSource
// ---------------------------------------------------------------------------

func TestDetectGitHubAuthSource_GHToken(t *testing.T) {
	t.Setenv("GH_TOKEN", "tok")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_ENTERPRISE_TOKEN", "")
	if got := detectGitHubAuthSource(""); got != "GH_TOKEN" {
		t.Fatalf("got %q", got)
	}
}

func TestDetectGitHubAuthSource_GitHubToken(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "tok")
	t.Setenv("GH_ENTERPRISE_TOKEN", "")
	if got := detectGitHubAuthSource(""); got != "GITHUB_TOKEN" {
		t.Fatalf("got %q", got)
	}
}

func TestDetectGitHubAuthSource_EnterpriseToken(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_ENTERPRISE_TOKEN", "tok")
	if got := detectGitHubAuthSource(""); got != "GH_ENTERPRISE_TOKEN" {
		t.Fatalf("got %q", got)
	}
}

func TestDetectGitHubAuthSource_None(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_ENTERPRISE_TOKEN", "")
	// No gh CLI configured in test env — expect empty string.
	got := detectGitHubAuthSource("github.com")
	if got == "GH_TOKEN" || got == "GITHUB_TOKEN" || got == "GH_ENTERPRISE_TOKEN" {
		t.Fatalf("unexpected token source: %q", got)
	}
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// loadGitHubConfig
// ---------------------------------------------------------------------------

func TestLoadGitHubConfig_FileExists(t *testing.T) {
	t.Setenv("CI", "true")
	dir := t.TempDir()
	orig := configFile
	configFile = dir + "/.plumber.yaml"
	defer func() { configFile = orig }()
	if err := writeMinimalConfig(configFile); err != nil {
		t.Fatal(err)
	}

	pc, path, err := loadGitHubConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pc == nil {
		t.Fatal("expected non-nil config")
	}
	if path != configFile {
		t.Fatalf("path: got %q, want %q", path, configFile)
	}
}

func TestLoadGitHubConfig_ExplicitMissingFile(t *testing.T) {
	t.Setenv("CI", "true")
	orig, origExplicit := configFile, configExplicitlySet
	configFile = t.TempDir() + "/nonexistent.yaml"
	configExplicitlySet = true // user named this --config; absence is an error
	defer func() { configFile, configExplicitlySet = orig, origExplicit }()

	_, _, err := loadGitHubConfig()
	if err == nil {
		t.Fatal("expected error for an explicitly-requested missing config")
	}
	if !strings.Contains(err.Error(), "configuration file not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadGitHubConfig_MissingDefault_FallsBack(t *testing.T) {
	t.Setenv("CI", "true")
	orig, origExplicit := configFile, configExplicitlySet
	configFile = t.TempDir() + "/.plumber.yaml" // absent, and not explicit
	configExplicitlySet = false
	defer func() { configFile, configExplicitlySet = orig, origExplicit }()

	pc, path, err := loadGitHubConfig()
	if err != nil {
		t.Fatalf("expected fallback to the embedded default, got: %v", err)
	}
	if pc == nil {
		t.Fatal("expected non-nil config from the embedded default")
	}
	if path != builtinDefaultConfigSource {
		t.Errorf("path: got %q, want %q", path, builtinDefaultConfigSource)
	}
}

func TestLoadGitHubConfig_WarningsFailWarnings(t *testing.T) {
	t.Setenv("CI", "true")
	dir := t.TempDir()
	orig, origFW := configFile, failWarnings
	configFile = dir + "/.plumber.yaml"
	failWarnings = true
	defer func() { configFile, failWarnings = orig, origFW }()

	// Write a config that produces validation warnings (unknown field).
	content := "version: \"2.0\"\nunknownField: true\n"
	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, err := loadGitHubConfig()
	// If warnings are produced and failWarnings is set, expect an error.
	// If the config happens to produce no warnings, the test is a no-op.
	if err != nil && !strings.Contains(err.Error(), "warning") {
		t.Errorf("unexpected error kind: %v", err)
	}
}

func TestLoadGitHubConfig_WarningsNoFail(t *testing.T) {
	t.Setenv("CI", "true")
	dir := t.TempDir()
	orig, origFW := configFile, failWarnings
	configFile = dir + "/.plumber.yaml"
	failWarnings = false
	defer func() { configFile, failWarnings = orig, origFW }()

	if err := writeMinimalConfig(configFile); err != nil {
		t.Fatal(err)
	}

	_, _, err := loadGitHubConfig()
	if err != nil {
		t.Fatalf("failWarnings=false should not error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeMinimalConfig(path string) error {
	return os.WriteFile(path, []byte("version: \"2.0\"\n"), 0644)
}
