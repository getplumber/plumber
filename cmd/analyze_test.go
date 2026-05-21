package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadConfigOrOffer — non-interactive paths (no TTY in CI or test runner).
//
// The interactive survey branch cannot be unit-tested without mocking the
// survey library; the paths below cover the three deterministic code paths:
//  1. Config file exists → loaded successfully, no prompt.
//  2. Config file missing, non-interactive → error with actionable hint.
//  3. Config file present but invalid YAML → configuration error (not a
//     "file not found" variant, so the offer logic is bypassed).

func TestLoadConfigOrOffer_FileExists(t *testing.T) {
	// Write a minimal valid .plumber.yaml to a temp dir.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".plumber.yaml")
	content := "version: \"2.0\"\n"
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	pc, path, warnings, err := loadConfigOrOffer(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pc == nil {
		t.Fatal("expected non-nil PlumberConfig")
	}
	if path != cfgPath {
		t.Fatalf("path: got %q, want %q", path, cfgPath)
	}
	_ = warnings // may be non-empty for a minimal config, that's fine
}

func TestLoadConfigOrOffer_MissingFile_NonInteractive(t *testing.T) {
	// Ensure non-interactive mode: CI env var forces isInteractiveInit to false.
	t.Setenv("CI", "true")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "nonexistent.yaml")

	_, _, _, err := loadConfigOrOffer(cfgPath)
	if err == nil {
		t.Fatal("expected an error for missing config file")
	}
	msg := err.Error()
	if !strings.Contains(msg, "configuration file not found") {
		t.Errorf("error should mention 'configuration file not found', got: %s", msg)
	}
	if !strings.Contains(msg, "plumber config generate") || !strings.Contains(msg, "plumber config init") {
		t.Errorf("error should include generation hint, got: %s", msg)
	}
}

func TestLoadConfigOrOffer_InvalidYAML_NonInteractive(t *testing.T) {
	t.Setenv("CI", "true")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".plumber.yaml")
	if err := os.WriteFile(cfgPath, []byte(":\tinvalid: yaml: [\n"), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	_, _, _, err := loadConfigOrOffer(cfgPath)
	if err == nil {
		t.Fatal("expected an error for invalid YAML")
	}
	// Must be a configuration error, not a "file not found" hint.
	msg := err.Error()
	if !strings.Contains(msg, "configuration error") {
		t.Errorf("error should mention 'configuration error', got: %s", msg)
	}
}
