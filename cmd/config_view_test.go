package cmd

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// newConfigViewTestCmd builds a command carrying the flags runConfigView
// reads (config, no-color), so a test can drive the handler directly.
func newConfigViewTestCmd() *cobra.Command {
	c := &cobra.Command{Use: "view", RunE: runConfigView}
	c.Flags().StringVarP(&configViewFile, "config", "c", ".plumber.yaml", "")
	c.Flags().BoolVar(&configViewNoColor, "no-color", false, "")
	return c
}

// No local config and no explicit --config: `config view` shows the embedded
// default rather than erroring (parity with the zero-config analyze fallback).
func TestRunConfigView_MissingDefault_ShowsEmbeddedDefault(t *testing.T) {
	origFile, origNoColor := configViewFile, configViewNoColor
	defer func() { configViewFile, configViewNoColor = origFile, origNoColor }()

	cmd := newConfigViewTestCmd()
	configViewFile = filepath.Join(t.TempDir(), ".plumber.yaml") // absent
	configViewNoColor = true

	var err error
	out := captureStdout(t, func() { err = runConfigView(cmd, nil) })
	if err != nil {
		t.Fatalf("expected fallback to the embedded default, got error: %v", err)
	}
	if !strings.Contains(out, "github:") && !strings.Contains(out, "gitlab:") {
		t.Errorf("expected embedded default with a provider section, got:\n%s", out)
	}
}

// An explicitly-named --config that does not exist must still error — the
// fallback is only for the default path, never for a file the user asked for.
func TestRunConfigView_ExplicitMissing_Errors(t *testing.T) {
	origFile, origNoColor := configViewFile, configViewNoColor
	defer func() { configViewFile, configViewNoColor = origFile, origNoColor }()

	cmd := newConfigViewTestCmd()
	missing := filepath.Join(t.TempDir(), "custom.yaml")
	configViewNoColor = true
	if err := cmd.Flags().Set("config", missing); err != nil { // marks --config changed
		t.Fatalf("set flag: %v", err)
	}

	// On this path runConfigView returns the error without printing the
	// config, so no stdout capture is needed (and capturing empty output
	// through the shared helper would deadlock).
	if err := runConfigView(cmd, nil); err == nil {
		t.Fatal("expected an error for an explicitly-requested missing --config (no fallback)")
	}
}
