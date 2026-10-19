package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
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

// capturedLog hooks the standard logger at debug level so a test asserts on what
// runConfigView logged, and restores it afterwards (mirrors capability.capturedLog).
func capturedLog(t *testing.T) *logrustest.Hook {
	t.Helper()
	std := logrus.StandardLogger()
	savedLevel, savedHooks := std.GetLevel(), std.Hooks
	std.SetLevel(logrus.DebugLevel)
	hook := logrustest.NewLocal(std)
	t.Cleanup(func() {
		std.ReplaceHooks(savedHooks)
		std.SetLevel(savedLevel)
	})
	return hook
}

// writeViewConfig writes a .plumber.yaml under t.TempDir() carrying capabilitiesYAML (the
// `capabilities:` key and whatever it holds, or "" for none) and returns its path.
func writeViewConfig(t *testing.T, capabilitiesYAML string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".plumber.yaml")
	if err := os.WriteFile(path, []byte("version: \"2.0\"\n"+capabilitiesYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// Spec 4.2: with no capabilities key declared, `config view` must show the effective list,
// not an empty file: the built-in secret_detection capability with all six built-in tools,
// since nothing before this fix in cmd/config.go ever printed it (runConfigView marshaled
// only the loaded PlumberConfig, whose Capabilities field is nil without a file key).
func TestRunConfigView_NoCapabilitiesKey_PrintsBuiltinSecretDetection(t *testing.T) {
	origFile, origNoColor := configViewFile, configViewNoColor
	defer func() { configViewFile, configViewNoColor = origFile, origNoColor }()

	cmd := newConfigViewTestCmd()
	configViewNoColor = true
	if err := cmd.Flags().Set("config", writeViewConfig(t, "")); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	var err error
	out := captureStdout(t, func() { err = runConfigView(cmd, nil) })
	if err != nil {
		t.Fatalf("runConfigView: %v", err)
	}
	if !strings.Contains(out, "capabilities:") || !strings.Contains(out, "name: secret_detection") {
		t.Fatalf("expected the built-in secret_detection block, got:\n%s", out)
	}
	for _, tool := range []string{"gitleaks", "betterleaks", "trufflehog", "detect-secrets", "ggshield", "gitlab-secret-detection"} {
		if !strings.Contains(out, "tool: "+tool) {
			t.Errorf("expected built-in tool %q in the capabilities block, got:\n%s", tool, out)
		}
	}
}

// Spec 4.2: a declared capability that does not name a built-in is prepended to the
// effective list, in the user's own order, with every built-in the file does not name
// still filled in after it.
func TestRunConfigView_FileDeclaresExtraCapability_PrintsItBeforeTheBuiltin(t *testing.T) {
	origFile, origNoColor := configViewFile, configViewNoColor
	defer func() { configViewFile, configViewNoColor = origFile, origNoColor }()

	cmd := newConfigViewTestCmd()
	configViewNoColor = true
	path := writeViewConfig(t, "capabilities:\n  - name: corp-secrets\n    recognizers:\n      - tool: in-house\n        commands: [\"scan-secrets*\"]\n")
	if err := cmd.Flags().Set("config", path); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	var err error
	out := captureStdout(t, func() { err = runConfigView(cmd, nil) })
	if err != nil {
		t.Fatalf("runConfigView: %v", err)
	}
	corp := strings.Index(out, "name: corp-secrets")
	secret := strings.Index(out, "name: secret_detection")
	if corp < 0 || secret < 0 || corp > secret {
		t.Fatalf("expected corp-secrets then secret_detection, got:\n%s", out)
	}
}

// Spec 4.2: a declared capability naming a built-in replaces that built-in whole: narrowing
// secret_detection to one recognizer must not also print the built-in's other recognizers.
func TestRunConfigView_FileRedeclaresBuiltin_PrintsOnlyTheDeclaredRecognizer(t *testing.T) {
	origFile, origNoColor := configViewFile, configViewNoColor
	defer func() { configViewFile, configViewNoColor = origFile, origNoColor }()

	cmd := newConfigViewTestCmd()
	configViewNoColor = true
	path := writeViewConfig(t, "capabilities:\n  - name: secret_detection\n    recognizers:\n      - tool: in-house\n        commands: [\"scan-secrets*\"]\n")
	if err := cmd.Flags().Set("config", path); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	var err error
	out := captureStdout(t, func() { err = runConfigView(cmd, nil) })
	if err != nil {
		t.Fatalf("runConfigView: %v", err)
	}
	if !strings.Contains(out, "name: secret_detection") || !strings.Contains(out, "tool: in-house") {
		t.Fatalf("expected the user's own recognizer under secret_detection, got:\n%s", out)
	}
	if strings.Contains(out, "gitleaks") {
		t.Fatalf("expected the built-in's recognizers gone (replaced whole), got:\n%s", out)
	}
}

// Spec 4.2 and 4.6: a malformed capabilities key never fails `config view`: it warns (the
// same one-line warning the provider shows) and falls back to printing the built-in list.
func TestRunConfigView_MalformedCapabilitiesKey_WarnsAndPrintsBuiltin(t *testing.T) {
	origFile, origNoColor := configViewFile, configViewNoColor
	defer func() { configViewFile, configViewNoColor = origFile, origNoColor }()

	cmd := newConfigViewTestCmd()
	configViewNoColor = true
	path := writeViewConfig(t, "capabilities:\n  name: secret_detection\n") // a map, not a list
	if err := cmd.Flags().Set("config", path); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	hook := capturedLog(t)
	var err error
	out := captureStdout(t, func() { err = runConfigView(cmd, nil) })
	if err != nil {
		t.Fatalf("runConfigView: %v", err)
	}
	if !strings.Contains(out, "name: secret_detection") || !strings.Contains(out, "tool: gitleaks") {
		t.Fatalf("expected the built-in block as the fallback, got:\n%s", out)
	}
	var warns []*logrus.Entry
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel {
			warns = append(warns, e)
		}
	}
	if len(warns) != 1 {
		t.Fatalf("warnings = %d, want exactly one", len(warns))
	}
	if !strings.Contains(warns[0].Message, "the built-in list is in force") {
		t.Fatalf("warning message = %q, want it to say the built-in list is in force", warns[0].Message)
	}
}
