package cmd

import (
	"os"
	"path/filepath"
	"testing"

	defaultconfig "github.com/getplumber/plumber/defaultConfig"
)

// Spec 4.2: the shipped default template gains a commented `capabilities:` example
// (defaultConfig/.plumber.yaml); being commented, it must not change what the template
// validates as, nor warn.
func TestRunConfigValidate_GeneratedTemplateWithCapabilitiesExample_IsValid(t *testing.T) {
	origFile, origFail := configValidateFile, failWarnings
	defer func() { configValidateFile, failWarnings = origFile, origFail }()

	path := filepath.Join(t.TempDir(), ".plumber.yaml")
	if err := os.WriteFile(path, defaultconfig.Get(), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}
	configValidateFile = path
	failWarnings = true // any warning fails the test outright

	var err error
	out := captureStdout(t, func() { err = runConfigValidate(nil, nil) })
	if err != nil {
		t.Fatalf("config validate on the generated template: %v", err)
	}
	if out == "" {
		t.Fatalf("expected the valid-configuration message, got nothing")
	}
}

// A real `capabilities:` key (not the commented example) must also validate cleanly: the
// capabilities key is never walked by ValidateKnownKeys (it is decoded, strictly, only when
// the effective list is built), so it must never surface as an unknown-key warning here.
func TestRunConfigValidate_RealCapabilitiesKey_IsValid(t *testing.T) {
	origFile, origFail := configValidateFile, failWarnings
	defer func() { configValidateFile, failWarnings = origFile, origFail }()

	path := filepath.Join(t.TempDir(), ".plumber.yaml")
	text := "version: \"2.0\"\ncapabilities:\n  - name: corp-secrets\n    recognizers:\n      - tool: in-house\n        commands: [\"scan-secrets*\"]\n"
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	configValidateFile = path
	failWarnings = true

	var err error
	out := captureStdout(t, func() { err = runConfigValidate(nil, nil) })
	if err != nil {
		t.Fatalf("config validate on a real capabilities key: %v", err)
	}
	if out == "" {
		t.Fatalf("expected the valid-configuration message, got nothing")
	}
}
