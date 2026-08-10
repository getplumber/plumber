package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"

	"github.com/getplumber/plumber/configuration"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
)

func TestConfigResolve_MaterializesOverlay(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, ".plumber.yaml")
	out := filepath.Join(dir, "resolved.yaml")
	overlay := `extends: plumber:default
github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      trustedGithubActions:
        - myorg
`
	if err := os.WriteFile(in, []byte(overlay), 0o600); err != nil {
		t.Fatal(err)
	}
	// The path exists, so the configExplicit value doesn't change the
	// outcome here; pass true since this mirrors an explicit -c in real use.
	if err := resolveConfigToFile(in, out, true); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "extends:") {
		t.Fatal("resolved output should not contain extends")
	}
	cfg := &configuration.PlumberConfig{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		t.Fatalf("resolved output not valid config: %v", err)
	}
	list := cfg.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.TrustedGithubActions

	// The overlay's own entry must survive the union.
	if !containsString(list, "myorg") {
		t.Fatalf("resolved trustedGithubActions must contain the overlay's own entry %q: %v", "myorg", list)
	}

	// A real curated base entry must also be present, proving the union
	// actually happened (not just that the overlay's list passed through).
	base, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "base")
	if err != nil {
		t.Fatalf("load base config: %v", err)
	}
	baseTrustedActions := base.GitHub.Controls.GithubActionMustComeFromAuthorizedSources.TrustedGithubActions
	if len(baseTrustedActions) == 0 {
		t.Fatal("test assumption broken: base trustedGithubActions is empty")
	}
	if !containsString(list, baseTrustedActions[0]) {
		t.Fatalf("resolved trustedGithubActions must contain curated base entry %q (union expected): %v", baseTrustedActions[0], list)
	}
}

// captureStdoutDeferred swaps os.Stdout for a pipe, runs fn, and returns
// everything fn wrote to stdout. os.Stdout is restored via defer so a
// failing fn (t.Fatal, which unwinds via runtime.Goexit, or a panic) cannot
// leave the swap in place and leak into later tests.
func captureStdoutDeferred(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// TestConfigResolve_StdoutOutput covers the default stdout branch of
// resolveConfigToFile (empty dst), which every other resolve test bypasses
// by passing an explicit output path.
func TestConfigResolve_StdoutOutput(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, ".plumber.yaml")
	overlay := `extends: plumber:default
github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      trustedGithubActions:
        - myorg
`
	if err := os.WriteFile(in, []byte(overlay), 0o600); err != nil {
		t.Fatal(err)
	}

	out := captureStdoutDeferred(t, func() {
		if err := resolveConfigToFile(in, "", true); err != nil {
			t.Fatalf("resolve: %v", err)
		}
	})

	if out == "" {
		t.Fatal("expected non-empty stdout output")
	}
	if strings.Contains(out, "extends:") {
		t.Fatal("resolved stdout output should not contain extends")
	}
	cfg := &configuration.PlumberConfig{}
	if err := yaml.Unmarshal([]byte(out), cfg); err != nil {
		t.Fatalf("resolved stdout output not valid config: %v", err)
	}
}

// An explicitly-named --config path that doesn't exist must hard-fail, not
// silently fall back to the embedded default. Otherwise `plumber config
// resolve -c typo.yaml -o .plumber.yaml` could write a permissive default
// config over a file the user intended to point at a stricter, hand-tuned
// one. Mirrors TestLoadConfigOrOffer_ExplicitMissingFile_Errors.
func TestConfigResolve_ExplicitMissingConfigErrors(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "typo.yaml")
	out := filepath.Join(dir, "resolved.yaml")

	err := resolveConfigToFile(missing, out, true)
	if err == nil {
		t.Fatal("expected an error for an explicitly-requested missing config file")
	}
	if !errors.Is(err, configuration.ErrConfigNotFound) {
		t.Fatalf("expected ErrConfigNotFound, got: %v", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Fatal("resolve must not write an output file when the explicit source is missing")
	}
}

// The zero-config path (no explicit --config, no local file) must still fall
// back to the embedded default so `plumber config resolve` works out of the
// box, same as runConfigView and loadConfigOrOffer.
func TestConfigResolve_ZeroConfigFallsBackToEmbeddedDefault(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, ".plumber.yaml") // does not exist
	out := filepath.Join(dir, "resolved.yaml")

	if err := resolveConfigToFile(missing, out, false); err != nil {
		t.Fatalf("expected fallback to the embedded default, got error: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "extends:") {
		t.Fatal("resolved output should not contain extends")
	}
	cfg := &configuration.PlumberConfig{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		t.Fatalf("resolved output not valid config: %v", err)
	}
	if cfg.GitHub == nil && cfg.GitLab == nil {
		t.Fatal("embedded default should populate at least one provider section")
	}
}
