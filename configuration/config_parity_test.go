package configuration

import (
	"os"
	"testing"

	"gopkg.in/yaml.v2"
)

// Plumber keeps two independent config files (getplumber/plumber#352):
//   - .plumber.yaml (repo root)        — Plumber's OWN self-scan config, the
//     one the Plumber workflow analyzes this repo with (auto-discovered).
//   - defaultConfig/.plumber.yaml      — the shipped default embedded in the
//     binary, the baseline every zero-config user gets.
//
// Their *values* may diverge freely (trust lists, enabled flags), but they
// must declare the same *set* of control blocks per provider. A control added
// to one file but forgotten in the other is drift: either the shipped default
// gains/loses a control the self-scan doesn't, or Plumber stops enforcing on
// itself something it ships to users. This test locks the control-key set
// while leaving every value free.
func TestSelfScanConfigControlsMatchDefault(t *testing.T) {
	const (
		selfScan       = "../.plumber.yaml"
		shippedDefault = "../defaultConfig/.plumber.yaml"
	)
	for _, provider := range []string{"gitlab", "github"} {
		self, selfHas := controlKeys(t, selfScan, provider)
		if !selfHas {
			// Plumber's self-scan config only declares the providers whose CI
			// the repo actually runs (GitHub-only today — no GitLab CI). A
			// provider it omits is intentionally out of scope for this drift
			// guard; the shipped default still declares both.
			t.Logf("self-scan config declares no %q section; skipping its drift check", provider)
			continue
		}
		def, defHas := controlKeys(t, shippedDefault, provider)
		if !defHas {
			t.Errorf("shipped default declares no %q section", provider)
			continue
		}

		for name := range def {
			if _, ok := self[name]; !ok {
				t.Errorf("provider %q: control %q is in defaultConfig/.plumber.yaml (shipped default) but missing from .plumber.yaml (self-scan) — add the block there too, or the two configs have drifted.", provider, name)
			}
		}
		for name := range self {
			if _, ok := def[name]; !ok {
				t.Errorf("provider %q: control %q is in .plumber.yaml (self-scan) but missing from defaultConfig/.plumber.yaml (shipped default) — add the block there too, or the two configs have drifted.", provider, name)
			}
		}
	}
}

// Both config files are consumed under --fail-warnings semantics:
//   - .plumber.yaml (self-scan) is loaded by the Plumber self-scan workflow
//     (`plumber analyze --fail-warnings`, auto-discovered from the repo root).
//   - defaultConfig/.plumber.yaml (shipped default) is embedded in the binary
//     in place by defaultConfig/embed.go and used by every zero-config user.
//
// TestSelfScanConfigControlsMatchDefault only compares control keys via a
// shallow unmarshal, so a malformed value would pass CI yet break at load.
// This runs each file through the real LoadPlumberConfig (version check,
// known-key schema, expression parsing over required/requiredGroups) and
// requires a clean load with a provider section and zero warnings.
func TestConfigFilesLoadAndValidate(t *testing.T) {
	for _, path := range []string{"../.plumber.yaml", "../defaultConfig/.plumber.yaml"} {
		pc, _, warnings, err := LoadPlumberConfig(path)
		if err != nil {
			t.Fatalf("%s must load without error: %v", path, err)
		}
		if pc == nil {
			t.Fatalf("%s: expected non-nil PlumberConfig", path)
		}
		if pc.GitHub == nil && pc.GitLab == nil {
			t.Errorf("%s should populate at least one provider section", path)
		}
		// Consumed under --fail-warnings, so any config warning (unknown key,
		// etc.) is a hard error (exit 2). Lock that in.
		if len(warnings) > 0 {
			t.Errorf("%s must load with zero warnings (consumed under --fail-warnings), got: %v", path, warnings)
		}
	}
}

// controlKeys returns the set of control keys under <provider>.controls, and
// whether that provider section is present at all. A section that is simply
// absent (present==false) is a caller decision to skip; a section present but
// malformed still fails hard.
func controlKeys(t *testing.T, path, provider string) (map[string]struct{}, bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	raw, exists := doc[provider]
	if !exists || raw == nil {
		return nil, false
	}
	prov, ok := raw.(map[any]any)
	if !ok {
		t.Fatalf("%s: malformed %q section", path, provider)
	}
	controls, ok := prov["controls"].(map[any]any)
	if !ok {
		t.Fatalf("%s: missing or malformed %q.controls section", path, provider)
	}
	out := make(map[string]struct{}, len(controls))
	for k := range controls {
		if s, ok := k.(string); ok {
			out[s] = struct{}{}
		}
	}
	return out, true
}
