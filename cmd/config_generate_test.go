package cmd

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"

	"github.com/getplumber/plumber/configuration"
)

func TestMinimalOverlayStarter_IsValidOverlay(t *testing.T) {
	s := minimalOverlayStarter()
	if !strings.Contains(s, "extends: plumber:default") {
		t.Fatal("starter must opt into overlay mode")
	}
	// The starter must load and resolve without error.
	cfg, _, _, err := configuration.LoadPlumberConfigFromBytes([]byte(s), "starter")
	if err != nil {
		t.Fatalf("starter does not resolve: %v", err)
	}
	if cfg.GitHub == nil && cfg.GitLab == nil {
		t.Fatal("resolved starter should inherit provider sections from base")
	}
	var m map[interface{}]interface{}
	if err := yaml.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("starter is not valid yaml: %v", err)
	}
}

// TestRunConfigGenerate_OverlayFlagWritesMinimalStarter drives the
// configGenerateOverlay branch of runConfigGenerate: with the flag set, the
// command must write minimalOverlayStarter() rather than the full embedded
// default template (that path is already covered by
// TestConfigGenerateMatchesEmbeddedDefault in cmd/init_test.go).
func TestRunConfigGenerate_OverlayFlagWritesMinimalStarter(t *testing.T) {
	dir := t.TempDir()
	out := dir + "/gen.plumber.yaml"

	prevOut, prevForce, prevOverlay := configGenerateOutput, configGenerateForce, configGenerateOverlay
	configGenerateOutput, configGenerateForce, configGenerateOverlay = out, true, true
	defer func() {
		configGenerateOutput, configGenerateForce, configGenerateOverlay = prevOut, prevForce, prevOverlay
	}()

	if err := runConfigGenerate(nil, nil); err != nil {
		t.Fatalf("config generate --overlay: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read generated file: %v", err)
	}
	if string(got) != minimalOverlayStarter() {
		t.Errorf("config generate --overlay output does not match minimalOverlayStarter (%d vs %d bytes)",
			len(got), len(minimalOverlayStarter()))
	}
	if !strings.Contains(string(got), "extends: plumber:default") {
		t.Errorf("overlay output missing extends: plumber:default")
	}
	// A marker only the full embedded default template carries; the overlay
	// starter must never contain it.
	if strings.Contains(string(got), "This is the shipped DEFAULT baseline") {
		t.Errorf("overlay output should not contain full default template content")
	}
}
