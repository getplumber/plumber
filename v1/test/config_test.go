//go:build cli

package test

import "testing"

// TestConfig covers the config subcommands: generate, init, view, validate,
// resolve, diff, slim and migrate.
func TestConfig(t *testing.T) {
	t.Parallel()
	// Input files under testdata/inputs.
	const (
		overlay = "overlay.plumber.yaml"
		warning = "warning.plumber.yaml"
		legacy  = "legacy.plumber.yaml"
		invalid = "invalid.plumber.yaml"
	)
	// generateFull writes a full config for the slim rows.
	generateFull := [][]string{{"config", "generate", "-o", "full.yaml"}}
	tests := []cliCase{
		{name: "config", args: []string{"config"}},

		// generate.
		{name: "config-generate", args: []string{"config", "generate"}, outputFiles: []string{".plumber.yaml"}},
		{
			name:        "config-generate-overlay",
			args:        []string{"config", "generate", "--overlay", "-o", "overlay.yaml"},
			outputFiles: []string{"overlay.yaml"},
		},
		{
			name:  "config-generate-exists",
			args:  []string{"config", "generate"},
			setup: [][]string{{"config", "generate"}},
		},
		{
			name:  "config-generate-force",
			args:  []string{"config", "generate", "--force", "--output", "custom.yaml"},
			setup: [][]string{{"config", "generate", "-o", "custom.yaml"}},
		},
		{
			name:  "config-generate-force-short",
			args:  []string{"config", "generate", "-f"},
			setup: [][]string{{"config", "generate"}},
		},

		// init needs a terminal, so every row stops before the prompt.
		{name: "config-init-no-terminal", args: []string{"config", "init"}},
		{name: "config-init-force-output", args: []string{"config", "init", "--force", "--output", "x.yaml"}},
		{name: "config-init-short-flags", args: []string{"config", "init", "-f", "-o", "x.yaml"}},

		// view.
		{name: "config-view-default-file", args: []string{"config", "view"}, setup: [][]string{{"config", "generate"}}},
		{name: "config-view-no-file", args: []string{"config", "view"}},
		{name: "config-view-overlay", args: []string{"config", "view", "-c", overlay}, inputs: []string{overlay}},
		{
			name:   "config-view-explain",
			args:   []string{"config", "view", "--config", overlay, "--explain"},
			inputs: []string{overlay},
			// Provenance lines come out of a map in random order (cmd/config_explain.go).
			sortLines: true,
		},
		{
			name:   "config-view-no-color",
			args:   []string{"config", "view", "-c", overlay, "--no-color"},
			inputs: []string{overlay},
		},

		// validate.
		{name: "config-validate-ok", args: []string{"config", "validate", "-c", overlay}, inputs: []string{overlay}},
		{
			name:   "config-validate-warning",
			args:   []string{"config", "validate", "--config", warning},
			inputs: []string{warning},
		},
		{
			name:   "config-validate-fail-warnings",
			args:   []string{"config", "validate", "-c", warning, "--fail-warnings"},
			inputs: []string{warning},
		},
		{name: "config-validate-legacy", args: []string{"config", "validate", "-c", legacy}, inputs: []string{legacy}},
		{
			name:   "config-validate-invalid-yaml",
			args:   []string{"config", "validate", "-c", invalid},
			inputs: []string{invalid},
		},
		{name: "config-validate-missing", args: []string{"config", "validate", "-c", "missing.yaml"}},

		// resolve.
		{name: "config-resolve", args: []string{"config", "resolve", "-c", overlay}, inputs: []string{overlay}},
		{
			name:        "config-resolve-to-file",
			args:        []string{"config", "resolve", "--config", overlay, "--output", "resolved.yaml"},
			inputs:      []string{overlay},
			outputFiles: []string{"resolved.yaml"},
		},
		{
			name:        "config-resolve-short-output",
			args:        []string{"config", "resolve", "-c", overlay, "-o", "resolved.yaml"},
			inputs:      []string{overlay},
			outputFiles: []string{"resolved.yaml"},
		},

		// diff.
		{name: "config-diff", args: []string{"config", "diff", "-c", overlay}, inputs: []string{overlay}},
		{
			name:   "config-diff-no-color",
			args:   []string{"config", "diff", "--config", overlay, "--no-color"},
			inputs: []string{overlay},
		},

		// slim.
		{name: "config-slim", args: []string{"config", "slim", "-c", "full.yaml"}, setup: generateFull},
		{
			name:        "config-slim-to-file",
			args:        []string{"config", "slim", "--config", "full.yaml", "--output", "slim.yaml"},
			setup:       generateFull,
			outputFiles: []string{"slim.yaml"},
		},
		{
			name:        "config-slim-short-output",
			args:        []string{"config", "slim", "-c", "full.yaml", "-o", "slim.yaml"},
			setup:       generateFull,
			outputFiles: []string{"slim.yaml"},
		},

		// migrate.
		{
			name:        "config-migrate",
			args:        []string{"config", "migrate", "--input", legacy},
			inputs:      []string{legacy},
			outputFiles: []string{legacy + ".v2"},
		},
		{
			name:        "config-migrate-output",
			args:        []string{"config", "migrate", "--input", legacy, "--output", "migrated.yaml"},
			inputs:      []string{legacy},
			outputFiles: []string{"migrated.yaml"},
		},
		{
			name:        "config-migrate-in-place",
			args:        []string{"config", "migrate", "--input", legacy, "--in-place"},
			inputs:      []string{legacy},
			outputFiles: []string{legacy, legacy + ".bak"},
		},
		{
			name:   "config-migrate-up-to-date",
			args:   []string{"config", "migrate", "--input", overlay},
			inputs: []string{overlay},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			runCase(t, tt)
		})
	}
}
