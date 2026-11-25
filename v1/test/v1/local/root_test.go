//go:build cli

package local

import "testing"

// TestRoot covers the top-level commands (help and version) and the unknown
// command error.
func TestRoot(t *testing.T) {
	t.Parallel()
	tests := []cliCase{
		{name: "help", args: []string{"help"}},
		{name: "unknown-command", args: []string{"bogus"}},
		{name: "version", args: []string{"version"}},
		{name: "version-flag-unsupported", args: []string{"--version"}},
		{name: "version-json", args: []string{"version", "--json"}},
		{name: "version-short", args: []string{"version", "--short"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			runCase(t, tt)
		})
	}
}
