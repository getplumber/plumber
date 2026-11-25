//go:build cli

package local

import "testing"

// TestHelpFlag has a --help row for every command, so a flag the refactoring
// drops or renames shows up in a golden diff. Add a row for each new command.
func TestHelpFlag(t *testing.T) {
	t.Parallel()
	tests := []cliCase{
		{name: "help-flag", args: []string{"--help"}},
		{name: "help-flag-help", args: []string{"help", "--help"}},
		{name: "help-flag-version", args: []string{"version", "--help"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			runCase(t, tt)
		})
	}
}
