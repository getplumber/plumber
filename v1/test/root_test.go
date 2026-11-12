//go:build cli

package test

import "testing"

// TestRoot covers the top-level commands (help, version, catalog and
// capabilities) and the unknown command and flag errors.
func TestRoot(t *testing.T) {
	t.Parallel()
	tests := []cliCase{
		{name: "help", args: []string{"help"}},
		{name: "help-analyze", args: []string{"help", "analyze"}},
		{name: "unknown-command", args: []string{"bogus"}, exit: 2},
		{name: "unknown-flag", args: []string{"analyze", "--nope"}, exit: 2},
		{name: "version-flag-unsupported", args: []string{"--version"}, exit: 2},
		{name: "version", args: []string{"version"}},
		{name: "version-verbose", args: []string{"-v", "version"}},
		{name: "catalog", args: []string{"catalog"}},
		{name: "capabilities", args: []string{"capabilities"}},
		{name: "capabilities-defaults", args: []string{"capabilities", "defaults"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			runCase(t, tt)
		})
	}
}
