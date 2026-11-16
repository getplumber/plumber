//go:build cli

package test

import "testing"

// TestHelpFlag has a --help row for every command, so a flag the refactoring
// drops or renames shows up in a golden diff. Add a row for each new command.
func TestHelpFlag(t *testing.T) {
	t.Parallel()
	tests := []cliCase{
		{name: "help-flag", args: []string{"--help"}},
		{name: "help-flag-analyze", args: []string{"analyze", "--help"}},
		{name: "help-flag-capabilities", args: []string{"capabilities", "--help"}},
		{name: "help-flag-capabilities-defaults", args: []string{"capabilities", "defaults", "--help"}},
		{name: "help-flag-catalog", args: []string{"catalog", "--help"}},
		{name: "help-flag-completion", args: []string{"completion", "--help"}},
		{name: "help-flag-completion-bash", args: []string{"completion", "bash", "--help"}},
		{name: "help-flag-completion-fish", args: []string{"completion", "fish", "--help"}},
		{name: "help-flag-completion-powershell", args: []string{"completion", "powershell", "--help"}},
		{name: "help-flag-completion-zsh", args: []string{"completion", "zsh", "--help"}},
		{name: "help-flag-config", args: []string{"config", "--help"}},
		{name: "help-flag-config-diff", args: []string{"config", "diff", "--help"}},
		{name: "help-flag-config-generate", args: []string{"config", "generate", "--help"}},
		{name: "help-flag-config-init", args: []string{"config", "init", "--help"}},
		{name: "help-flag-config-migrate", args: []string{"config", "migrate", "--help"}},
		{name: "help-flag-config-resolve", args: []string{"config", "resolve", "--help"}},
		{name: "help-flag-config-slim", args: []string{"config", "slim", "--help"}},
		{name: "help-flag-config-validate", args: []string{"config", "validate", "--help"}},
		{name: "help-flag-config-view", args: []string{"config", "view", "--help"}},
		{name: "help-flag-explain", args: []string{"explain", "--help"}},
		{name: "help-flag-help", args: []string{"help", "--help"}},
		{name: "help-flag-score-compare", args: []string{"score-compare", "--help"}},
		{name: "help-flag-version", args: []string{"version", "--help"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			runCase(t, tt)
		})
	}
}
