//go:build cli

package test

import "testing"

// TestCompletion covers the completion script of every shell, with and
// without descriptions.
func TestCompletion(t *testing.T) {
	t.Parallel()
	tests := []cliCase{
		{name: "completion", args: []string{"completion"}},
		{name: "completion-bash", args: []string{"completion", "bash"}},
		{name: "completion-zsh", args: []string{"completion", "zsh"}},
		{name: "completion-fish", args: []string{"completion", "fish"}},
		{name: "completion-powershell", args: []string{"completion", "powershell"}},
		{name: "completion-bash-no-descriptions", args: []string{"completion", "bash", "--no-descriptions"}},
		{name: "completion-zsh-no-descriptions", args: []string{"completion", "zsh", "--no-descriptions"}},
		{name: "completion-fish-no-descriptions", args: []string{"completion", "fish", "--no-descriptions"}},
		{name: "completion-powershell-no-descriptions", args: []string{"completion", "powershell", "--no-descriptions"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			runCase(t, tt)
		})
	}
}
