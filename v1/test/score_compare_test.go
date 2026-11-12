//go:build cli

package test

import "testing"

// TestScoreCompare covers score-compare, a hidden command.
func TestScoreCompare(t *testing.T) {
	t.Parallel()
	tests := []cliCase{
		{
			name:   "score-compare",
			args:   []string{"score-compare", "--input", "score-compare"},
			inputs: []string{"score-compare"},
		},
		{
			name:        "score-compare-to-file",
			args:        []string{"score-compare", "--input", "score-compare", "--output", "report.md"},
			inputs:      []string{"score-compare"},
			outputFiles: []string{"report.md"},
		},
		{name: "score-compare-missing-input", args: []string{"score-compare"}, exit: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			runCase(t, tt)
		})
	}
}
