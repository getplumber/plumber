package cmd

import "testing"

// The progress bar redraws in place with `\r`, which only a real
// terminal can render — a CI job log or a pipe shows every frame as a
// separate line, drowning the output (#309). The bar therefore
// requires all three: human output enabled (--print), not verbose
// (debug logs replace the bar), and a terminal on stderr.
func TestShouldShowProgress(t *testing.T) {
	cases := []struct {
		name                         string
		printOutput, verbose, isTerm bool
		want                         bool
	}{
		{"terminal quiet run shows the bar", true, false, true, true},
		{"non-TTY (CI log, pipe) never shows the bar", true, false, false, false},
		{"verbose replaces the bar with debug logs", true, true, true, false},
		{"print=false disables all human output", false, false, true, false},
		{"print=false non-TTY stays silent", false, false, false, false},
		{"verbose on non-TTY stays bar-free", true, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldShowProgress(tc.printOutput, tc.verbose, tc.isTerm); got != tc.want {
				t.Errorf("shouldShowProgress(%v, %v, %v) = %v, want %v",
					tc.printOutput, tc.verbose, tc.isTerm, got, tc.want)
			}
		})
	}
}
