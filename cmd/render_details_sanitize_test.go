package cmd

import (
	"strings"
	"testing"
	"unicode"
)

// TestSanitizeTerminal guards the terminal-output neutralization: repo-derived
// finding text must not carry control/escape bytes into the operator's
// terminal, while ordinary text is left byte-for-byte unchanged.
func TestSanitizeTerminal(t *testing.T) {
	t.Run("plain text is unchanged", func(t *testing.T) {
		in := "Job 'build' uses image alpine:latest (mutable tag)"
		if got := sanitizeTerminal(in); got != in {
			t.Fatalf("plain text altered: %q -> %q", in, got)
		}
	})

	t.Run("tab becomes space", func(t *testing.T) {
		if got := sanitizeTerminal("a\tb"); got != "a b" {
			t.Fatalf("tab not normalized: %q", got)
		}
	})

	t.Run("escape sequences are stripped", func(t *testing.T) {
		// ANSI clear-screen, OSC hyperlink, and a bare ESC.
		in := "clean\x1b[2J\x1b]8;;http://evil\x07link\x1b"
		got := sanitizeTerminal(in)
		for _, r := range got {
			if unicode.IsControl(r) {
				t.Fatalf("control rune %U survived in %q", r, got)
			}
		}
		if !strings.HasPrefix(got, "clean") {
			t.Fatalf("legit text lost: %q", got)
		}
	})
}
