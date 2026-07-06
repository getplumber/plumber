package control

import (
	"strings"
	"testing"
)

// TestSanitizeMarkdownInline guards the MR-comment neutralization: repo-derived
// finding text must not inject Markdown links/images or new lines into a
// comment posted with Plumber's identity.
func TestSanitizeMarkdownInline(t *testing.T) {
	t.Run("link syntax is escaped", func(t *testing.T) {
		got := sanitizeMarkdownInline("see [click me](http://evil.example)")
		// The bracket/paren glue that forms a Markdown link must be escaped,
		// so no raw "](" remains to render as a clickable link.
		if strings.Contains(got, "](") {
			t.Fatalf("link glue survived: %q", got)
		}
		if !strings.Contains(got, `\[`) || !strings.Contains(got, `\]`) {
			t.Fatalf("brackets not escaped: %q", got)
		}
	})

	t.Run("image syntax is escaped", func(t *testing.T) {
		got := sanitizeMarkdownInline("![x](http://tracker.example/p.png)")
		if strings.Contains(got, "](") {
			t.Fatalf("image glue survived: %q", got)
		}
	})

	t.Run("newlines and control chars are neutralized", func(t *testing.T) {
		got := sanitizeMarkdownInline("line1\n### injected heading\r\nline2\x00")
		if strings.ContainsAny(got, "\n\r\x00") {
			t.Fatalf("newline/control survived: %q", got)
		}
	})

	t.Run("emphasis is escaped", func(t *testing.T) {
		got := sanitizeMarkdownInline("a *b* _c_ `d`")
		if !strings.Contains(got, `\*`) || !strings.Contains(got, `\_`) || !strings.Contains(got, "\\`") {
			t.Fatalf("emphasis/code not escaped: %q", got)
		}
	})

	t.Run("mention and reference chars are escaped", func(t *testing.T) {
		got := sanitizeMarkdownInline("ping @all see #123 and !45 for 50% $x")
		for _, sub := range []string{`\@`, `\#`, `\!`, `\%`, `\$`} {
			if !strings.Contains(got, sub) {
				t.Fatalf("expected %q escaped in %q", sub, got)
			}
		}
	})

	t.Run("plain text is preserved verbatim", func(t *testing.T) {
		in := "Job build uses a mutable tag"
		if got := sanitizeMarkdownInline(in); got != in {
			t.Fatalf("plain text altered: %q -> %q", in, got)
		}
	})
}
