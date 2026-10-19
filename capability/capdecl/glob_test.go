package capdecl

import (
	"strings"
	"testing"
	"time"
)

// Spec 4.3, the globs: `*` any run (a `/` included), `?` exactly one character (a rune),
// `[...]` a class with ranges, `[!...]` and `[^...]` its negation, a `]` first in the class
// literal, `\x` the character x; case-sensitive, on the whole subject.
func TestGlob_Spec43_Semantics(t *testing.T) {
	cases := []struct {
		pattern, subject string
		want             bool
	}{
		{"*gitleaks*", "gitleaks detect", true},
		{"*gitleaks*", "docker.io/zricethezav/gitleaks", true},
		{"*gitleaks*", "trufflehog filesystem .", false},
		{"gitleaks", "gitleaks", true},
		{"gitleaks", "gitleaks detect", false},
		{"gitleaks", "run gitleaks", false},
		{"*gitleaks*", "GITLEAKS detect", false},
		{"Jobs/Secret-Detection*", "Jobs/Secret-Detection.gitlab-ci.yml", true},
		{"*/secret-detection/*", "gitlab.com/components/secret-detection/secret-detection", true},
		{"a*c", "a/b/c", true},
		{"*", "", true},
		{"*", "a/b", true},
		{"", "", true},
		{"", "a", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"a?c", "abbc", false},
		{"a?c", "a/c", true},
		{"a?c", "aéc", true},
		{"??", "é", false},
		{"*é*", "café crème", true},
		{"[a-z]x", "bx", true},
		{"[a-z]x", "Bx", false},
		{"[a-cx-z]", "y", true},
		{"[a-cx-z]", "m", false},
		{"[!a]b", "cb", true},
		{"[!a]b", "ab", false},
		{"[^a]b", "cb", true},
		{"[^a]b", "ab", false},
		{"[]a]", "]", true},
		{"[]a]", "a", true},
		{"[]a]", "b", false},
		{"[!]a]", "]", false},
		{"[!]a]", "b", true},
		{"[-a]", "-", true},
		{"[a-]", "-", true},
		{"[é-ê]", "ê", true},
		{`\*`, "*", true},
		{`\*`, "a", false},
		{`\?`, "a", false},
		{`\[a]`, "[a]", true},
		{`a\\b`, `a\b`, true},
		{`\é`, "é", true},
		{"*b*a*a*", "xbyaza", true},
		{"*b*a*a*", "xbyaz", false},
		{"*ggshield*secret*", "ggshield secret scan ci", true},
		{"*ggshield*secret*", "ggshield scan ci", false},
	}
	for _, c := range cases {
		g, err := CompileGlob(c.pattern)
		if err != nil {
			t.Errorf("CompileGlob(%q): %v", c.pattern, err)
			continue
		}
		if got := g.Match(c.subject); got != c.want {
			t.Errorf("CompileGlob(%q).Match(%q) = %v, want %v", c.pattern, c.subject, got, c.want)
		}
	}
}

// Spec 4.3 and 4.6: the two syntax errors, the same two the platform's ValidGlob refuses at
// PUT: a class left unclosed and a trailing backslash. A backslash inside a class is a
// literal there (ValidGlob scans a class to its first `]` after the leading one).
func TestGlob_Spec43_SyntaxErrors(t *testing.T) {
	for _, p := range []string{"[abc", "a[", "[", "[]", "[!]", "[^]", `a\`, `\`, `[a]\`} {
		if _, err := CompileGlob(p); err == nil {
			t.Errorf("CompileGlob(%q) = nil error, want a syntax error", p)
		}
	}
	for _, p := range []string{"[]]", "[!]]", `[\]`, `\[`, "]", "a]b"} {
		if _, err := CompileGlob(p); err != nil {
			t.Errorf("CompileGlob(%q) = %v, want it valid", p, err)
		}
	}
}

// matchWithin fails t unless pattern matched against subject returns within 2 s.
func matchWithin(t *testing.T, pattern, subject string) bool {
	t.Helper()
	g, err := CompileGlob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	var got bool
	done := make(chan struct{})
	go func() { got = g.Match(subject); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("CompileGlob(%q).Match on a %d byte subject took over 2 s", pattern, len(subject))
	}
	return got
}

// Spec 4.3: a pattern comes from the user and a subject from any developer's script line,
// so a match is bounded by len(subject) * len(pattern), never exponential: patterns with
// several literal runs on 256 KiB subjects built to make a backtracker explode return well
// within 2 s.
func TestGlob_Spec43_AdversarialInputsAreBounded(t *testing.T) {
	const size = 256 << 10
	if matchWithin(t, "*b*a*a*", strings.Repeat("a", size)+"b") {
		t.Fatal(`"*b*a*a*" must not match a subject with no "a" after its only "b"`)
	}
	if matchWithin(t, "*ggshield*secret*", strings.Repeat("ggshield ", size/len("ggshield "))) {
		t.Fatal(`"*ggshield*secret*" must not match a line without "secret"`)
	}
	if matchWithin(t, "*a*a*a*a*a*a*a*a*", strings.Repeat("b", size)) {
		t.Fatal(`"*a*a*a*a*a*a*a*a*" must not match a subject without "a"`)
	}
}
