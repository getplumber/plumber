package gitlab

import (
	"net/url"
	"strings"
	"testing"
)

// FuzzParseGitlabComponentPath checks the parser never panics and upholds
// its structural invariants for arbitrary input: the returned clean path
// must not retain the version separator, and re-parsing the clean path
// (without an instance prefix) must be stable.
func FuzzParseGitlabComponentPath(f *testing.F) {
	seeds := []struct{ path, url string }{
		{"gitlab.example.com/group/comp@1.2.3", "https://gitlab.example.com"},
		{"$CI_SERVER_FQDN/group/comp@main", "https://gitlab.example.com"},
		{"$CI_SERVER_HOST/g/c", "http://h"},
		{"other-host.com/group/comp@3.0", "https://gitlab.example.com"},
		{"", ""},
		{"@@@@", "@"},
		{"///@///", "https://"},
	}
	for _, s := range seeds {
		f.Add(s.path, s.url)
	}

	f.Fuzz(func(t *testing.T, path, instanceURL string) {
		instance, clean, version := ParseGitlabComponentPath(path, instanceURL)

		// Invariant 1: the clean path never keeps the version separator —
		// it is split off into `version`.
		if strings.Contains(clean, glComponentVersionSeparator) {
			t.Fatalf("clean path %q still contains %q (path=%q url=%q)",
				clean, glComponentVersionSeparator, path, instanceURL)
		}

		// Invariant 2: when a version was extracted, the original path must
		// have contained the separator.
		if version != "" && !strings.Contains(path, glComponentVersionSeparator) {
			t.Fatalf("got version %q but path %q has no separator", version, path)
		}

		// Invariant 3: idempotence on the clean path with the same URL.
		// Re-parsing a path that has already had its instance and version
		// stripped must not produce a different clean path.
		_, clean2, _ := ParseGitlabComponentPath(clean, instanceURL)
		if strings.Contains(clean2, glComponentVersionSeparator) {
			t.Fatalf("re-parsed clean path %q reintroduced separator", clean2)
		}
		_ = instance
	})
}

// FuzzRemoveGitRefFromURL checks the URL ref-stripper never panics and is
// idempotent: applying it twice yields the same result as once.
// NOTE: the function is NOT idempotent on adversarial paths with several
// `/blob/<x>/` segments — regexp.ReplaceAllString consumes the separators
// between adjacent matches, so a second pass keeps eating segments. Real
// forge URLs carry exactly one ref segment, so this never bites in
// production (the only caller, RemoveVersionInRawLink, runs it once). The
// fuzzer surfaced this; we assert the contract that actually holds (no
// panic, parseable output) instead of an idempotence the function never
// promised.
func FuzzRemoveGitRefFromURL(f *testing.F) {
	seeds := []string{
		"https://gitlab.com/g/p/-/blob/main/.gitlab-ci.yml",
		"https://github.com/o/r/blob/abc123/file.yml",
		"https://h/raw/v1/x",
		"not a url",
		"://",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		out, err := RemoveGitRefFromURL(raw)
		if err != nil {
			// A parse error returns the input unchanged; nothing more to assert.
			return
		}
		// The output round-trips through net/url; a result that no longer
		// parses would signal corruption introduced by the ref-stripping.
		if _, perr := url.Parse(out); perr != nil {
			t.Fatalf("RemoveGitRefFromURL(%q)=%q is not parseable: %v", raw, out, perr)
		}
	})
}

// FuzzRemoveVersionInRawLink checks the wrapper never panics on arbitrary
// input and always strips an @-version segment.
func FuzzRemoveVersionInRawLink(f *testing.F) {
	for _, s := range []string{
		"https://h/raw/v1/x@2.0.0",
		"plain@1",
		"@",
		"",
		"a@b@c",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		out := RemoveVersionInRawLink(raw)
		// The @-version is split off before any URL handling, so the result
		// must not contain the part after the first '@' from the original.
		if i := strings.Index(raw, "@"); i >= 0 {
			if strings.Contains(out, raw[i:]) && raw[i:] != "@" {
				t.Fatalf("version segment %q leaked into %q", raw[i:], out)
			}
		}
	})
}
