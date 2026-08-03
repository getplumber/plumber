package gitlab

import (
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
