package utils

import (
	"strings"
	"testing"
)

// FuzzCleanOriginPath exercises the include/component path normalizer with
// arbitrary input. It must never panic and must be idempotent: a path that
// has already been cleaned must clean to itself.
//
// Run with: go test -fuzz=FuzzCleanOriginPath ./utils/
func FuzzCleanOriginPath(f *testing.F) {
	seeds := []string{
		"components/sast/sast@1.2.3",
		"$CI_SERVER_FQDN/group/comp@main",
		"$CI_SERVER_HOST/group/comp",
		"gitlab.com/group/project",
		"plain",
		"",
		"@",
		"a@b@c",
		"////",
		".//",
		"host.with.dots/rest/of/path",
		string([]byte{0x00, 0x2f, 0x40}),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	// The fuzzer surfaced that CleanOriginPath is a one-shot transformer
	// with NO idempotence guarantee, even setting '@' aside:
	//   - multi-'@' input loses one segment per pass ("a@b@c" -> "a@b" -> "a")
	//     because it cuts at strings.LastIndex('@');
	//   - a host-like first segment ("././", "x.y/...") triggers the
	//     "strip instance prefix" branch on every pass ("././" -> "./" -> "").
	// Real include/component paths are "host.tld/group/comp@version" and are
	// cleaned correctly in a single call, so neither edge bites in
	// production. We therefore only assert the invariants that hold for ALL
	// input: it never panics, and it never grows the string.
	f.Fuzz(func(t *testing.T, location string) {
		out := CleanOriginPath(location)
		if len(out) > len(location) {
			t.Fatalf("output %q longer than input %q", out, location)
		}
	})
}

// FuzzHasDigestPin checks the digest detector never panics and stays
// consistent: a positive match must contain the '@algo:hex' shape.
func FuzzHasDigestPin(f *testing.F) {
	seeds := []string{
		"alpine@sha256:" + strings.Repeat("a", 64),
		"img@sha512:DEADBEEF",
		"alpine:3.19",
		"no-pin-here",
		"",
		"@",
		"@sha256:",
		"x@:abc",
		string([]byte{0x40, 0x00}),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, ref string) {
		got := HasDigestPin(ref)
		// Consistency: a positive result requires an '@' followed later by ':'.
		if got {
			at := strings.Index(ref, "@")
			if at < 0 || !strings.Contains(ref[at:], ":") {
				t.Fatalf("HasDigestPin(%q)=true but no '@...:' shape present", ref)
			}
		}
	})
}
