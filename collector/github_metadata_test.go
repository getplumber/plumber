package collector

import (
	"testing"

	version "github.com/hashicorp/go-version"
)

// Test_versionInRange locks the ISSUE-703 range-filter semantics.
// The scenario comes from a real-world false positive: the codeql-
// action pinned at v4.35.1 was flagged for GHSA-vqf5-2xx6-9wfm
// whose range covers `>= 3.26.11, <= 3.28.2` and `>= 2.26.11, <
// 3.0.0`. A strict semver check keeps v4.35.1 out of either range
// and silences the false positive.
func Test_versionInRange(t *testing.T) {
	cases := []struct {
		ver, rng string
		want     bool
	}{
		{"3.28.2", ">= 3.26.11, <= 3.28.2", true},  // upper bound inclusive
		{"3.28.3", ">= 3.26.11, <= 3.28.2", false}, // past upper bound
		{"3.26.10", ">= 3.26.11, <= 3.28.2", false},
		{"4.35.1", ">= 3.26.11, <= 3.28.2", false}, // real-world regression
		{"2.30.0", ">= 2.26.11, < 3.0.0", true},
		{"3.0.0", ">= 2.26.11, < 3.0.0", false},
		// Empty / unparseable ranges degrade to "affects everything"
		// so a broken advisory never silences a real CVE.
		{"1.0.0", "", true},
		{"1.0.0", "nonsense-range", true},
	}
	for _, c := range cases {
		v, err := version.NewVersion(c.ver)
		if err != nil {
			t.Fatalf("version parse %q: %v", c.ver, err)
		}
		got := _versionInRange(v, c.rng)
		if got != c.want {
			t.Errorf("_versionInRange(%q, %q) = %v, want %v", c.ver, c.rng, got, c.want)
		}
	}
}

// Test_moreSpecificTag locks the SHA-collision tie-break: when one
// commit carries both a moving major alias and the exact release tag,
// the advisory range filter must resolve to the exact release so the
// alias ("v4" -> 4.0.0) cannot drag the ref into a vulnerable range.
func Test_moreSpecificTag(t *testing.T) {
	cases := []struct {
		a, b, want string
	}{
		{"v4", "v4.3.0", "v4.3.0"},     // exact release beats major alias
		{"v4.3.0", "v4", "v4.3.0"},     // order-independent
		{"v44", "v44.0.0", "v44.0.0"},  // alias vs exact, no patch segment
		{"v4.3.0", "latest", "v4.3.0"}, // semver beats non-semver
		{"latest", "v4.3.0", "v4.3.0"},
		{"v4.3.0", "v4.3.1", "v4.3.1"}, // same precision -> higher version
	}
	for _, c := range cases {
		if got := _moreSpecificTag(c.a, c.b); got != c.want {
			t.Errorf("_moreSpecificTag(%q, %q) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
}

// Test_resolveRefToVersion_commitSHA is the ISSUE-703 regression for a
// commit SHA that starts with a digit. hashicorp/go-version parses
// "2d756ea…" as 2.0.0-d756ea…; resolveRefToVersion must take the SHA
// branch instead of returning that bogus value, otherwise every
// advisory for the action is silently dropped. The client is offline
// (see TestMain), so the SHA simply resolves to no tag -> nil.
func Test_resolveRefToVersion_commitSHA(t *testing.T) {
	c := NewGitHubMetadataClient()
	sha := "2d756ea4c53f7f6b397767d8723b3a10a9f35bf2"
	if v := c.resolveRefToVersion("tj-actions", "changed-files", sha); v != nil {
		t.Errorf("resolveRefToVersion(%s) = %v, want nil (SHA must not parse as semver)", sha, v)
	}
	if v := c.resolveRefToVersion("actions", "download-artifact", "v4.3.0"); v == nil || v.String() != "4.3.0" {
		t.Errorf("resolveRefToVersion(v4.3.0) = %v, want 4.3.0", v)
	}
}

// Test_partialTagBounds locks the moving-tag recognition: only bare
// major (`v4`) and major.minor (`v4.1`) tags resolve to a span;
// exact tags, SHAs and non-semver refs do not.
func Test_partialTagBounds(t *testing.T) {
	cases := []struct {
		ref               string
		wantOK            bool
		wantFloor, wantHi string
	}{
		{"v4", true, "4.0.0", "4.999999.999999"},
		{"4", true, "4.0.0", "4.999999.999999"},
		{"v44", true, "44.0.0", "44.999999.999999"},
		{"v4.1", true, "4.1.0", "4.1.999999"},
		{"v4.1.0", false, "", ""}, // exact version — not a moving tag
		{"main", false, "", ""},
		{"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", false, "", ""},
	}
	for _, c := range cases {
		floor, ceil, ok := _partialTagBounds(c.ref)
		if ok != c.wantOK {
			t.Errorf("_partialTagBounds(%q) ok = %v, want %v", c.ref, ok, c.wantOK)
			continue
		}
		if !ok {
			continue
		}
		wantFloor, _ := version.NewVersion(c.wantFloor)
		wantHi, _ := version.NewVersion(c.wantHi)
		if !floor.Equal(wantFloor) || !ceil.Equal(wantHi) {
			t.Errorf("_partialTagBounds(%q) = (%s, %s), want (%s, %s)", c.ref, floor, ceil, c.wantFloor, c.wantHi)
		}
	}
}

// Test_refCoveredByRange is the ISSUE-195 regression: a moving major /
// major.minor tag is reported for an advisory only when the whole span
// it floats across is vulnerable, while exact pins keep the plain
// single-version semantics.
func Test_refCoveredByRange(t *testing.T) {
	cases := []struct {
		ref, rng, ver string
		want          bool
	}{
		// Moving tags — partial: flagged only if the whole series is vulnerable.
		{"v4", ">= 4.0.0, < 4.1.3", "", false},   // download-artifact@v4 vs GHSA-cxww — the FP this fixes
		{"v44", "<= 45.0.7", "", true},           // all of v44.x is vulnerable
		{"v4.1", ">= 4.0.0, < 4.1.3", "", false}, // moving minor tag — only 4.1.0-4.1.2 affected
		{"v5", ">= 5, < 6.4.0", "", true},        // all of v5.x is vulnerable
		// Exact pins / resolved SHAs — single-version check, unchanged.
		{"v4.1.0", ">= 4.0.0, < 4.1.3", "4.1.0", true},  // exact in-range pin still fires
		{"v4.3.0", ">= 4.0.0, < 4.1.3", "4.3.0", false}, // exact out-of-range stays silent
	}
	for _, c := range cases {
		var rv *version.Version
		if c.ver != "" {
			rv, _ = version.NewVersion(c.ver)
		}
		got := _refCoveredByRange(c.ref, rv, c.rng)
		if got != c.want {
			t.Errorf("_refCoveredByRange(%q, %q) = %v, want %v", c.ref, c.rng, got, c.want)
		}
	}
}
