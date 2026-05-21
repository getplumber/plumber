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
