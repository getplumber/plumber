package gitlab

import (
	"testing"
)

func TestSplitComponentPath(t *testing.T) {
	cases := []struct{ in, project, component string }{
		// Nested-group third-party component (#156).
		{"RadianDevCore/tools/pre-commit-crocodile/commits", "RadianDevCore/tools/pre-commit-crocodile", "commits"},
		// GitLab built-in.
		{"components/secret-detection/secret-detection", "components/secret-detection", "secret-detection"},
		// Single segment (degenerate).
		{"foo", "", "foo"},
	}
	for _, c := range cases {
		p, comp := splitComponentPath(c.in)
		if p != c.project || comp != c.component {
			t.Errorf("splitComponentPath(%q) = (%q,%q), want (%q,%q)", c.in, p, comp, c.project, c.component)
		}
	}
}

func TestLatestSemver(t *testing.T) {
	if got := latestSemver([]string{"8.2.0", "8.2.1", "8.1.0"}); got != "8.2.1" {
		t.Errorf("got %q want 8.2.1", got)
	}
	// Numeric, not lexicographic: 10 > 9.
	if got := latestSemver([]string{"9.0.0", "10.0.0", "1.0.0"}); got != "10.0.0" {
		t.Errorf("got %q want 10.0.0 (numeric ordering)", got)
	}
	if got := latestSemver(nil); got != "" {
		t.Errorf("empty input: got %q want \"\"", got)
	}
	// Input slice must not be mutated (we sort a copy).
	in := []string{"8.2.0", "8.2.1"}
	_ = latestSemver(in)
	if in[0] != "8.2.0" {
		t.Errorf("input was mutated: %v", in)
	}
}

func TestLatestCatalogVersion(t *testing.T) {
	res := &CICatalogResource{Versions: []CICatalogResourceVersion{
		{Name: "8.2.1", Components: []CIComponent{{Name: "commits"}}},
		{Name: "8.2.0", Components: []CIComponent{{Name: "commits"}}},
		{Name: "8.1.0", Components: []CIComponent{{Name: "commits"}}},
	}}
	if got := latestCatalogVersion(res, "commits"); got != "8.2.1" {
		t.Errorf("got %q want 8.2.1", got)
	}
	// Component absent everywhere -> "".
	if got := latestCatalogVersion(res, "nope"); got != "" {
		t.Errorf("absent component: got %q want \"\"", got)
	}
	// Component removed in the newest release -> latest version that still has it.
	removed := &CICatalogResource{Versions: []CICatalogResourceVersion{
		{Name: "8.2.1", Components: []CIComponent{{Name: "other"}}},
		{Name: "8.2.0", Components: []CIComponent{{Name: "commits"}}},
	}}
	if got := latestCatalogVersion(removed, "commits"); got != "8.2.0" {
		t.Errorf("removed-in-latest: got %q want 8.2.0", got)
	}
	if got := latestCatalogVersion(nil, "commits"); got != "" {
		t.Errorf("nil resource: got %q want \"\"", got)
	}
}
