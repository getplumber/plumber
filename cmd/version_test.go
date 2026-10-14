package cmd

import "testing"

// A `go install github.com/getplumber/plumber@latest` build gets no ldflags,
// so Version stays "dev" and the update check never runs for it. The module
// version Go stamps into the binary is the fallback; it is "(devel)" for a
// local `go build`, and must then leave the ldflags value alone.
func TestVersionFromBuildInfo(t *testing.T) {
	cases := []struct {
		name     string
		ldflags  string
		mainVer  string
		expected string
	}{
		{"release build keeps the ldflags version", "0.6.2", "v0.6.2", "0.6.2"},
		{"go install stamps the module version", "dev", "v0.6.2", "0.6.2"},
		{"go install of a pseudo-version", "dev", "v0.6.3-0.20261014120000-abcdef123456", "0.6.3-0.20261014120000-abcdef123456"},
		{"local go build stays dev", "dev", "(devel)", "dev"},
		{"no build info stays dev", "dev", "", "dev"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveVersion(tc.ldflags, tc.mainVer); got != tc.expected {
				t.Errorf("resolveVersion(%q, %q) = %q, want %q", tc.ldflags, tc.mainVer, got, tc.expected)
			}
		})
	}
}
