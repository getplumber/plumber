package ir

import "testing"

// TestActionName pins the name a `uses:` reference resolves to: owner and
// repository lower-cased, the subpath as written, the ref dropped.
func TestActionName(t *testing.T) {
	for _, tc := range []struct{ uses, want string }{
		{"actions/checkout@v4", "actions/checkout"},
		{"Actions/Checkout@v4", "actions/checkout"},
		{"Actions/Cache/Restore@v4", "actions/cache/Restore"},
		{"github/codeql-action/init@v3", "github/codeql-action/init"},
		{"MyOrg/Repo", "myorg/repo"},
		{"docker", "docker"},
		{"", ""},
	} {
		if got := ActionName(tc.uses); got != tc.want {
			t.Errorf("ActionName(%q) = %q, want %q", tc.uses, got, tc.want)
		}
	}
}
