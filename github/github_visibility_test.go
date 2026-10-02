package github

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// TestFetchGitHubRepoVisibility covers the full status matrix:
// public/private repos resolve from the `private` field, and every
// failure mode (no auth, not found, server error) degrades to unknown
// rather than surfacing an error -- FetchGitHubRepoVisibility never
// returns one.
func TestFetchGitHubRepoVisibility(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"public repo", 200, `{"default_branch":"main","private":false}`, ir.VisibilityPublic},
		{"private repo", 200, `{"default_branch":"main","private":true}`, ir.VisibilityPrivate},
		{"no token", 401, `{"message":"Requires authentication"}`, ir.VisibilityUnknown},
		{"not found", 404, `{"message":"Not Found"}`, ir.VisibilityUnknown},
		{"server error", 500, `oops`, ir.VisibilityUnknown},
		{"internal repo", 200, `{"default_branch":"main","private":false,"visibility":"internal"}`, ir.VisibilityPrivate},
		{"visibility wins over private", 200, `{"private":true,"visibility":"public"}`, ir.VisibilityPublic},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/repos/acme/widget" {
					t.Errorf("path = %s", r.URL.Path)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			// Reuses the swapRESTClient helper from
			// github_branch_protection_test.go (same package): it
			// already overrides the newGitHubRESTClient seam with a
			// client pointed at the httptest server and restores it
			// via t.Cleanup.
			swapRESTClient(t, srv)
			if got := FetchGitHubRepoVisibility("github.com", "acme", "widget"); got != tc.want {
				t.Errorf("visibility = %q, want %q", got, tc.want)
			}
		})
	}
}
