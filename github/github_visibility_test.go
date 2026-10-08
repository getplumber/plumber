package github

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// TestFetchGitHubRepoIdentityVisibility covers the full status matrix of
// the visibility half of FetchGitHubRepoIdentity: public/private repos
// resolve from the `private` field, and every failure mode (no auth, not
// found, server error) degrades to unknown rather than surfacing an
// error, the lookup never returns one.
func TestFetchGitHubRepoIdentityVisibility(t *testing.T) {
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
			if got, _ := FetchGitHubRepoIdentity("github.com", "acme", "widget"); got != tc.want {
				t.Errorf("visibility = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestFetchGitHubRepoIdentity checks that the one repository lookup
// answers both the visibility and the canonical owner/repo GitHub
// returns for the repository: the API follows renames, so a repository
// asked for under its former name answers with its current one. Any
// failure leaves the full name empty, so the caller keeps the path it
// was given.
func TestFetchGitHubRepoIdentity(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantVis  string
		wantName string
	}{
		{"renamed repo", 200, `{"private":false,"full_name":"react/react"}`, ir.VisibilityPublic, "react/react"},
		{"case differs", 200, `{"private":true,"full_name":"Acme/Widget"}`, ir.VisibilityPrivate, "Acme/Widget"},
		{"no full name", 200, `{"private":false}`, ir.VisibilityPublic, ""},
		{"malformed full name", 200, `{"private":false,"full_name":"widget"}`, ir.VisibilityPublic, ""},
		{"not found", 404, `{"message":"Not Found"}`, ir.VisibilityUnknown, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/repos/acme/widget" {
					t.Errorf("path = %s", r.URL.Path)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			swapRESTClient(t, srv)
			vis, name := FetchGitHubRepoIdentity("github.com", "acme", "widget")
			if vis != tc.wantVis || name != tc.wantName {
				t.Errorf("identity = (%q, %q), want (%q, %q)", vis, name, tc.wantVis, tc.wantName)
			}
			if calls != 1 {
				t.Errorf("lookup made %d calls, want 1", calls)
			}
		})
	}
}
