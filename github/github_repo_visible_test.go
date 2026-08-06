package github

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// GitHubRepoVisible is the probe that disambiguates a zero-branch fetch: a repo
// that is nonexistent, renamed, or invisible to the token returns no branches
// with no error, which would otherwise read as a clean branchMustBeProtected
// pass. Its contract is deliberately the opposite of FetchGitHubDefaultBranch,
// which folds 404/401 into a silent empty success, so these cases pin the
// distinction that the fix depends on.
func TestGitHubRepoVisible(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		wantVisible bool
		wantErr     bool
	}{
		{name: "200 means visible", status: http.StatusOK, wantVisible: true, wantErr: false},
		{name: "404 means not visible, not an error", status: http.StatusNotFound, wantVisible: false, wantErr: false},
		{name: "401 means not visible, not an error", status: http.StatusUnauthorized, wantVisible: false, wantErr: false},
		{name: "500 is an error, not a verdict", status: http.StatusInternalServerError, wantVisible: false, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				if tc.status == http.StatusOK {
					_, _ = w.Write([]byte(`{"default_branch":"main"}`))
				}
			}))
			defer server.Close()
			swapRESTClient(t, server)

			visible, err := GitHubRepoVisible("", "owner", "repo")
			if visible != tc.wantVisible {
				t.Errorf("visible = %v, want %v", visible, tc.wantVisible)
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
