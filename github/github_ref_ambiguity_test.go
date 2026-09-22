package github

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cli/go-gh/v2/pkg/api"
)

// newBranchProbeClient builds a metadata client whose /branches/{ref}
// endpoint answers with the given status and body; every other path 404s.
func newBranchProbeClient(t *testing.T, status int, body string) *GitHubMetadataClient {
	t.Helper()
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, s := `{"message":"Not Found"}`, http.StatusNotFound
		if strings.Contains(r.URL.Path, "/branches/") {
			b, s = body, status
		}
		return &http.Response{
			StatusCode: s,
			Body:       io.NopCloser(strings.NewReader(b)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})
	c := NewGitHubMetadataClientForHost("")
	rest, err := api.NewRESTClient(api.ClientOptions{AuthToken: "x", Transport: rt})
	if err != nil {
		t.Fatalf("new rest client: %v", err)
	}
	c.rest = rest
	return c
}

// Test_resolveUncached_renameRedirectIsNotAmbiguous drives the whole
// resolution for the exact #482 shape: `v2` is a tag upstream, and
// /branches/v2 answers 200 with the renamed "releases/v2". The ref must
// resolve as an unambiguous tag. The positive twin (a real branch named v2)
// keeps ISSUE-402's genuine case alive.
func Test_resolveUncached_renameRedirectIsNotAmbiguous(t *testing.T) {
	const (
		owner = "github"
		repo  = "codeql-action"
		sha   = "8dca8a82000000000000000000000000000000ab"
	)
	newClient := func(t *testing.T, branchBody string) *GitHubMetadataClient {
		rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			p := r.URL.Path
			body, status := `{"message":"Not Found"}`, http.StatusNotFound
			switch {
			case p == "/repos/"+owner+"/"+repo:
				body, status = `{"archived":false,"stargazers_count":0}`, http.StatusOK
			case strings.Contains(p, "/releases"):
				body, status = `[]`, http.StatusOK
			case strings.HasPrefix(p, "/advisories"):
				body, status = `[]`, http.StatusOK
			case strings.Contains(p, "/git/ref/tags/v2"):
				body, status = `{"object":{"sha":"`+sha+`","type":"commit"}}`, http.StatusOK
			case strings.Contains(p, "/branches/v2"):
				body, status = branchBody, http.StatusOK
			}
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
				Request:    r,
			}, nil
		})
		c := NewGitHubMetadataClientForHost("")
		rest, err := api.NewRESTClient(api.ClientOptions{AuthToken: "x", Transport: rt})
		if err != nil {
			t.Fatalf("new rest client: %v", err)
		}
		c.rest = rest
		return c
	}

	t.Run("redirect to the renamed branch: tag, not ambiguous", func(t *testing.T) {
		m := newClient(t, `{"name":"releases/v2","protected":false}`).resolveUncached(owner, repo, "v2")
		if m.RefKind != "tag" || !m.RefExists {
			t.Fatalf("v2 must resolve as an existing tag, got kind=%q exists=%v", m.RefKind, m.RefExists)
		}
		if m.RefIsAmbiguous {
			t.Fatal("a rename redirect must not make the tag ambiguous (#482, ISSUE-402 false positive)")
		}
	})
	t.Run("a real branch of the same name stays ambiguous", func(t *testing.T) {
		m := newClient(t, `{"name":"v2","protected":false}`).resolveUncached(owner, repo, "v2")
		if !m.RefIsAmbiguous {
			t.Fatal("a tag AND a branch both named v2 is the genuine ISSUE-402 case and must stay flagged")
		}
	})
}

// Test_branchExists_renameRedirectIsNotABranch is the #482 regression guard
// (ISSUE-402 false positive). GitHub keeps a renamed branch's old name as a
// redirect: GET /branches/v2 answers 200 with the RENAMED branch
// ("releases/v2"). A 200 alone is therefore not proof that a branch named
// v2 exists; only a 200 whose name equals the requested ref is.
func Test_branchExists_renameRedirectIsNotABranch(t *testing.T) {
	t.Run("exact name is a branch", func(t *testing.T) {
		c := newBranchProbeClient(t, http.StatusOK, `{"name":"v2","protected":false}`)
		if !c.branchExists("github", "codeql-action", "v2") {
			t.Fatal("a 200 whose name equals the ref IS a branch of that name")
		}
	})
	t.Run("rename redirect is not a branch of that name", func(t *testing.T) {
		c := newBranchProbeClient(t, http.StatusOK, `{"name":"releases/v2","protected":false}`)
		if c.branchExists("github", "codeql-action", "v2") {
			t.Fatal("a 200 carrying a different name is a rename redirect, not a branch named v2 (#482)")
		}
	})
	t.Run("404 is not a branch", func(t *testing.T) {
		c := newBranchProbeClient(t, http.StatusNotFound, `{"message":"Branch not found"}`)
		if c.branchExists("github", "codeql-action", "v3") {
			t.Fatal("404 must not read as a branch")
		}
	})
}
