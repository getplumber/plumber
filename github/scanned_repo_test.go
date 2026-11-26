package github

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"

	"github.com/getplumber/plumber/internal/httpcount"
	"github.com/getplumber/plumber/internal/ir"
)

// productionScannedRepoGraphQL is the constructor the run uses, kept aside
// before init replaces it for every test.
var productionScannedRepoGraphQL = newScannedRepoGraphQL

// enterpriseHost is a GitHub Enterprise Server host. The tests that cover
// the REST reads of the scanned repository use it, since github.com reads
// them from the GraphQL query.
const enterpriseHost = "ghes.example.com"

// A test that reaches the scanned repository's query on github.com without
// stubbing it fails instead of querying GitHub.
func init() {
	// A retried query waits between tries; the tests keep the two retries
	// and drop the waits.
	unfinishedRetryDelays = []time.Duration{0, 0}
	newScannedRepoGraphQL = func(string) (*api.GraphQLClient, error) {
		return nil, errors.New("test: the scanned repository's GraphQL client is not stubbed")
	}
}

// resetScannedRepos forgets every answer the run kept.
func resetScannedRepos() {
	scannedRepos.Lock()
	defer scannedRepos.Unlock()
	scannedRepos.m = map[string]*scannedRepo{}
}

// swapScannedRepoGraphQL points the scanned-repository loader at gql and
// starts every test from an empty cache.
func swapScannedRepoGraphQL(t *testing.T, gql *api.GraphQLClient, err error) {
	t.Helper()
	orig := newScannedRepoGraphQL
	newScannedRepoGraphQL = func(string) (*api.GraphQLClient, error) { return gql, err }
	resetScannedRepos()
	t.Cleanup(func() {
		newScannedRepoGraphQL = orig
		resetScannedRepos()
	})
}

// restRecorder is a REST server that answers routes and records every path
// it was asked, so a test can assert which reads stayed on REST.
func restRecorder(t *testing.T, routes map[string]string) *[]string {
	t.Helper()
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		body, ok := routes[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	swapRESTClient(t, srv)
	return &paths
}

// acmeWidget is the answer of a private repository renamed to Acme/Widget,
// whose default branch main is protected by a classic rule, whose stable
// branch is protected by a ruleset only, and one of whose latest releases
// the github-actions bot published.
const acmeWidget = `{"data":{"repository":{
	"nameWithOwner":"Acme/Widget","visibility":"PRIVATE","isPrivate":true,
	"defaultBranchRef":{"name":"main","refUpdateRule":{"pattern":"main"},"rules":{"totalCount":0}},
	"b0":{"name":"stable","refUpdateRule":null,"rules":{"totalCount":1}},
	"b1":null,
	"b2":{"name":"feature","refUpdateRule":null,"rules":{"totalCount":0}},
	"releases":{"nodes":[{"author":{"login":"someone"}},{"author":{"login":"github-actions[bot]"}}]}
},"rateLimit":{"cost":1,"remaining":4999}}}`

// TestScannedRepo_OneQueryAnswersEveryRead: the default branch, the
// visibility, the canonical name, the existence and protected flag of each
// asked branch and the bot release all come from one query. Only the
// protection details of the protected branches stay on REST.
func TestScannedRepo_OneQueryAnswersEveryRead(t *testing.T) {
	gql, queries := stubbedGraphQL(t, func(graphQLRequest) (string, int) { return acmeWidget, 200 })
	swapScannedRepoGraphQL(t, gql, nil)
	paths := restRecorder(t, map[string]string{
		"/repos/acme/widget/branches/main/protection": `{"allow_force_pushes":{"enabled":true}}`,
		"/repos/acme/widget/rules/branches/main":      `[]`,
		"/repos/acme/widget/rules/branches/stable":    `[{"type":"pull_request","parameters":{"require_code_owner_review":true}}]`,
	})

	PrefetchScannedRepo("", "acme", "widget", []string{"stable", "gone", "feature"})

	if def, err := FetchGitHubDefaultBranch("", "acme", "widget"); def != "main" || err != nil {
		t.Errorf("default branch = %q, %v; want main", def, err)
	}
	if vis, name := FetchGitHubRepoIdentity("", "acme", "widget"); vis != ir.VisibilityPrivate || name != "Acme/Widget" {
		t.Errorf("identity = %q, %q; want private, Acme/Widget", vis, name)
	}
	if visible, err := GitHubRepoVisible("", "acme", "widget"); !visible || err != nil {
		t.Errorf("visible = %v, %v; want true", visible, err)
	}
	if !defaultTokenFromEffect("", "acme", "widget") {
		t.Error("a release by github-actions[bot] must prove the effect route")
	}
	branches, err := FetchGitHubBranchProtection("", "acme", "widget", BranchFetchOptions{
		ExactNames: []string{"stable", "gone", "feature", "main"},
	})
	if err != nil {
		t.Fatalf("branch protection: %v", err)
	}
	want := []ir.Branch{
		{Name: "stable", Protected: true, CodeOwnerApprovalRequired: true, ProtectionDetailsKnown: true},
		{Name: "feature"},
		{Name: "main", Protected: true, AllowForcePush: true, ProtectionDetailsKnown: true},
	}
	if !reflect.DeepEqual(branches, want) {
		t.Errorf("branches = %+v\nwant %+v", branches, want)
	}
	if len(*queries) != 1 {
		t.Fatalf("sent %d queries, want 1", len(*queries))
	}
	wantREST := []string{
		"/repos/acme/widget/branches/stable/protection",
		"/repos/acme/widget/rules/branches/stable",
		"/repos/acme/widget/branches/main/protection",
		"/repos/acme/widget/rules/branches/main",
	}
	if !reflect.DeepEqual(*paths, wantREST) {
		t.Errorf("REST paths = %v\nwant %v", *paths, wantREST)
	}
}

// TestScannedRepo_SendsValuesAsVariables: the owner, the name and each
// branch travel as variables, never in the query text.
func TestScannedRepo_SendsValuesAsVariables(t *testing.T) {
	gql, queries := stubbedGraphQL(t, func(graphQLRequest) (string, int) { return acmeWidget, 200 })
	swapScannedRepoGraphQL(t, gql, nil)

	PrefetchScannedRepo("", "acme", "widget", []string{"stable", "gone", "feature"})

	if len(*queries) != 1 {
		t.Fatalf("sent %d queries, want 1", len(*queries))
	}
	q := (*queries)[0]
	for _, v := range []string{"acme", "widget", "stable", "gone", "feature"} {
		if strings.Contains(q.Query, v) {
			t.Errorf("query text carries %q:\n%s", v, q.Query)
		}
	}
	wantVars := map[string]any{
		"owner": "acme", "name": "widget",
		"b0": "refs/heads/stable", "b1": "refs/heads/gone", "b2": "refs/heads/feature",
		"releases": float64(defaultTokenRunsPerPage),
	}
	if !reflect.DeepEqual(q.Variables, wantVars) {
		t.Errorf("variables = %v\nwant %v", q.Variables, wantVars)
	}
	if !strings.Contains(q.Query, "rateLimit") {
		t.Error("the query must ask for its cost")
	}
}

// TestScannedRepo_ReadsLoadOnFirstUse: a read with no prefetch sends the
// query itself, once, and a branch the prefetch did not ask costs one more
// query for the missing names only.
func TestScannedRepo_ReadsLoadOnFirstUse(t *testing.T) {
	gql, queries := stubbedGraphQL(t, func(q graphQLRequest) (string, int) {
		if _, ok := q.Variables["b0"]; ok {
			return `{"data":{"repository":{"b0":{"name":"dev","refUpdateRule":null,"rules":{"totalCount":0}}}}}`, 200
		}
		return acmeWidget, 200
	})
	swapScannedRepoGraphQL(t, gql, nil)
	restRecorder(t, nil)

	if def, _ := FetchGitHubDefaultBranch("", "acme", "widget"); def != "main" {
		t.Errorf("default branch = %q, want main", def)
	}
	if vis, _ := FetchGitHubRepoIdentity("", "acme", "widget"); vis != ir.VisibilityPrivate {
		t.Errorf("visibility = %q", vis)
	}
	if len(*queries) != 1 {
		t.Fatalf("sent %d queries before the branch read, want 1", len(*queries))
	}
	branches, err := FetchGitHubBranchProtection("", "acme", "widget", BranchFetchOptions{ExactNames: []string{"dev"}})
	if err != nil || len(branches) != 1 || branches[0].Name != "dev" || branches[0].Protected {
		t.Fatalf("branches = %+v, %v; want dev, unprotected", branches, err)
	}
	if len(*queries) != 2 {
		t.Fatalf("sent %d queries, want 2", len(*queries))
	}
	if got := (*queries)[1].Variables; got["b0"] != "refs/heads/dev" || got["b1"] != nil {
		t.Errorf("second query variables = %v, want dev only", got)
	}
}

// TestScannedRepo_LaterBranchQueryFails: a branch a later read asks costs
// one more query, and that query can fail as a whole. The branch is then
// unverified, never absent: a 500 is an error, as REST's was, and a 401
// the quiet degrade. What the first query answered stays.
func TestScannedRepo_LaterBranchQueryFails(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		wantErr bool
	}{
		{"server error", 500, true},
		{"unauthorized", 401, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gql, queries := stubbedGraphQL(t, func(q graphQLRequest) (string, int) {
				if _, later := q.Variables["releases"]; !later {
					return `{"message":"no"}`, tc.status
				}
				return acmeWidget, 200
			})
			swapScannedRepoGraphQL(t, gql, nil)
			restRecorder(t, nil)

			if def, _ := FetchGitHubDefaultBranch("", "acme", "widget"); def != "main" {
				t.Fatalf("default branch = %q, want main", def)
			}
			sent := len(*queries)
			branches, err := FetchGitHubBranchProtection("", "acme", "widget", BranchFetchOptions{ExactNames: []string{"dev"}})
			if len(*queries) == sent {
				t.Fatal("the branch read sent no query")
			}
			if len(branches) != 0 {
				t.Errorf("branches = %+v, want none", branches)
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, want an error: %v", err, tc.wantErr)
			}
			scannedRepos.Lock()
			fact := scannedRepos.m["|acme/widget"].branches["dev"]
			scannedRepos.Unlock()
			if fact.err == nil {
				t.Errorf("dev = %+v, want the query's error kept: an unread branch is not an absent one", fact)
			}
			// The first answer is still read.
			if vis, _ := FetchGitHubRepoIdentity("", "acme", "widget"); vis != ir.VisibilityPrivate {
				t.Errorf("visibility = %q, want private", vis)
			}
		})
	}
}

// TestScannedRepo_NotFound: a repository GitHub answers null for reads as
// REST's 404 did: no default branch and no error, unknown visibility, not
// visible, and no branches.
func TestScannedRepo_NotFound(t *testing.T) {
	gql, _ := stubbedGraphQL(t, func(graphQLRequest) (string, int) {
		return `{"data":{"repository":null},"errors":[{"type":"NOT_FOUND","path":["repository"],"message":"Could not resolve to a Repository with the name 'acme/widget'."}]}`, 200
	})
	swapScannedRepoGraphQL(t, gql, nil)
	restRecorder(t, nil)

	if def, err := FetchGitHubDefaultBranch("", "acme", "widget"); def != "" || err != nil {
		t.Errorf("default branch = %q, %v; want empty, nil", def, err)
	}
	if vis, name := FetchGitHubRepoIdentity("", "acme", "widget"); vis != ir.VisibilityUnknown || name != "" {
		t.Errorf("identity = %q, %q; want unknown", vis, name)
	}
	if visible, err := GitHubRepoVisible("", "acme", "widget"); visible || err != nil {
		t.Errorf("visible = %v, %v; want false, nil", visible, err)
	}
	if branches, err := FetchGitHubBranchProtection("", "acme", "widget", BranchFetchOptions{ExactNames: []string{"main"}}); len(branches) != 0 || err != nil {
		t.Errorf("branches = %+v, %v; want none", branches, err)
	}
	if defaultTokenFromEffect("", "acme", "widget") {
		t.Error("an unreadable repository proves nothing")
	}
}

// TestScannedRepo_Forbidden: a repository the token may name but not read
// (SAML SSO, missing scope), which GraphQL answers FORBIDDEN, reads as REST's
// 403 did: a quiet degrade, never an error. No default branch, unknown
// visibility, not visible, and no branches.
func TestScannedRepo_Forbidden(t *testing.T) {
	gql, _ := stubbedGraphQL(t, func(graphQLRequest) (string, int) {
		return `{"data":{"repository":null},"errors":[{"type":"FORBIDDEN","path":["repository"],"message":"Resource protected by organization SAML enforcement."}]}`, 200
	})
	swapScannedRepoGraphQL(t, gql, nil)
	restRecorder(t, nil)

	if def, err := FetchGitHubDefaultBranch("", "acme", "widget"); def != "" || err != nil {
		t.Errorf("default branch = %q, %v; want empty, nil", def, err)
	}
	if vis, name := FetchGitHubRepoIdentity("", "acme", "widget"); vis != ir.VisibilityUnknown || name != "" {
		t.Errorf("identity = %q, %q; want unknown", vis, name)
	}
	if visible, err := GitHubRepoVisible("", "acme", "widget"); visible || err != nil {
		t.Errorf("visible = %v, %v; want false, nil", visible, err)
	}
	if branches, err := FetchGitHubBranchProtection("", "acme", "widget", BranchFetchOptions{ExactNames: []string{"main"}}); branches != nil || err != nil {
		t.Errorf("branches = %+v, %v; want nil, nil", branches, err)
	}
}

// TestScannedRepo_FailedQuery: a query that fails as a whole keeps each
// read's REST contract for the same status. A 401 reads like REST's 401
// (quiet degrade); a 500 surfaces as an error where REST's did.
func TestScannedRepo_FailedQuery(t *testing.T) {
	t.Run("unauthorized", func(t *testing.T) {
		gql, _ := stubbedGraphQL(t, func(graphQLRequest) (string, int) { return `{"message":"Bad credentials"}`, 401 })
		swapScannedRepoGraphQL(t, gql, nil)
		restRecorder(t, nil)
		if def, err := FetchGitHubDefaultBranch("", "acme", "widget"); def != "" || err != nil {
			t.Errorf("default branch = %q, %v; want empty, nil", def, err)
		}
		if visible, err := GitHubRepoVisible("", "acme", "widget"); visible || err != nil {
			t.Errorf("visible = %v, %v; want false, nil", visible, err)
		}
		if branches, err := FetchGitHubBranchProtection("", "acme", "widget", BranchFetchOptions{ExactNames: []string{"main"}}); branches != nil || err != nil {
			t.Errorf("branches = %+v, %v; want nil, nil", branches, err)
		}
	})
	t.Run("server error", func(t *testing.T) {
		gql, _ := stubbedGraphQL(t, func(graphQLRequest) (string, int) { return `oops`, 500 })
		swapScannedRepoGraphQL(t, gql, nil)
		restRecorder(t, nil)
		if _, err := FetchGitHubDefaultBranch("", "acme", "widget"); err == nil {
			t.Error("default branch: want an error")
		}
		if _, err := GitHubRepoVisible("", "acme", "widget"); err == nil {
			t.Error("visible: want an error")
		}
		if _, err := FetchGitHubBranchProtection("", "acme", "widget", BranchFetchOptions{ExactNames: []string{"main"}}); err == nil {
			t.Error("branch protection: want an error")
		}
		if vis, _ := FetchGitHubRepoIdentity("", "acme", "widget"); vis != ir.VisibilityUnknown {
			t.Errorf("visibility = %q, want unknown", vis)
		}
	})
	t.Run("branch alias failed", func(t *testing.T) {
		gql, _ := stubbedGraphQL(t, func(graphQLRequest) (string, int) {
			return `{"data":{"repository":{"nameWithOwner":"acme/widget","visibility":"PUBLIC","defaultBranchRef":null,"b0":null,"releases":{"nodes":[]}}},"errors":[{"type":"INTERNAL","path":["repository","b0"],"message":"timeout"}]}`, 200
		})
		swapScannedRepoGraphQL(t, gql, nil)
		restRecorder(t, nil)
		if _, err := FetchGitHubBranchProtection("", "acme", "widget", BranchFetchOptions{ExactNames: []string{"main"}}); err == nil {
			t.Error("a branch GitHub could not answer must not read as absent")
		}
		if vis, _ := FetchGitHubRepoIdentity("", "acme", "widget"); vis != ir.VisibilityPublic {
			t.Errorf("visibility = %q, want public", vis)
		}
	})
}

// TestScannedRepo_NoToken: without a token the reads fail as the REST
// client did, with ErrAuthRequired.
func TestScannedRepo_NoToken(t *testing.T) {
	swapScannedRepoGraphQL(t, nil, ErrAuthRequired)
	restRecorder(t, nil)
	if _, err := FetchGitHubDefaultBranch("", "acme", "widget"); err != ErrAuthRequired {
		t.Errorf("default branch error = %v, want ErrAuthRequired", err)
	}
}

// TestScannedRepo_EnterpriseStaysOnREST: on GitHub Enterprise Server the
// reads keep their REST requests and no query is sent.
func TestScannedRepo_EnterpriseStaysOnREST(t *testing.T) {
	gql, queries := stubbedGraphQL(t, func(graphQLRequest) (string, int) { return acmeWidget, 200 })
	swapScannedRepoGraphQL(t, gql, nil)
	paths := restRecorder(t, map[string]string{"/repos/acme/widget": `{"default_branch":"trunk"}`})

	PrefetchScannedRepo("ghes.example.com", "acme", "widget", []string{"main"})
	if def, _ := FetchGitHubDefaultBranch("ghes.example.com", "acme", "widget"); def != "trunk" {
		t.Errorf("default branch = %q, want trunk", def)
	}
	if len(*queries) != 0 {
		t.Errorf("sent %d queries on GHES, want 0", len(*queries))
	}
	if len(*paths) != 1 {
		t.Errorf("REST paths = %v, want the repository read", *paths)
	}
}

// TestScannedRepo_RetriesAQueryGitHubCouldNotFinish: one 5xx must not cost
// the run the default branch, the visibility, the identity, the branch
// protection and the bot release together. The query cannot be made
// smaller, so it is sent again, and the reads get the answer.
//
// The same holds for a timeout GitHub answers as a 200 with an error.
func TestScannedRepo_RetriesAQueryGitHubCouldNotFinish(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"502", `bad gateway`, 502},
		{"timeout answered 200", timeoutBody, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := true
			gql, queries := stubbedGraphQL(t, func(graphQLRequest) (string, int) {
				if first {
					first = false
					return tc.body, tc.status
				}
				return acmeWidget, 200
			})
			swapScannedRepoGraphQL(t, gql, nil)
			restRecorder(t, nil)

			if def, err := FetchGitHubDefaultBranch("", "acme", "widget"); def != "main" || err != nil {
				t.Errorf("default branch = %q, %v; want main, nil", def, err)
			}
			if vis, _ := FetchGitHubRepoIdentity("", "acme", "widget"); vis != ir.VisibilityPrivate {
				t.Errorf("visibility = %q, want private", vis)
			}
			if len(*queries) != 2 {
				t.Errorf("sent %d queries, want 2 (the failure, then the retry)", len(*queries))
			}
		})
	}
}

// TestScannedRepo_RetriesAreBounded: a query GitHub keeps failing is sent
// once plus one time per retry delay, then the failure is kept for the run
// and the reads report it. An error that is not a 5xx or a timeout (here a
// 401, and a rate limit answered as a 200) is never sent again.
func TestScannedRepo_RetriesAreBounded(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		status int
		want   int
	}{
		{"server error", `{"message":"no"}`, 500, 1 + len(unfinishedRetryDelays)},
		{"timeout answered 200", timeoutBody, 200, 1 + len(unfinishedRetryDelays)},
		{"unauthorized", `{"message":"no"}`, 401, 1},
		{"rate limited", rateLimited, 200, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gql, queries := stubbedGraphQL(t, func(graphQLRequest) (string, int) { return tc.body, tc.status })
			swapScannedRepoGraphQL(t, gql, nil)
			restRecorder(t, nil)
			_, _ = FetchGitHubDefaultBranch("", "acme", "widget")
			_, _ = GitHubRepoVisible("", "acme", "widget")
			if len(*queries) != tc.want {
				t.Errorf("sent %d queries, want %d", len(*queries), tc.want)
			}
		})
	}
}

// TestScannedRepo_FieldErrorIsNotAnAnswer: an error GitHub ties to one of
// the repository's own fields must not read as that field's empty value.
// An unread default branch is not "no default branch" (which would turn
// defaultMustBeProtected into a silent no-op), unread releases are not "no
// bot release", and a repository nulled by a field's error is not "not
// found". REST failed the matching request in each case.
func TestScannedRepo_FieldErrorIsNotAnAnswer(t *testing.T) {
	t.Run("default branch", func(t *testing.T) {
		gql, _ := stubbedGraphQL(t, func(graphQLRequest) (string, int) {
			return `{"data":{"repository":{"nameWithOwner":"acme/widget","visibility":"PUBLIC","isPrivate":false,"defaultBranchRef":null,"releases":{"nodes":[{"author":{"login":"github-actions[bot]"}}]}}},"errors":[{"path":["repository","defaultBranchRef","rules"],"message":"timeout"}]}`, 200
		})
		swapScannedRepoGraphQL(t, gql, nil)
		restRecorder(t, nil)
		if def, err := FetchGitHubDefaultBranch("", "acme", "widget"); def != "" || err == nil || !strings.Contains(err.Error(), "timeout") {
			t.Errorf("default branch = %q, %v; want GitHub's error", def, err)
		}
		// The fields GitHub did answer are still read.
		if vis, name := FetchGitHubRepoIdentity("", "acme", "widget"); vis != ir.VisibilityPublic || name != "acme/widget" {
			t.Errorf("identity = %q, %q; want public, acme/widget", vis, name)
		}
		if visible, err := GitHubRepoVisible("", "acme", "widget"); !visible || err != nil {
			t.Errorf("visible = %v, %v; want true", visible, err)
		}
		if !defaultTokenFromEffect("", "acme", "widget") {
			t.Error("the releases were answered: the bot release must be read")
		}
	})
	t.Run("releases", func(t *testing.T) {
		gql, _ := stubbedGraphQL(t, func(graphQLRequest) (string, int) {
			return `{"data":{"repository":{"nameWithOwner":"acme/widget","visibility":"PUBLIC","isPrivate":false,"defaultBranchRef":{"name":"main","refUpdateRule":null,"rules":{"totalCount":0}},"releases":null}},"errors":[{"path":["repository","releases"],"message":"releases timed out"}]}`, 200
		})
		swapScannedRepoGraphQL(t, gql, nil)
		restRecorder(t, nil)
		hook := logtest.NewGlobal()
		origLevel := logrus.GetLevel()
		logrus.SetLevel(logrus.DebugLevel)
		t.Cleanup(func() {
			logrus.SetLevel(origLevel)
			hook.Reset()
		})
		if defaultTokenFromEffect("", "acme", "widget") {
			t.Error("unread releases must not prove the effect route")
		}
		logged := false
		for _, e := range hook.AllEntries() {
			if strings.Contains(e.Message, "releases timed out") {
				logged = true
			}
		}
		if !logged {
			t.Error("the releases GitHub could not answer must be logged, not read as no bot release")
		}
		if def, err := FetchGitHubDefaultBranch("", "acme", "widget"); def != "main" || err != nil {
			t.Errorf("default branch = %q, %v; want main", def, err)
		}
	})
	t.Run("field error nulls the repository", func(t *testing.T) {
		gql, _ := stubbedGraphQL(t, func(graphQLRequest) (string, int) {
			return `{"data":{"repository":null},"errors":[{"path":["repository","releases"],"message":"releases timed out"}]}`, 200
		})
		swapScannedRepoGraphQL(t, gql, nil)
		restRecorder(t, nil)
		if visible, err := GitHubRepoVisible("", "acme", "widget"); visible || err == nil {
			t.Errorf("visible = %v, %v; want an error, not a repository that does not exist", visible, err)
		}
		if _, err := FetchGitHubDefaultBranch("", "acme", "widget"); err == nil {
			t.Error("default branch: want an error, not the quiet degrade of a missing repository")
		}
	})
}

// TestNewScannedRepoGraphQL runs the constructor the tests replace. The
// scanned repository is read with the run's own token, never
// PLUMBER_METADATA_TOKEN: that token alone is no token (ErrAuthRequired).
// With one, the client sends it through httpcount.DefaultTransport, which
// counts the query and never answers it from memory.
func TestNewScannedRepoGraphQL(t *testing.T) {
	isolate := func(t *testing.T) {
		t.Helper()
		for _, env := range []string{EnvMetadataToken, "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GH_HOST"} {
			t.Setenv(env, "")
		}
		t.Setenv("GH_CONFIG_DIR", t.TempDir())
		t.Setenv("GH_PATH", filepath.Join(t.TempDir(), "no-gh")) // no keyring login through `gh auth token`
	}
	t.Run("the metadata token alone is no token", func(t *testing.T) {
		isolate(t)
		t.Setenv(EnvMetadataToken, "ghp_metadata")
		if gql, err := productionScannedRepoGraphQL(""); gql != nil || err != ErrAuthRequired {
			t.Fatalf("client = %v, err = %v; want ErrAuthRequired", gql, err)
		}
	})
	t.Run("sends the run's token through the counting transport", func(t *testing.T) {
		isolate(t)
		t.Setenv("GH_TOKEN", "ghp_scan")
		t.Setenv(EnvMetadataToken, "ghp_metadata")
		var got []*http.Request
		orig := httpcount.DefaultTransport
		httpcount.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			got = append(got, r)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"data":{}}`)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Request:    r,
			}, nil
		})
		t.Cleanup(func() { httpcount.DefaultTransport = orig })

		gql, err := productionScannedRepoGraphQL("")
		if err != nil || gql == nil {
			t.Fatalf("client = %v, err = %v; want a client", gql, err)
		}
		var data map[string]json.RawMessage
		if err := gql.Do("{ viewer { login } }", nil, &data); err != nil {
			t.Fatalf("query: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("httpcount.DefaultTransport saw %d requests, want the query", len(got))
		}
		if auth := got[0].Header.Get("Authorization"); auth != "token ghp_scan" {
			t.Errorf("Authorization = %q, want the run's token, never the metadata token", auth)
		}
		if host := got[0].URL.Host; host != "api.github.com" {
			t.Errorf("host = %q, want api.github.com", host)
		}
	})
}

// TestPrefetchScannedRepo_NeedsOwnerAndRepo: with no owner or no
// repository there is nothing to ask, so no query is sent.
func TestPrefetchScannedRepo_NeedsOwnerAndRepo(t *testing.T) {
	gql, queries := stubbedGraphQL(t, func(graphQLRequest) (string, int) { return acmeWidget, 200 })
	swapScannedRepoGraphQL(t, gql, nil)

	PrefetchScannedRepo("", "", "widget", []string{"main"})
	PrefetchScannedRepo("", "acme", "", []string{"main"})
	if len(*queries) != 0 {
		t.Errorf("sent %d queries, want 0", len(*queries))
	}
	scannedRepos.Lock()
	kept := len(scannedRepos.m)
	scannedRepos.Unlock()
	if kept != 0 {
		t.Errorf("kept %d answers, want none", kept)
	}
}

// TestScannedRepo_AsksEachBranchOnce: an empty name and a repeated one
// cost no alias of their own.
func TestScannedRepo_AsksEachBranchOnce(t *testing.T) {
	gql, queries := stubbedGraphQL(t, func(graphQLRequest) (string, int) {
		return `{"data":{"repository":{"nameWithOwner":"acme/widget","b0":{"name":"dev","refUpdateRule":null,"rules":{"totalCount":0}},"b1":null}}}`, 200
	})
	swapScannedRepoGraphQL(t, gql, nil)

	PrefetchScannedRepo("", "acme", "widget", []string{"", "dev", "dev", "gone", ""})

	if len(*queries) != 1 {
		t.Fatalf("sent %d queries, want 1", len(*queries))
	}
	wantVars := map[string]any{
		"owner": "acme", "name": "widget",
		"b0": "refs/heads/dev", "b1": "refs/heads/gone",
		"releases": float64(defaultTokenRunsPerPage),
	}
	if got := (*queries)[0].Variables; !reflect.DeepEqual(got, wantVars) {
		t.Errorf("variables = %v\nwant %v", got, wantVars)
	}
	scannedRepos.Lock()
	branches := scannedRepos.m["|acme/widget"].branches
	scannedRepos.Unlock()
	want := map[string]branchFact{"dev": {exists: true}, "gone": {}}
	if !reflect.DeepEqual(branches, want) {
		t.Errorf("branches = %+v, want %+v", branches, want)
	}
}

// TestScannedRepo_LaterBranchClientFails: a branch a later read asks needs
// the GraphQL client again. Without one the read fails with the client's
// error, and what the first query answered stays.
func TestScannedRepo_LaterBranchClientFails(t *testing.T) {
	gql, queries := stubbedGraphQL(t, func(graphQLRequest) (string, int) { return acmeWidget, 200 })
	swapScannedRepoGraphQL(t, gql, nil)
	restRecorder(t, nil)

	if def, _ := FetchGitHubDefaultBranch("", "acme", "widget"); def != "main" {
		t.Fatalf("default branch = %q, want main", def)
	}
	// swapScannedRepoGraphQL's cleanup restores the constructor.
	newScannedRepoGraphQL = func(string) (*api.GraphQLClient, error) { return nil, errors.New("boom") }

	branches, err := FetchGitHubBranchProtection("", "acme", "widget", BranchFetchOptions{ExactNames: []string{"dev"}})
	if len(branches) != 0 || err == nil || !strings.Contains(err.Error(), "github graphql client: boom") {
		t.Errorf("branches = %+v, err = %v; want the client's error", branches, err)
	}
	if len(*queries) != 1 {
		t.Errorf("sent %d queries, want the first one only", len(*queries))
	}
	// A read that asks no new branch needs no client.
	if vis, name := FetchGitHubRepoIdentity("", "acme", "widget"); vis != ir.VisibilityPrivate || name != "Acme/Widget" {
		t.Errorf("identity = %q, %q; want the first answer", vis, name)
	}
}

// TestScannedRepo_LaterBranchQueryNotFound: the repository can be gone by
// the time a later read asks one more branch. That branch then reads as
// REST's 404 did, no branch and no error, and the first answer stays.
func TestScannedRepo_LaterBranchQueryNotFound(t *testing.T) {
	gql, queries := stubbedGraphQL(t, func(q graphQLRequest) (string, int) {
		if _, first := q.Variables["releases"]; !first {
			return `{"data":{"repository":null},"errors":[{"type":"NOT_FOUND","path":["repository"],"message":"Could not resolve to a Repository"}]}`, 200
		}
		return acmeWidget, 200
	})
	swapScannedRepoGraphQL(t, gql, nil)
	restRecorder(t, nil)

	if def, _ := FetchGitHubDefaultBranch("", "acme", "widget"); def != "main" {
		t.Fatalf("default branch = %q, want main", def)
	}
	branches, err := FetchGitHubBranchProtection("", "acme", "widget", BranchFetchOptions{ExactNames: []string{"dev"}})
	if len(branches) != 0 || err != nil {
		t.Errorf("branches = %+v, err = %v; want none and no error", branches, err)
	}
	if len(*queries) != 2 {
		t.Errorf("sent %d queries, want 2", len(*queries))
	}
	scannedRepos.Lock()
	fact := scannedRepos.m["|acme/widget"].branches["dev"]
	scannedRepos.Unlock()
	if !errors.Is(fact.err, errRepoNotFound) {
		t.Errorf("dev = %+v, want the repository's not-found kept", fact)
	}
	if def, err := FetchGitHubDefaultBranch("", "acme", "widget"); def != "main" || err != nil {
		t.Errorf("default branch = %q, %v; want the first answer", def, err)
	}
}

// TestScannedRepoErrors reads a query's error into the aliases it fails
// and the error that spoils the whole repository.
func TestScannedRepoErrors(t *testing.T) {
	gqlErr := func(items ...api.GraphQLErrorItem) error { return &api.GraphQLError{Errors: items} }
	item := func(typ, message string, path ...any) api.GraphQLErrorItem {
		return api.GraphQLErrorItem{Type: typ, Message: message, Path: path}
	}
	plain := errors.New("HTTP 502")
	unknownType := gqlErr(item("INTERNAL", "boom", "repository"))
	noPath := gqlErr(item("RATE_LIMITED", "slow down"))
	elsewhere := gqlErr(item("", "cost unavailable", "rateLimit"))
	for _, tc := range []struct {
		name       string
		err        error
		wantFailed map[string]string
		wantErr    error
	}{
		{name: "no error"},
		{name: "not a GraphQL error", err: plain, wantErr: plain},
		{name: "repository not found", err: gqlErr(item("NOT_FOUND", "gone", "repository")), wantErr: errRepoNotFound},
		{name: "repository forbidden", err: gqlErr(item("FORBIDDEN", "sso", "repository")), wantErr: errRepoForbidden},
		{name: "repository error of another type", err: unknownType, wantErr: unknownType},
		{name: "error with no path", err: noPath, wantErr: noPath},
		{name: "error outside the repository", err: elsewhere, wantErr: elsewhere},
		{
			name: "aliases, the first error of each kept",
			err: gqlErr(
				item("", "b0 first", "repository", "b0", "rules"),
				item("", "b0 second", "repository", "b0"),
				item("", "releases timed out", "repository", "releases"),
			),
			wantFailed: map[string]string{"b0": "b0 first", "releases": "releases timed out"},
		},
		{
			// The repository's own error wins over an alias's.
			name:    "alias error then repository not found",
			err:     gqlErr(item("", "b0 failed", "repository", "b0"), item("NOT_FOUND", "gone", "repository")),
			wantErr: errRepoNotFound,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			failed, err := scannedRepoErrors(tc.err)
			if err != tc.wantErr {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
			got := map[string]string{}
			for alias, ferr := range failed {
				got[alias] = ferr.Error()
			}
			if len(got) != len(tc.wantFailed) || (len(got) > 0 && !reflect.DeepEqual(got, tc.wantFailed)) {
				t.Errorf("failed = %v, want %v", got, tc.wantFailed)
			}
		})
	}
}

// TestNullRepositoryError: a repository GitHub answers null for does not
// exist, unless a field's error nulled it. With several failed fields the
// error is the alphabetically first one's, the same on every run.
func TestNullRepositoryError(t *testing.T) {
	if err := nullRepositoryError(nil); err != errRepoNotFound {
		t.Errorf("no failed field: err = %v, want errRepoNotFound", err)
	}
	if err := nullRepositoryError(map[string]error{}); err != errRepoNotFound {
		t.Errorf("empty failed fields: err = %v, want errRepoNotFound", err)
	}
	releases, def, branch := errors.New("releases"), errors.New("default branch"), errors.New("branch")
	for range 20 { // map order must not pick the error
		if err := nullRepositoryError(map[string]error{"releases": releases, "defaultBranchRef": def, "b0": branch}); err != branch {
			t.Fatalf("err = %v, want b0's, the alphabetically first alias", err)
		}
	}
}

// TestScannedRepo_SeveralFieldErrorsNullTheRepository: a repository nulled
// by errors on two of its fields reports one of them, the same on every
// run, and never reads as a repository that does not exist.
func TestScannedRepo_SeveralFieldErrorsNullTheRepository(t *testing.T) {
	gql, _ := stubbedGraphQL(t, func(graphQLRequest) (string, int) {
		return `{"data":{"repository":null},"errors":[{"path":["repository","releases"],"message":"releases timed out"},{"path":["repository","defaultBranchRef"],"message":"default branch timed out"}]}`, 200
	})
	swapScannedRepoGraphQL(t, gql, nil)
	restRecorder(t, nil)
	if visible, err := GitHubRepoVisible("", "acme", "widget"); visible || err == nil || err.Error() != "default branch timed out" {
		t.Errorf("visible = %v, %v; want the default branch's error", visible, err)
	}
}

// TestScannedRepo_DecodesPartialFields: a release whose author GitHub no
// longer knows (a deleted account) does not hide the bot release after it,
// a default branch protected by a ruleset alone is protected, and a
// default branch with no name is no default branch.
func TestScannedRepo_DecodesPartialFields(t *testing.T) {
	t.Run("null author and ruleset-only default branch", func(t *testing.T) {
		gql, _ := stubbedGraphQL(t, func(graphQLRequest) (string, int) {
			return `{"data":{"repository":{"nameWithOwner":"acme/widget","visibility":"PUBLIC","isPrivate":false,
				"defaultBranchRef":{"name":"main","refUpdateRule":null,"rules":{"totalCount":1}},
				"releases":{"nodes":[{"author":null},{"author":{"login":"github-actions[bot]"}}]}}}}`, 200
		})
		swapScannedRepoGraphQL(t, gql, nil)
		restRecorder(t, map[string]string{"/repos/acme/widget/rules/branches/main": `[]`})

		if !defaultTokenFromEffect("", "acme", "widget") {
			t.Error("a release with no author must not hide the bot release after it")
		}
		branches, err := FetchGitHubBranchProtection("", "acme", "widget", BranchFetchOptions{ExactNames: []string{"main"}})
		if err != nil || len(branches) != 1 || branches[0].Name != "main" || !branches[0].Protected {
			t.Errorf("branches = %+v, %v; want main protected by its ruleset", branches, err)
		}
	})
	t.Run("no bot release", func(t *testing.T) {
		gql, _ := stubbedGraphQL(t, func(graphQLRequest) (string, int) {
			return `{"data":{"repository":{"nameWithOwner":"acme/widget","visibility":"PUBLIC","isPrivate":false,
				"defaultBranchRef":{"name":"main","refUpdateRule":null,"rules":{"totalCount":0}},
				"releases":{"nodes":[{"author":null},{"author":{"login":"someone"}}]}}}}`, 200
		})
		swapScannedRepoGraphQL(t, gql, nil)
		restRecorder(t, nil)
		if defaultTokenFromEffect("", "acme", "widget") {
			t.Error("no release by github-actions[bot]: the effect route proves nothing")
		}
	})
	t.Run("default branch with no name", func(t *testing.T) {
		gql, _ := stubbedGraphQL(t, func(graphQLRequest) (string, int) {
			return `{"data":{"repository":{"nameWithOwner":"acme/widget","visibility":"PUBLIC","isPrivate":false,
				"defaultBranchRef":{"name":"","refUpdateRule":{"pattern":"*"},"rules":{"totalCount":0}},
				"releases":{"nodes":[]}}}}`, 200
		})
		swapScannedRepoGraphQL(t, gql, nil)
		restRecorder(t, nil)
		if def, err := FetchGitHubDefaultBranch("", "acme", "widget"); def != "" || err != nil {
			t.Errorf("default branch = %q, %v; want none", def, err)
		}
		scannedRepos.Lock()
		branches := scannedRepos.m["|acme/widget"].branches
		scannedRepos.Unlock()
		if len(branches) != 0 {
			t.Errorf("branches = %+v, want no branch kept under an empty name", branches)
		}
	})
}

// TestScannedRepoBranch_NotAsked: a branch the query did not ask has no
// answer. Reading it is an error, never a branch that does not exist.
func TestScannedRepoBranch_NotAsked(t *testing.T) {
	r := &scannedRepo{branches: map[string]branchFact{"main": {exists: true}}}
	b, err := r.branch(nil, "acme", "widget", "dev")
	if b != nil || err == nil || !strings.Contains(err.Error(), `branch "dev" was not asked`) {
		t.Errorf("branch = %+v, err = %v; want the not-asked error", b, err)
	}
	if b, err := r.branch(nil, "acme", "widget", "main"); err != nil || b == nil || b.Name != "main" || b.Protected {
		t.Errorf("branch = %+v, err = %v; want main, unprotected", b, err)
	}
}

// TestScannedRepo_RecordsTheQueryCost: the scanned repository's query asks
// for its cost and keeps it for the --debug report.
func TestScannedRepo_RecordsTheQueryCost(t *testing.T) {
	gql, _ := stubbedGraphQL(t, func(graphQLRequest) (string, int) { return acmeWidget, 200 })
	swapScannedRepoGraphQL(t, gql, nil)
	before := len(httpcount.Default.Snapshot().GraphQL)

	PrefetchScannedRepo("", "acme", "widget", nil)

	want := []httpcount.GraphQLQuery{{Label: "scanned repository", Cost: 1, Remaining: 4999}}
	if got := graphQLCostsSince(before); !reflect.DeepEqual(got, want) {
		t.Errorf("recorded costs = %+v, want %+v", got, want)
	}
}
