package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
)

// graphQLMetadataClient is a metadata client whose GraphQL queries go to
// respond; it has no REST client, so a REST read fails the test run with a
// nil dereference rather than reaching GitHub.
func graphQLMetadataClient(t *testing.T, respond func(graphQLRequest) (string, int)) (*GitHubMetadataClient, *[]graphQLRequest) {
	t.Helper()
	gql, got := stubbedGraphQL(t, respond)
	c := NewGitHubMetadataClientForHost("")
	c.disabled = false
	c.gql = gql
	c.rest = nil
	c.dotcom = true
	return c, got
}

// TestQueryRepos_SendsValuesAsVariables: the owner, the repository and the
// ref come from the scanned workflows, so they travel as variables and
// never in the query text.
func TestQueryRepos_SendsValuesAsVariables(t *testing.T) {
	c, got := graphQLMetadataClient(t, func(graphQLRequest) (string, int) {
		return `{"data":{}}`, 200
	})
	c.queryRepos([]repoRequest{{owner: "acme-corp", repo: "tool-x", info: true, advisories: true, refs: []string{"v1.2"}}})
	if len(*got) != 1 {
		t.Fatalf("queries = %d, want 1", len(*got))
	}
	q := (*got)[0]
	for _, v := range []string{"acme-corp", "tool-x", "v1.2"} {
		if strings.Contains(q.Query, v) {
			t.Errorf("query text carries %q:\n%s", v, q.Query)
		}
	}
	var values []string
	for _, v := range q.Variables {
		if s, ok := v.(string); ok {
			values = append(values, s)
		}
	}
	for _, want := range []string{"acme-corp", "tool-x", "refs/tags/v1.2", "refs/heads/v1.2", "v1.2", "acme-corp/tool-x"} {
		if !slices.Contains(values, want) {
			t.Errorf("variables %v lack %q", values, want)
		}
	}
}

// TestQueryRepos_ObjectLookupFollowsTheRefShape: a full SHA is looked up
// by oid (lower-cased, GitHub keys objects by the exact SHA), a plain name
// by expression, and a ref outside the plain-name grammar is not looked up
// at all, since an expression would read another object than the ref.
func TestQueryRepos_ObjectLookupFollowsTheRefShape(t *testing.T) {
	c, got := graphQLMetadataClient(t, func(graphQLRequest) (string, int) {
		return `{"data":{}}`, 200
	})
	sha := strings.Repeat("AB", 20)
	c.queryRepos([]repoRequest{{owner: "o", repo: "r", refs: []string{sha, "main", "v1@{0}"}}})
	q := (*got)[0]
	if !strings.Contains(q.Query, "object(oid: $x0_0)") {
		t.Errorf("SHA not looked up by oid:\n%s", q.Query)
	}
	if q.Variables["x0_0"] != strings.ToLower(sha) {
		t.Errorf("oid variable = %v, want the lower-cased SHA", q.Variables["x0_0"])
	}
	if !strings.Contains(q.Query, "object(expression: $x0_1)") {
		t.Errorf("plain name not looked up by expression:\n%s", q.Query)
	}
	if _, ok := q.Variables["x0_2"]; ok || strings.Contains(q.Query, "$x0_2") {
		t.Errorf("a ref outside the grammar was looked up as an object:\n%s", q.Query)
	}
}

const decodeAnswer = `{"data":{
 "rateLimit":{"cost":1,"remaining":4990},
 "r0":{
  "nameWithOwner":"new-owner/tool","isArchived":true,"stargazerCount":42,
  "releases":{"nodes":[
    {"tagName":"v2.0.0","isDraft":false,"isPrerelease":false},
    {"tagName":"v3.0.0-rc1","isDraft":false,"isPrerelease":true}
  ],"pageInfo":{"hasNextPage":false,"endCursor":"x"}},
  "t0":{"target":{"__typename":"Tag","oid":"tagobj","target":{"__typename":"Commit","oid":"c200"}}},
  "h0":{"name":"v2.0.0"},
  "x0":{"__typename":"Tag","oid":"tagobj","target":{"__typename":"Commit","oid":"c200"}},
  "l0":{"immutable":true},
  "t1":null,"h1":null,"x1":null,"l1":null
 },
 "a0":{"nodes":[
  {"advisory":{"ghsaId":"GHSA-1","severity":"MODERATE"},"package":{"name":"old-owner/tool"},"vulnerableVersionRange":"< 2.0.0","firstPatchedVersion":{"identifier":"2.0.0"}},
  {"advisory":{"ghsaId":"GHSA-2","severity":"CRITICAL"},"package":{"name":"someone/else"},"vulnerableVersionRange":"< 1","firstPatchedVersion":null}
 ]}
}}`

// TestQueryRepos_DecodesTheAnswer: one answer fills every cache the
// lookups read.
func TestQueryRepos_DecodesTheAnswer(t *testing.T) {
	c, _ := graphQLMetadataClient(t, func(graphQLRequest) (string, int) { return decodeAnswer, 200 })
	missing := strings.Repeat("e", 40)
	c.queryRepos([]repoRequest{{owner: "old-owner", repo: "tool", info: true, advisories: true, refs: []string{"v2.0.0", missing}}})

	info := c.repoCache["old-owner/tool"]
	if !info.fetched || info.err != nil || !info.archived || info.stars != 42 || info.fullName != "new-owner/tool" {
		t.Errorf("repo info = %+v", info)
	}
	if rel := c.releases["old-owner/tool"]; len(rel) != 2 || rel[0] != (releaseFact{tag: "v2.0.0"}) || !rel[1].prerelease {
		t.Errorf("releases = %+v", rel)
	}
	f := c.refFacts["old-owner/tool@v2.0.0"]
	if f == nil || f.tag == nil || f.tag.Oid != "tagobj" || f.tag.Target == nil || f.tag.Target.Oid != "c200" {
		t.Fatalf("tag facts = %+v", f)
	}
	if !f.branch || !f.objectChecked || f.object == nil || f.object.Typename != "Tag" || f.release == nil || !*f.release {
		t.Errorf("ref facts = %+v", f)
	}
	g := c.refFacts["old-owner/tool@"+missing]
	if g == nil || g.tag != nil || g.branch || !g.objectChecked || g.object != nil || g.release != nil || g.failed {
		t.Errorf("absent ref facts = %+v", g)
	}
	adv := c.advisoryCache["old-owner/tool"]
	if len(adv) != 1 || adv[0] != (advisoryInfo{GhsaID: "GHSA-1", VulnerableRange: "< 2.0.0", PatchedVersions: "2.0.0", Severity: "medium"}) {
		t.Errorf("advisories = %+v, want GHSA-1 only, MODERATE read as medium", adv)
	}
	if len(c.DegradedChecks()) != 0 {
		t.Errorf("degraded = %v, want none", c.DegradedChecks())
	}
}

// TestQueryRepos_NotFoundAliasIsUnreadable: a repository GitHub cannot
// resolve is unreadable, like the REST 404, and the other repositories of
// the same query keep their answers.
func TestQueryRepos_NotFoundAliasIsUnreadable(t *testing.T) {
	c, _ := graphQLMetadataClient(t, func(graphQLRequest) (string, int) {
		return `{"data":{"r0":null,"r1":{"nameWithOwner":"o/good","isArchived":false,"stargazerCount":3,"t0":null,"h0":{"name":"main"},"x0":{"__typename":"Commit","oid":"c1"},"l0":null}},
		 "errors":[{"type":"NOT_FOUND","path":["r0"],"message":"Could not resolve to a Repository with the name 'o/gone'."}]}`, 200
	})
	c.queryRepos([]repoRequest{
		{owner: "o", repo: "gone", info: true, refs: []string{"main"}},
		{owner: "o", repo: "good", info: true, refs: []string{"main"}},
	})
	gone := c.repoCache["o/gone"]
	if !gone.fetched || gone.err == nil || !strings.Contains(gone.err.Error(), "Could not resolve") {
		t.Errorf("gone = %+v, want an unreadable repository", gone)
	}
	if f := c.refFacts["o/gone@main"]; f == nil || !f.failed {
		t.Errorf("gone ref facts = %+v, want failed", f)
	}
	if good := c.repoCache["o/good"]; good.err != nil || good.stars != 3 {
		t.Errorf("good = %+v", good)
	}
	if f := c.refFacts["o/good@main"]; f == nil || f.failed || !f.branch {
		t.Errorf("good ref facts = %+v", f)
	}
}

// TestQueryRepos_FailedQueryIsCouldNotVerify: a query that fails as a
// whole (rate limit, 5xx) leaves every repository and advisory of it
// could-not-verify, never missing (plumber#619's expired-token guarantee).
func TestQueryRepos_FailedQueryIsCouldNotVerify(t *testing.T) {
	c, _ := graphQLMetadataClient(t, func(graphQLRequest) (string, int) {
		return `{"message":"Bad credentials"}`, 401
	})
	c.queryRepos([]repoRequest{{owner: "o", repo: "r", info: true, advisories: true, refs: []string{"v1"}}})
	if info := c.repoCache["o/r"]; !info.fetched || info.err == nil {
		t.Errorf("repo = %+v, want unreadable", info)
	}
	if f := c.refFacts["o/r@v1"]; f == nil || !f.failed {
		t.Errorf("ref facts = %+v, want failed", f)
	}
	if adv, ok := c.advisoryCache["o/r"]; !ok || len(adv) != 0 {
		t.Errorf("advisories = %v (cached %v), want an empty cached list", adv, ok)
	}
	if d := strings.Join(c.DegradedChecks(), "\n"); !strings.Contains(d, "Advisory Database could not be queried") {
		t.Errorf("degraded = %q, want the advisory warning", d)
	}
}

// TestQueryRepos_SplitsAQueryGitHubCouldNotFinish: GitHub answers 502 when
// a query runs past its time limit (seen on vercel/next.js, 11 s). The
// query is sent again in halves, down to one repository, so one slow
// repository spoils only its own answer.
func TestQueryRepos_SplitsAQueryGitHubCouldNotFinish(t *testing.T) {
	c, got := graphQLMetadataClient(t, func(q graphQLRequest) (string, int) {
		if q.Variables["n1"] != nil || q.Variables["n0"] == "slow" {
			return `<html>502 Bad Gateway</html>`, 502
		}
		return `{"data":{"r0":{"nameWithOwner":"o/` + q.Variables["n0"].(string) + `","isArchived":false,"stargazerCount":1}}}`, 200
	})
	c.queryRepos([]repoRequest{
		{owner: "o", repo: "fast", info: true},
		{owner: "o", repo: "slow", info: true},
		{owner: "o", repo: "quick", info: true},
	})
	// 3 repositories, then 1 + 2, then the 2 as 1 + 1.
	if len(*got) != 5 {
		t.Fatalf("queries = %d, want 5", len(*got))
	}
	for _, name := range []string{"fast", "quick"} {
		if e := c.repoCache["o/"+name]; e.err != nil || e.fullName != "o/"+name {
			t.Errorf("%s = %+v, want read", name, e)
		}
	}
	if e := c.repoCache["o/slow"]; e.err == nil {
		t.Errorf("slow = %+v, want could-not-verify", e)
	}
}

// timeoutBody is GitHub answering 200 for a query it gave up on: no
// data, and one error with neither a path nor a type.
const timeoutBody = `{"data":null,"errors":[{"message":"Something went wrong while executing your query. This may be the result of a timeout, or it could be a GitHub bug. Please include ` + "`ABCD:1234`" + ` when reporting this issue."}]}`

// rateLimited is GitHub refusing a query over the rate limit: also a 200
// with an error that has no path, but one a smaller or later query would
// hit the same way.
const rateLimited = `{"errors":[{"type":"RATE_LIMITED","message":"API rate limit exceeded for user ID 1."}]}`

// TestUnfinished: only GitHub giving up on a query counts (a 5xx, our own
// timeout, a timeout answered as a 200). A refusal never does, since
// sending the query again or smaller would fail the same way.
func TestUnfinished(t *testing.T) {
	gqlErr := func(items ...api.GraphQLErrorItem) error { return &api.GraphQLError{Errors: items} }
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"502", &api.HTTPError{StatusCode: 502}, true},
		{"504", &api.HTTPError{StatusCode: 504}, true},
		{"401", &api.HTTPError{StatusCode: 401}, false},
		{"403", &api.HTTPError{StatusCode: 403}, false},
		{"our timeout", fmt.Errorf("post: %w", context.DeadlineExceeded), true},
		{"timeout answered 200", gqlErr(api.GraphQLErrorItem{Message: "Something went wrong while executing your query. This may be the result of a timeout, or it could be a GitHub bug."}), true},
		{"timeout answered 200, docs message", gqlErr(api.GraphQLErrorItem{Message: "We couldn't respond to your request in time. Sorry about that."}), true},
		{"wrapped", fmt.Errorf("query: %w", gqlErr(api.GraphQLErrorItem{Message: "Something went wrong while executing your query."})), true},
		{"rate limited", gqlErr(api.GraphQLErrorItem{Type: "RATE_LIMITED", Message: "API rate limit exceeded for user ID 1."}), false},
		{"typed, same message", gqlErr(api.GraphQLErrorItem{Type: "FORBIDDEN", Message: "Something went wrong while executing your query."}), false},
		{"tied to an alias", gqlErr(api.GraphQLErrorItem{Path: []any{"r0"}, Message: "Something went wrong while executing your query."}), false},
		{"another message", gqlErr(api.GraphQLErrorItem{Message: "Parse error on \"}\""}), false},
		{"timeout beside a refusal", gqlErr(
			api.GraphQLErrorItem{Message: "Something went wrong while executing your query."},
			api.GraphQLErrorItem{Type: "RATE_LIMITED", Message: "API rate limit exceeded"}), false},
		{"no items", gqlErr(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := unfinished(tc.err); got != tc.want {
				t.Errorf("unfinished(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestQueryRepos_SplitsAQueryGitHubAnsweredATimeout: a timeout GitHub
// answers as a 200 with an error is split like a 502, so one slow
// repository spoils only its own answer instead of the whole batch.
func TestQueryRepos_SplitsAQueryGitHubAnsweredATimeout(t *testing.T) {
	c, got := graphQLMetadataClient(t, func(q graphQLRequest) (string, int) {
		if q.Variables["n1"] != nil || q.Variables["n0"] == "slow" {
			return timeoutBody, 200
		}
		return `{"data":{"r0":{"nameWithOwner":"o/` + q.Variables["n0"].(string) + `","isArchived":false,"stargazerCount":1}}}`, 200
	})
	c.queryRepos([]repoRequest{
		{owner: "o", repo: "fast", info: true},
		{owner: "o", repo: "slow", info: true},
		{owner: "o", repo: "quick", info: true},
	})
	// 3 repositories, then 1 + 2, then the 2 as 1 + 1.
	if len(*got) != 5 {
		t.Fatalf("queries = %d, want 5", len(*got))
	}
	for _, name := range []string{"fast", "quick"} {
		if e := c.repoCache["o/"+name]; e.err != nil || e.fullName != "o/"+name {
			t.Errorf("%s = %+v, want read", name, e)
		}
	}
	if e := c.repoCache["o/slow"]; e.err == nil {
		t.Errorf("slow = %+v, want could-not-verify", e)
	}
}

// TestQueryRepos_RateLimitIsNotSplit: a rate limit also answers 200 with an
// error that has no path, but halves would be refused the same way: the
// batch is sent once and every repository is could-not-verify.
func TestQueryRepos_RateLimitIsNotSplit(t *testing.T) {
	c, got := graphQLMetadataClient(t, func(graphQLRequest) (string, int) { return rateLimited, 200 })
	c.queryRepos([]repoRequest{
		{owner: "o", repo: "a", info: true},
		{owner: "o", repo: "b", info: true},
		{owner: "o", repo: "c", info: true},
	})
	if len(*got) != 1 {
		t.Fatalf("queries = %d, want 1", len(*got))
	}
	for _, name := range []string{"a", "b", "c"} {
		if e := c.repoCache["o/"+name]; e.err == nil {
			t.Errorf("%s = %+v, want could-not-verify", name, e)
		}
	}
}

// TestQueryRepos_SplitsAQueryThatTimesOut: a batch our own timeout cuts
// short (metadataQueryTimeout) is split like one GitHub answers 5xx, so a
// single slow repository only spoils its own answer.
func TestQueryRepos_SplitsAQueryThatTimesOut(t *testing.T) {
	orig := metadataQueryTimeout
	metadataQueryTimeout = 50 * time.Millisecond
	t.Cleanup(func() { metadataQueryTimeout = orig })

	var got []graphQLRequest
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var q graphQLRequest
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &q); err != nil {
			t.Errorf("graphql request body: %v", err)
		}
		got = append(got, q)
		for k, v := range q.Variables {
			if strings.HasPrefix(k, "n") && v == "slow" {
				<-r.Context().Done() // GitHub takes longer than we wait
				return nil, r.Context().Err()
			}
		}
		text := `{"data":{"r0":{"nameWithOwner":"o/` + q.Variables["n0"].(string) + `","isArchived":false,"stargazerCount":1}}}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(text)),
			Header: http.Header{"Content-Type": []string{"application/json"}}, Request: r}, nil
	})
	gql, err := api.NewGraphQLClient(api.ClientOptions{AuthToken: "x", Transport: rt})
	if err != nil {
		t.Fatalf("new graphql client: %v", err)
	}
	c := NewGitHubMetadataClientForHost("")
	c.disabled, c.gql, c.rest, c.dotcom = false, gql, nil, true

	c.queryRepos([]repoRequest{
		{owner: "o", repo: "fast", info: true},
		{owner: "o", repo: "slow", info: true},
		{owner: "o", repo: "quick", info: true},
	})
	// 3 repositories, then 1 + 2, then the 2 as 1 + 1.
	if len(got) != 5 {
		t.Fatalf("queries = %d, want 5", len(got))
	}
	for _, name := range []string{"fast", "quick"} {
		if e := c.repoCache["o/"+name]; e.err != nil || e.fullName != "o/"+name {
			t.Errorf("%s = %+v, want read", name, e)
		}
	}
	if e := c.repoCache["o/slow"]; e.err == nil {
		t.Errorf("slow = %+v, want could-not-verify", e)
	}
}

// TestQueryRepos_ReadsTheNewest150Releases: the REST walk read three pages
// of 50; the GraphQL one reads 100, then the next 50 when there are more,
// and stops there.
func TestQueryRepos_ReadsTheNewest150Releases(t *testing.T) {
	page := func(n int, next bool) string {
		var nodes []string
		for i := range n {
			nodes = append(nodes, fmt.Sprintf(`{"tagName":"v1.0.%d","isDraft":false,"isPrerelease":false}`, i))
		}
		return fmt.Sprintf(`{"nodes":[%s],"pageInfo":{"hasNextPage":%t,"endCursor":"cur"}}`, strings.Join(nodes, ","), next)
	}
	c, got := graphQLMetadataClient(t, func(q graphQLRequest) (string, int) {
		if _, second := q.Variables["c0"]; second {
			return `{"data":{"r0":{"releases":` + page(50, true) + `}}}`, 200
		}
		return `{"data":{"r0":{"nameWithOwner":"o/r","isArchived":false,"stargazerCount":1,"releases":` + page(100, true) + `}}}`, 200
	})
	c.queryRepos([]repoRequest{{owner: "o", repo: "r", info: true}})
	if len(*got) != 2 {
		t.Fatalf("queries = %d, want 2", len(*got))
	}
	second := (*got)[1]
	if second.Variables["c0"] != "cur" || !strings.Contains(second.Query, "releases(first: 50, after: $c0") {
		t.Errorf("second query = %s %v", second.Query, second.Variables)
	}
	if n := len(c.releases["o/r"]); n != 150 {
		t.Errorf("releases = %d, want 150", n)
	}
}

// TestQueryRepos_EnterpriseKeepsImmutableAndAdvisoriesOffGraphQL: GitHub
// Enterprise Server's schema may lack Release.immutable and the ACTIONS
// advisory ecosystem, so on a GHES host neither is asked in GraphQL.
func TestQueryRepos_EnterpriseKeepsImmutableAndAdvisoriesOffGraphQL(t *testing.T) {
	c, got := graphQLMetadataClient(t, func(graphQLRequest) (string, int) { return `{"data":{}}`, 200 })
	c.dotcom = false
	c.queryRepos([]repoRequest{{owner: "o", repo: "r", info: true, advisories: true, refs: []string{"v1"}}})
	q := (*got)[0].Query
	if strings.Contains(q, "immutable") || strings.Contains(q, "securityVulnerabilities") {
		t.Errorf("GHES query asks a github.com-only field:\n%s", q)
	}
	if _, ok := c.advisoryCache["o/r"]; ok {
		t.Error("GHES advisories cached from GraphQL, want them left to the REST lookup")
	}
}

// TestQueryTags_PeelsToTheCommitAndPages: the tag listing maps each commit
// to its most specific tag, peeling annotated tags, over as many pages as
// GitHub has.
func TestQueryTags_PeelsToTheCommitAndPages(t *testing.T) {
	c, got := graphQLMetadataClient(t, func(q graphQLRequest) (string, int) {
		if q.Variables["c0"] == nil {
			return `{"data":{"r0":{"refs":{"nodes":[
				{"name":"v4","target":{"__typename":"Commit","oid":"c4"}},
				{"name":"v4.3.0","target":{"__typename":"Tag","oid":"t430","target":{"__typename":"Commit","oid":"c4"}}}
			],"pageInfo":{"hasNextPage":true,"endCursor":"p2"}}}}}`, 200
		}
		return `{"data":{"r0":{"refs":{"nodes":[
			{"name":"v3.0.0","target":{"__typename":"Tag","oid":"t300","target":{"__typename":"Tag","oid":"t300b","target":{"__typename":"Commit","oid":"c3"}}}},
			{"name":"tree-tag","target":{"__typename":"Tree","oid":"tr"}}
		],"pageInfo":{"hasNextPage":false,"endCursor":"p3"}}}}}`, 200
	})
	c.queryTags([]repoKey{{"o", "r"}})
	if len(*got) != 2 {
		t.Fatalf("queries = %d, want 2", len(*got))
	}
	want := map[string]string{"c4": "v4.3.0", "c3": "v3.0.0"}
	if tags := c.sha2tagCache["o/r"]; !maps.Equal(tags, want) {
		t.Errorf("sha2tag = %v, want %v", tags, want)
	}
}

// TestQueryTags_StopsAtMaxTagPages: a repository whose listing never ends
// is read maxTagPages pages deep and no further, as the REST walk was.
func TestQueryTags_StopsAtMaxTagPages(t *testing.T) {
	page := 0
	c, got := graphQLMetadataClient(t, func(graphQLRequest) (string, int) {
		page++
		n := strconv.Itoa(page)
		return `{"data":{"r0":{"refs":{"nodes":[{"name":"v` + n + `.0.0","target":{"__typename":"Commit","oid":"c` + n + `"}}],"pageInfo":{"hasNextPage":true,"endCursor":"p` + n + `"}}}}}`, 200
	})
	c.queryTags([]repoKey{{"o", "r"}})
	if len(*got) != maxTagPages {
		t.Fatalf("queries = %d, want %d", len(*got), maxTagPages)
	}
	tags := c.sha2tagCache["o/r"]
	if len(tags) != maxTagPages || tags["c1"] != "v1.0.0" || tags["c"+strconv.Itoa(maxTagPages)] != "v"+strconv.Itoa(maxTagPages)+".0.0" {
		t.Errorf("sha2tag = %v, want the tag of each of the %d pages", tags, maxTagPages)
	}
}

// TestQueryRepos_UnpatchedAdvisory: an advisory of the package that has no
// patched version (firstPatchedVersion null) is kept with an empty patched
// version, and its severity is read lower-cased, as the policies match it.
func TestQueryRepos_UnpatchedAdvisory(t *testing.T) {
	c, _ := graphQLMetadataClient(t, func(graphQLRequest) (string, int) {
		return `{"data":{"a0":{"nodes":[
			{"advisory":{"ghsaId":"GHSA-9","severity":"CRITICAL"},"package":{"name":"O/R"},"vulnerableVersionRange":"<= 3.1.0","firstPatchedVersion":null},
			{"advisory":{"ghsaId":"GHSA-8","severity":"HIGH"},"package":{"name":"o/r"},"vulnerableVersionRange":"< 2.0.0","firstPatchedVersion":{"identifier":"2.0.0"}}
		]}}}`, 200
	})
	c.queryRepos([]repoRequest{{owner: "o", repo: "r", advisories: true}})
	want := []advisoryInfo{
		{GhsaID: "GHSA-9", VulnerableRange: "<= 3.1.0", Severity: "critical"},
		{GhsaID: "GHSA-8", VulnerableRange: "< 2.0.0", PatchedVersions: "2.0.0", Severity: "high"},
	}
	if adv := c.advisoryCache["o/r"]; !slices.Equal(adv, want) {
		t.Errorf("advisories = %+v\nwant %+v", adv, want)
	}
	if len(c.DegradedChecks()) != 0 {
		t.Errorf("degraded = %v, want none", c.DegradedChecks())
	}
}

// TestQueryTags_FailureKeepsWhatWasRead: a page that fails ends the
// listing of that repository; the tags already read stay.
func TestQueryTags_FailureKeepsWhatWasRead(t *testing.T) {
	c, _ := graphQLMetadataClient(t, func(q graphQLRequest) (string, int) {
		if q.Variables["c0"] == nil {
			return `{"data":{"r0":{"refs":{"nodes":[{"name":"v1.0.0","target":{"__typename":"Commit","oid":"c1"}}],"pageInfo":{"hasNextPage":true,"endCursor":"p2"}}}}}`, 200
		}
		return `{"message":"rate limited"}`, 403
	})
	c.queryTags([]repoKey{{"o", "r"}})
	if tags := c.sha2tagCache["o/r"]; tags["c1"] != "v1.0.0" {
		t.Errorf("sha2tag = %v, want the first page kept", tags)
	}
}

// TestQueryRepos_RecordsTheQueryCost: every query asks for its rateLimit
// cost, which the --debug report lists.
func TestQueryRepos_RecordsTheQueryCost(t *testing.T) {
	c, got := graphQLMetadataClient(t, func(graphQLRequest) (string, int) {
		return `{"data":{"rateLimit":{"cost":3,"remaining":4000}}}`, 200
	})
	var recorded []graphQLCost
	c.recordCost = func(gc graphQLCost) { recorded = append(recorded, gc) }
	c.queryRepos([]repoRequest{{owner: "o", repo: "r", info: true}})
	if !strings.Contains((*got)[0].Query, "rateLimit { cost remaining }") {
		t.Errorf("query does not ask its cost:\n%s", (*got)[0].Query)
	}
	if len(recorded) != 1 || recorded[0].Cost != 3 || recorded[0].Remaining != 4000 || recorded[0].Label == "" {
		t.Errorf("recorded = %+v", recorded)
	}
}
