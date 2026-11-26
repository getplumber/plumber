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
	logtest "github.com/sirupsen/logrus/hooks/test"
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

// releasesPageBody is a releases connection of n releases.
func releasesPageBody(n int, next bool, cursor string) string {
	var nodes []string
	for i := range n {
		nodes = append(nodes, fmt.Sprintf(`{"tagName":"v1.0.%d","isDraft":false,"isPrerelease":false}`, i))
	}
	return fmt.Sprintf(`{"nodes":[%s],"pageInfo":{"hasNextPage":%t,"endCursor":%q}}`, strings.Join(nodes, ","), next, cursor)
}

// TestQueryRepos_FailedSecondReleasesPageKeepsTheFirst: the second page of
// releases only adds to the first. When it fails, as a whole or for that
// repository alone, or answers something unreadable, the 100 releases
// already read stay and the repository is still readable.
func TestQueryRepos_FailedSecondReleasesPageKeepsTheFirst(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"rate limited", `{"message":"rate limited"}`, 403},
		{"server error", `<html>502 Bad Gateway</html>`, 502},
		{"timeout answered 200", timeoutBody, 200},
		{"error on the alias", `{"data":{"r0":null},"errors":[{"path":["r0"],"message":"timeout"}]}`, 200},
		{"null alias", `{"data":{"r0":null}}`, 200},
		{"unreadable alias", `{"data":{"r0":"x"}}`, 200},
		{"unreadable releases", `{"data":{"r0":{"releases":"x"}}}`, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, got := graphQLMetadataClient(t, func(q graphQLRequest) (string, int) {
				if _, second := q.Variables["c0"]; second {
					return tc.body, tc.status
				}
				return `{"data":{"r0":{"nameWithOwner":"o/r","isArchived":false,"stargazerCount":1,"releases":` + releasesPageBody(100, true, "cur") + `}}}`, 200
			})
			c.queryRepos([]repoRequest{{owner: "o", repo: "r", info: true}})
			if len(*got) != 2 {
				t.Fatalf("queries = %d, want 2 (the second page is asked once)", len(*got))
			}
			rel := c.releases["o/r"]
			if len(rel) != 100 || rel[0].tag != "v1.0.0" || rel[99].tag != "v1.0.99" {
				t.Errorf("releases = %d, want the 100 of the first page kept", len(rel))
			}
			if e := c.repoCache["o/r"]; !e.fetched || e.err != nil || e.fullName != "o/r" {
				t.Errorf("repo = %+v, want it still readable", e)
			}
			if tag := c.latestReleaseTag("o", "r"); tag != "v1.0.99" {
				t.Errorf("latest release = %q, want v1.0.99 from the first page", tag)
			}
		})
	}
}

// TestQueryRepos_SecondReleasesPageFailsForOneRepository: an error on one
// repository's second page leaves the other's 50 more releases read.
func TestQueryRepos_SecondReleasesPageFailsForOneRepository(t *testing.T) {
	c, _ := graphQLMetadataClient(t, func(q graphQLRequest) (string, int) {
		if _, second := q.Variables["c0"]; second {
			return `{"data":{"r0":null,"r1":{"releases":` + releasesPageBody(50, false, "") + `}},"errors":[{"path":["r0","releases"],"message":"timeout"}]}`, 200
		}
		first := `{"nameWithOwner":"o/x","isArchived":false,"stargazerCount":1,"releases":` + releasesPageBody(100, true, "cur") + `}`
		return `{"data":{"r0":` + first + `,"r1":` + first + `}}`, 200
	})
	c.queryRepos([]repoRequest{{owner: "o", repo: "a", info: true}, {owner: "o", repo: "b", info: true}})
	if n := len(c.releases["o/a"]); n != 100 {
		t.Errorf("o/a releases = %d, want the first page kept", n)
	}
	if n := len(c.releases["o/b"]); n != 150 {
		t.Errorf("o/b releases = %d, want 150", n)
	}
}

// TestQueryRepos_AliasWithoutAnswerIsUnreadable: a repository alias that
// is null or missing, with no error of its own, is unreadable. Its refs
// are could-not-verify, never absent: impostor-commit (ISSUE-707) fires
// only on a confirmed absence.
func TestQueryRepos_AliasWithoutAnswerIsUnreadable(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"null", `{"data":{"r0":null}}`},
		{"missing", `{"data":{}}`},
		{"not an object", `{"data":{"r0":5}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, got := graphQLMetadataClient(t, func(graphQLRequest) (string, int) { return tc.body, 200 })
			c.queryRepos([]repoRequest{{owner: "o", repo: "r", info: true, refs: []string{shaA}}})
			e := c.repoCache["o/r"]
			if !e.fetched || e.err == nil {
				t.Fatalf("repo = %+v, want unreadable", e)
			}
			if tc.name != "not an object" && !strings.Contains(e.err.Error(), "r0") {
				t.Errorf("repo error = %v, want it to name r0", e.err)
			}
			if f := c.refFacts["o/r@"+shaA]; f == nil || !f.failed || f.err == nil {
				t.Errorf("ref facts = %+v, want failed", f)
			}
			if exists, checked := c.commitResolves("o", "r", shaA); exists || checked {
				t.Errorf("commitResolves = %v, %v; want could-not-verify", exists, checked)
			}
			if rel := c.releases["o/r"]; rel != nil {
				t.Errorf("releases = %v, want none", rel)
			}
			if len(*got) != 1 {
				t.Errorf("queries = %d, want 1", len(*got))
			}
		})
	}
}

// TestQueryRepos_AdvisoryAliasFailsAlone: an advisory lookup that fails
// while its repository answers is cached empty and recorded as a degraded
// check, so it never reads as "no advisories"; the repository stays read.
func TestQueryRepos_AdvisoryAliasFailsAlone(t *testing.T) {
	const repo = `"r0":{"nameWithOwner":"o/r","isArchived":false,"stargazerCount":7}`
	for _, tc := range []struct{ name, body, cause string }{
		{"error on the alias", `{"data":{` + repo + `,"a0":null},"errors":[{"path":["a0"],"message":"boom"}]}`, "boom"},
		{"null", `{"data":{` + repo + `,"a0":null}}`, "a0"},
		{"missing", `{"data":{` + repo + `}}`, "a0"},
		{"not an object", `{"data":{` + repo + `,"a0":"garbage"}}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := graphQLMetadataClient(t, func(graphQLRequest) (string, int) { return tc.body, 200 })
			c.queryRepos([]repoRequest{{owner: "o", repo: "r", info: true, advisories: true}})
			if adv, ok := c.advisoryCache["o/r"]; !ok || adv == nil || len(adv) != 0 {
				t.Errorf("advisories = %v (cached %v), want an empty cached list", adv, ok)
			}
			d := strings.Join(c.DegradedChecks(), "\n")
			if !strings.Contains(d, "o/r: the GitHub Advisory Database could not be queried") || !strings.Contains(d, tc.cause) {
				t.Errorf("degraded = %q, want the advisory warning with %q", d, tc.cause)
			}
			if e := c.repoCache["o/r"]; e.err != nil || e.stars != 7 {
				t.Errorf("repo = %+v, want it read", e)
			}
		})
	}
}

// TestQueryRepos_ErrorUnderAnAlias: an error on a field under a
// repository alias spoils that repository only, with the first message
// GitHub gave for it. An error whose path does not start at an alias
// spoils the whole answer.
func TestQueryRepos_ErrorUnderAnAlias(t *testing.T) {
	const a = `"r0":{"nameWithOwner":"o/a","isArchived":false,"stargazerCount":1,"t0":null,"h0":{"name":"main"},"x0":null,"l0":null}`
	const b = `"r1":{"nameWithOwner":"o/b","isArchived":false,"stargazerCount":2,"t0":null,"h0":{"name":"main"},"x0":null,"l0":null}`
	reqs := []repoRequest{
		{owner: "o", repo: "a", info: true, refs: []string{"main"}},
		{owner: "o", repo: "b", info: true, refs: []string{"main"}},
	}
	t.Run("nested field", func(t *testing.T) {
		c, _ := graphQLMetadataClient(t, func(graphQLRequest) (string, int) {
			return `{"data":{` + a + `,` + b + `},"errors":[{"path":["r0","l0"],"message":"first"},{"path":["r0","t0"],"message":"second"}]}`, 200
		})
		c.queryRepos(reqs)
		if e := c.repoCache["o/a"]; e.err == nil || e.err.Error() != "first" {
			t.Errorf("o/a = %+v, want the first error GitHub gave", e)
		}
		if f := c.refFacts["o/a@main"]; f == nil || !f.failed || f.branch {
			t.Errorf("o/a ref facts = %+v, want failed", f)
		}
		if e := c.repoCache["o/b"]; e.err != nil || e.stars != 2 {
			t.Errorf("o/b = %+v, want it read", e)
		}
		if f := c.refFacts["o/b@main"]; f == nil || f.failed || !f.branch {
			t.Errorf("o/b ref facts = %+v, want read", f)
		}
	})
	t.Run("path that names no alias", func(t *testing.T) {
		c, got := graphQLMetadataClient(t, func(graphQLRequest) (string, int) {
			return `{"data":{` + a + `,` + b + `},"errors":[{"path":[0],"message":"odd"}]}`, 200
		})
		c.queryRepos(reqs)
		for _, name := range []string{"a", "b"} {
			if e := c.repoCache["o/"+name]; e.err == nil {
				t.Errorf("o/%s = %+v, want could-not-verify", name, e)
			}
			if f := c.refFacts["o/"+name+"@main"]; f == nil || !f.failed {
				t.Errorf("o/%s ref facts = %+v, want failed", name, f)
			}
		}
		if len(*got) != 1 {
			t.Errorf("queries = %d, want 1 (not split)", len(*got))
		}
	})
}

// TestQueryRepos_NoGraphQLClient: a client with no GraphQL client answers
// could-not-verify for everything and sends nothing.
func TestQueryRepos_NoGraphQLClient(t *testing.T) {
	c, got := graphQLMetadataClient(t, func(graphQLRequest) (string, int) { return `{"data":{}}`, 200 })
	c.gql = nil
	c.queryRepos([]repoRequest{{owner: "o", repo: "r", info: true, advisories: true, refs: []string{"v1"}}})
	if e := c.repoCache["o/r"]; !e.fetched || e.err != errNoGraphQL {
		t.Errorf("repo = %+v, want errNoGraphQL", e)
	}
	if f := c.refFacts["o/r@v1"]; f == nil || !f.failed {
		t.Errorf("ref facts = %+v, want failed", f)
	}
	if d := strings.Join(c.DegradedChecks(), "\n"); !strings.Contains(d, "Advisory Database could not be queried") {
		t.Errorf("degraded = %q, want the advisory warning", d)
	}
	c.queryTags([]repoKey{{"o", "r"}})
	if tags, ok := c.sha2tagCache["o/r"]; !ok || len(tags) != 0 {
		t.Errorf("sha2tag = %v (cached %v), want an empty cached listing", tags, ok)
	}
	if len(*got) != 0 {
		t.Errorf("queries = %d, want 0", len(*got))
	}
}

// TestQueryRepos_QueryCostGuards: the cost is recorded when GitHub gives
// it, also beside an alias error; an answer without it records nothing,
// and a client with no recorder does not fail.
func TestQueryRepos_QueryCostGuards(t *testing.T) {
	reqs := []repoRequest{{owner: "o", repo: "r", info: true}}
	t.Run("no rateLimit field", func(t *testing.T) {
		c, _ := graphQLMetadataClient(t, func(graphQLRequest) (string, int) { return `{"data":{"r0":{"nameWithOwner":"o/r"}}}`, 200 })
		var recorded []graphQLCost
		c.recordCost = func(gc graphQLCost) { recorded = append(recorded, gc) }
		c.queryRepos(reqs)
		if len(recorded) != 0 {
			t.Errorf("recorded = %+v, want nothing", recorded)
		}
	})
	t.Run("failed query", func(t *testing.T) {
		c, _ := graphQLMetadataClient(t, func(graphQLRequest) (string, int) { return `{"message":"no"}`, 401 })
		var recorded []graphQLCost
		c.recordCost = func(gc graphQLCost) { recorded = append(recorded, gc) }
		c.queryRepos(reqs)
		if len(recorded) != 0 {
			t.Errorf("recorded = %+v, want nothing", recorded)
		}
	})
	t.Run("no recorder", func(t *testing.T) {
		c, _ := graphQLMetadataClient(t, func(graphQLRequest) (string, int) {
			return `{"data":{"rateLimit":{"cost":3,"remaining":4000},"r0":{"nameWithOwner":"o/r"}}}`, 200
		})
		c.recordCost = nil
		c.queryRepos(reqs)
		if e := c.repoCache["o/r"]; e.err != nil || e.fullName != "o/r" {
			t.Errorf("repo = %+v, want it read", e)
		}
	})
	t.Run("beside an alias error", func(t *testing.T) {
		c, _ := graphQLMetadataClient(t, func(graphQLRequest) (string, int) {
			return `{"data":{"rateLimit":{"cost":2,"remaining":10},"r0":null},"errors":[{"type":"NOT_FOUND","path":["r0"],"message":"gone"}]}`, 200
		})
		var recorded []graphQLCost
		c.recordCost = func(gc graphQLCost) { recorded = append(recorded, gc) }
		c.queryRepos(reqs)
		want := graphQLCost{Label: "action metadata: 1 repositories", Cost: 2, Remaining: 10}
		if len(recorded) != 1 || recorded[0] != want {
			t.Errorf("recorded = %+v, want %+v", recorded, want)
		}
	})
}

// TestQueryRepos_MalformedReleases: a repository whose releases are
// missing or unreadable is read with no releases, and a next page GitHub
// gives no cursor for is not asked.
func TestQueryRepos_MalformedReleases(t *testing.T) {
	for _, tc := range []struct {
		name, releases string
		want           int
	}{
		{"missing", ``, 0},
		{"null", `,"releases":null`, 0},
		{"not an object", `,"releases":"x"`, 0},
		{"next page without a cursor", `,"releases":` + releasesPageBody(3, true, ""), 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, got := graphQLMetadataClient(t, func(graphQLRequest) (string, int) {
				return `{"data":{"r0":{"nameWithOwner":"o/r","isArchived":true,"stargazerCount":1` + tc.releases + `}}}`, 200
			})
			c.queryRepos([]repoRequest{{owner: "o", repo: "r", info: true}})
			if len(*got) != 1 {
				t.Errorf("queries = %d, want 1 (no second page)", len(*got))
			}
			if n := len(c.releases["o/r"]); n != tc.want {
				t.Errorf("releases = %d, want %d", n, tc.want)
			}
			if e := c.repoCache["o/r"]; e.err != nil || !e.archived {
				t.Errorf("repo = %+v, want it read", e)
			}
		})
	}
}

// TestQueryRepos_ChunksPastTheChunkSize: more repositories than one query
// takes go out in several, the aliases starting again at r0 in each, and
// every answer lands under its own repository. The second pages of
// releases are chunked the same way.
func TestQueryRepos_ChunksPastTheChunkSize(t *testing.T) {
	var sizes, pageSizes []int
	c, _ := graphQLMetadataClient(t, func(q graphQLRequest) (string, int) {
		var parts []string
		_, second := q.Variables["c0"]
		n := 0
		for ; q.Variables["n"+strconv.Itoa(n)] != nil; n++ {
			name := q.Variables["n"+strconv.Itoa(n)].(string)
			if second {
				parts = append(parts, fmt.Sprintf(`"r%d":{"releases":{"nodes":[{"tagName":"second-%s"}],"pageInfo":{"hasNextPage":false,"endCursor":""}}}`, n, name))
				continue
			}
			parts = append(parts, fmt.Sprintf(`"r%d":{"nameWithOwner":"o/%s","isArchived":false,"stargazerCount":1,"releases":{"nodes":[{"tagName":"first-%s"}],"pageInfo":{"hasNextPage":true,"endCursor":"cur-%s"}}}`, n, name, name, name))
		}
		if second {
			pageSizes = append(pageSizes, n)
			for i := range n {
				if want := "cur-" + q.Variables["n"+strconv.Itoa(i)].(string); q.Variables["c"+strconv.Itoa(i)] != want {
					t.Errorf("cursor c%d = %v, want %s", i, q.Variables["c"+strconv.Itoa(i)], want)
				}
			}
		} else {
			sizes = append(sizes, n)
		}
		return `{"data":{` + strings.Join(parts, ",") + `}}`, 200
	})
	var reqs []repoRequest
	for i := range metadataChunkSize + 1 {
		reqs = append(reqs, repoRequest{owner: "o", repo: "repo" + strconv.Itoa(i), info: true})
	}
	c.queryRepos(reqs)
	if want := []int{metadataChunkSize, 1}; !slices.Equal(sizes, want) || !slices.Equal(pageSizes, want) {
		t.Fatalf("query sizes = %v, second pages = %v; want %v for both", sizes, pageSizes, want)
	}
	for _, r := range reqs {
		key := "o/" + r.repo
		if e := c.repoCache[key]; e.err != nil || e.fullName != key {
			t.Errorf("%s = %+v, want its own answer", key, e)
		}
		want := []releaseFact{{tag: "first-" + r.repo}, {tag: "second-" + r.repo}}
		if rel := c.releases[key]; !slices.Equal(rel, want) {
			t.Errorf("%s releases = %+v, want %+v", key, rel, want)
		}
	}
}

// TestQueryRepos_DecodedRefFactsFollowTheRefShape: a ref outside the
// plain-name grammar was not looked up as an object, so its facts say the
// object was not checked rather than that it is absent. The release is
// asked on github.com only.
func TestQueryRepos_DecodedRefFactsFollowTheRefShape(t *testing.T) {
	const answer = `{"data":{"r0":{
		"t0":null,"h0":null,"x0":{"__typename":"Commit","oid":"c1"},"l0":null,
		"t1":null,"h1":{"name":"main"},"x1":{"__typename":"Commit","oid":"c2"},"l1":{"immutable":false},
		"t2":{"target":{"__typename":"Commit","oid":"c3"}},"h2":null,"l2":{"immutable":true}
	}}}`
	sha := strings.Repeat("AB", 20)
	refs := []string{sha, "main", "v1@{0}"}
	for _, dotcom := range []bool{true, false} {
		t.Run(fmt.Sprintf("dotcom=%v", dotcom), func(t *testing.T) {
			c, got := graphQLMetadataClient(t, func(graphQLRequest) (string, int) { return answer, 200 })
			c.dotcom = dotcom
			c.queryRepos([]repoRequest{{owner: "o", repo: "r", refs: refs}})
			if asked := strings.Contains((*got)[0].Query, "release(tagName:"); asked != dotcom {
				t.Errorf("release asked = %v, want %v", asked, dotcom)
			}
			bySha := c.refFacts["o/r@"+sha]
			if bySha == nil || bySha.failed || !bySha.objectChecked || bySha.object == nil || bySha.object.Oid != "c1" || bySha.branch || bySha.tag != nil || bySha.release != nil {
				t.Errorf("SHA facts = %+v", bySha)
			}
			main := c.refFacts["o/r@main"]
			if main == nil || !main.branch || !main.objectChecked || main.object == nil || main.object.Oid != "c2" {
				t.Fatalf("branch facts = %+v", main)
			}
			odd := c.refFacts["o/r@v1@{0}"]
			if odd == nil || odd.failed || odd.objectChecked || odd.object != nil || odd.tag == nil || odd.tag.Oid != "c3" {
				t.Fatalf("facts of a ref outside the grammar = %+v, want the object not checked", odd)
			}
			if exists, checked := c.commitResolves("o", "r", "v1@{0}"); exists || checked {
				t.Errorf("commitResolves = %v, %v; want could-not-verify", exists, checked)
			}
			if dotcom {
				if main.release == nil || *main.release || odd.release == nil || !*odd.release {
					t.Errorf("releases = %v, %v; want false, true", main.release, odd.release)
				}
			}
		})
	}
}

// TestQueryRepos_EnterpriseRecordsNoRelease: a GitHub Enterprise Server
// answer carries no release alias, so the ref facts hold none and the
// advisories stay off the GraphQL cache.
func TestQueryRepos_EnterpriseRecordsNoRelease(t *testing.T) {
	c, _ := graphQLMetadataClient(t, func(graphQLRequest) (string, int) {
		return `{"data":{"r0":{"nameWithOwner":"o/r","isArchived":false,"stargazerCount":1,"t0":{"target":{"__typename":"Commit","oid":"c1"}},"h0":null,"x0":{"__typename":"Commit","oid":"c1"}}}}`, 200
	})
	c.dotcom = false
	c.queryRepos([]repoRequest{{owner: "o", repo: "r", info: true, advisories: true, refs: []string{"v1"}}})
	f := c.refFacts["o/r@v1"]
	if f == nil || f.failed || f.release != nil || f.tag == nil || f.tag.Oid != "c1" || !f.objectChecked || f.object == nil {
		t.Errorf("ref facts = %+v, want the tag read and no release", f)
	}
	if _, ok := c.advisoryCache["o/r"]; ok {
		t.Error("advisories cached from GraphQL on GHES")
	}
	if len(c.DegradedChecks()) != 0 {
		t.Errorf("degraded = %v, want none", c.DegradedChecks())
	}
}

// tagsPage is one repository's page of a tag listing.
func tagsPage(next bool, cursor string, tags ...string) string {
	var nodes []string
	for i := 0; i+1 < len(tags); i += 2 {
		nodes = append(nodes, fmt.Sprintf(`{"name":%q,"target":{"__typename":"Commit","oid":%q}}`, tags[i], tags[i+1]))
	}
	return fmt.Sprintf(`{"refs":{"nodes":[%s],"pageInfo":{"hasNextPage":%t,"endCursor":%q}}}`, strings.Join(nodes, ","), next, cursor)
}

// TestQueryTags_SeveralRepositories: repositories are listed together. One
// whose listing ended leaves the next round, where the others take the
// aliases from r0 again; each repository keeps its own tags and cursor.
func TestQueryTags_SeveralRepositories(t *testing.T) {
	c, got := graphQLMetadataClient(t, func(q graphQLRequest) (string, int) {
		if q.Variables["n1"] != nil {
			return `{"data":{"r0":` + tagsPage(false, "", "v1.0.0", "a1") + `,"r1":` + tagsPage(true, "p2", "v2.0.0", "b1") + `}}`, 200
		}
		return `{"data":{"r0":` + tagsPage(false, "", "v2.1.0", "b2") + `}}`, 200
	})
	c.queryTags([]repoKey{{"o", "a"}, {"o", "b"}})
	if len(*got) != 2 {
		t.Fatalf("queries = %d, want 2", len(*got))
	}
	first, second := (*got)[0].Variables, (*got)[1].Variables
	if first["n0"] != "a" || first["n1"] != "b" || first["c0"] != nil || first["c1"] != nil {
		t.Errorf("first round = %v, want a and b from their first page", first)
	}
	if second["n0"] != "b" || second["c0"] != "p2" || second["n1"] != nil {
		t.Errorf("second round = %v, want b alone as r0, after p2", second)
	}
	if _, ok := second["c1"]; ok {
		t.Errorf("second round = %v, want no second repository", second)
	}
	if tags := c.sha2tagCache["o/a"]; !maps.Equal(tags, map[string]string{"a1": "v1.0.0"}) {
		t.Errorf("o/a = %v", tags)
	}
	if tags := c.sha2tagCache["o/b"]; !maps.Equal(tags, map[string]string{"b1": "v2.0.0", "b2": "v2.1.0"}) {
		t.Errorf("o/b = %v", tags)
	}
}

// TestQueryTags_OneRepositoryFails: an error on one repository of a
// listing is logged and ends that repository's listing with what was
// read, cached so it is not listed again; the other keeps its tags.
func TestQueryTags_OneRepositoryFails(t *testing.T) {
	hook := logtest.NewGlobal()
	t.Cleanup(hook.Reset)
	c, got := graphQLMetadataClient(t, func(graphQLRequest) (string, int) {
		return `{"data":{"r0":null,"r1":` + tagsPage(false, "", "v2.0.0", "b1", "", "b9") + `},"errors":[{"path":["r0"],"message":"listing timed out"}]}`, 200
	})
	c.queryTags([]repoKey{{"o", "a"}, {"o", "b"}})
	if len(*got) != 1 {
		t.Fatalf("queries = %d, want 1 (a failed listing is not asked again)", len(*got))
	}
	if tags, ok := c.sha2tagCache["o/a"]; !ok || tags == nil || len(tags) != 0 {
		t.Errorf("o/a = %v (cached %v), want an empty cached listing", tags, ok)
	}
	// The tag with no name is skipped.
	if tags := c.sha2tagCache["o/b"]; !maps.Equal(tags, map[string]string{"b1": "v2.0.0"}) {
		t.Errorf("o/b = %v, want its named tag only", tags)
	}
	var warned []string
	for _, e := range hook.AllEntries() {
		if strings.Contains(e.Message, "could not fetch tags for") {
			warned = append(warned, e.Message)
		}
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "o/a on page 1") || !strings.Contains(warned[0], "listing timed out") {
		t.Errorf("warnings = %q, want one naming o/a, page 1 and GitHub's error", warned)
	}
}

// TestQueryTags_FailureIsLoggedAndCached: a listing that fails, on its
// first page or a later one, is logged with the page, is not asked again
// and is cached with what was read.
func TestQueryTags_FailureIsLoggedAndCached(t *testing.T) {
	for _, tc := range []struct {
		name        string
		failAt      int
		wantQueries int
		want        map[string]string
	}{
		{"first page", 1, 1, map[string]string{}},
		{"second page", 2, 2, map[string]string{"c1": "v1.0.0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook := logtest.NewGlobal()
			t.Cleanup(hook.Reset)
			page := 0
			c, got := graphQLMetadataClient(t, func(graphQLRequest) (string, int) {
				page++
				if page == tc.failAt {
					return `{"message":"rate limited"}`, 403
				}
				return `{"data":{"r0":` + tagsPage(true, "p2", "v1.0.0", "c1") + `}}`, 200
			})
			c.queryTags([]repoKey{{"o", "r"}})
			if len(*got) != tc.wantQueries {
				t.Errorf("queries = %d, want %d", len(*got), tc.wantQueries)
			}
			if tags, ok := c.sha2tagCache["o/r"]; !ok || tags == nil || !maps.Equal(tags, tc.want) {
				t.Errorf("sha2tag = %v (cached %v), want %v", tags, ok, tc.want)
			}
			logged := false
			for _, e := range hook.AllEntries() {
				if strings.Contains(e.Message, fmt.Sprintf("could not fetch tags for o/r on page %d", tc.failAt)) {
					logged = true
				}
			}
			if !logged {
				t.Errorf("no warning for page %d", tc.failAt)
			}
		})
	}
}

// TestDoRetrying_OurOwnTimeout: a try our own timeout cuts short is sent
// again, with a fresh timeout of its own.
func TestDoRetrying_OurOwnTimeout(t *testing.T) {
	orig := metadataQueryTimeout
	metadataQueryTimeout = 50 * time.Millisecond
	t.Cleanup(func() { metadataQueryTimeout = orig })

	tries := 0
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		tries++
		if tries == 1 {
			<-r.Context().Done() // GitHub takes longer than we wait
			return nil, r.Context().Err()
		}
		if err := r.Context().Err(); err != nil {
			t.Errorf("try %d starts with a spent context: %v", tries, err)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"data":{"viewer":{"login":"me"}}}`)),
			Header: http.Header{"Content-Type": []string{"application/json"}}, Request: r}, nil
	})
	gql, err := api.NewGraphQLClient(api.ClientOptions{AuthToken: "x", Transport: rt})
	if err != nil {
		t.Fatalf("new graphql client: %v", err)
	}
	var data struct {
		Viewer struct{ Login string }
	}
	if err := doRetrying(gql, "{ viewer { login } }", nil, &data); err != nil {
		t.Fatalf("doRetrying = %v, want the second try's answer", err)
	}
	if tries != 2 || data.Viewer.Login != "me" {
		t.Errorf("tries = %d, login = %q; want 2, me", tries, data.Viewer.Login)
	}
}
