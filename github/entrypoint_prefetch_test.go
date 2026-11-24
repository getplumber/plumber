package github

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cli/go-gh/v2/pkg/api"

	"github.com/getplumber/plumber/internal/ir"
)

// graphQLRequest is one query the stubbed GraphQL endpoint received.
type graphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

// stubbedGraphQL is a GraphQL client whose endpoint answers respond, and
// the requests it received.
func stubbedGraphQL(t *testing.T, respond func(graphQLRequest) (string, int)) (*api.GraphQLClient, *[]graphQLRequest) {
	t.Helper()
	var got []graphQLRequest
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var q graphQLRequest
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &q); err != nil {
			t.Errorf("graphql request body: %v", err)
		}
		got = append(got, q)
		text, status := respond(q)
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(text)),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Request:    r,
		}, nil
	})
	gql, err := api.NewGraphQLClient(api.ClientOptions{AuthToken: "x", Transport: rt})
	if err != nil {
		t.Fatalf("new graphql client: %v", err)
	}
	return gql, &got
}

// TestPrefetchAbsent_NullObjectIsAbsent: a candidate GitHub answers null
// for, in a repository that answered, is absent and read without a
// request; one that exists is still read from the raw host. Every
// untrusted value travels as a variable, never in the query text.
func TestPrefetchAbsent_NullObjectIsAbsent(t *testing.T) {
	t.Setenv(EnvDisableGitHubAPI, "0")
	gql, queries := stubbedGraphQL(t, func(graphQLRequest) (string, int) {
		return `{"data":{"r0":{"p0":null,"p1":{"__typename":"Blob"}}}}`, http.StatusOK
	})
	stub := newStub(map[string]string{"acme/js@v1:dist/index.js": "console.log(1)"})
	defs := tokenFetcher(stub.fetch, nil)
	defs.gql = gql
	defs.prefetchAbsent([]candidateRef{{owner: "acme", repo: "js", ref: "v1", paths: []string{"action.js", "dist/index.js"}}})

	if len(*queries) != 1 {
		t.Fatalf("want one query, got %d", len(*queries))
	}
	q := (*queries)[0]
	for _, untrusted := range []string{"acme", "v1:action.js"} {
		if strings.Contains(q.Query, untrusted) {
			t.Fatalf("query text carries %q: %s", untrusted, q.Query)
		}
	}
	if q.Variables["o0"] != "acme" || q.Variables["n0"] != "js" || q.Variables["e0_0"] != "v1:action.js" || q.Variables["e0_1"] != "v1:dist/index.js" {
		t.Fatalf("variables = %v", q.Variables)
	}

	if _, st := defs.read("acme", "js", "v1", "action.js"); st != fetchMissing {
		t.Fatalf("action.js: status = %v, want fetchMissing", st)
	}
	if text, st := defs.read("acme", "js", "v1", "dist/index.js"); st != fetchOK || text != "console.log(1)" {
		t.Fatalf("dist/index.js: got %q, %v, want the raw host's file", text, st)
	}
	if stub.calls["acme/js@v1:action.js"] != 0 || stub.calls["acme/js@v1:dist/index.js"] != 1 {
		t.Fatalf("raw requests = %v, want only the file that exists", stub.calls)
	}
}

// TestPrefetchAbsent_ErrorMarksNothing: a query GitHub answers with an
// error (a repository behind SAML SSO, a rate limit, a 5xx) proves
// nothing, so every candidate is read as before.
func TestPrefetchAbsent_ErrorMarksNothing(t *testing.T) {
	t.Setenv(EnvDisableGitHubAPI, "0")
	for name, answer := range map[string]struct {
		body   string
		status int
	}{
		"sso":         {`{"data":{"r0":null},"errors":[{"type":"FORBIDDEN","path":["r0"],"message":"Resource protected by organization SAML enforcement."}]}`, http.StatusOK},
		"5xx":         {`{"message":"Server Error"}`, http.StatusBadGateway},
		"whole query": {`{"data":{"r0":{"p0":null}},"errors":[{"type":"RATE_LIMITED","message":"API rate limit exceeded"}]}`, http.StatusOK},
		// GitHub keeps the repository but nulls the one object it failed
		// to resolve: that null is the error, not an absent file.
		"one object": {`{"data":{"r0":{"p0":null}},"errors":[{"path":["r0","p0"],"message":"Something went wrong while executing your query."}]}`, http.StatusOK},
	} {
		t.Run(name, func(t *testing.T) {
			gql, _ := stubbedGraphQL(t, func(graphQLRequest) (string, int) { return answer.body, answer.status })
			stub := newStub(map[string]string{})
			defs := tokenFetcher(stub.fetch, nil)
			defs.gql = gql
			defs.prefetchAbsent([]candidateRef{{owner: "sso-org", repo: "js", ref: "v1", paths: []string{"action.js"}}})
			defs.read("sso-org", "js", "v1", "action.js")
			if stub.calls["sso-org/js@v1:action.js"] != 1 {
				t.Fatalf("raw requests = %v, want the candidate read as before", stub.calls)
			}
		})
	}
}

// TestPrefetchAbsent_ErrorOnOneRepositoryKeepsTheOthers: an error GitHub
// ties to one repository of a chunk (deleted, renamed, behind SAML SSO)
// drops that repository's answers only; the others still count.
func TestPrefetchAbsent_ErrorOnOneRepositoryKeepsTheOthers(t *testing.T) {
	t.Setenv(EnvDisableGitHubAPI, "0")
	gql, _ := stubbedGraphQL(t, func(graphQLRequest) (string, int) {
		return `{"data":{"r0":{"p0":null},"r1":null},"errors":[{"type":"NOT_FOUND","path":["r1"],"message":"Could not resolve to a Repository with the name 'gone/js'."}]}`, http.StatusOK
	})
	stub := newStub(map[string]string{})
	defs := tokenFetcher(stub.fetch, nil)
	defs.gql = gql
	defs.prefetchAbsent([]candidateRef{
		{owner: "acme", repo: "js", ref: "v1", paths: []string{"action.js"}},
		{owner: "gone", repo: "js", ref: "v1", paths: []string{"action.js"}},
	})
	defs.read("acme", "js", "v1", "action.js")
	defs.read("gone", "js", "v1", "action.js")
	if stub.calls["acme/js@v1:action.js"] != 0 || stub.calls["gone/js@v1:action.js"] != 1 {
		t.Fatalf("raw requests = %v, want acme/js answered by the prefetch and gone/js read as before", stub.calls)
	}
}

// TestPrefetchAbsent_SendsNothing: no GraphQL client (no token, client
// disabled), the offline switch, and references a request must never
// carry send no query.
func TestPrefetchAbsent_SendsNothing(t *testing.T) {
	refused := []candidateRef{
		{owner: "acme", repo: "js", ref: "v1:secret", paths: []string{"action.js"}},
		{owner: "../x", repo: "js", ref: "v1", paths: []string{"action.js"}},
		{owner: "acme", repo: "js", ref: "a..b", paths: []string{"action.js"}},
		// rev-parse operators GraphQL would evaluate, the raw host not
		{owner: "acme", repo: "js", ref: "main~1", paths: []string{"action.js"}},
		{owner: "acme", repo: "js", ref: "v1^", paths: []string{"action.js"}},
		{owner: "acme", repo: "js", ref: "v1^{/fix}", paths: []string{"action.js"}},
		// a subpath climbing out of the repository
		{owner: "acme", repo: "js", ref: "v1", paths: []string{"../../x/action.js"}},
	}
	t.Run("refused references", func(t *testing.T) {
		t.Setenv(EnvDisableGitHubAPI, "0")
		gql, queries := stubbedGraphQL(t, func(graphQLRequest) (string, int) { return `{"data":{}}`, http.StatusOK })
		defs := tokenFetcher(newStub(nil).fetch, nil)
		defs.gql = gql
		defs.prefetchAbsent(refused)
		if len(*queries) != 0 {
			t.Fatalf("want no query, got %d", len(*queries))
		}
	})
	t.Run("offline", func(t *testing.T) {
		t.Setenv(EnvDisableGitHubAPI, "1")
		gql, queries := stubbedGraphQL(t, func(graphQLRequest) (string, int) { return `{"data":{}}`, http.StatusOK })
		defs := tokenFetcher(newStub(nil).fetch, nil)
		defs.gql = gql
		defs.prefetchAbsent([]candidateRef{{owner: "acme", repo: "js", ref: "v1", paths: []string{"action.js"}}})
		if len(*queries) != 0 {
			t.Fatalf("want no query, got %d", len(*queries))
		}
	})
	t.Run("no client", func(t *testing.T) {
		t.Setenv(EnvDisableGitHubAPI, "0")
		defs := tokenFetcher(newStub(nil).fetch, nil)
		defs.prefetchAbsent([]candidateRef{{owner: "acme", repo: "js", ref: "v1", paths: []string{"action.js"}}})
		if len(defs.absent) != 0 {
			t.Fatalf("absent = %v, want nothing without a client", defs.absent)
		}
	})
	// GraphQL has no anonymous access. With no token anywhere go-gh builds
	// no client, so the metadata client is disabled and the fetcher gets no
	// GraphQL client: an anonymous run never sends a query bound to fail.
	t.Run("no token", func(t *testing.T) {
		t.Setenv(EnvDisableGitHubAPI, "0")
		for _, env := range []string{EnvMetadataToken, "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GH_HOST"} {
			t.Setenv(env, "")
		}
		t.Setenv("GH_CONFIG_DIR", t.TempDir())
		t.Setenv("GH_PATH", filepath.Join(t.TempDir(), "no-gh")) // no keyring login through `gh auth token`
		client := NewGitHubMetadataClientForHost("")
		defs := newDefinitionFetcher(newStub(nil).fetch, client)
		if client.Available() || client.gql != nil || defs.gql != nil {
			t.Fatalf("available = %v, client gql = %v, fetcher gql = %v, want no GraphQL client without a token", client.Available(), client.gql != nil, defs.gql != nil)
		}
	})
	t.Run("stubbed metadata client", func(t *testing.T) {
		t.Setenv(EnvDisableGitHubAPI, "0")
		t.Setenv(EnvMetadataToken, "test-token") // as the tests that scan mutable exec
		client := stubbedMetadataClient(t, func(*http.Request) (string, int) { return `{}`, http.StatusNotFound })
		if client.gql != nil {
			t.Fatal("stubbedMetadataClient keeps a live GraphQL client: tests would query api.github.com")
		}
	})
}

// TestPrefetchAbsent_Chunks: a run with many actions sends one query per
// chunk of prefetchChunkSize references.
func TestPrefetchAbsent_Chunks(t *testing.T) {
	t.Setenv(EnvDisableGitHubAPI, "0")
	gql, queries := stubbedGraphQL(t, func(graphQLRequest) (string, int) { return `{"data":{}}`, http.StatusOK })
	defs := tokenFetcher(newStub(nil).fetch, nil)
	defs.gql = gql
	refs := make([]candidateRef, prefetchChunkSize+1)
	for i := range refs {
		refs[i] = candidateRef{owner: "acme", repo: "js", ref: "v1", paths: []string{"action.js"}}
	}
	defs.prefetchAbsent(refs)
	if len(*queries) != 2 {
		t.Fatalf("want 2 queries for %d references, got %d", len(refs), len(*queries))
	}
}

// TestCandidateRefs: one entry per container the mutable-exec scan reads,
// its candidates under the action's subpath; first-party actions, local
// and docker references are not scanned, so not checked.
func TestCandidateRefs(t *testing.T) {
	p := &ir.NormalizedPipeline{Jobs: []ir.Job{
		{Uses: []ir.Action{{Uses: "acme/js@v1"}, {Uses: "actions/checkout@v4"}, {Uses: "./local"}}},
		{Uses: []ir.Action{{Uses: "Acme/JS@v1"}, {Uses: "acme/mono/tools/lint@v2"}, {Uses: "docker://alpine:3"}}},
	}}
	got := candidateRefs(p, newDefinitionFetcher(nil, nil))
	want := []candidateRef{
		{owner: "acme", repo: "js", ref: "v1", paths: entrypointCandidates},
		{owner: "acme", repo: "mono", ref: "v2", paths: []string{"tools/lint/action.js", "tools/lint/index.js", "tools/lint/dist/index.js", "tools/lint/src/index.js"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidateRefs = %+v, want %+v", got, want)
	}
}

// TestEnrichActions_PrefetchSkipsAbsentEntrypoints runs the prefetch the
// way a scan does: the paths candidateRefs asks about must be the paths
// the mutable-exec scan reads (a subpath action included), so a candidate
// GitHub reports absent costs no raw read, while the one that exists and
// the declared main: are still read.
func TestEnrichActions_PrefetchSkipsAbsentEntrypoints(t *testing.T) {
	t.Setenv(EnvDisableGitHubAPI, "0")
	t.Setenv(EnvMetadataToken, "test-token")
	stub := newStub(map[string]string{
		"acme/mono@v2:tools/lint/action.yml":    "name: lint\nruns:\n  using: node20\n  main: dist/main.js\n",
		"acme/mono@v2:tools/lint/dist/main.js":  "console.log(1)",
		"acme/mono@v2:tools/lint/dist/index.js": "console.log(2)",
		"acme/js@v1:action.yml":                 composite(),
	})
	client := stubbedMetadataClient(t, func(*http.Request) (string, int) { return `{}`, http.StatusNotFound })
	gql, queries := stubbedGraphQL(t, func(q graphQLRequest) (string, int) {
		// Answer from the request's own variables, whatever their order:
		// dist/index.js exists, every other candidate does not.
		data := map[string]map[string]any{}
		for name, v := range q.Variables {
			ri, pj, ok := strings.Cut(strings.TrimPrefix(name, "e"), "_")
			if !strings.HasPrefix(name, "e") || !ok {
				continue
			}
			if data["r"+ri] == nil {
				data["r"+ri] = map[string]any{}
			}
			var obj any
			if strings.HasSuffix(v.(string), ":dist/index.js") || strings.HasSuffix(v.(string), "/dist/index.js") {
				obj = map[string]string{"__typename": "Blob"}
			}
			data["r"+ri]["p"+pj] = obj
		}
		body, _ := json.Marshal(map[string]any{"data": data})
		return string(body), http.StatusOK
	})
	client.gql = gql
	defs := tokenFetcher(stub.fetch, client)
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "acme/app", Jobs: []ir.Job{oneJob("acme/mono/tools/lint@v2", "acme/js@v1")}}
	resolveNestedActions(p, defs, nestedScope{projectPath: "acme/app"})
	enrichActions(p, client, defs, true, nil)

	if len(*queries) != 1 {
		t.Fatalf("want one prefetch query, got %d", len(*queries))
	}
	for _, key := range []string{
		"acme/mono@v2:tools/lint/action.js", "acme/mono@v2:tools/lint/index.js", "acme/mono@v2:tools/lint/src/index.js",
		"acme/js@v1:action.js", "acme/js@v1:index.js", "acme/js@v1:src/index.js",
	} {
		if n := stub.calls[key]; n != 0 {
			t.Errorf("%s read %d times, want 0: GitHub said it does not exist", key, n)
		}
	}
	for _, key := range []string{"acme/mono@v2:tools/lint/dist/index.js", "acme/mono@v2:tools/lint/dist/main.js", "acme/js@v1:dist/index.js"} {
		if n := stub.calls[key]; n != 1 {
			t.Errorf("%s read %d times, want 1", key, n)
		}
	}
}

// TestCandidateRefs_sealedFetcherSkipsUnadmittedNested: once the container
// budget is passed, the fetcher is sealed and a nested action the walk did
// not admit is never read (spec 4.3, R8), so the prefetch must not name
// it either. An admitted nested action and a workflow's own action are
// still asked about.
func TestCandidateRefs_sealedFetcherSkipsUnadmittedNested(t *testing.T) {
	defs := newDefinitionFetcher(nil, nil)
	defs.actions[containerKey("acme", "kept", "", "v1")] = actionDefinition{}
	defs.seal()
	p := &ir.NormalizedPipeline{Jobs: []ir.Job{{Uses: []ir.Action{
		{Uses: "acme/kept@v1", Nested: true},
		{Uses: "acme/cut@v1", Nested: true},
		{Uses: "acme/top@v1"},
	}}}}
	got := candidateRefs(p, defs)
	want := []candidateRef{
		{owner: "acme", repo: "kept", ref: "v1", paths: entrypointCandidates},
		{owner: "acme", repo: "top", ref: "v1", paths: entrypointCandidates},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidateRefs = %+v, want %+v", got, want)
	}
}
