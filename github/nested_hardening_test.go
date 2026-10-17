package github

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/getplumber/plumber/internal/ir"
)

// TestResolveNested_BudgetCutEntriesAreNeverEnriched pins spec 4.3 and R8
// (whole-branch review finding 3, coordinator ruling 3a): the container
// budget bounds the run's requests. One composite with 300 JavaScript
// children trips the budget at 100, and neither the mutable-exec scan nor
// the metadata enrichment reads a definition or a repository the walk did
// not admit.
func TestResolveNested_BudgetCutEntriesAreNeverEnriched(t *testing.T) {
	t.Setenv(EnvDisableGitHubAPI, "0")
	t.Setenv(EnvMetadataToken, "test-token")
	files := map[string]string{}
	var kids []string
	for i := range 300 {
		u := fmt.Sprintf("evil/leaf%d@v1", i)
		kids = append(kids, u)
		files[fmt.Sprintf("evil/leaf%d@v1:action.yml", i)] = "runs:\n  using: node20\n  main: index.js\n"
	}
	files["acme/b@v1:action.yml"] = composite(kids...)
	stub := newStub(files)
	var apiPaths []string
	client := stubbedMetadataClient(t, func(r *http.Request) (string, int) {
		apiPaths = append(apiPaths, r.URL.Path)
		return `{"message":"Not Found"}`, http.StatusNotFound
	})
	defs := newDefinitionFetcher(stub.fetch, client)
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "acme/app", Jobs: []ir.Job{oneJob("acme/b@v1")}}
	resolveNestedActions(p, defs, nestedScope{projectPath: "acme/app"})
	if !p.NestedBudgetExceeded {
		t.Fatal("300 children pass the budget of 100 containers")
	}
	cut := map[string]bool{}
	for _, u := range p.UnexpandedActions {
		if u.Reason == ir.UnexpandedBudget {
			cut[strings.TrimSuffix(u.Uses, "@v1")] = true
		}
	}
	if len(cut) != 300-MaxNestedContainers {
		t.Fatalf("want %d references cut by the budget, got %d", 300-MaxNestedContainers, len(cut))
	}
	enrichActions(p, client, defs, true, nil)
	for key, n := range stub.calls {
		if repo, _, _ := strings.Cut(key, "@"); cut[repo] && n > 0 {
			t.Fatalf("%s was read %d times, past the budget", key, n)
		}
	}
	for _, path := range apiPaths {
		for repo := range cut {
			if strings.Contains(path, "/repos/"+repo+"/") || strings.HasSuffix(path, "/repos/"+repo) {
				t.Fatalf("the metadata enrichment asked %s for a reference past the budget", path)
			}
		}
	}
	if d := defs.action("evil", "leaf299", "", "v1"); d.Status == fetchOK || stub.calls["evil/leaf299@v1:action.yml"] != 0 {
		t.Fatalf("past the budget the fetcher refuses a key the walk did not admit, got %+v", d)
	}
}

// TestResolveNested_OversizedDefinitionIsFetch pins coordinator ruling 3b:
// a remote definition is read with the workflow bound (1 MiB), past it the
// reference is listed with reason fetch, while an entrypoint keeps the
// mutable-exec scan's own bound.
func TestResolveNested_OversizedDefinitionIsFetch(t *testing.T) {
	big := composite() + "# " + strings.Repeat("x", 2<<20) + "\n"
	stub := newStub(map[string]string{
		"acme/b@v1:action.yml": composite("acme/c@v1"),
		"acme/c@v1:action.yml": big,
		"acme/c@v1:dist/x.js":  big,
	})
	p := resolveWith(t, stub, nestedScope{}, oneJob("acme/b@v1"))
	want := []ir.UnexpandedAction{{Uses: "acme/c@v1", Via: []string{"acme/b@v1"}, Reason: ir.UnexpandedFetch}}
	if len(p.UnexpandedActions) != 1 || p.UnexpandedActions[0].Uses != want[0].Uses || p.UnexpandedActions[0].Reason != want[0].Reason {
		t.Fatalf("a 2 MiB definition is reason fetch, got %+v", p.UnexpandedActions)
	}
	defs := newDefinitionFetcher(stub.fetch, nil)
	if _, st := defs.read("acme", "c", "v1", "dist/x.js"); st != fetchOK {
		t.Fatalf("an entrypoint keeps its own bound, got status %v", st)
	}
}

// TestResolveMutableExec_DropsTheDefinitionText pins coordinator ruling 3c:
// once the mutable-exec scan consumed a definition, the cache keeps its
// status and path only, so the run never holds every body to its end.
func TestResolveMutableExec_DropsTheDefinitionText(t *testing.T) {
	t.Setenv(EnvDisableGitHubAPI, "0")
	t.Setenv(EnvMetadataToken, "test-token")
	stub := newStub(map[string]string{
		"acme/b@v1:action.yml": "runs:\n  using: node20\n  main: index.js\n",
		"acme/b@v1:index.js":   "console.log(1)\n",
	})
	defs := newDefinitionFetcher(stub.fetch, nil)
	if d := defs.action("acme", "b", "", "v1"); d.Text == "" {
		t.Fatal("the walk reads the text")
	}
	resolveMutableExec("acme/b@v1", defs, map[string]*ir.MutableRemoteExec{})
	d := defs.actions[containerKey("acme", "b", "", "v1")]
	if d.Text != "" || d.Status != fetchOK || d.Path != "action.yml" {
		t.Fatalf("after the scan the cache keeps status and path only, got %+v", d)
	}
	if n := stub.calls["acme/b@v1:action.yml"]; n != 1 {
		t.Fatalf("the definition is read once, got %d", n)
	}
}

// TestResolveNested_InvalidReferencesAreNeverFetched pins SECURITY item 1
// and Task 1 ruling L4 (whole-branch review finding 4, coordinator ruling
// 4): an owner, repository, subpath or ref outside GitHub's grammar is
// never fetched, it is listed with reason fetch and named in a warning,
// while a valid reference with a subpath round-trips unchanged.
func TestResolveNested_InvalidReferencesAreNeverFetched(t *testing.T) {
	stub := newStub(map[string]string{
		"acme/b@v1:action.yml": composite("../../user?@x", "acme/c@v1#frag", "acme/../x@v1", "acme/d/sub/../../x@v1", "owner/repo/sub/path@v1"),
	})
	p := resolveWith(t, stub, nestedScope{}, oneJob("acme/b@v1"))
	for key := range stub.calls {
		if strings.Contains(key, "..") || strings.Contains(key, "#") || strings.Contains(key, "?") {
			t.Fatalf("an invalid reference was fetched: %s", key)
		}
	}
	if n := stub.calls["owner/repo@v1:sub/path/action.yml"]; n != 1 {
		t.Fatalf("a valid owner/repo/sub/path@v1 is read once at sub/path/action.yml, got %d (calls %v)", n, stub.calls)
	}
	var fetch []string
	for _, u := range p.UnexpandedActions {
		if u.Reason == ir.UnexpandedFetch {
			fetch = append(fetch, u.Uses)
			if !u.Invalid {
				t.Errorf("%s is listed without its invalid mark, the capped fetch warning names the reason from it", u.Uses)
			}
		}
	}
	slices.Sort(fetch)
	want := []string{"../../user?@x", "acme/../x@v1", "acme/c@v1#frag", "acme/d/sub/../../x@v1"}
	if !slices.Equal(fetch, want) {
		t.Fatalf("unexpanded fetch = %q, want %q", fetch, want)
	}
	if len(p.AdvisoryWarnings) != 0 {
		t.Errorf("an invalid reference adds no warning of its own (re-review N2), got %q", p.AdvisoryWarnings)
	}
}

// TestResolveNested_ThousandsOfInvalidStepsAddNoWarningLine pins the
// re-review N2: 3000 invalid steps add no advisory line of their own, each
// that is an entry is listed once with reason fetch and its invalid mark,
// so the capped fetch warning (ten lines, then one) is all the run prints.
func TestResolveNested_ThousandsOfInvalidStepsAddNoWarningLine(t *testing.T) {
	var kids []string
	for i := range 3000 {
		kids = append(kids, fmt.Sprintf("acme/c@v1#%d", i))
	}
	stub := newStub(map[string]string{"acme/b@v1:action.yml": composite(kids...)})
	p := resolveWith(t, stub, nestedScope{}, oneJob("acme/b@v1"))
	if len(p.AdvisoryWarnings) != 0 {
		t.Fatalf("3000 invalid steps add %d advisory lines, want 0", len(p.AdvisoryWarnings))
	}
	invalid := 0
	for _, u := range p.UnexpandedActions {
		if u.Invalid && u.Reason == ir.UnexpandedFetch {
			invalid++
		}
	}
	// Each step is an entry before its container is refused, so the per-job
	// entry bound keeps 1000 of them, the rest listed with reason budget.
	if invalid != MaxNestedEntriesPerJob {
		t.Fatalf("%d invalid references listed, want %d", invalid, MaxNestedEntriesPerJob)
	}
}

// TestResolveNested_OversizedFirstDefinitionIsThatReferenceOnly pins the
// re-review N1 (spec 4.3, R6, ruling M1): a definition past the 1 MiB bound
// is that reference's own outcome, reason fetch, even when it is the run's
// first remote read. It never stands for a network cause, so the rest of
// the closure keeps expanding and the run is not api_disabled.
func TestResolveNested_OversizedFirstDefinitionIsThatReferenceOnly(t *testing.T) {
	stub := newStub(map[string]string{
		"aaa/big@v1:action.yml":  composite() + "# " + strings.Repeat("x", 2<<20) + "\n",
		"acme/b@v1:action.yml":   composite("evil/c@main"),
		"evil/c@main:action.yml": composite(),
	})
	p := resolveWith(t, stub, nestedScope{}, oneJob("aaa/big@v1", "acme/b@v1"))
	if p.NestedUnresolvedCause != "" {
		t.Fatalf("an oversized definition is no run-wide cause, got %q", p.NestedUnresolvedCause)
	}
	if len(p.UnexpandedActions) != 1 || p.UnexpandedActions[0].Uses != "aaa/big@v1" || p.UnexpandedActions[0].Reason != ir.UnexpandedFetch {
		t.Fatalf("unexpanded = %+v, want aaa/big@v1 with reason fetch only", p.UnexpandedActions)
	}
	want := []string{
		"aaa/big@v1 |  |  | 10",
		"acme/b@v1 |  |  | 11",
		"evil/c@main | acme/b@v1 | acme/b@v1:action.yml:7 | 11",
	}
	if got := entries(p.Jobs[0]); !slices.Equal(got, want) {
		t.Fatalf("entries = %q, want %q", got, want)
	}
}

// TestResolveMutableExec_CaseVariantsReadTheDefinitionOnce pins the
// re-review N3 (ruling 3c, R8): the scan is memoised by the container key,
// owner and repo case-folded, so eight case variants of one reference read
// its definition once.
func TestResolveMutableExec_CaseVariantsReadTheDefinitionOnce(t *testing.T) {
	t.Setenv(EnvDisableGitHubAPI, "0")
	t.Setenv(EnvMetadataToken, "test-token")
	stub := newStub(map[string]string{
		"acme/b@v1:action.yml": "runs:\n  using: node20\n  main: index.js\n",
		"acme/b@v1:index.js":   "console.log(1)\n",
	})
	defs := newDefinitionFetcher(stub.fetch, nil)
	cache := map[string]*ir.MutableRemoteExec{}
	for _, u := range []string{"acme/b@v1", "Acme/b@v1", "ACME/b@v1", "acme/B@v1", "Acme/B@v1", "aCme/b@v1", "acMe/b@v1", "ACME/B@v1"} {
		resolveMutableExec(u, defs, cache)
	}
	reads := 0
	for key, n := range stub.calls {
		if strings.EqualFold(key, "acme/b@v1:action.yml") || strings.EqualFold(key, "acme/b@v1:action.yaml") {
			reads += n
		}
	}
	if reads != 1 {
		t.Fatalf("8 case variants read the definition %d times, want 1 (calls %v)", reads, stub.calls)
	}
}

// TestValidActionReference pins the grammar of coordinator ruling 4, one
// case per shape.
func TestValidActionReference(t *testing.T) {
	for _, tc := range []struct {
		owner, repo, subpath, ref string
		ok                        bool
	}{
		{"owner", "repo", "sub/path", "v1", true},
		{"my-org", "my.repo_x-1", "", "releases/v1.2", true},
		{"..", "..", "user?", "x", false},
		{"acme", "c", "", "v1#frag", false},
		{"acme", ".", "", "v1", false},
		{"acme", "..", "", "v1", false},
		{"acme", "d", "sub/../..", "v1", false},
		{strings.Repeat("a", 40), "r", "", "v1", false},
		{"under_score", "r", "", "v1", false},
		{"acme", "r", "", "", false},
		{"acme", "r", "", "a..b", false},
		{"acme", "r", "", "v1?x", false},
		{"acme", "r", "", "v%31", false},
		{"acme", "r", "", "v@{1}", false},
		{"acme", "r", "", `v\1`, false},
		{"acme", "r", "", "v 1", false},
		{"acme", "r", "", "v\x01", false},
	} {
		if got := validActionReference(tc.owner, tc.repo, tc.subpath, tc.ref); got != tc.ok {
			t.Errorf("validActionReference(%q, %q, %q, %q) = %v, want %v", tc.owner, tc.repo, tc.subpath, tc.ref, got, tc.ok)
		}
	}
}

// TestFetchFileContent_EscapesThePathAndTheRef pins coordinator ruling 4:
// the contents API path is built from escaped segments and the ref is a
// query value, so a `?` in a subpath never opens a query of its own.
func TestFetchFileContent_EscapesThePathAndTheRef(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.EscapedPath(), r.URL.RawQuery
		_, _ = w.Write([]byte(`{"encoding":"base64","content":"` + b64("x") + `"}`))
	}))
	rest := newTestRESTClient(t, srv)
	if _, err := fetchFileContent(rest, "victim", "private", "deploy/x.txt?/action.yml", "main"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/repos/victim/private/contents/deploy/x.txt%3F/action.yml" || gotQuery != "ref=main" {
		t.Fatalf("path %q query %q", gotPath, gotQuery)
	}
	if _, err := fetchFileContent(rest, "owner", "repo", "sub/path/action.yml", "releases/v1"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/repos/owner/repo/contents/sub/path/action.yml" || gotQuery != "ref=releases%2Fv1" {
		t.Fatalf("a valid reference round-trips: path %q query %q", gotPath, gotQuery)
	}
}

// TestRawContentURL_EscapesEverySegment pins coordinator ruling 4 on the
// raw host: every path segment is escaped, the ref keeps its slashes since
// it is a path there.
func TestRawContentURL_EscapesEverySegment(t *testing.T) {
	if got, want := rawContentURL("victim", "private", "main", "deploy/x.txt?/action.yml"), "https://raw.githubusercontent.com/victim/private/main/deploy/x.txt%3F/action.yml"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got, want := rawContentURL("owner", "repo", "releases/v1", "sub/path/action.yml"), "https://raw.githubusercontent.com/owner/repo/releases/v1/sub/path/action.yml"; got != want {
		t.Fatalf("a valid reference round-trips: got %q, want %q", got, want)
	}
}

// TestDefinitionFetcher_ContentsFallbackHasADeadline pins SECURITY item 1
// (whole-branch review finding 7, coordinator ruling 7): a stalled contents
// API answer ends at the fallback's deadline as a fetch error, never a hang.
func TestDefinitionFetcher_ContentsFallbackHasADeadline(t *testing.T) {
	t.Setenv(EnvDisableGitHubAPI, "0")
	saved := contentsFetchTimeout
	contentsFetchTimeout = 50 * time.Millisecond
	t.Cleanup(func() { contentsFetchTimeout = saved })
	srv := httptestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	defs := newDefinitionFetcher(nil, nil)
	defs.rest = newTestRESTClient(t, srv)
	start := time.Now()
	if _, st := defs.read("acme", "b", "v1", "action.yml"); st != fetchError {
		t.Fatalf("a stalled fallback is a fetch error, got %v", st)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the fallback waited %s past its deadline", d)
	}
}

// aliasedEntry resolves one job calling acme/b@v1, whose definition is
// text, and returns the entry of evil/exfil@main the splice appended.
func aliasedEntry(t *testing.T, text string) (ir.Action, bool) {
	t.Helper()
	p := resolveWith(t, newStub(map[string]string{"acme/b@v1:action.yml": text}), nestedScope{}, oneJob("acme/b@v1"))
	for _, a := range p.Jobs[0].Uses {
		if a.Uses == "evil/exfil@main" {
			return a, true
		}
	}
	return ir.Action{}, false
}

// TestResolveNested_AliasedUsesIsSpliced pins the review of PR 549 (the
// alias evasion): a step whose uses: is an alias of an anchor hung on a
// previous step's name: scalar runs the referenced action, so it is spliced
// in at the alias's own line, never dropped.
func TestResolveNested_AliasedUsesIsSpliced(t *testing.T) {
	a, ok := aliasedEntry(t, "runs:\n  using: composite\n  steps:\n    - name: &ref evil/exfil@main\n      run: echo setup\n      shell: bash\n    - uses: *ref\n")
	if !ok {
		t.Fatal("uses: *ref resolves to evil/exfil@main and is spliced in")
	}
	if !a.Nested || a.DefinedIn != "acme/b@v1:action.yml:7" || !slices.Equal(a.Via, []string{"acme/b@v1"}) {
		t.Fatalf("the aliased step is a nested entry defined at its own line, got %+v", a)
	}
}

// TestResolveNested_WholeStepAliasIsSpliced pins the review of PR 549: a
// whole-step alias (- *step) runs the anchored mapping, so it is spliced in
// at the alias's own line, the step the runner executes.
func TestResolveNested_WholeStepAliasIsSpliced(t *testing.T) {
	a, ok := aliasedEntry(t, "runs:\n  using: composite\n  steps:\n    - uses: acme/ok@v1\n      with: &step\n        uses: evil/exfil@main\n    - *step\n")
	if !ok {
		t.Fatal("- *step resolves to evil/exfil@main and is spliced in")
	}
	if a.DefinedIn != "acme/b@v1:action.yml:7" {
		t.Fatalf("a whole-step alias is defined at the alias's own line, got %q", a.DefinedIn)
	}
}

// TestResolveNested_MergeKeyUsesIsSpliced pins the review of PR 549: a
// <<: *base merge key contributing uses: runs the merged action, so it is
// spliced in at the step's own line.
func TestResolveNested_MergeKeyUsesIsSpliced(t *testing.T) {
	a, ok := aliasedEntry(t, "runs:\n  using: composite\n  steps:\n    - uses: acme/ok@v1\n      with: &base\n        uses: evil/exfil@main\n    - <<: *base\n      name: merged\n")
	if !ok {
		t.Fatal("<<: *base contributes uses: evil/exfil@main, spliced in")
	}
	if a.DefinedIn != "acme/b@v1:action.yml:7" || a.Name != "merged" {
		t.Fatalf("a merged step is defined at its own line with its own name, got %+v", a)
	}
}

// TestParseCompositeSteps_AliasBombsFailCleanly pins the review of PR 549:
// a self-referential anchor or an exponential alias structure ends as a
// parse error, fast and bounded, and the container is listed unexpanded
// with reason fetch, never a hang or a silent pass.
func TestParseCompositeSteps_AliasBombsFailCleanly(t *testing.T) {
	var laughs strings.Builder
	laughs.WriteString("runs:\n  using: composite\n  steps:\n    - uses: acme/ok@v1\n      with:\n        l0: &l0 [x, x, x, x, x, x, x, x, x, x]\n")
	for i := 1; i < 9; i++ {
		p := fmt.Sprintf("*l%d", i-1)
		fmt.Fprintf(&laughs, "        l%d: &l%d [%s]\n", i, i, strings.Join(slices.Repeat([]string{p}, 10), ", "))
	}
	laughs.WriteString("    - uses: acme/two@v1\n      with:\n        all: *l8\n")
	cases := map[string]string{
		"self-referential": "runs:\n  using: composite\n  steps:\n    - &loop\n      uses: acme/ok@v1\n      with:\n        self: *loop\n",
		"exponential":      laughs.String(),
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			if _, _, err := parseCompositeSteps(text); err == nil {
				t.Fatal("the alias structure is a parse error")
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Fatalf("the parse took %s", d)
			}
			p := resolveWith(t, newStub(map[string]string{"acme/b@v1:action.yml": text}), nestedScope{}, oneJob("acme/b@v1"))
			if len(p.UnexpandedActions) != 1 || p.UnexpandedActions[0].Uses != "acme/b@v1" || p.UnexpandedActions[0].Reason != ir.UnexpandedFetch {
				t.Fatalf("the container is listed with reason fetch, got %+v", p.UnexpandedActions)
			}
		})
	}
}
