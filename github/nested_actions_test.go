package github

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// stubDefinitions serves action files keyed "owner/repo@ref:path" and
// counts every read, so a test can assert one request per container.
type stubDefinitions struct {
	files map[string]string
	errs  map[string]bool
	calls map[string]int
}

func newStub(files map[string]string) *stubDefinitions {
	return &stubDefinitions{files: files, errs: map[string]bool{}, calls: map[string]int{}}
}

func (s *stubDefinitions) fetch(owner, repo, ref, p string) (string, fetchStatus) {
	key := owner + "/" + repo + "@" + ref + ":" + p
	s.calls[key]++
	if s.errs[key] {
		return "", fetchError
	}
	if v, ok := s.files[key]; ok {
		return v, fetchOK
	}
	return "", fetchMissing
}

// composite renders a composite action.yml whose `uses:` steps start at
// line 7, one per line: name, runs, using, steps, then a run step on 5-6.
func composite(uses ...string) string {
	var b strings.Builder
	b.WriteString("name: x\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo hi\n")
	for _, u := range uses {
		b.WriteString("    - uses: " + u + "\n")
	}
	return b.String()
}

// resolveWith runs the stage over jobs with the stub as the raw host, the
// API on and a token present (so an absent file is a leaf, spec 4.3).
func resolveWith(t *testing.T, stub *stubDefinitions, scope nestedScope, jobs ...ir.Job) *ir.NormalizedPipeline {
	t.Helper()
	t.Setenv(EnvDisableGitHubAPI, "0")
	t.Setenv(EnvMetadataToken, "test-token")
	if scope.projectPath == "" {
		scope.projectPath = "acme/app"
	}
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: scope.projectPath, Jobs: jobs}
	resolveNestedActions(p, newDefinitionFetcher(stub.fetch, nil), scope)
	return p
}

// entry renders one resolved entry for comparison: uses | via | definedIn | line.
func entry(a ir.Action) string {
	return a.Uses + " | " + strings.Join(a.Via, " > ") + " | " + a.DefinedIn + " | " + strconv.Itoa(a.Line)
}

func entries(job ir.Job) []string {
	out := make([]string, 0, len(job.Uses))
	for _, a := range job.Uses {
		out = append(out, entry(a))
	}
	return out
}

func oneJob(uses ...string) ir.Job {
	j := ir.Job{Name: "ci/build", OriginFile: ".github/workflows/ci.yml"}
	for i, u := range uses {
		j.Uses = append(j.Uses, ir.Action{Uses: u, Line: 10 + i})
	}
	return j
}

func httptestServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s
}

// TestResolveNested_ReproductionChainInRunnerOrder pins spec 3.1 on the
// shape of the reproduction: A uses B, B uses C and D, D uses E. The
// nested entries follow the entry that pulled them in, in the order the
// container declares them, at the workflow step's line (R9).
func TestResolveNested_ReproductionChainInRunnerOrder(t *testing.T) {
	stub := newStub(map[string]string{
		"acme/b@main:action.yml": composite("acme/c@main", "acme/d@main"),
		"acme/c@main:action.yml": composite(),
		"acme/d@main:action.yml": composite("acme/e@main"),
		"acme/e@main:action.yml": composite(),
	})
	p := resolveWith(t, stub, nestedScope{}, oneJob("acme/b@main"))
	want := []string{
		"acme/b@main |  |  | 10",
		"acme/c@main | acme/b@main | acme/b@main:action.yml:7 | 10",
		"acme/d@main | acme/b@main | acme/b@main:action.yml:8 | 10",
		"acme/e@main | acme/b@main > acme/d@main | acme/d@main:action.yml:7 | 10",
	}
	if got := entries(p.Jobs[0]); !slices.Equal(got, want) {
		t.Fatalf("resolved entries:\n got %q\nwant %q", got, want)
	}
	for _, a := range p.Jobs[0].Uses[1:] {
		if !a.Nested {
			t.Errorf("%s must be nested", a.Uses)
		}
	}
	if p.Jobs[0].Uses[0].Nested || len(p.UnexpandedActions) != 0 || p.NestedBudgetExceeded || p.NestedUnresolvedCause != "" {
		t.Fatalf("a healthy closure leaves the direct entry direct and lists nothing: %+v", p)
	}
}

// TestResolveNested_CycleTerminates pins spec 4.3: A uses B, B uses A
// terminates, every reference listed once.
func TestResolveNested_CycleTerminates(t *testing.T) {
	stub := newStub(map[string]string{
		"acme/a@v1:action.yml": composite("acme/b@v1"),
		"acme/b@v1:action.yml": composite("acme/a@v1"),
	})
	p := resolveWith(t, stub, nestedScope{}, oneJob("acme/a@v1"))
	want := []string{
		"acme/a@v1 |  |  | 10",
		"acme/b@v1 | acme/a@v1 | acme/a@v1:action.yml:7 | 10",
	}
	if got := entries(p.Jobs[0]); !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	if stub.calls["acme/a@v1:action.yml"] != 1 || stub.calls["acme/b@v1:action.yml"] != 1 {
		t.Fatalf("a cycle costs one fetch per container, got %v", stub.calls)
	}
}

// TestResolveNested_DiamondFetchedOnce pins spec 4.3 and R5: two paths
// to E are two entries, E is fetched once for the whole run.
func TestResolveNested_DiamondFetchedOnce(t *testing.T) {
	stub := newStub(map[string]string{
		"acme/b@v1:action.yml": composite("acme/c@v1", "acme/d@v1"),
		"acme/c@v1:action.yml": composite("acme/e@v1"),
		"acme/d@v1:action.yml": composite("acme/e@v1"),
		"acme/e@v1:action.yml": composite(),
	})
	other := ir.Job{Name: "ci/other", Uses: []ir.Action{{Uses: "acme/e@v1", Line: 3}}}
	p := resolveWith(t, stub, nestedScope{}, oneJob("acme/b@v1"), other)
	var paths []string
	for _, a := range p.Jobs[0].Uses {
		if a.Uses == "acme/e@v1" {
			paths = append(paths, strings.Join(a.Via, " > "))
		}
	}
	if !slices.Equal(paths, []string{"acme/b@v1 > acme/c@v1", "acme/b@v1 > acme/d@v1"}) {
		t.Fatalf("two paths to E, got %q", paths)
	}
	if n := stub.calls["acme/e@v1:action.yml"]; n != 1 {
		t.Fatalf("E fetched %d times, want 1", n)
	}
}

// TestResolveNested_BudgetOverflowListsTheRest pins R3 and R8: the 101st
// new container is not fetched, it is listed with reason budget, and the
// pipeline says the budget was exceeded. The direct reference is not counted.
func TestResolveNested_BudgetOverflowListsTheRest(t *testing.T) {
	files := map[string]string{}
	var children []string
	for i := 1; i <= MaxNestedContainers+1; i++ {
		children = append(children, "acme/x"+strconv.Itoa(i)+"@v1")
		files["acme/x"+strconv.Itoa(i)+"@v1:action.yml"] = composite()
	}
	files["acme/root@v1:action.yml"] = composite(children...)
	stub := newStub(files)
	p := resolveWith(t, stub, nestedScope{}, oneJob("acme/root@v1"))
	if !p.NestedBudgetExceeded {
		t.Fatal("past MaxNestedContainers the pipeline must say the budget was exceeded")
	}
	last := children[len(children)-1]
	if len(p.UnexpandedActions) != 1 || p.UnexpandedActions[0].Uses != last || p.UnexpandedActions[0].Reason != ir.UnexpandedBudget || !slices.Equal(p.UnexpandedActions[0].Via, []string{"acme/root@v1"}) {
		t.Fatalf("unexpanded = %+v, want %s via acme/root@v1 (budget)", p.UnexpandedActions, last)
	}
	if stub.calls[last[:strings.Index(last, "@")]+"@v1:action.yml"] != 0 {
		t.Fatal("the container past the budget must not be fetched")
	}
	if got := len(p.Jobs[0].Uses); got != MaxNestedContainers+2 {
		t.Fatalf("the root and its %d steps stay entries, got %d", MaxNestedContainers+1, got)
	}
}

// TestResolveNested_FetchErrorWarnsWithoutDegrading pins spec 4.3: one
// failed fetch, the API otherwise answering, is reason fetch, the
// reference stays an entry, the budget is not exceeded, no R6 cause.
func TestResolveNested_FetchErrorWarnsWithoutDegrading(t *testing.T) {
	stub := newStub(map[string]string{"acme/b@v1:action.yml": composite("acme/c@v1")})
	stub.errs["acme/c@v1:action.yml"] = true
	p := resolveWith(t, stub, nestedScope{}, oneJob("acme/b@v1"))
	if len(p.Jobs[0].Uses) != 2 || p.Jobs[0].Uses[1].Uses != "acme/c@v1" {
		t.Fatalf("the unreadable reference is still judged, got %q", entries(p.Jobs[0]))
	}
	if len(p.UnexpandedActions) != 1 || p.UnexpandedActions[0].Reason != ir.UnexpandedFetch || p.UnexpandedActions[0].Uses != "acme/c@v1" {
		t.Fatalf("unexpanded = %+v", p.UnexpandedActions)
	}
	if p.NestedBudgetExceeded || p.NestedUnresolvedCause != "" {
		t.Fatal("one failed fetch neither degrades nor marks the closure unresolved")
	}
}

// TestResolveNested_ExpressionRecordedNeverFetched pins spec 3.3.
func TestResolveNested_ExpressionRecordedNeverFetched(t *testing.T) {
	stub := newStub(map[string]string{"acme/b@v1:action.yml": composite("${{ inputs.action }}")})
	p := resolveWith(t, stub, nestedScope{}, oneJob("acme/b@v1"))
	if len(p.Jobs[0].Uses) != 1 {
		t.Fatalf("an expression is never an entry, got %q", entries(p.Jobs[0]))
	}
	if len(p.UnexpandedActions) != 1 || p.UnexpandedActions[0].Uses != "${{ inputs.action }}" || p.UnexpandedActions[0].Reason != ir.UnexpandedExpression || !slices.Equal(p.UnexpandedActions[0].Via, []string{"acme/b@v1"}) {
		t.Fatalf("unexpanded = %+v", p.UnexpandedActions)
	}
	for key := range stub.calls {
		if strings.Contains(key, "${{") {
			t.Fatalf("an expression must never be fetched, got %q", key)
		}
	}
}

// TestResolveNested_RelativeIsTheScannedWorkspace pins spec 3.3 as ruled
// by the live probe of 2026-10-16: the runner resolves `./x` inside a
// remote composite against the job's workspace, the scanned repository's
// checkout. B's `./.github/actions/local` present in the SCANNED
// repository expands from there, an absent one is a silent leaf, and B's
// own repository is never read for either.
func TestResolveNested_RelativeIsTheScannedWorkspace(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "actions", "local")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "action.yml"), []byte(composite("acme/e@v1")), 0o600); err != nil {
		t.Fatal(err)
	}
	stub := newStub(map[string]string{
		"acme/b@v1:action.yml":                       composite("./.github/actions/local", "./.github/actions/absent"),
		"acme/b@v1:.github/actions/local/action.yml": composite("evil/never@v1"),
		"acme/e@v1:action.yml":                       composite(),
	})
	p := resolveWith(t, stub, nestedScope{readLocal: diskReader(root), localOnDisk: true}, oneJob("acme/b@v1"))
	want := []string{
		"acme/b@v1 |  |  | 10",
		"./.github/actions/local | acme/b@v1 | acme/b@v1:action.yml:7 | 10",
		"acme/e@v1 | acme/b@v1 > ./.github/actions/local | ./.github/actions/local/action.yml:7 | 10",
		"./.github/actions/absent | acme/b@v1 | acme/b@v1:action.yml:8 | 10",
	}
	if got := entries(p.Jobs[0]); !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for key, n := range stub.calls {
		if strings.HasPrefix(key, "acme/b@v1:.github/") && n > 0 {
			t.Fatalf("a relative reference never reads the container's repository, got %q", key)
		}
	}
	if len(p.UnexpandedActions) != 0 {
		t.Fatalf("an absent workspace path is a silent leaf, got %+v", p.UnexpandedActions)
	}
}

// TestResolveNested_LocalCompositeFromDisk pins spec 3.3 in local mode:
// a vendored composite is read from disk, not counted, and what it pulls
// in becomes visible.
func TestResolveNested_LocalCompositeFromDisk(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "actions", "x")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "action.yml"), []byte(composite("evil/e@main")), 0o600); err != nil {
		t.Fatal(err)
	}
	stub := newStub(map[string]string{"evil/e@main:action.yml": composite()})
	p := resolveWith(t, stub, nestedScope{readLocal: diskReader(root), localOnDisk: true}, oneJob("./.github/actions/x"))
	want := []string{
		"./.github/actions/x |  |  | 10",
		"evil/e@main | ./.github/actions/x | ./.github/actions/x/action.yml:7 | 10",
	}
	if got := entries(p.Jobs[0]); !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestResolveNested_LocalCompositeExpandsOffline pins R6 in local mode
// (review of PR 549): with the offline switch on, the scanned
// repository's own composite is still read from disk and what it nests is
// spliced in with its provenance, while nothing is fetched remotely.
func TestResolveNested_LocalCompositeExpandsOffline(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "actions", "x")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "action.yml"), []byte(composite("evil/e@main")), 0o600); err != nil {
		t.Fatal(err)
	}
	stub := newStub(map[string]string{"evil/e@main:action.yml": composite()})
	t.Setenv(EnvMetadataToken, "test-token")
	t.Setenv(EnvDisableGitHubAPI, "1")
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "acme/app", Jobs: []ir.Job{oneJob("./.github/actions/x")}}
	resolveNestedActions(p, newDefinitionFetcher(stub.fetch, nil), nestedScope{projectPath: "acme/app", readLocal: diskReader(root), localOnDisk: true})
	want := []string{
		"./.github/actions/x |  |  | 10",
		"evil/e@main | ./.github/actions/x | ./.github/actions/x/action.yml:7 | 10",
	}
	if got := entries(p.Jobs[0]); !slices.Equal(got, want) {
		t.Fatalf("the local composite expands offline:\n got %q\nwant %q", got, want)
	}
	if len(stub.calls) != 0 {
		t.Fatalf("no remote read is attempted offline, got %v", stub.calls)
	}
	// The nested remote reference cannot be read offline: R6 names the
	// switch and lists it api_disabled with its chain, never a budget.
	if p.NestedUnresolvedCause != "the GitHub API is disabled ("+EnvDisableGitHubAPI+")" || p.NestedBudgetExceeded {
		t.Fatalf("R6 names the offline switch and never degrades: %+v", p)
	}
	if len(p.UnexpandedActions) != 1 || p.UnexpandedActions[0].Uses != "evil/e@main" || p.UnexpandedActions[0].Reason != ir.UnexpandedAPIDisabled || !slices.Equal(p.UnexpandedActions[0].Via, []string{"./.github/actions/x"}) {
		t.Fatalf("unexpanded = %+v, want evil/e@main (api_disabled) via ./.github/actions/x", p.UnexpandedActions)
	}
}

// TestResolveNested_LocalOnlyClosureOfflineHasNoCause pins R6 in local
// mode (review of PR 549): a local composite that nests only another
// local composite needs no remote read, so the offline switch names no
// cause and lists nothing.
func TestResolveNested_LocalOnlyClosureOfflineHasNoCause(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{"x": composite("./.github/actions/y"), "y": composite()} {
		dir := filepath.Join(root, ".github", "actions", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "action.yml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stub := newStub(nil)
	t.Setenv(EnvMetadataToken, "test-token")
	t.Setenv(EnvDisableGitHubAPI, "1")
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "acme/app", Jobs: []ir.Job{oneJob("./.github/actions/x")}}
	resolveNestedActions(p, newDefinitionFetcher(stub.fetch, nil), nestedScope{projectPath: "acme/app", readLocal: diskReader(root), localOnDisk: true})
	want := []string{
		"./.github/actions/x |  |  | 10",
		"./.github/actions/y | ./.github/actions/x | ./.github/actions/x/action.yml:7 | 10",
	}
	if got := entries(p.Jobs[0]); !slices.Equal(got, want) {
		t.Fatalf("the local closure expands offline:\n got %q\nwant %q", got, want)
	}
	if len(stub.calls) != 0 || p.NestedUnresolvedCause != "" || len(p.UnexpandedActions) != 0 || p.NestedBudgetExceeded {
		t.Fatalf("a local-only closure reads nothing remotely and names no cause: calls %v, %+v", stub.calls, p)
	}
}

// TestResolveNested_LocalCompositeRemoteMode pins spec 3.3 in remote
// mode: the scanned repository's composites are read through the contents
// API at the scanned ref.
func TestResolveNested_LocalCompositeRemoteMode(t *testing.T) {
	const ciYAML = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/x\n"
	serve := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"encoding":"base64","content":"` + b64(body) + `"}`))
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/acme/app/contents/.github/workflows", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"name":"ci.yml","path":".github/workflows/ci.yml","type":"file"}]`))
	})
	mux.HandleFunc("/repos/acme/app/contents/.github/workflows/ci.yml", serve(ciYAML))
	mux.HandleFunc("/repos/acme/app/contents/.github/actions/x/action.yml", serve(composite("./.github/actions/y")))
	mux.HandleFunc("/repos/acme/app/contents/.github/actions/y/action.yml", serve(composite()))
	swapRESTClient(t, httptestServer(t, mux))

	p, partial, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil)
	if err != nil || len(partial) != 0 {
		t.Fatalf("scan: %v %v", err, partial)
	}
	want := []string{
		"./.github/actions/x |  |  | 6",
		"./.github/actions/y | ./.github/actions/x | ./.github/actions/x/action.yml:7 | 6",
	}
	if got := entries(p.Jobs[0]); !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestResolveNested_TrustedCompositeExpanded pins R4: collection is
// uniform, a GitHub-owned composite is fetched and expanded like any other.
func TestResolveNested_TrustedCompositeExpanded(t *testing.T) {
	stub := newStub(map[string]string{"github/codeql-action@v3:init/action.yml": composite("third-party/x@main")})
	p := resolveWith(t, stub, nestedScope{}, oneJob("github/codeql-action/init@v3"))
	if len(p.Jobs[0].Uses) != 2 || p.Jobs[0].Uses[1].Uses != "third-party/x@main" || !slices.Equal(p.Jobs[0].Uses[1].Via, []string{"github/codeql-action/init@v3"}) {
		t.Fatalf("the trusted composite's child must be an entry, got %q", entries(p.Jobs[0]))
	}
}

// TestResolveNested_NoAPIScoresOnDirectReferences pins R6 at collection:
// with the offline switch the closure is unresolved, every direct
// reference is listed api_disabled, nothing is appended, the cause is named.
func TestResolveNested_NoAPIScoresOnDirectReferences(t *testing.T) {
	stub := newStub(map[string]string{"acme/b@v1:action.yml": composite("acme/c@v1")})
	t.Setenv(EnvMetadataToken, "test-token")
	t.Setenv(EnvDisableGitHubAPI, "1")
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "acme/app", Jobs: []ir.Job{oneJob("acme/b@v1", "docker://alpine:3")}}
	resolveNestedActions(p, newDefinitionFetcher(stub.fetch, nil), nestedScope{projectPath: "acme/app"})
	if len(p.Jobs[0].Uses) != 2 {
		t.Fatalf("nothing is appended without the API, got %q", entries(p.Jobs[0]))
	}
	if p.NestedUnresolvedCause == "" || p.NestedBudgetExceeded {
		t.Fatalf("R6 names a cause and never degrades: %+v", p)
	}
	if len(p.UnexpandedActions) != 1 || p.UnexpandedActions[0].Uses != "acme/b@v1" || p.UnexpandedActions[0].Reason != ir.UnexpandedAPIDisabled {
		t.Fatalf("unexpanded = %+v", p.UnexpandedActions)
	}
}

// TestResolveNested_MutableExecReusesTheDefinition pins spec 4.2: the
// mutable-exec scan reads the definition the walk fetched, one request
// for each container's action.yml for the whole run.
func TestResolveNested_MutableExecReusesTheDefinition(t *testing.T) {
	stub := newStub(map[string]string{
		"acme/b@v1:action.yml": composite("acme/c@v1"),
		"acme/c@v1:action.yml": composite(),
	})
	t.Setenv(EnvDisableGitHubAPI, "0")
	t.Setenv(EnvMetadataToken, "test-token")
	client := stubbedMetadataClient(t, func(*http.Request) (string, int) { return `{}`, http.StatusNotFound })
	defs := newDefinitionFetcher(stub.fetch, client)
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "acme/app", Jobs: []ir.Job{oneJob("acme/b@v1")}}
	resolveNestedActions(p, defs, nestedScope{projectPath: "acme/app"})
	enrichActions(p, client, defs, true, nil)
	for _, key := range []string{"acme/b@v1:action.yml", "acme/c@v1:action.yml"} {
		if n := stub.calls[key]; n != 1 {
			t.Errorf("%s read %d times, want 1 (walk and mutable-exec scan share the fetch)", key, n)
		}
	}
}

// TestCountUniqueActionRefs_CountsTheClosure pins spec 4.1: the progress
// total counts the closure.
func TestCountUniqueActionRefs_CountsTheClosure(t *testing.T) {
	stub := newStub(map[string]string{
		"acme/b@main:action.yml": composite("acme/c@main", "acme/d@main"),
		"acme/d@main:action.yml": composite("acme/e@main"),
	})
	p := resolveWith(t, stub, nestedScope{}, oneJob("acme/b@main"))
	if n := countUniqueActionRefs(p); n != 4 {
		t.Fatalf("countUniqueActionRefs = %d, want 4", n)
	}
	if n := TotalProgressStepsForPipeline(p); n != 8 {
		t.Fatalf("TotalProgressStepsForPipeline = %d, want 8", n)
	}
}

// TestParseCompositeSteps_LinesAndLeaves pins spec 4.2: runs.using ==
// composite yields the uses steps in order with their lines, any other
// runs.using is a leaf (R2).
func TestParseCompositeSteps_LinesAndLeaves(t *testing.T) {
	ok, steps, err := parseCompositeSteps("runs:\n  using: composite\n  steps:\n    - name: Setup\n      uses: acme/setup@abc # v1.2.0\n      with:\n        token: ${{ inputs.token }}\n    - run: echo\n      shell: bash\n    - uses: acme/two@v2\n")
	if err != nil || !ok || len(steps) != 2 {
		t.Fatalf("composite: ok=%v err=%v steps=%+v", ok, err, steps)
	}
	if steps[0].uses != "acme/setup@abc" || steps[0].line != 5 || steps[0].name != "Setup" || steps[0].comment != "v1.2.0" || steps[0].with["token"] != "${{ inputs.token }}" {
		t.Fatalf("first step = %+v", steps[0])
	}
	if steps[1].uses != "acme/two@v2" || steps[1].line != 10 {
		t.Fatalf("second step = %+v", steps[1])
	}
	if ok, steps, err := parseCompositeSteps("runs:\n  using: node20\n  main: dist/index.js\n"); ok || steps != nil || err != nil {
		t.Fatalf("a JavaScript action is a leaf, got ok=%v steps=%v err=%v", ok, steps, err)
	}
}

// noToken clears every token the fetcher reads, the API on.
func noToken(t *testing.T) {
	t.Helper()
	t.Setenv(EnvDisableGitHubAPI, "0")
	for _, k := range []string{EnvMetadataToken, "GH_TOKEN", "GITHUB_TOKEN"} {
		t.Setenv(k, "")
	}
}

// TestResolveNested_LaterMissingWithoutTokenIsThatReferenceOnly pins
// coordinator ruling M1 (round 1): past the first remote read, a missing
// definition with no token is that reference alone, reason fetch. B's
// other children stay, no R6 cause, not degraded.
func TestResolveNested_LaterMissingWithoutTokenIsThatReferenceOnly(t *testing.T) {
	noToken(t)
	stub := newStub(map[string]string{
		"acme/b@v1:action.yml": composite("acme/c@v1", "evil/missing@v1"),
		"acme/c@v1:action.yml": composite(),
	})
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "acme/app", Jobs: []ir.Job{oneJob("acme/b@v1")}}
	resolveNestedActions(p, newDefinitionFetcher(stub.fetch, nil), nestedScope{projectPath: "acme/app"})
	want := []string{
		"acme/b@v1 |  |  | 10",
		"acme/c@v1 | acme/b@v1 | acme/b@v1:action.yml:7 | 10",
		"evil/missing@v1 | acme/b@v1 | acme/b@v1:action.yml:8 | 10",
	}
	if got := entries(p.Jobs[0]); !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	if p.NestedUnresolvedCause != "" || p.NestedBudgetExceeded {
		t.Fatalf("a later missing read neither unresolves nor degrades: cause %q, overflow %v", p.NestedUnresolvedCause, p.NestedBudgetExceeded)
	}
	if len(p.UnexpandedActions) != 1 || p.UnexpandedActions[0].Uses != "evil/missing@v1" || p.UnexpandedActions[0].Reason != ir.UnexpandedFetch || !slices.Equal(p.UnexpandedActions[0].Via, []string{"acme/b@v1"}) {
		t.Fatalf("unexpanded = %+v, want evil/missing@v1 via acme/b@v1 (fetch)", p.UnexpandedActions)
	}
}

// TestResolveNested_FirstMissingWithoutTokenUnresolves pins ruling M1 and
// R6: the FIRST remote read answering missing with no token leaves the
// whole closure unresolved, the direct reference listed api_disabled.
func TestResolveNested_FirstMissingWithoutTokenUnresolves(t *testing.T) {
	noToken(t)
	stub := newStub(map[string]string{"acme/c@v1:action.yml": composite()})
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "acme/app", Jobs: []ir.Job{oneJob("acme/private@v1", "acme/c@v1")}}
	resolveNestedActions(p, newDefinitionFetcher(stub.fetch, nil), nestedScope{projectPath: "acme/app"})
	if p.NestedUnresolvedCause == "" || p.NestedBudgetExceeded {
		t.Fatalf("R6 names a cause and never degrades: cause %q, overflow %v", p.NestedUnresolvedCause, p.NestedBudgetExceeded)
	}
	if len(p.Jobs[0].Uses) != 2 {
		t.Fatalf("nothing is appended, got %q", entries(p.Jobs[0]))
	}
}

// TestResolveNested_FirstFetchErrorUnresolves pins spec section 7 (R6),
// review of PR 549: the FIRST remote read of the run answering fetchError
// (rate limit or network) leaves the whole closure unresolved, same as a
// missing file with no token, the direct reference listed api_disabled.
func TestResolveNested_FirstFetchErrorUnresolves(t *testing.T) {
	stub := newStub(nil)
	stub.errs["acme/x@v1:action.yml"] = true
	p := resolveWith(t, stub, nestedScope{}, oneJob("acme/x@v1"))
	if p.NestedUnresolvedCause != "the first action definition could not be fetched (rate limit or network)" {
		t.Fatalf("cause = %q, want the first-read fetchError sentence", p.NestedUnresolvedCause)
	}
	if p.NestedBudgetExceeded {
		t.Fatal("a first-read fetch error is R6, never the budget")
	}
	if len(p.Jobs[0].Uses) != 1 {
		t.Fatalf("nothing is appended, got %q", entries(p.Jobs[0]))
	}
	if len(p.UnexpandedActions) != 1 || p.UnexpandedActions[0].Uses != "acme/x@v1" || p.UnexpandedActions[0].Reason != ir.UnexpandedAPIDisabled {
		t.Fatalf("unexpanded = %+v, want acme/x@v1 (api_disabled)", p.UnexpandedActions)
	}
}

// TestResolveNested_OversizedLocalCompositeIsFetch pins spec 4.3 (review
// L1): a local composite the reader refuses (past maxWorkflowFileBytes) is
// reason fetch, never a silent leaf.
func TestResolveNested_OversizedLocalCompositeIsFetch(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "actions", "x")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	big := composite("evil/e@main") + "# " + strings.Repeat("x", maxWorkflowFileBytes) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "action.yml"), []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	p := resolveWith(t, newStub(nil), nestedScope{readLocal: diskReader(root), localOnDisk: true}, oneJob("./.github/actions/x"))
	if len(p.Jobs[0].Uses) != 1 {
		t.Fatalf("an unreadable composite appends nothing, got %q", entries(p.Jobs[0]))
	}
	if len(p.UnexpandedActions) != 1 || p.UnexpandedActions[0].Uses != "./.github/actions/x" || p.UnexpandedActions[0].Reason != ir.UnexpandedFetch {
		t.Fatalf("unexpanded = %+v, want ./.github/actions/x (fetch)", p.UnexpandedActions)
	}
}

// TestResolveNested_EntriesPerJobBound pins coordinator ruling 5: a
// two-wide lattice of 12 levels (24 containers, 4,094 paths) stops at
// MaxNestedEntriesPerJob appended entries, lists the rest with reason
// budget and records the overflow (R3).
func TestResolveNested_EntriesPerJobBound(t *testing.T) {
	files := map[string]string{}
	name := func(level int, side string) string { return "acme/l" + strconv.Itoa(level) + side + "@v1" }
	for level := 1; level <= 12; level++ {
		for _, side := range []string{"a", "b"} {
			key := strings.TrimSuffix(name(level, side), "@v1") + "@v1:action.yml"
			if level == 12 {
				files[key] = composite()
				continue
			}
			files[key] = composite(name(level+1, "a"), name(level+1, "b"))
		}
	}
	p := resolveWith(t, newStub(files), nestedScope{}, oneJob(name(1, "a")))
	if got := len(p.Jobs[0].Uses); got != 1+MaxNestedEntriesPerJob {
		t.Fatalf("len(Uses) = %d, want %d", got, 1+MaxNestedEntriesPerJob)
	}
	if !p.NestedBudgetExceeded {
		t.Fatal("past MaxNestedEntriesPerJob the pipeline must say the budget was exceeded")
	}
	if !slices.ContainsFunc(p.UnexpandedActions, func(u ir.UnexpandedAction) bool { return u.Reason == ir.UnexpandedBudget }) {
		t.Fatalf("the entries past the bound are listed budget, got %d unexpanded", len(p.UnexpandedActions))
	}
}

// TestResolveNested_EscapingPathNeverFetched pins the ingestion hardening
// rule (review L4, ruled in scope): a relative directory or a subpath that
// climbs out of its repository after cleaning is never read, kept as an
// entry and listed with reason fetch.
func TestResolveNested_EscapingPathNeverFetched(t *testing.T) {
	stub := newStub(map[string]string{"acme/b@v1:action.yml": composite("./../../other/x", "acme/c/../../other/y@v1")})
	localReads := 0
	scope := nestedScope{readLocal: func(string) (string, fetchStatus) { localReads++; return "", fetchMissing }}
	p := resolveWith(t, stub, scope, oneJob("acme/b@v1"))
	if len(p.Jobs[0].Uses) != 3 {
		t.Fatalf("both references stay entries, got %q", entries(p.Jobs[0]))
	}
	for key := range stub.calls {
		if strings.Contains(key, "other") || strings.Contains(key, "..") {
			t.Fatalf("an escaping path must never be fetched, got %q", key)
		}
	}
	if localReads != 0 {
		t.Fatalf("an escaping path must never be read locally, got %d reads", localReads)
	}
	var refused []string
	for _, u := range p.UnexpandedActions {
		if u.Reason == ir.UnexpandedFetch && slices.Equal(u.Via, []string{"acme/b@v1"}) {
			refused = append(refused, u.Uses)
		}
	}
	if !slices.Equal(refused, []string{"./../../other/x", "acme/c/../../other/y@v1"}) {
		t.Fatalf("unexpanded = %+v", p.UnexpandedActions)
	}
	if got, st := newDefinitionFetcher(stub.fetch, nil).read("acme", "b", "v1", "../../other/x/action.yml"); got != "" || st != fetchError {
		t.Fatalf("the fetcher refuses an escaping path itself, got %v", st)
	}
}

// TestDefinitionFetcherForHost_EnterpriseNeverReadsTheRawHost pins spec
// 4.2 (review L6, ruled in scope): on a GitHub Enterprise Server host the
// definition comes from that host's contents API, the raw host of
// github.com is never asked.
func TestDefinitionFetcherForHost_EnterpriseNeverReadsTheRawHost(t *testing.T) {
	t.Setenv(EnvDisableGitHubAPI, "0")
	t.Setenv(EnvMetadataToken, "test-token")
	rawRequests := 0
	saved := rawHTTPClient.Transport
	rawHTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		rawRequests++
		return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody, Header: make(http.Header), Request: r}, nil
	})
	t.Cleanup(func() { rawHTTPClient.Transport = saved })
	var apiPaths []string
	client := stubbedMetadataClient(t, func(r *http.Request) (string, int) {
		apiPaths = append(apiPaths, r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/repos/acme/b/contents/action.yml") {
			return `{"encoding":"base64","content":"` + b64(composite()) + `"}`, http.StatusOK
		}
		return `{"message":"Not Found"}`, http.StatusNotFound
	})
	for _, host := range []string{"ghes.example.com", "https://ghes.example.com/api/v3/"} {
		defs := definitionFetcherForHost(host, client)
		if d := defs.action("acme", "b", "", "v1"); d.Status != fetchOK {
			t.Fatalf("%s: the contents API answers, got status %v (paths %q)", host, d.Status, apiPaths)
		}
	}
	if rawRequests != 0 {
		t.Fatalf("a GitHub Enterprise Server run never asks the raw host, got %d requests", rawRequests)
	}
	for _, host := range []string{"", "api.github.com", "https://api.github.com"} {
		if definitionFetcherForHost(host, client).raw == nil {
			t.Fatalf("%q is github.com: the raw host stays first", host)
		}
	}
}

// TestReadWith_FallsBackToContentsAPIOnGitHubCom pins the readWith fallback
// on github.com (review of PR 549, spec section 4.2): a private or
// token-gated repository the raw host cannot read falls back to the
// authenticated contents API, both when the raw host answers missing and
// when it errors outright, and the composite it serves still splices its
// steps into the job with their via.
func TestReadWith_FallsBackToContentsAPIOnGitHubCom(t *testing.T) {
	for _, tc := range []struct {
		name string
		// rawErr selects the raw host's answer for the container's
		// action.yml: fetchMissing (the default, nothing stubbed) or
		// fetchError when true.
		rawErr bool
	}{
		{name: "raw host misses, contents API serves it"},
		{name: "raw host errors, contents API serves it", rawErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvDisableGitHubAPI, "0")
			t.Setenv(EnvMetadataToken, "test-token")
			stub := newStub(map[string]string{})
			if tc.rawErr {
				stub.errs["acme/b@v1:action.yml"] = true
			}
			var apiPaths []string
			client := stubbedMetadataClient(t, func(r *http.Request) (string, int) {
				apiPaths = append(apiPaths, r.URL.Path)
				if strings.HasSuffix(r.URL.Path, "/repos/acme/b/contents/action.yml") {
					return `{"encoding":"base64","content":"` + b64(composite("acme/c@v1")) + `"}`, http.StatusOK
				}
				return `{"message":"Not Found"}`, http.StatusNotFound
			})
			defs := newDefinitionFetcher(stub.fetch, client)
			p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "acme/app", Jobs: []ir.Job{oneJob("acme/b@v1")}}
			resolveNestedActions(p, defs, nestedScope{projectPath: "acme/app"})
			if d := defs.action("acme", "b", "", "v1"); d.Status != fetchOK {
				t.Fatalf("%s: the contents API must answer, got status %v (paths %q)", tc.name, d.Status, apiPaths)
			}
			if n := stub.calls["acme/b@v1:action.yml"]; n != 1 {
				t.Fatalf("%s: the raw host must be tried first, exactly once, got %d calls", tc.name, n)
			}
			want := []string{
				"acme/b@v1 |  |  | 10",
				"acme/c@v1 | acme/b@v1 | acme/b@v1:action.yml:7 | 10",
			}
			if got := entries(p.Jobs[0]); !slices.Equal(got, want) {
				t.Fatalf("%s: the composite's step must splice in with its via:\n got %q\nwant %q", tc.name, got, want)
			}
		})
	}
}
