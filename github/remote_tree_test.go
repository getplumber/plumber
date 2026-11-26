package github

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// fakeFile is one file of a gitRepo.
type fakeFile struct {
	text string
	// mode is the git mode, 0 meaning a regular file (0o100644).
	mode      int
	truncated bool
	// served, when set, is the text GitHub's answer carries instead of
	// text: GraphQL's Blob.text is not byte-faithful (it rewrote a literal
	// "\u0000" in home-assistant/core's detect-duplicate-issues.yml).
	served string
}

// blob is the file as the query answers it, with the oid of its real
// content.
func (f fakeFile) blob() map[string]any {
	text := f.text
	if f.served != "" {
		text = f.served
	}
	return map[string]any{"__typename": "Blob", "text": text, "oid": gitBlobOID(f.text), "isTruncated": f.truncated, "isBinary": false}
}

// gitRepo is a repository the fake GraphQL endpoint answers from: the
// refs that exist (as GraphQL expressions: refs/heads/x, refs/tags/x, a SHA,
// HEAD) and the files every ref holds, unless byRef gives a ref its own.
type gitRepo struct {
	missing bool
	refs    []string
	files   map[string]fakeFile
	byRef   map[string]map[string]fakeFile
}

func (f gitRepo) tree(ref string) (map[string]fakeFile, bool) {
	for _, r := range f.refs {
		if r == ref {
			if files, ok := f.byRef[ref]; ok {
				return files, true
			}
			return f.files, true
		}
	}
	return nil, false
}

// answer resolves one expression the way GitHub does: "<ref>" is the
// ref's commit, "<ref>:<path>" a blob or a tree, anything else null.
func (f gitRepo) answer(expr string) any {
	ref, p, hasPath := strings.Cut(expr, ":")
	files, ok := f.tree(ref)
	if !ok {
		return nil
	}
	if !hasPath {
		return map[string]any{"__typename": "Commit"}
	}
	if file, ok := files[p]; ok {
		return file.blob()
	}
	var entries []map[string]any
	seen := map[string]bool{}
	for fp, file := range files {
		prefix := p + "/"
		if p == "" {
			prefix = "" // "<ref>:" is the root tree
		}
		rest, ok := strings.CutPrefix(fp, prefix)
		if !ok {
			continue
		}
		name, _, isDir := strings.Cut(rest, "/")
		if seen[name] {
			continue
		}
		seen[name] = true
		if isDir {
			entries = append(entries, map[string]any{"name": name, "path": prefix + name, "mode": 0o40000, "object": map[string]any{}})
			continue
		}
		mode := file.mode
		if mode == 0 {
			mode = 0o100644
		}
		entries = append(entries, map[string]any{"name": name, "path": fp, "mode": mode,
			"object": file.blob()})
	}
	if len(entries) == 0 {
		return nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i]["name"].(string) < entries[j]["name"].(string) })
	return map[string]any{"entries": entries}
}

// respond answers a query whose aliases are named like its variables.
func (f gitRepo) respond(q graphQLRequest) (string, int) {
	if f.missing {
		return `{"data":{"repository":null},"errors":[{"type":"NOT_FOUND","path":["repository"],"message":"Could not resolve to a Repository"}]}`, 200
	}
	repo := map[string]any{}
	for alias, v := range q.Variables {
		if alias == "owner" || alias == "name" {
			continue
		}
		repo[alias] = f.answer(v.(string))
	}
	body, _ := json.Marshal(map[string]any{"data": map[string]any{"repository": repo, "rateLimit": map[string]any{"cost": 1, "remaining": 4999}}})
	return string(body), 200
}

// swapGitRepo serves repo over GraphQL and returns the queries it got.
func swapGitRepo(t *testing.T, repo gitRepo) *[]graphQLRequest {
	t.Helper()
	gql, queries := stubbedGraphQL(t, repo.respond)
	swapScannedRepoGraphQL(t, gql, nil)
	return queries
}

const probeWorkflow = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: [{ run: echo }]\n"

// TestWorkflowTree_OneQueryReadsListingAndFiles: the listing and every
// workflow file come from one query, with no REST request. Only regular
// .yml/.yaml files count (a symlink is skipped, as REST lists it as
// "symlink"), the lockfile is noticed, and every value is a variable.
func TestWorkflowTree_OneQueryReadsListingAndFiles(t *testing.T) {
	queries := swapGitRepo(t, gitRepo{
		refs: []string{"refs/heads/main"},
		files: map[string]fakeFile{
			".github/workflows/b.yaml":       {text: probeWorkflow},
			".github/workflows/a.yml":        {text: probeWorkflow, mode: 0o100755},
			".github/workflows/link.yml":     {text: "a.yml", mode: 0o120000},
			".github/workflows/README.md":    {text: "doc"},
			".github/workflows/actions.lock": {text: "lock"},
		},
	})
	paths := restRecorder(t, nil)

	p, partial, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil)
	if err != nil || len(partial) != 0 {
		t.Fatalf("scan: %v %v", err, partial)
	}
	var got []string
	for _, w := range p.AnalyzedWorkflows {
		got = append(got, w.Path)
	}
	if want := []string{".github/workflows/a.yml", ".github/workflows/b.yaml"}; !reflect.DeepEqual(got, want) {
		t.Errorf("workflows = %v, want %v", got, want)
	}
	if p.WorkflowLockfilePath != githubWorkflowLockfile {
		t.Errorf("lockfile = %q, want %q", p.WorkflowLockfilePath, githubWorkflowLockfile)
	}
	if len(*queries) != 1 {
		t.Errorf("sent %d queries, want 1", len(*queries))
	}
	if len(*paths) != 0 {
		t.Errorf("REST paths = %v, want none", *paths)
	}
	for _, q := range *queries {
		for _, v := range []string{"acme", "app", "refs/heads/main", githubWorkflowsSubdir} {
			if strings.Contains(q.Query, v) {
				t.Errorf("query text carries %q:\n%s", v, q.Query)
			}
		}
	}
}

// TestWorkflowTree_BranchBeforeTag: a branch and a tag with the same name
// read the branch, as REST's ?ref= does (experiment
// test/2026-11-25-ref-precedence on getplumber-examples/cli-working-lab,
// where GraphQL's bare "name:path" read the tag).
func TestWorkflowTree_BranchBeforeTag(t *testing.T) {
	swapGitRepo(t, gitRepo{
		refs: []string{"refs/heads/v2", "refs/tags/v2"},
		byRef: map[string]map[string]fakeFile{
			"refs/heads/v2": {".github/workflows/ci.yml": {text: "name: branch\n" + probeWorkflow}},
			"refs/tags/v2":  {".github/workflows/ci.yml": {text: "name: tag\n" + probeWorkflow}},
		},
	})
	restRecorder(t, nil)

	p, _, err := ScanGitHubWorkflowsRemote("", "acme", "app", "v2", false, false, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(p.AnalyzedWorkflows) != 1 || !strings.HasPrefix(p.AnalyzedWorkflows[0].Content, "name: branch") {
		t.Errorf("read %+v, want the branch's file", p.AnalyzedWorkflows)
	}
}

// TestWorkflowTree_RefShapes: a tag, a SHA, the default branch (no ref)
// and a ref of another kind all read in one or two queries.
func TestWorkflowTree_RefShapes(t *testing.T) {
	files := map[string]fakeFile{".github/workflows/ci.yml": {text: probeWorkflow}}
	for _, tc := range []struct {
		ref, exists string
		queries     int
	}{
		{"v1.2.3", "refs/tags/v1.2.3", 1},
		{"0123456789abcdef0123456789abcdef01234567", "0123456789abcdef0123456789abcdef01234567", 1},
		{"", "HEAD", 1},
		{"refs/pull/7/head", "refs/pull/7/head", 1},
		{"pull/7/head", "pull/7/head", 2},
	} {
		t.Run(tc.exists, func(t *testing.T) {
			queries := swapGitRepo(t, gitRepo{refs: []string{tc.exists}, files: files})
			restRecorder(t, nil)
			p, _, err := ScanGitHubWorkflowsRemote("", "acme", "app", tc.ref, false, false, nil)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if len(p.AnalyzedWorkflows) != 1 {
				t.Errorf("read %d workflows, want 1", len(p.AnalyzedWorkflows))
			}
			if len(*queries) != tc.queries {
				t.Errorf("sent %d queries, want %d", len(*queries), tc.queries)
			}
		})
	}
}

// TestWorkflowTree_TruncatedFileReadsOverREST: a file GitHub truncates in
// the answer is read over the contents API instead.
func TestWorkflowTree_TruncatedFileReadsOverREST(t *testing.T) {
	swapGitRepo(t, gitRepo{
		refs:  []string{"refs/heads/main"},
		files: map[string]fakeFile{".github/workflows/big.yml": {text: "on: pu", truncated: true}},
	})
	paths := restRecorder(t, map[string]string{
		"/repos/acme/app/contents/.github/workflows/big.yml": `{"encoding":"base64","content":"` + b64(probeWorkflow) + `"}`,
	})

	p, partial, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil)
	if err != nil || len(partial) != 0 {
		t.Fatalf("scan: %v %v", err, partial)
	}
	if len(p.AnalyzedWorkflows) != 1 || p.AnalyzedWorkflows[0].Content != probeWorkflow {
		t.Errorf("read %+v, want the REST content", p.AnalyzedWorkflows)
	}
	if want := []string{"/repos/acme/app/contents/.github/workflows/big.yml"}; !reflect.DeepEqual(*paths, want) {
		t.Errorf("REST paths = %v, want %v", *paths, want)
	}
}

// TestWorkflowTree_AlteredTextReadsOverREST: a file whose text does not
// hash to its blob oid (GitHub rewrote part of it) is read over the
// contents API, so the report keeps the file as it is.
func TestWorkflowTree_AlteredTextReadsOverREST(t *testing.T) {
	const real = "on: push\n# replace(/[\\u0000-\\u001F]/g)\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: [{ run: echo }]\n"
	swapGitRepo(t, gitRepo{
		refs:  []string{"refs/heads/main"},
		files: map[string]fakeFile{".github/workflows/ci.yml": {text: real, served: strings.ReplaceAll(real, `\u0000`, `\^@`)}},
	})
	paths := restRecorder(t, map[string]string{
		"/repos/acme/app/contents/.github/workflows/ci.yml": `{"encoding":"base64","content":"` + b64(real) + `"}`,
	})

	p, partial, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil)
	if err != nil || len(partial) != 0 {
		t.Fatalf("scan: %v %v", err, partial)
	}
	if len(p.AnalyzedWorkflows) != 1 || p.AnalyzedWorkflows[0].Content != real {
		t.Errorf("read %+v, want the file as it is", p.AnalyzedWorkflows)
	}
	if len(*paths) != 1 {
		t.Errorf("REST paths = %v, want the one file", *paths)
	}
}

// TestGitBlobOID matches git's own blob id of "hello\n".
func TestGitBlobOID(t *testing.T) {
	if got, want := gitBlobOID("hello\n"), "ce013625030ba8dba906f756967f9e9ca394464a"; got != want {
		t.Errorf("gitBlobOID = %s, want %s", got, want)
	}
}

// TestWorkflowTree_FailedQuery: a query GitHub fails as a whole fails the
// listing, as a failed listing did.
func TestWorkflowTree_FailedQuery(t *testing.T) {
	gql, _ := stubbedGraphQL(t, func(graphQLRequest) (string, int) { return `{"message":"Bad credentials"}`, 401 })
	swapScannedRepoGraphQL(t, gql, nil)
	restRecorder(t, nil)
	if _, _, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil); err == nil || !strings.Contains(err.Error(), "list workflows") {
		t.Errorf("err = %v, want the listing error", err)
	}
}

// TestWorkflowTree_AliasErrorNullsTheRepository: an error on one alias can
// null the repository. It is that error, not a repository that does not
// exist.
func TestWorkflowTree_AliasErrorNullsTheRepository(t *testing.T) {
	gql, _ := stubbedGraphQL(t, func(graphQLRequest) (string, int) {
		return `{"data":{"repository":null},"errors":[{"path":["repository","t0"],"message":"tree timed out"}]}`, 200
	})
	swapScannedRepoGraphQL(t, gql, nil)
	restRecorder(t, nil)
	_, _, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil)
	if err == nil || !strings.Contains(err.Error(), "tree timed out") || strings.Contains(err.Error(), "not found") {
		t.Errorf("err = %v, want GitHub's error, not a missing repository", err)
	}
}

// TestLocalComposites_OneQuery: the local composites the workflows call
// are read in one more query, action.yml or action.yaml. A composite only
// another composite calls reads over REST.
func TestLocalComposites_OneQuery(t *testing.T) {
	const ci = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/x\n      - uses: ./.github/actions/z\n      - uses: ./../outside\n"
	queries := swapGitRepo(t, gitRepo{
		refs: []string{"refs/heads/main"},
		files: map[string]fakeFile{
			".github/workflows/ci.yml":      {text: ci},
			".github/actions/x/action.yml":  {text: composite("./.github/actions/y")},
			".github/actions/z/action.yaml": {text: composite()},
		},
	})
	paths := restRecorder(t, map[string]string{
		"/repos/acme/app/contents/.github/actions/y/action.yml": `{"encoding":"base64","content":"` + b64(composite()) + `"}`,
	})

	p, partial, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil)
	if err != nil || len(partial) != 0 {
		t.Fatalf("scan: %v %v", err, partial)
	}
	if len(*queries) != 2 {
		t.Fatalf("sent %d queries, want 2", len(*queries))
	}
	var exprs []string
	for k, v := range (*queries)[1].Variables {
		if k != "owner" && k != "name" {
			exprs = append(exprs, v.(string))
		}
	}
	sort.Strings(exprs)
	want := []string{
		"refs/heads/main:.github/actions/x",
		"refs/heads/main:.github/actions/x/action.yaml",
		"refs/heads/main:.github/actions/x/action.yml",
		"refs/heads/main:.github/actions/z",
		"refs/heads/main:.github/actions/z/action.yaml",
		"refs/heads/main:.github/actions/z/action.yml",
	}
	if !reflect.DeepEqual(exprs, want) {
		t.Errorf("composite expressions = %v\nwant %v", exprs, want)
	}
	if want := []string{"/repos/acme/app/contents/.github/actions/y/action.yml"}; !reflect.DeepEqual(*paths, want) {
		t.Errorf("REST paths = %v, want %v", *paths, want)
	}
	got := strings.Join(entries(p.Jobs[0]), "\n")
	for _, u := range []string{"./.github/actions/x |", "./.github/actions/y |", "./.github/actions/z |"} {
		if !strings.Contains(got, u) {
			t.Errorf("job entries %q, missing %s", got, u)
		}
	}
}

// TestLocalComposites_SymlinkReadsOverREST: a Blob carries no git mode, and
// the blob of a symlink holds the path it points at, not a definition. The
// directory's listing gives the mode, and a definition that is not a
// regular file reads over the contents API, which follows the link. Without
// it the composite's own steps would never be resolved.
func TestLocalComposites_SymlinkReadsOverREST(t *testing.T) {
	const ci = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/x\n      - uses: ./\n"
	queries := swapGitRepo(t, gitRepo{
		refs: []string{"refs/heads/main"},
		files: map[string]fakeFile{
			".github/workflows/ci.yml":     {text: ci},
			".github/actions/x/action.yml": {text: "../shared/action.yml", mode: 0o120000},
			// The root composite (uses: ./) is a regular file: its
			// directory is the root tree, "<rev>:".
			"action.yml": {text: composite("./.github/actions/root-step")},
		},
	})
	paths := restRecorder(t, map[string]string{
		"/repos/acme/app/contents/.github/actions/x/action.yml":         `{"encoding":"base64","content":"` + b64(composite("./.github/actions/y")) + `"}`,
		"/repos/acme/app/contents/.github/actions/y/action.yml":         `{"encoding":"base64","content":"` + b64(composite()) + `"}`,
		"/repos/acme/app/contents/.github/actions/root-step/action.yml": `{"encoding":"base64","content":"` + b64(composite()) + `"}`,
	})

	p, partial, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil)
	if err != nil || len(partial) != 0 {
		t.Fatalf("scan: %v %v", err, partial)
	}
	if len(*queries) != 2 {
		t.Fatalf("sent %d queries, want 2", len(*queries))
	}
	asked := strings.Join(*paths, "\n")
	if !strings.Contains(asked, "/repos/acme/app/contents/.github/actions/x/action.yml") {
		t.Errorf("REST paths = %v, want the symlinked definition read over the contents API", *paths)
	}
	if strings.Contains(asked, "/repos/acme/app/contents/action.yml") {
		t.Errorf("REST paths = %v, want the root definition (a regular file) read from the query", *paths)
	}
	got := strings.Join(entries(p.Jobs[0]), "\n")
	for _, u := range []string{"./.github/actions/x |", "./.github/actions/y |", "./.github/actions/root-step |"} {
		if !strings.Contains(got, u) {
			t.Errorf("job entries %q, missing %s", got, u)
		}
	}
}

// TestLocalComposites_UnlistedDirectoryReadsOverREST: when GitHub could not
// list a composite's directory, the mode of its definition is unknown, so
// the definition reads over REST rather than being trusted as a blob.
func TestLocalComposites_UnlistedDirectoryReadsOverREST(t *testing.T) {
	repo := gitRepo{
		refs: []string{"refs/heads/main"},
		files: map[string]fakeFile{
			".github/workflows/ci.yml":     {text: "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/x\n"},
			".github/actions/x/action.yml": {text: composite()},
		},
	}
	gql, _ := stubbedGraphQL(t, func(q graphQLRequest) (string, int) {
		body, status := repo.respond(q)
		for alias, v := range q.Variables {
			if v == "refs/heads/main:.github/actions/x" {
				var answer map[string]any
				_ = json.Unmarshal([]byte(body), &answer)
				answer["data"].(map[string]any)["repository"].(map[string]any)[alias] = nil
				answer["errors"] = []map[string]any{{"path": []string{"repository", alias}, "message": "timeout"}}
				out, _ := json.Marshal(answer)
				return string(out), status
			}
		}
		return body, status
	})
	swapScannedRepoGraphQL(t, gql, nil)
	paths := restRecorder(t, map[string]string{
		"/repos/acme/app/contents/.github/actions/x/action.yml": `{"encoding":"base64","content":"` + b64(composite()) + `"}`,
	})

	if _, partial, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil); err != nil || len(partial) != 0 {
		t.Fatalf("scan: %v %v", err, partial)
	}
	if want := []string{"/repos/acme/app/contents/.github/actions/x/action.yml"}; !reflect.DeepEqual(*paths, want) {
		t.Errorf("REST paths = %v, want %v", *paths, want)
	}
}
