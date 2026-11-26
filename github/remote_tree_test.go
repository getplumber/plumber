package github

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/httpcount"
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
	// binary and noText are a file GitHub answers no usable text for.
	binary, noText bool
}

// blob is the file as the query answers it, with the oid of its real
// content.
func (f fakeFile) blob() map[string]any {
	text := f.text
	if f.served != "" {
		text = f.served
	}
	blob := map[string]any{"__typename": "Blob", "text": text, "oid": gitBlobOID(f.text), "isTruncated": f.truncated, "isBinary": f.binary}
	if f.noText {
		blob["text"] = nil
	}
	return blob
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
		// The shortest and longest names shaped like a SHA are read as
		// written in the first query; one character less or more is a ref
		// of another kind.
		{"0123abc", "0123abc", 1},
		{"0123ab", "0123ab", 2},
		{"0123456789abcdef0123456789abcdef012345678", "0123456789abcdef0123456789abcdef012345678", 2},
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

// TestWorkflowTree_EmptyRepository: a repository with no commit has no
// HEAD. Scanned at its default branch it has no workflows, which is not
// the missing ref of ISSUE #222: a named ref that does not exist is still
// an error.
func TestWorkflowTree_EmptyRepository(t *testing.T) {
	queries := swapGitRepo(t, gitRepo{refs: nil})
	restRecorder(t, nil)
	p, partial, err := ScanGitHubWorkflowsRemote("", "acme", "app", "", false, false, nil)
	if err != nil || len(partial) != 0 {
		t.Fatalf("scan: %v %v; want no error", err, partial)
	}
	if len(p.Jobs) != 0 || p.WorkflowFileCount != 0 {
		t.Errorf("jobs = %v, files = %d; want none", jobNames(p.Jobs), p.WorkflowFileCount)
	}
	if len(*queries) != 1 {
		t.Errorf("sent %d queries, want 1", len(*queries))
	}
	if _, _, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil); err == nil || !strings.Contains(err.Error(), `"main" not found`) {
		t.Errorf("named ref: err = %v, want the missing ref error", err)
	}
}

// TestWorkflowTree_CommitAliasFailed: an error GitHub ties to a
// candidate's commit is that error. The candidate must not read as a ref
// that does not exist, which would move on to the next candidate (a tag
// of the same name) or report the ref missing.
func TestWorkflowTree_CommitAliasFailed(t *testing.T) {
	repo := gitRepo{
		refs: []string{"refs/heads/main", "refs/tags/main"},
		files: map[string]fakeFile{
			".github/workflows/ci.yml": {text: probeWorkflow},
		},
	}
	gql, _ := stubbedGraphQL(t, func(q graphQLRequest) (string, int) {
		body, status := repo.respond(q)
		var answer map[string]any
		_ = json.Unmarshal([]byte(body), &answer)
		// c0 is the branch's commit.
		answer["data"].(map[string]any)["repository"].(map[string]any)["c0"] = nil
		answer["errors"] = []map[string]any{{"path": []string{"repository", "c0"}, "message": "commit timed out"}}
		out, _ := json.Marshal(answer)
		return string(out), status
	})
	swapScannedRepoGraphQL(t, gql, nil)
	restRecorder(t, nil)
	p, _, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil)
	if err == nil || !strings.Contains(err.Error(), "commit timed out") {
		t.Errorf("err = %v (pipeline %v), want GitHub's error", err, p)
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

// swapPatchedGitRepo serves repo like swapGitRepo, after patch changed the
// repository's fields of each answer. The errors patch returns travel with
// the answer.
func swapPatchedGitRepo(t *testing.T, repo gitRepo, patch func(q graphQLRequest, fields map[string]any) []map[string]any) *[]graphQLRequest {
	t.Helper()
	gql, queries := stubbedGraphQL(t, func(q graphQLRequest) (string, int) {
		body, status := repo.respond(q)
		var answer map[string]any
		_ = json.Unmarshal([]byte(body), &answer)
		if errs := patch(q, answer["data"].(map[string]any)["repository"].(map[string]any)); errs != nil {
			answer["errors"] = errs
		}
		out, _ := json.Marshal(answer)
		return string(out), status
	})
	swapScannedRepoGraphQL(t, gql, nil)
	return queries
}

// aliasReading is the alias of q that reads expr, "" when q has none.
func aliasReading(q graphQLRequest, expr string) string {
	for alias, v := range q.Variables {
		if v == expr {
			return alias
		}
	}
	return ""
}

// failAlias nulls the alias of q reading expr and returns GitHub's error
// for it, nil when q does not read expr.
func failAlias(q graphQLRequest, fields map[string]any, expr, message string) []map[string]any {
	alias := aliasReading(q, expr)
	if alias == "" {
		return nil
	}
	fields[alias] = nil
	return []map[string]any{{"path": []string{"repository", alias}, "message": message}}
}

// usesX is a workflow whose one job calls the local composite x.
const usesX = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/x\n"

// contentsBody is the contents API's answer for a file holding text.
func contentsBody(text string) string {
	return `{"encoding":"base64","content":"` + b64(text) + `"}`
}

// TestWorkflowTree_TreeAliasFailed: an error GitHub ties to the workflows
// tree of a ref that exists is that error. A tree GitHub could not read
// must not read as a repository with no workflows, which scores a vacuous
// 100% (ISSUE #222).
func TestWorkflowTree_TreeAliasFailed(t *testing.T) {
	swapPatchedGitRepo(t, gitRepo{
		refs:  []string{"refs/heads/main"},
		files: map[string]fakeFile{".github/workflows/ci.yml": {text: probeWorkflow}},
	}, func(q graphQLRequest, fields map[string]any) []map[string]any {
		return failAlias(q, fields, "refs/heads/main:"+githubWorkflowsSubdir, "tree timed out")
	})
	restRecorder(t, nil)
	p, _, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil)
	if err == nil || !strings.Contains(err.Error(), "tree timed out") {
		t.Errorf("err = %v (pipeline %v), want GitHub's error", err, p)
	}
}

// TestWorkflowTree_OtherRefTreeQueryFails: a ref that is neither a branch
// nor a tag costs a second query for its tree. That query failing, as a
// whole or on its one alias, fails the listing: the ref exists, so an
// unread tree is not an empty pipeline.
func TestWorkflowTree_OtherRefTreeQueryFails(t *testing.T) {
	repo := gitRepo{
		refs:  []string{"pull/7/head"},
		files: map[string]fakeFile{".github/workflows/ci.yml": {text: probeWorkflow}},
	}
	for _, tc := range []struct {
		name, body string
		status     int
		want       string
	}{
		{"server error", `oops`, 500, "HTTP 500"},
		{"tree alias failed", `{"data":{"repository":{"t0":null}},"errors":[{"path":["repository","t0"],"message":"tree timed out"}]}`, 200, "tree timed out"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			second := 0
			gql, _ := stubbedGraphQL(t, func(q graphQLRequest) (string, int) {
				// The first query asks each candidate's commit; the second
				// reads the tree only.
				if _, first := q.Variables["c0"]; first {
					return repo.respond(q)
				}
				second++
				return tc.body, tc.status
			})
			swapScannedRepoGraphQL(t, gql, nil)
			restRecorder(t, nil)
			p, _, err := ScanGitHubWorkflowsRemote("", "acme", "app", "pull/7/head", false, false, nil)
			if second == 0 {
				t.Fatal("the tree of a ref of another kind was not asked in a second query")
			}
			if err == nil || !strings.Contains(err.Error(), "list workflows") || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v (pipeline %v), want the listing error carrying %q", err, p, tc.want)
			}
		})
	}
}

// TestWorkflowTree_ForbiddenRepository: a repository GitHub refuses to
// show the token fails the listing with that refusal. It is neither a
// repository with no workflows nor one that does not exist.
func TestWorkflowTree_ForbiddenRepository(t *testing.T) {
	gql, _ := stubbedGraphQL(t, func(graphQLRequest) (string, int) {
		return `{"data":{"repository":null},"errors":[{"type":"FORBIDDEN","path":["repository"],"message":"Resource protected by organization SAML enforcement."}]}`, 200
	})
	swapScannedRepoGraphQL(t, gql, nil)
	restRecorder(t, nil)
	p, _, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil)
	if err == nil || !strings.Contains(err.Error(), "list workflows") || !strings.Contains(err.Error(), "forbidden") || strings.Contains(err.Error(), "not found") {
		t.Errorf("err = %v (pipeline %v), want the listing refused, not a missing repository", err, p)
	}
}

// TestWorkflowTree_RetriesAQueryGitHubCouldNotFinish: the tree query
// cannot be made smaller, so one 5xx (or a timeout answered as a 200) is
// sent again instead of costing the run its workflows.
func TestWorkflowTree_RetriesAQueryGitHubCouldNotFinish(t *testing.T) {
	repo := gitRepo{
		refs:  []string{"refs/heads/main"},
		files: map[string]fakeFile{".github/workflows/ci.yml": {text: probeWorkflow}},
	}
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"502", `bad gateway`, 502},
		{"timeout answered 200", timeoutBody, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := true
			gql, queries := stubbedGraphQL(t, func(q graphQLRequest) (string, int) {
				if first {
					first = false
					return tc.body, tc.status
				}
				return repo.respond(q)
			})
			swapScannedRepoGraphQL(t, gql, nil)
			restRecorder(t, nil)
			p, partial, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil)
			if err != nil || len(partial) != 0 {
				t.Fatalf("scan: %v %v", err, partial)
			}
			if len(p.AnalyzedWorkflows) != 1 {
				t.Errorf("read %d workflows, want 1", len(p.AnalyzedWorkflows))
			}
			if len(*queries) != 2 {
				t.Errorf("sent %d queries, want 2 (the failure, then the retry)", len(*queries))
			}
		})
	}
}

// TestWorkflowTree_ErrorOutsideTheRepositoryFailsTheQuery: an error GitHub
// ties to nothing under the repository (here the query's own cost) spoils
// the whole answer, so the listing fails instead of trusting the rest.
func TestWorkflowTree_ErrorOutsideTheRepositoryFailsTheQuery(t *testing.T) {
	swapPatchedGitRepo(t, gitRepo{
		refs:  []string{"refs/heads/main"},
		files: map[string]fakeFile{".github/workflows/ci.yml": {text: probeWorkflow}},
	}, func(graphQLRequest, map[string]any) []map[string]any {
		return []map[string]any{{"path": []string{"rateLimit"}, "message": "cost unavailable"}}
	})
	restRecorder(t, nil)
	p, _, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil)
	if err == nil || !strings.Contains(err.Error(), "cost unavailable") {
		t.Errorf("err = %v (pipeline %v), want GitHub's error", err, p)
	}
}

// TestWorkflowTree_FileWithoutTextReadsOverREST: a file GitHub flags as
// binary, or answers no text for, is read over the contents API.
func TestWorkflowTree_FileWithoutTextReadsOverREST(t *testing.T) {
	for _, tc := range []struct {
		name string
		file fakeFile
	}{
		{"binary", fakeFile{text: probeWorkflow, binary: true}},
		{"no text", fakeFile{text: probeWorkflow, noText: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			swapGitRepo(t, gitRepo{
				refs:  []string{"refs/heads/main"},
				files: map[string]fakeFile{".github/workflows/ci.yml": tc.file},
			})
			paths := restRecorder(t, map[string]string{
				"/repos/acme/app/contents/.github/workflows/ci.yml": contentsBody(probeWorkflow),
			})
			p, partial, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil)
			if err != nil || len(partial) != 0 {
				t.Fatalf("scan: %v %v", err, partial)
			}
			if len(p.AnalyzedWorkflows) != 1 || p.AnalyzedWorkflows[0].Content != probeWorkflow {
				t.Errorf("read %+v, want the REST content", p.AnalyzedWorkflows)
			}
			if want := []string{"/repos/acme/app/contents/.github/workflows/ci.yml"}; !reflect.DeepEqual(*paths, want) {
				t.Errorf("REST paths = %v, want %v", *paths, want)
			}
		})
	}
}

// TestWorkflowTree_KeepsRegularFilesSortedByName: the listing GitHub
// answers is not trusted to be sorted or to hold files only. A submodule
// and a directory named like a workflow are skipped, and the files come
// out by name.
func TestWorkflowTree_KeepsRegularFilesSortedByName(t *testing.T) {
	entry := func(name string, mode int) map[string]any {
		return map[string]any{"name": name, "path": githubWorkflowsSubdir + "/" + name, "mode": mode, "object": fakeFile{text: probeWorkflow}.blob()}
	}
	body, _ := json.Marshal(map[string]any{"data": map[string]any{"repository": map[string]any{
		"c0": map[string]any{"__typename": "Commit"},
		"t0": map[string]any{"entries": []map[string]any{
			entry("z.yml", 0o100644),
			entry("sub.yml", 0o160000),
			entry("dir.yml", 0o40000),
			entry("m.yaml", 0o100755),
			entry("a.yml", 0o100644),
		}},
	}}})
	gql, _ := stubbedGraphQL(t, func(graphQLRequest) (string, int) { return string(body), 200 })
	swapScannedRepoGraphQL(t, gql, nil)
	paths := restRecorder(t, nil)

	p, partial, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil)
	if err != nil || len(partial) != 0 {
		t.Fatalf("scan: %v %v", err, partial)
	}
	var got []string
	for _, w := range p.AnalyzedWorkflows {
		got = append(got, w.Path)
	}
	want := []string{".github/workflows/a.yml", ".github/workflows/m.yaml", ".github/workflows/z.yml"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("workflows = %v, want %v", got, want)
	}
	if p.WorkflowFileCount != 3 {
		t.Errorf("file count = %d, want 3", p.WorkflowFileCount)
	}
	if len(*paths) != 0 {
		t.Errorf("REST paths = %v, want none", *paths)
	}
}

// TestLocalCompositeDirs: the directories the composite query reads are
// the local composites the steps call, once each and cleaned. A reference
// holding an expression, one climbing out of the repository and one that
// is not local are left to the nested walk.
func TestLocalCompositeDirs(t *testing.T) {
	got := localCompositeDirs([]string{
		"./.github/actions/${{ matrix.a }}",
		" ./.github/actions/x ",
		"./.github/actions/x",
		"./.github/actions/x/",
		"acme/b@v1",
		"docker://alpine:3",
		"./../outside",
		"./",
		"./.github/actions/y",
	})
	if want := []string{".github/actions/x", "", ".github/actions/y"}; !reflect.DeepEqual(got, want) {
		t.Errorf("localCompositeDirs = %q, want %q", got, want)
	}
	if got := localCompositeDirs(nil); got != nil {
		t.Errorf("localCompositeDirs(nil) = %q, want nil", got)
	}
}

// TestRegularFile: a definition is trusted as a blob only when its
// directory lists it as a regular or executable file. A symlink, a
// submodule, a name the listing does not hold and a listing GitHub did not
// give all answer false: the mode is then unknown.
func TestRegularFile(t *testing.T) {
	listing := json.RawMessage(`{"entries":[
		{"name":"action.yml","mode":33188},
		{"name":"run.yml","mode":33261},
		{"name":"link.yml","mode":40960},
		{"name":"sub.yml","mode":57344},
		{"name":"dir.yml","mode":16384}
	]}`)
	for _, tc := range []struct {
		name string
		raw  json.RawMessage
		file string
		want bool
	}{
		{"regular", listing, "action.yml", true},
		{"executable", listing, "run.yml", true},
		{"symlink", listing, "link.yml", false},
		{"submodule", listing, "sub.yml", false},
		{"directory", listing, "dir.yml", false},
		{"not listed", listing, "action.yaml", false},
		{"null listing", json.RawMessage(`null`), "action.yml", false},
		{"no listing", nil, "action.yml", false},
		{"unreadable listing", json.RawMessage(`"x"`), "action.yml", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := regularFile(tc.raw, tc.file); got != tc.want {
				t.Errorf("regularFile = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestLocalComposites_ExecutableDefinitionReadsFromTheQuery: an action.yml
// with the executable bit is a regular file, so it is read from the query
// with no REST request.
func TestLocalComposites_ExecutableDefinitionReadsFromTheQuery(t *testing.T) {
	queries := swapGitRepo(t, gitRepo{
		refs: []string{"refs/heads/main"},
		files: map[string]fakeFile{
			".github/workflows/ci.yml":     {text: usesX},
			".github/actions/x/action.yml": {text: composite("./.github/actions/y"), mode: 0o100755},
			".github/actions/y/action.yml": {text: composite()},
		},
	})
	paths := restRecorder(t, map[string]string{
		"/repos/acme/app/contents/.github/actions/y/action.yml": contentsBody(composite()),
	})

	p, partial, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil)
	if err != nil || len(partial) != 0 {
		t.Fatalf("scan: %v %v", err, partial)
	}
	if len(*queries) != 2 {
		t.Fatalf("sent %d queries, want 2", len(*queries))
	}
	// y is only called by x, so it reads over REST; x must not.
	if want := []string{"/repos/acme/app/contents/.github/actions/y/action.yml"}; !reflect.DeepEqual(*paths, want) {
		t.Errorf("REST paths = %v, want %v", *paths, want)
	}
	if got := strings.Join(entries(p.Jobs[0]), "\n"); !strings.Contains(got, "./.github/actions/y |") {
		t.Errorf("job entries %q, missing the step of the executable definition", got)
	}
}

// TestLocalComposites_ReadAtTheTreeRev: the composites are read at the
// expression the workflows were found at (the tag, HEAD), so both come
// from the same commit.
func TestLocalComposites_ReadAtTheTreeRev(t *testing.T) {
	for _, tc := range []struct{ ref, exists string }{
		{"v1", "refs/tags/v1"},
		{"", "HEAD"},
		{"0123456789abcdef0123456789abcdef01234567", "0123456789abcdef0123456789abcdef01234567"},
	} {
		t.Run(tc.exists, func(t *testing.T) {
			queries := swapGitRepo(t, gitRepo{
				refs: []string{tc.exists},
				files: map[string]fakeFile{
					".github/workflows/ci.yml":     {text: usesX},
					".github/actions/x/action.yml": {text: composite()},
				},
			})
			paths := restRecorder(t, nil)
			if _, partial, err := ScanGitHubWorkflowsRemote("", "acme", "app", tc.ref, false, false, nil); err != nil || len(partial) != 0 {
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
				tc.exists + ":.github/actions/x",
				tc.exists + ":.github/actions/x/action.yaml",
				tc.exists + ":.github/actions/x/action.yml",
			}
			if !reflect.DeepEqual(exprs, want) {
				t.Errorf("composite expressions = %v\nwant %v", exprs, want)
			}
			if len(*paths) != 0 {
				t.Errorf("REST paths = %v, want none", *paths)
			}
		})
	}
}

// TestLocalComposites_DefinitionAliasFailed: an error GitHub ties to a
// definition nulls that alias. The null is the error, not a file that does
// not exist: the definition reads over REST and its steps are still
// resolved.
func TestLocalComposites_DefinitionAliasFailed(t *testing.T) {
	swapPatchedGitRepo(t, gitRepo{
		refs: []string{"refs/heads/main"},
		files: map[string]fakeFile{
			".github/workflows/ci.yml":     {text: usesX},
			".github/actions/x/action.yml": {text: composite("./.github/actions/y")},
		},
	}, func(q graphQLRequest, fields map[string]any) []map[string]any {
		return failAlias(q, fields, "refs/heads/main:.github/actions/x/action.yml", "blob timed out")
	})
	paths := restRecorder(t, map[string]string{
		"/repos/acme/app/contents/.github/actions/x/action.yml": contentsBody(composite("./.github/actions/y")),
		"/repos/acme/app/contents/.github/actions/y/action.yml": contentsBody(composite()),
	})

	p, partial, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil)
	if err != nil || len(partial) != 0 {
		t.Fatalf("scan: %v %v", err, partial)
	}
	if asked := strings.Join(*paths, "\n"); !strings.Contains(asked, "/repos/acme/app/contents/.github/actions/x/action.yml") {
		t.Errorf("REST paths = %v, want the definition GitHub could not answer read over the contents API", *paths)
	}
	if got := strings.Join(entries(p.Jobs[0]), "\n"); !strings.Contains(got, "./.github/actions/y |") {
		t.Errorf("job entries %q, missing the composite's own step", got)
	}
}

// TestLocalComposites_QueryFails: the composite query failing as a whole
// answers nothing about any definition. Each one reads over REST and the
// scan goes on, with no error.
func TestLocalComposites_QueryFails(t *testing.T) {
	repo := gitRepo{
		refs: []string{"refs/heads/main"},
		files: map[string]fakeFile{
			".github/workflows/ci.yml":     {text: usesX},
			".github/actions/x/action.yml": {text: composite("./.github/actions/y")},
		},
	}
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"server error", `oops`, 500},
		{"rate limited", rateLimited, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gql, _ := stubbedGraphQL(t, func(q graphQLRequest) (string, int) {
				if aliasReading(q, "refs/heads/main:.github/actions/x") != "" {
					return tc.body, tc.status
				}
				return repo.respond(q)
			})
			swapScannedRepoGraphQL(t, gql, nil)
			paths := restRecorder(t, map[string]string{
				"/repos/acme/app/contents/.github/actions/x/action.yml": contentsBody(composite("./.github/actions/y")),
				"/repos/acme/app/contents/.github/actions/y/action.yml": contentsBody(composite()),
			})

			p, partial, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil)
			if err != nil || len(partial) != 0 {
				t.Fatalf("scan: %v %v; a failed composite query must not fail the scan", err, partial)
			}
			if asked := strings.Join(*paths, "\n"); !strings.Contains(asked, "/repos/acme/app/contents/.github/actions/x/action.yml") {
				t.Errorf("REST paths = %v, want the definition read over the contents API", *paths)
			}
			got := strings.Join(entries(p.Jobs[0]), "\n")
			for _, u := range []string{"./.github/actions/x |", "./.github/actions/y |"} {
				if !strings.Contains(got, u) {
					t.Errorf("job entries %q, missing %s", got, u)
				}
			}
		})
	}
}

// TestLocalComposites_UnusableBlobReadsOverREST: a definition GitHub
// truncates, or whose text does not hash to its oid, reads over the
// contents API like a workflow file does, so the composite's steps come
// from the file as it is.
func TestLocalComposites_UnusableBlobReadsOverREST(t *testing.T) {
	real := composite("./.github/actions/y")
	for _, tc := range []struct {
		name string
		file fakeFile
	}{
		{"truncated", fakeFile{text: "name: x\nruns:\n  using: comp", truncated: true}},
		{"altered text", fakeFile{text: real, served: composite("./.github/actions/wrong")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			swapGitRepo(t, gitRepo{
				refs: []string{"refs/heads/main"},
				files: map[string]fakeFile{
					".github/workflows/ci.yml":     {text: usesX},
					".github/actions/x/action.yml": tc.file,
				},
			})
			paths := restRecorder(t, map[string]string{
				"/repos/acme/app/contents/.github/actions/x/action.yml": contentsBody(real),
				"/repos/acme/app/contents/.github/actions/y/action.yml": contentsBody(composite()),
			})

			p, partial, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil)
			if err != nil || len(partial) != 0 {
				t.Fatalf("scan: %v %v", err, partial)
			}
			if asked := strings.Join(*paths, "\n"); !strings.Contains(asked, "/repos/acme/app/contents/.github/actions/x/action.yml") {
				t.Errorf("REST paths = %v, want the definition read over the contents API", *paths)
			}
			got := strings.Join(entries(p.Jobs[0]), "\n")
			if !strings.Contains(got, "./.github/actions/y |") || strings.Contains(got, "./.github/actions/wrong") {
				t.Errorf("job entries %q, want the steps of the file as it is", got)
			}
		})
	}
}

// graphQLCostsSince are the query costs the run recorded after the first n.
func graphQLCostsSince(n int) []httpcount.GraphQLQuery {
	return httpcount.Default.Snapshot().GraphQL[n:]
}

// TestWorkflowTree_RecordsTheQueryCost: the tree query and the composite
// query ask for their cost and keep it for the --debug report, each under
// its own label.
func TestWorkflowTree_RecordsTheQueryCost(t *testing.T) {
	queries := swapGitRepo(t, gitRepo{
		refs: []string{"refs/heads/main"},
		files: map[string]fakeFile{
			".github/workflows/ci.yml":     {text: usesX},
			".github/actions/x/action.yml": {text: composite()},
		},
	})
	restRecorder(t, nil)
	before := len(httpcount.Default.Snapshot().GraphQL)

	if _, partial, err := ScanGitHubWorkflowsRemote("", "acme", "app", "main", false, false, nil); err != nil || len(partial) != 0 {
		t.Fatalf("scan: %v %v", err, partial)
	}
	want := []httpcount.GraphQLQuery{
		{Label: "remote workflows", Cost: 1, Remaining: 4999},
		{Label: "local composites", Cost: 1, Remaining: 4999},
	}
	if got := graphQLCostsSince(before); !reflect.DeepEqual(got, want) {
		t.Errorf("recorded costs = %+v\nwant %+v", got, want)
	}
	for _, q := range *queries {
		if !strings.Contains(q.Query, "rateLimit { cost remaining }") {
			t.Errorf("the query must ask for its cost:\n%s", q.Query)
		}
	}
}
