package github

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// b64 wraps base64-encoded content the way the GitHub Contents API
// does: standard encoding, then 60-char line wrap. The decoder in
// fetchFileContent strips whitespace before decoding so either
// wrapped or unwrapped form should work; tests use unwrapped for
// brevity.
func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestScanGitHubWorkflowsRemote_HappyPath(t *testing.T) {
	const ciYAML = `name: CI
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0349d3a4ad11e92923b09a26
      - run: echo build
`
	const releaseYAML = `name: Release
on:
  push:
    tags: ['v*']
permissions:
  contents: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0349d3a4ad11e92923b09a26
`

	swapGitRepo(t, gitRepo{
		refs: []string{"refs/heads/main"},
		files: map[string]fakeFile{
			".github/workflows/ci.yml":      {text: ciYAML},
			".github/workflows/release.yml": {text: releaseYAML},
			".github/workflows/README.md":   {text: "doc"}, // ignored: not yml/yaml
		},
	})
	restRecorder(t, nil)

	pipeline, partial, err := ScanGitHubWorkflowsRemote("", "owner", "repo", "main", false, false, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(partial) != 0 {
		t.Errorf("unexpected partial errors: %v", partial)
	}
	if pipeline.ProjectPath != "owner/repo" {
		t.Errorf("ProjectPath = %q, want owner/repo", pipeline.ProjectPath)
	}
	if pipeline.DefaultBranch != "main" {
		t.Errorf("DefaultBranch = %q, want main", pipeline.DefaultBranch)
	}
	// Two workflows × one job each = 2 jobs.
	if len(pipeline.Jobs) != 2 {
		t.Fatalf("expected 2 jobs, got %d: %+v", len(pipeline.Jobs), jobNames(pipeline.Jobs))
	}

	// The remote scan retains the fetched workflow files for the JSON report's
	// analyzed-CI-config block (#443): the two YAML files with their content,
	// under their repo-relative paths; the README is not a workflow and is
	// excluded.
	byPath := map[string]string{}
	for _, w := range pipeline.AnalyzedWorkflows {
		byPath[w.Path] = w.Content
	}
	if len(byPath) != 2 {
		t.Fatalf("retained %d workflow files, want 2: %+v", len(byPath), pipeline.AnalyzedWorkflows)
	}
	if byPath[".github/workflows/ci.yml"] != ciYAML {
		t.Errorf("ci.yml content = %q, want the fetched YAML verbatim", byPath[".github/workflows/ci.yml"])
	}
	if byPath[".github/workflows/release.yml"] != releaseYAML {
		t.Errorf("release.yml content = %q, want the fetched YAML verbatim", byPath[".github/workflows/release.yml"])
	}
	if _, present := byPath[".github/workflows/README.md"]; present {
		t.Error("README.md retained as a workflow file; it must be excluded")
	}
}

func TestScanGitHubWorkflowsRemote_NoWorkflowsDir(t *testing.T) {
	// An existing repo+ref that has no .github/workflows directory
	// degrades gracefully to an empty pipeline (no findings fire). The
	// tree answers null while the repository and the ref exist, which
	// tells it apart from a missing repo/branch (which hard-errors, #222).
	swapGitRepo(t, gitRepo{refs: []string{"refs/heads/main"}, files: map[string]fakeFile{"README.md": {text: "x"}}})
	restRecorder(t, nil)

	pipeline, partial, err := ScanGitHubWorkflowsRemote("", "owner", "repo", "main", false, false, nil)
	if err != nil {
		t.Fatalf("expected nil error on 404, got %v", err)
	}
	if len(partial) != 0 {
		t.Errorf("expected no partial errors, got %v", partial)
	}
	if len(pipeline.Jobs) != 0 {
		t.Errorf("expected zero jobs, got %d", len(pipeline.Jobs))
	}
}

func TestScanGitHubWorkflowsRemote_NonexistentRepoErrors(t *testing.T) {
	// #222: a repo that does not exist must be a hard error, not an empty
	// pipeline that the scorer renders as 100% compliant. GitHub answers
	// the repository null.
	swapGitRepo(t, gitRepo{missing: true})
	restRecorder(t, nil)

	_, _, err := ScanGitHubWorkflowsRemote("", "owner", "repo", "main", false, false, nil)
	if err == nil {
		t.Fatal("expected a hard error for a non-existent repository, got nil (vacuous 100% bug #222)")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should say the repository was not found, got: %v", err)
	}
}

func TestScanGitHubWorkflowsRemote_NonexistentBranchErrors(t *testing.T) {
	// #222: a branch that does not exist must be a hard error. The repo
	// exists but no candidate of the ref (branch, tag, as written) does.
	swapGitRepo(t, gitRepo{refs: []string{"refs/heads/main"}, files: map[string]fakeFile{".github/workflows/ci.yml": {text: "on: push"}}})
	restRecorder(t, nil)

	_, _, err := ScanGitHubWorkflowsRemote("", "owner", "repo", "lolxkdaksjdad", false, false, nil)
	if err == nil {
		t.Fatal("expected a hard error for a non-existent branch, got nil (vacuous 100% bug #222)")
	}
	if !strings.Contains(err.Error(), "lolxkdaksjdad") || !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should clearly say the ref was not found, got: %v", err)
	}
}

func TestScanGitHubWorkflowsRemote_FetchErrorRecordedAsPartial(t *testing.T) {
	// Listing succeeds but one of the files returns 500. The other
	// file should still be parsed; the failure is recorded in
	// partial errors, not a hard error.
	const goodYAML = `name: good
on: [push]
permissions: read-all
jobs:
  ok:
    runs-on: ubuntu-latest
    steps: [{ run: echo ok }]
`
	// broken.yml comes back truncated, so it reads over REST, which fails.
	swapGitRepo(t, gitRepo{
		refs: []string{"refs/heads/main"},
		files: map[string]fakeFile{
			".github/workflows/good.yml":   {text: goodYAML},
			".github/workflows/broken.yml": {text: "on: pu", truncated: true},
		},
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/contents/.github/workflows/broken.yml", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	pipeline, partial, err := ScanGitHubWorkflowsRemote("", "owner", "repo", "main", false, false, nil)
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(partial) != 1 {
		t.Errorf("expected 1 partial error (broken.yml), got %d: %v", len(partial), partial)
	}
	if len(pipeline.Jobs) != 1 {
		t.Errorf("expected 1 job (from good.yml), got %d", len(pipeline.Jobs))
	}
}

func TestScanGitHubWorkflowsRemote_RetainsUnparseableFile(t *testing.T) {
	// A file that fetches successfully but fails to parse is still retained on
	// AnalyzedWorkflows (recorded before the parse, #443), so the analyzed CI
	// file is reported even when it does not parse; the parse failure lands as
	// an invalid workflow, not a partial error (#517). Mirror of the local
	// collectWorkflowJobs guarantee.
	const brokenYAML = "jobs: [unterminated\n"
	swapGitRepo(t, gitRepo{refs: []string{"refs/heads/main"}, files: map[string]fakeFile{".github/workflows/broken.yml": {text: brokenYAML}}})
	restRecorder(t, nil)

	pipeline, partial, err := ScanGitHubWorkflowsRemote("", "owner", "repo", "main", false, false, nil)
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(partial) != 0 {
		t.Errorf("expected no partial errors for the unparseable file, got %d: %v", len(partial), partial)
	}
	if len(pipeline.InvalidWorkflows) != 1 {
		t.Fatalf("expected 1 invalid workflow, got %d: %+v", len(pipeline.InvalidWorkflows), pipeline.InvalidWorkflows)
	}
	if pipeline.InvalidWorkflows[0].Path != ".github/workflows/broken.yml" {
		t.Errorf("invalid workflow path = %q, want %q", pipeline.InvalidWorkflows[0].Path, ".github/workflows/broken.yml")
	}
	if len(pipeline.AnalyzedWorkflows) != 1 {
		t.Fatalf("expected the unparseable file to still be retained, got %d: %+v", len(pipeline.AnalyzedWorkflows), pipeline.AnalyzedWorkflows)
	}
	w := pipeline.AnalyzedWorkflows[0]
	if w.Path != ".github/workflows/broken.yml" || w.Content != brokenYAML {
		t.Errorf("retained workflow = %+v, want the fetched path and verbatim content despite the parse failure", w)
	}
}

func TestScanGitHubWorkflowsRemote_InvalidWorkflowReportedSeparately(t *testing.T) {
	// Mirrors the local-scan test: an undefined YAML anchor fetches fine but
	// GitHub refuses to run it. It must not withhold the whole run (#517).
	const goodYAML = `name: good
on: [push]
jobs:
  ok:
    runs-on: ubuntu-latest
    steps: [{ run: echo ok }]
`
	const anchorYAML = `name: Anchor Aliases
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: *checkout_with
`
	swapGitRepo(t, gitRepo{
		refs: []string{"refs/heads/main"},
		files: map[string]fakeFile{
			".github/workflows/good.yml":           {text: goodYAML},
			".github/workflows/anchor-aliases.yml": {text: anchorYAML},
		},
	})
	restRecorder(t, nil)

	pipeline, partial, err := ScanGitHubWorkflowsRemote("", "owner", "repo", "main", false, false, nil)
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(partial) != 0 {
		t.Fatalf("expected no partial errors, got %v", partial)
	}
	if len(pipeline.Jobs) != 1 {
		t.Fatalf("expected 1 job from the valid file only, got %d", len(pipeline.Jobs))
	}
	if len(pipeline.InvalidWorkflows) != 1 {
		t.Fatalf("expected 1 invalid workflow, got %d: %+v", len(pipeline.InvalidWorkflows), pipeline.InvalidWorkflows)
	}
	inv := pipeline.InvalidWorkflows[0]
	if inv.Path != ".github/workflows/anchor-aliases.yml" {
		t.Errorf("path = %q, want %q", inv.Path, ".github/workflows/anchor-aliases.yml")
	}
	if !strings.Contains(inv.Error, "unknown anchor 'checkout_with'") {
		t.Errorf("error = %q, want it to contain %q", inv.Error, "unknown anchor 'checkout_with'")
	}
}

// TestScanGitHubWorkflowsRemote_InvalidWorkflowsSortedByPath pins parity
// with the local scanner (github/github_workflows.go): InvalidWorkflows
// is sorted by path regardless of the order the listing names the files
// in, not just however the Contents API happened to return them.
func TestScanGitHubWorkflowsRemote_InvalidWorkflowsSortedByPath(t *testing.T) {
	const anchorYAML = `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: *checkout_with
`
	const unterminatedYAML = "jobs: [unterminated\n"
	swapGitRepo(t, gitRepo{
		refs: []string{"refs/heads/main"},
		files: map[string]fakeFile{
			".github/workflows/zebra.yml": {text: anchorYAML},
			".github/workflows/alpha.yml": {text: unterminatedYAML},
		},
	})
	restRecorder(t, nil)

	pipeline, _, err := ScanGitHubWorkflowsRemote("", "owner", "repo", "main", false, false, nil)
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(pipeline.InvalidWorkflows) != 2 {
		t.Fatalf("expected 2 invalid workflows, got %d: %+v", len(pipeline.InvalidWorkflows), pipeline.InvalidWorkflows)
	}
	if pipeline.InvalidWorkflows[0].Path != ".github/workflows/alpha.yml" || pipeline.InvalidWorkflows[1].Path != ".github/workflows/zebra.yml" {
		t.Errorf("InvalidWorkflows not sorted by path: %+v", pipeline.InvalidWorkflows)
	}
}

func TestScanGitHubWorkflowsRemote_BadEncoding(t *testing.T) {
	// Defensive: if the API returns content under a non-base64
	// encoding (today none does, but the field exists), surface the
	// failure as a partial error rather than corrupting the parse. The
	// file reads over REST because the tree answer truncated it.
	swapGitRepo(t, gitRepo{refs: []string{"HEAD"}, files: map[string]fakeFile{".github/workflows/ci.yml": {text: "on:", truncated: true}}})
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/contents/.github/workflows/ci.yml", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"content": "raw-bytes-without-encoding", "encoding": "utf-8"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	_, partial, err := ScanGitHubWorkflowsRemote("", "owner", "repo", "", false, false, nil)
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(partial) != 1 {
		t.Errorf("expected exactly one partial error, got %d: %v", len(partial), partial)
	}
}

func TestScanGitHubWorkflowsRemote_RejectsEmptyOwnerOrRepo(t *testing.T) {
	if _, _, err := ScanGitHubWorkflowsRemote("", "", "repo", "main", false, false, nil); err == nil {
		t.Error("expected error for empty owner")
	}
	if _, _, err := ScanGitHubWorkflowsRemote("", "owner", "", "main", false, false, nil); err == nil {
		t.Error("expected error for empty repo")
	}
}

func jobNames(jobs []ir.Job) []string {
	out := make([]string, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, j.Name)
	}
	return out
}

// TestIsAuthTokenMissing covers the matcher that decides whether to
// surface the actionable errAuthRequired versus an unrelated error
// from go-gh. False on nil, false on unrelated errors, true on the
// specific go-gh "authentication token not found" message.
func TestIsAuthTokenMissing(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unrelated", &stubError{msg: "connection refused"}, false},
		{"go-gh phrasing", &stubError{msg: "authentication token not found for host github.com"}, true},
		{"substring match in larger wrap", &stubError{msg: "client init: authentication token not found: configure GH_TOKEN"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAuthTokenMissing(tc.err); got != tc.want {
				t.Errorf("isAuthTokenMissing(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

type stubError struct{ msg string }

func (s *stubError) Error() string { return s.msg }
