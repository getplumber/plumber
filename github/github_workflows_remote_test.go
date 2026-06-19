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

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/contents/.github/workflows", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"name": "ci.yml", "path": ".github/workflows/ci.yml", "type": "file"},
			{"name": "release.yml", "path": ".github/workflows/release.yml", "type": "file"},
			{"name": "README.md", "path": ".github/workflows/README.md", "type": "file"}, // ignored: not yml/yaml
		})
	})
	mux.HandleFunc("/repos/owner/repo/contents/.github/workflows/ci.yml", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"content":  b64(ciYAML),
			"encoding": "base64",
		})
	})
	mux.HandleFunc("/repos/owner/repo/contents/.github/workflows/release.yml", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"content":  b64(releaseYAML),
			"encoding": "base64",
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	pipeline, partial, err := ScanGitHubWorkflowsRemote("", "owner", "repo", "main", false, nil)
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
}

func TestScanGitHubWorkflowsRemote_NoWorkflowsDir(t *testing.T) {
	// An existing repo+ref that has no .github/workflows directory
	// degrades gracefully to an empty pipeline (no findings fire).
	// The listing 404s, but the repo and ref probes succeed, so this is
	// distinguished from a missing repo/branch (which hard-errors, #222).
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/contents/.github/workflows", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})
	mux.HandleFunc("/repos/owner/repo", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"full_name": "owner/repo"})
	})
	mux.HandleFunc("/repos/owner/repo/commits/main", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	pipeline, partial, err := ScanGitHubWorkflowsRemote("", "owner", "repo", "main", false, nil)
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
	// pipeline that the scorer renders as 100% compliant. The workflows
	// listing 404s (the repo is gone) and so does the repo-existence probe.
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/contents/.github/workflows", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})
	mux.HandleFunc("/repos/owner/repo", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	_, _, err := ScanGitHubWorkflowsRemote("", "owner", "repo", "main", false, nil)
	if err == nil {
		t.Fatal("expected a hard error for a non-existent repository, got nil (vacuous 100% bug #222)")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should say the repository was not found, got: %v", err)
	}
}

func TestScanGitHubWorkflowsRemote_NonexistentBranchErrors(t *testing.T) {
	// #222: a branch that does not exist must be a hard error. The repo
	// exists (200) but the requested ref 404s, as does the workflows listing.
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/contents/.github/workflows", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})
	mux.HandleFunc("/repos/owner/repo", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"full_name": "owner/repo"})
	})
	mux.HandleFunc("/repos/owner/repo/commits/lolxkdaksjdad", func(w http.ResponseWriter, _ *http.Request) {
		// Real GitHub answers a missing ref on the commits endpoint with
		// 422 "No commit found for SHA", not 404.
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "No commit found for SHA: lolxkdaksjdad"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	_, _, err := ScanGitHubWorkflowsRemote("", "owner", "repo", "lolxkdaksjdad", false, nil)
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
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/contents/.github/workflows", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"name": "good.yml", "path": ".github/workflows/good.yml", "type": "file"},
			{"name": "broken.yml", "path": ".github/workflows/broken.yml", "type": "file"},
		})
	})
	mux.HandleFunc("/repos/owner/repo/contents/.github/workflows/good.yml", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"content": b64(goodYAML), "encoding": "base64"})
	})
	mux.HandleFunc("/repos/owner/repo/contents/.github/workflows/broken.yml", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	pipeline, partial, err := ScanGitHubWorkflowsRemote("", "owner", "repo", "main", false, nil)
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

func TestScanGitHubWorkflowsRemote_BadEncoding(t *testing.T) {
	// Defensive: if the API returns content under a non-base64
	// encoding (today none does, but the field exists), surface the
	// failure as a partial error rather than corrupting the parse.
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/contents/.github/workflows", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"name": "ci.yml", "path": ".github/workflows/ci.yml", "type": "file"},
		})
	})
	mux.HandleFunc("/repos/owner/repo/contents/.github/workflows/ci.yml", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"content": "raw-bytes-without-encoding", "encoding": "utf-8"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	swapRESTClient(t, server)

	_, partial, err := ScanGitHubWorkflowsRemote("", "owner", "repo", "", false, nil)
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(partial) != 1 {
		t.Errorf("expected exactly one partial error, got %d: %v", len(partial), partial)
	}
}

func TestScanGitHubWorkflowsRemote_RejectsEmptyOwnerOrRepo(t *testing.T) {
	if _, _, err := ScanGitHubWorkflowsRemote("", "", "repo", "main", false, nil); err == nil {
		t.Error("expected error for empty owner")
	}
	if _, _, err := ScanGitHubWorkflowsRemote("", "owner", "", "main", false, nil); err == nil {
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
