package control

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	githubpkg "github.com/getplumber/plumber/github"
)

func TestIsNetworkError(t *testing.T) {
	network := []string{
		`Post "https://gitlab.com/api/graphql": net/http: request canceled (Client.Timeout exceeded while awaiting headers)`,
		"context deadline exceeded",
		`Get "https://api.github.com/...": dial tcp: lookup api.github.com: no such host`,
		"dial tcp 1.2.3.4:443: connect: connection refused",
		"read: connection reset by peer",
	}
	for _, msg := range network {
		if !isNetworkError(errors.New(msg)) {
			t.Errorf("expected network error for %q", msg)
		}
	}

	definitive := []string{
		"GET .../tags: 404 Not Found",
		"401 Unauthorized",
		"403 Forbidden: IP allow list",
		"yaml: line 3: mapping values are not allowed",
		"",
	}
	for _, msg := range definitive {
		if isNetworkError(errors.New(msg)) {
			t.Errorf("did not expect network error for %q", msg)
		}
	}
	if isNetworkError(nil) {
		t.Error("nil must not be a network error")
	}
	// Wrapped errors are matched via the message chain.
	if !isNetworkError(fmt.Errorf("collect images: %w", errors.New("i/o timeout"))) {
		t.Error("wrapped i/o timeout should match")
	}
}

func TestMarkDegraded(t *testing.T) {
	r := &AnalysisResult{}
	markDegraded(r, "reason A")
	markDegraded(r, "reason A") // dedup
	markDegraded(r, "reason B")
	if !r.DataCollectionDegraded {
		t.Fatal("expected degraded flag set")
	}
	if len(r.DegradedReasons) != 2 {
		t.Fatalf("expected 2 deduped reasons, got %v", r.DegradedReasons)
	}
	markDegraded(nil, "noop") // must not panic
}

func TestDegradedReasonsFromGitHubCollection(t *testing.T) {
	t.Run("healthy run yields no reasons", func(t *testing.T) {
		if got := degradedReasonsFromGitHubCollection(0, false); got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})

	t.Run("skipped workflow files", func(t *testing.T) {
		got := degradedReasonsFromGitHubCollection(3, false)
		if len(got) != 1 {
			t.Fatalf("expected 1 reason, got %d: %v", len(got), got)
		}
		if want := "3 workflow file(s) could not be fetched and were skipped"; got[0] != want {
			t.Fatalf("reason = %q, want %q", got[0], want)
		}
	})

	t.Run("branch fetch failure", func(t *testing.T) {
		got := degradedReasonsFromGitHubCollection(0, true)
		if len(got) != 1 {
			t.Fatalf("expected 1 reason, got %d: %v", len(got), got)
		}
	})

	t.Run("both failure modes", func(t *testing.T) {
		got := degradedReasonsFromGitHubCollection(2, true)
		if len(got) != 2 {
			t.Fatalf("expected 2 reasons, got %d: %v", len(got), got)
		}
	})
}

func TestApplyGitHubDegraded(t *testing.T) {
	t.Run("healthy run leaves result clean", func(t *testing.T) {
		r := &AnalysisResult{}
		applyGitHubDegraded(r, 0, false)
		if r.DataCollectionDegraded {
			t.Fatal("expected DataCollectionDegraded false")
		}
		if len(r.DegradedReasons) != 0 {
			t.Fatalf("expected no reasons, got %v", r.DegradedReasons)
		}
	})

	t.Run("partial files set degraded", func(t *testing.T) {
		r := &AnalysisResult{}
		applyGitHubDegraded(r, 4, false)
		if !r.DataCollectionDegraded {
			t.Fatal("expected DataCollectionDegraded true")
		}
		if len(r.DegradedReasons) != 1 {
			t.Fatalf("expected 1 reason, got %v", r.DegradedReasons)
		}
	})

	t.Run("branch fetch failure sets degraded", func(t *testing.T) {
		r := &AnalysisResult{}
		applyGitHubDegraded(r, 0, true)
		if !r.DataCollectionDegraded {
			t.Fatal("expected DataCollectionDegraded true")
		}
		if len(r.DegradedReasons) != 1 {
			t.Fatalf("expected 1 reason, got %v", r.DegradedReasons)
		}
	})

	t.Run("both modes accumulate reasons", func(t *testing.T) {
		r := &AnalysisResult{}
		applyGitHubDegraded(r, 2, true)
		if !r.DataCollectionDegraded {
			t.Fatal("expected DataCollectionDegraded true")
		}
		if len(r.DegradedReasons) != 2 {
			t.Fatalf("expected 2 reasons, got %v", r.DegradedReasons)
		}
	})

	// A run whose only problem is a workflow file GitHub itself refuses to
	// run must not read as data-collection-degraded (#517): the file was
	// fetched fine, it is reported through ISSUE-423 instead.
	t.Run("invalid workflow alone leaves the run clean", func(t *testing.T) {
		tmp := t.TempDir()
		wfDir := filepath.Join(tmp, ".github", "workflows")
		if err := os.MkdirAll(wfDir, 0o755); err != nil {
			t.Fatal(err)
		}
		invalid := `name: Anchor Aliases
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: *checkout_with
`
		if err := os.WriteFile(filepath.Join(wfDir, "anchor-aliases.yml"), []byte(invalid), 0o644); err != nil {
			t.Fatal(err)
		}

		pipeline, partial, err := githubpkg.ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
		if err != nil {
			t.Fatalf("unexpected scan error: %v", err)
		}
		if len(pipeline.InvalidWorkflows) != 1 {
			t.Fatalf("expected 1 invalid workflow, got %d", len(pipeline.InvalidWorkflows))
		}

		r := &AnalysisResult{}
		applyGitHubDegraded(r, len(partial), false)
		if r.DataCollectionDegraded {
			t.Fatalf("expected DataCollectionDegraded false, got reasons %v", r.DegradedReasons)
		}
	})
}
