package gitlab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveLocalIncludesContainment checks that include:local resolution
// stays within the analyzed repository: an in-repo include is inlined, while
// an include whose path resolves outside the repository (directly or via a
// symlink) is not read.
func TestResolveLocalIncludesContainment(t *testing.T) {
	repo := t.TempDir()
	outside := t.TempDir()

	external := filepath.Join(outside, "external.txt")
	if err := os.WriteFile(external, []byte("EXTERNAL"), 0o600); err != nil {
		t.Fatalf("seed external file: %v", err)
	}

	if err := os.MkdirAll(filepath.Join(repo, "templates"), 0o755); err != nil {
		t.Fatalf("mkdir templates: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "templates", "build.yml"), []byte("build:\n  script: echo hi\n"), 0o600); err != nil {
		t.Fatalf("seed template: %v", err)
	}

	rel, err := filepath.Rel(repo, external)
	if err != nil {
		t.Fatalf("compute rel: %v", err)
	}

	t.Run("relative path outside repo is rejected", func(t *testing.T) {
		ci := []byte("include:\n  - local: '" + rel + "'\n")
		if _, err := ResolveLocalIncludes(ci, repo); err == nil {
			t.Fatal("expected rejection for include resolving outside the repo, got nil")
		} else if !strings.Contains(err.Error(), "outside the repository") {
			t.Fatalf("error should explain containment, got: %v", err)
		}
	})

	t.Run("bare-string path outside repo is rejected", func(t *testing.T) {
		ci := []byte("include: '" + rel + "'\n")
		if _, err := ResolveLocalIncludes(ci, repo); err == nil {
			t.Fatal("expected rejection for bare-string include resolving outside the repo, got nil")
		}
	})

	t.Run("symlink pointing outside repo is rejected", func(t *testing.T) {
		link := filepath.Join(repo, "link")
		if err := os.Symlink(external, link); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
		ci := []byte("include:\n  - local: 'link'\n")
		if _, err := ResolveLocalIncludes(ci, repo); err == nil {
			t.Fatal("expected rejection for symlink resolving outside the repo, got nil")
		}
	})

	t.Run("oversized in-repo include is rejected", func(t *testing.T) {
		big := filepath.Join(repo, "big.yml")
		if err := os.WriteFile(big, make([]byte, maxLocalIncludeBytes+1), 0o600); err != nil {
			t.Fatalf("seed oversized include: %v", err)
		}
		ci := []byte("include:\n  - local: 'big.yml'\n")
		if _, err := ResolveLocalIncludes(ci, repo); err == nil {
			t.Fatal("expected rejection for an oversized include, got nil")
		} else if !strings.Contains(err.Error(), "limit") {
			t.Fatalf("error should mention the size limit, got: %v", err)
		}
	})

	t.Run("in-repo include is inlined", func(t *testing.T) {
		ci := []byte("include:\n  - local: 'templates/build.yml'\nstages:\n  - build\n")
		out, err := ResolveLocalIncludes(ci, repo)
		if err != nil {
			t.Fatalf("in-repo include should resolve, got error: %v", err)
		}
		if !strings.Contains(string(out), "echo hi") {
			t.Fatalf("resolved output should inline the template, got: %s", out)
		}
	})
}

func TestPathWithinInclude(t *testing.T) {
	root := filepath.FromSlash("/home/ci/repo")
	cases := []struct {
		target string
		want   bool
	}{
		{filepath.FromSlash("/home/ci/repo"), true},
		{filepath.FromSlash("/home/ci/repo/templates/build.yml"), true},
		{filepath.FromSlash("/home/ci/other/file"), false},
		{filepath.FromSlash("/etc/hosts"), false},
		{filepath.FromSlash("/home/ci/repo-sibling/file"), false}, // prefix-string trap
	}
	for _, tc := range cases {
		if got := pathWithin(root, tc.target); got != tc.want {
			t.Errorf("pathWithin(%q, %q) = %v, want %v", root, tc.target, got, tc.want)
		}
	}
}
