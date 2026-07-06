package github

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanDockerfilesSortedByPath(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "z"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	pathZ := filepath.Join(root, "z", "Dockerfile")
	pathA := filepath.Join(root, "a", "Dockerfile")
	mustWriteFile(t, pathZ, "FROM alpine:3\n")
	mustWriteFile(t, pathA, "FROM alpine:3\n")

	dfs := scanDockerfiles(root)
	if len(dfs) != 2 {
		t.Fatalf("expected 2 dockerfiles, got %d", len(dfs))
	}
	if dfs[0].Path >= dfs[1].Path {
		t.Fatalf("expected lexicographic path order, got %q before %q", dfs[0].Path, dfs[1].Path)
	}
	if dfs[0].Path != pathA || dfs[1].Path != pathZ {
		t.Fatalf("expected a before z, got %q then %q", dfs[0].Path, dfs[1].Path)
	}
}

// TestScanDockerfilesSkipsSymlinks guards the no-follow behavior: a committed
// symlink whose name matches the Dockerfile pattern must not be followed out of
// the repository, while a real in-repo Dockerfile is still scanned.
func TestScanDockerfilesSkipsSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	// A file outside the repo an attacker-planted symlink would point at.
	secret := filepath.Join(outside, "secret")
	mustWriteFile(t, secret, "FROM leaked:tag\n")

	// A legitimate in-repo Dockerfile.
	real := filepath.Join(root, "Dockerfile")
	mustWriteFile(t, real, "FROM alpine:3\n")

	// A committed symlink whose name matches the scan pattern.
	link := filepath.Join(root, "Dockerfile.evil")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	dfs := scanDockerfiles(root)
	foundReal := false
	for _, df := range dfs {
		if df.Path == link {
			t.Fatalf("symlinked Dockerfile candidate was scanned: %q", df.Path)
		}
		if df.Path == real {
			foundReal = true
		}
	}
	if !foundReal {
		t.Fatalf("legit in-repo Dockerfile not scanned; got %+v", dfs)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
