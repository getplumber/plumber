package collector

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

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
