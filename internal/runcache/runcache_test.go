package runcache

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyOfARemoteProject(t *testing.T) {
	got := Key("github", "Getplumber-Examples/Plumber-Example-Critical", "/somewhere")
	if want := "github/getplumber-examples/plumber-example-critical.json"; got != want {
		t.Errorf("Key = %q, want %q", got, want)
	}
	if got := Key("gitlab", "group/sub/project", ""); got != "gitlab/group/sub/project.json" {
		t.Errorf("nested group Key = %q", got)
	}
}

// A project path is read off a remote or a flag: no segment may climb out
// of the cache or add a separator of its own.
func TestKeySanitizesEverySegment(t *testing.T) {
	for _, project := range []string{"../../etc/passwd", "a/../../b", `..\..\x/y`, "Own er/re:po", "/abs/../x", "a//b"} {
		got := Key("Git/Hub", project, "")
		if !filepath.IsLocal(got) || filepath.Clean(got) != got {
			t.Errorf("Key(%q) = %q leaves the cache", project, got)
		}
		for _, seg := range strings.Split(got, "/") {
			if seg == ".." || seg == "." || seg == "" || strings.ContainsAny(seg, `\: `) || seg != strings.ToLower(seg) {
				t.Errorf("Key(%q) = %q has segment %q", project, got, seg)
			}
		}
	}
	if got := Key("Git/Hub", "Own er/re:po", ""); got != "git-hub/own-er/re-po.json" {
		t.Errorf("Key = %q", got)
	}
}

func TestKeyOfALocalAnalysisHashesTheWorkingDirectory(t *testing.T) {
	sum := sha256.Sum256([]byte("/home/u/repo"))
	want := "local/" + hex.EncodeToString(sum[:])[:16] + ".json"
	if got := Key("github", "", "/home/u/repo"); got != want {
		t.Errorf("Key = %q, want %q", got, want)
	}
	if Key("github", "", "/home/u/other") == want {
		t.Error("two directories share one key")
	}
}

func TestWriteIsPrivateAtomicAndMovesLast(t *testing.T) {
	root := filepath.Join(t.TempDir(), "plumber", "runs")
	rel := "github/o/r.json"
	if err := Write(root, rel, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := Write(root, rel, []byte(`{"a":2}`)); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil || string(got) != `{"a":2}` {
		t.Fatalf("file = %q, %v", got, err)
	}
	for _, p := range []string{filepath.Join(root, rel), filepath.Join(root, "last")} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", p, st.Mode().Perm())
		}
	}
	for _, dir := range []string{root, filepath.Join(root, "github", "o")} {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".") {
				t.Errorf("temporary file left behind: %s", filepath.Join(dir, e.Name()))
			}
		}
	}
	if err := Write(root, "local/abc.json", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	last, err := Last(root)
	if err != nil || last != filepath.Join(root, "local", "abc.json") {
		t.Errorf("Last = %q, %v", last, err)
	}
}

func TestWriteRefusesAPathOutsideTheCache(t *testing.T) {
	root := t.TempDir()
	if err := Write(root, "../x.json", []byte(`{}`)); err == nil {
		t.Error("Write accepted a path outside the cache")
	}
}

func TestLastWithNoRun(t *testing.T) {
	_, err := Last(t.TempDir())
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Last = %v, want a not-exist error", err)
	}
}

func TestLastRejectsAPointerOutsideTheCache(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "last"), []byte("../../etc/passwd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Last(root); err == nil {
		t.Error("Last followed a pointer out of the cache")
	}
}

func TestFindAProject(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{"github/o/r.json", "gitlab/o/r.json", "github/o/only.json"} {
		if err := Write(root, rel, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := Find(root, "", "O/Only"); err != nil || got != filepath.Join(root, "github", "o", "only.json") {
		t.Errorf("Find = %q, %v", got, err)
	}
	if got, err := Find(root, "gitlab", "o/r"); err != nil || got != filepath.Join(root, "gitlab", "o", "r.json") {
		t.Errorf("Find with provider = %q, %v", got, err)
	}
	if _, err := Find(root, "", "o/r"); err == nil || !strings.Contains(err.Error(), "--provider") {
		t.Errorf("an ambiguous project = %v, want a --provider hint", err)
	}
	if _, err := Find(root, "", "o/none"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing project = %v, want a not-exist error", err)
	}
}
