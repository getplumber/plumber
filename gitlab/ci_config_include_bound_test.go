package gitlab

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A config that lists the same local include many times must not inline it
// once per entry: duplicates resolve to a single copy and the total number
// of distinct local includes is bounded.
func TestResolveLocalIncludesDeduplicatesAndCaps(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "big.yml"),
		[]byte("marker_dedupe: once\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var inc strings.Builder
	inc.WriteString("include:\n")
	for i := 0; i < 2000; i++ {
		inc.WriteString("  - big.yml\n")
	}
	inc.WriteString("job:\n  script: [echo hi]\n")
	out, err := ResolveLocalIncludes([]byte(inc.String()), root)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Deduplication: the same file listed 2000 times is inlined exactly once,
	// so its unique marker appears once (a size bound alone would also pass
	// under the cap, so assert the marker count directly).
	if n := strings.Count(string(out), "marker_dedupe: once"); n != 1 {
		t.Fatalf("duplicate include inlined %d times, want exactly 1", n)
	}
}

// A config listing many DISTINCT local includes inlines at most the cap,
// so the content of the files beyond it is absent from the result.
func TestResolveLocalIncludesCapsDistinctFiles(t *testing.T) {
	root := t.TempDir()
	total := maxLocalIncludes + 50
	var inc strings.Builder
	inc.WriteString("include:\n")
	for i := 0; i < total; i++ {
		name := "inc" + strconv.Itoa(i) + ".yml"
		if err := os.WriteFile(filepath.Join(root, name),
			[]byte("v"+strconv.Itoa(i)+": marker"+strconv.Itoa(i)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		inc.WriteString("  - " + name + "\n")
	}
	inc.WriteString("job:\n  script: [echo hi]\n")
	out, err := ResolveLocalIncludes([]byte(inc.String()), root)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	s := string(out)
	present := 0
	for i := 0; i < total; i++ {
		if strings.Contains(s, "marker"+strconv.Itoa(i)) {
			present++
		}
	}
	if present > maxLocalIncludes {
		t.Fatalf("inlined %d distinct includes, want at most %d", present, maxLocalIncludes)
	}
	if !strings.Contains(s, "marker0") {
		t.Fatal("expected the first includes to be inlined")
	}
}
