package github

import (
	"os"
	"path/filepath"
	"testing"
)

// collectWorkflowJobs retains each scanned workflow file for the JSON report's
// analyzed-CI-config block (#443): under its repo-relative path, with content
// preserved, sorted by path, and recorded before parsing so an unparseable
// workflow is still reported as analyzed.
func TestCollectWorkflowJobsRetainsFiles(t *testing.T) {
	root := t.TempDir()
	wf := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o755); err != nil {
		t.Fatal(err)
	}
	valid := "name: %s\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	// Names deliberately out of alphabetical order to prove sorting by path.
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(wf, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	zebra := "name: zebra\non: push\njobs:\n  z:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo z\n"
	alpha := "name: alpha\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo a\n"
	broken := "jobs: [unterminated\n"
	_ = valid
	write("zebra.yml", zebra)
	write("alpha.yaml", alpha)
	write("broken.yml", broken)

	_, files, partial, err := collectWorkflowJobs(root)
	if err != nil {
		t.Fatalf("collectWorkflowJobs: %v", err)
	}

	// All three files retained, including the unparseable one (recorded before
	// the parse), sorted by repo-relative path.
	wantPaths := []string{
		".github/workflows/alpha.yaml",
		".github/workflows/broken.yml",
		".github/workflows/zebra.yml",
	}
	if len(files) != len(wantPaths) {
		t.Fatalf("retained %d files, want %d: %+v", len(files), len(wantPaths), files)
	}
	for i, want := range wantPaths {
		if files[i].Path != want {
			t.Errorf("files[%d].Path = %q, want %q (sorted by path)", i, files[i].Path, want)
		}
	}

	// Content is preserved verbatim, and the broken file being present proves
	// retention happens before the parse failure.
	byPath := map[string]string{}
	for _, f := range files {
		byPath[f.Path] = f.Content
	}
	if byPath[".github/workflows/alpha.yaml"] != alpha {
		t.Errorf("alpha content = %q, want it preserved", byPath[".github/workflows/alpha.yaml"])
	}
	if byPath[".github/workflows/broken.yml"] != broken {
		t.Errorf("broken content = %q, want the unparseable file retained verbatim", byPath[".github/workflows/broken.yml"])
	}

	// The unparseable file surfaces as a partial error, not an abort.
	if len(partial) == 0 {
		t.Error("want a partial error for the unparseable workflow, got none")
	}
}
