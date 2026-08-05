package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
	githubpkg "github.com/getplumber/plumber/github"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// fixtureRoot is the checked-in workflow set used by the CSV-injection guard.
// It lives under testdata/ so the Go tool ignores it, GitHub never schedules
// the workflows, and Plumber's own self-scan does not pick them up: they are
// not in the repository's real .github/workflows/.
const fixtureRoot = "testdata/csv-injection"

// fixtureNames maps each checked-in file to the hostile name it is scanned
// under. The payload lives in the FILE NAME, but those names are not safe to
// commit: a leading space is mishandled by Windows, and `=` / full-width
// characters make a checkout awkward on other tooling. Keeping the repo copies
// inert and applying the real name at copy time exercises the same code path
// without shipping a file nobody can check out.
var fixtureNames = map[string]string{
	"bare-trigger.yml":  "=evil.yml",
	"leading-space.yml": " =spacebypass.yml",
	"fullwidth.yml":     "＝fullwidth.yml",
}

// copyFixtureRepo materialises the fixture as a scannable repository root in a
// temp dir, renaming each file to its hostile form. The collector reads from
// disk, so the files have to exist somewhere it can walk; copying keeps the
// originals pristine and the test hermetic.
func copyFixtureRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	src := filepath.Join(fixtureRoot, ".github", "workflows")
	dst := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("read fixture %s: %v", src, err)
	}
	if len(entries) != len(fixtureNames) {
		t.Fatalf("fixture has %d files, want %d; update fixtureNames", len(entries), len(fixtureNames))
	}
	for _, e := range entries {
		payloadName, ok := fixtureNames[e.Name()]
		if !ok {
			t.Fatalf("fixture file %q has no entry in fixtureNames", e.Name())
		}
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(dst, payloadName), data, 0o644); err != nil {
			t.Fatalf("write %s: %v", payloadName, err)
		}
	}
	return root
}

// End-to-end guard for CSV formula injection (CWE-1236).
//
// The unit tests cover csvSafeCell in isolation; this one exercises the chain a
// real attacker would use. A scanned repository controls its workflow FILE
// NAMES, and the collector derives a job's name from the file's base name
// ("<basename>/<jobid>"), which lands verbatim in the CSV `context` column. So
// a workflow named `=evil.yml` puts an attacker-chosen formula at the start of
// a cell, in a report documented for opening in a spreadsheet.
//
// The fixture covers three distinct vectors: a bare trigger, a leading space
// (trimmed by some importers before evaluation), and a full-width variant
// (evaluated in some locales, and invisible to a byte-wise check).
func TestCSVInjection_WorkflowFilenameReachesContextColumnEscaped(t *testing.T) {
	root := copyFixtureRepo(t)

	// Real collection: this is what turns a file name into a job name.
	// Metadata enrichment and the mutable-exec source scan are off so the test
	// makes no network calls.
	pipeline, _, err := githubpkg.ScanGitHubWorkflowsWithProgress("demo/demo", "main", root, "", false, false, nil)
	if err != nil {
		t.Fatalf("ScanGitHubWorkflowsWithProgress: %v", err)
	}
	if len(pipeline.Jobs) == 0 {
		t.Fatal("collector found no jobs in the fixture")
	}

	// Build one finding per collected job, exactly as a rule would.
	entries := []control.ControlEntry{{ControlName: "actionsMustBePinnedByCommitSha", DisplayName: "Pin"}}
	result := &control.AnalysisResult{CiValid: true}
	for _, job := range pipeline.Jobs {
		result.Findings = append(result.Findings, opaengine.Finding{
			Code: "ISSUE-701", Severity: "high", Job: job.Name,
			Message: "unpinned action", File: job.OriginFile,
		})
	}

	records := buildCSV(entries, result)
	const contextCol = 6

	var checked int
	for _, row := range records[1:] {
		if row[0] == "" {
			continue // summary row for a non-failing control
		}
		ctx := row[contextCol]
		// The attacker-controlled name must still be present: the guard
		// neutralizes, it does not silently drop data.
		if !strings.Contains(ctx, "evil") && !strings.Contains(ctx, "bypass") && !strings.Contains(ctx, "fullwidth") {
			t.Errorf("context %q does not carry the job name", ctx)
		}
		// ...and it must not begin with anything a spreadsheet evaluates.
		if !strings.HasPrefix(ctx, "'") {
			t.Errorf("context %q is not neutralized; a spreadsheet would evaluate it", ctx)
		}
		checked++
	}
	if checked != len(pipeline.Jobs) {
		t.Fatalf("checked %d rows, want %d (one per fixture job)", checked, len(pipeline.Jobs))
	}
}

// The fixture's step names are attacker-controlled too, and they reach the
// finding's step (and so the fingerprint). Nothing should crash or drop them.
func TestCSVInjection_FixtureStepNamesAreCollected(t *testing.T) {
	root := copyFixtureRepo(t)
	pipeline, _, err := githubpkg.ScanGitHubWorkflowsWithProgress("demo/demo", "main", root, "", false, false, nil)
	if err != nil {
		t.Fatalf("ScanGitHubWorkflowsWithProgress: %v", err)
	}
	var withFormulaStep int
	for _, job := range pipeline.Jobs {
		for _, a := range job.Uses {
			if a.Name == "" {
				continue
			}
			switch a.Name[0] {
			case '=', '+', '-', '@', '\t', '\r':
				withFormulaStep++
			default:
				// full-width variants are multi-byte; count them by prefix.
				for _, p := range []string{"＝", "＋", "－", "＠"} {
					if strings.HasPrefix(a.Name, p) {
						withFormulaStep++
					}
				}
			}
		}
	}
	if withFormulaStep == 0 {
		t.Fatal("fixture no longer carries formula-shaped step names; the guard would not be exercised")
	}
}
