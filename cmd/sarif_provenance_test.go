package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/getplumber/plumber/control"
)

// SARIF carries the analyzed commit in its standard slot,
// run.versionControlProvenance, so Code Scanning relates the run to the exact
// revision (#443).
func TestSARIFCarriesVersionControlProvenance(t *testing.T) {
	sha := "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"
	result := &control.AnalysisResult{
		CiValid:           true,
		ArtifactCommitSHA: sha,
		ArtifactRef:       "release/2.0",
		ArtifactRepoURI:   "https://gitlab.com/acme/target",
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "out.sarif")
	if err := writeSARIFToFile(result, path, "gitlab"); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	raw, _ := os.ReadFile(path)
	var log map[string]any
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("sarif not JSON: %v", err)
	}
	run := log["runs"].([]any)[0].(map[string]any)
	vcp, ok := run["versionControlProvenance"].([]any)
	if !ok || len(vcp) == 0 {
		t.Fatalf("versionControlProvenance missing: %v", run["versionControlProvenance"])
	}
	d := vcp[0].(map[string]any)
	if d["revisionId"] != sha {
		t.Errorf("revisionId = %v, want the resolved sha", d["revisionId"])
	}
	if d["repositoryUri"] != "https://gitlab.com/acme/target" {
		t.Errorf("repositoryUri = %v, want the project web URL", d["repositoryUri"])
	}
	if d["branch"] != "release/2.0" {
		t.Errorf("branch = %v, want the resolved ref", d["branch"])
	}
}

// versionControlProvenance is gated on the repo URI, not the commit, so a scan
// that named the repository but could not resolve the commit still emits the
// block with repositoryUri and no revisionId (#443).
func TestSARIFProvenancePartialWhenCommitUnresolved(t *testing.T) {
	result := &control.AnalysisResult{
		CiValid:         true,
		ArtifactRepoURI: "https://gitlab.com/acme/target",
		ArtifactRef:     "develop",
		// ArtifactCommitSHA intentionally empty (e.g. a remote cross-project scan)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "out.sarif")
	if err := writeSARIFToFile(result, path, "gitlab"); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	raw, _ := os.ReadFile(path)
	var log map[string]any
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("sarif not JSON: %v", err)
	}
	run := log["runs"].([]any)[0].(map[string]any)
	vcp, ok := run["versionControlProvenance"].([]any)
	if !ok || len(vcp) == 0 {
		t.Fatalf("versionControlProvenance missing; it must still emit when the repo URI resolved: %v", run["versionControlProvenance"])
	}
	d := vcp[0].(map[string]any)
	if d["repositoryUri"] != "https://gitlab.com/acme/target" {
		t.Errorf("repositoryUri = %v, want the project web URL", d["repositoryUri"])
	}
	if rev, present := d["revisionId"]; present && rev != "" {
		t.Errorf("revisionId = %v, want it omitted when no commit resolved", rev)
	}
}

// With no resolved commit, SARIF omits versionControlProvenance rather than
// emitting an empty or HEAD-bearing entry.
func TestSARIFOmitsProvenanceWhenUnresolved(t *testing.T) {
	result := &control.AnalysisResult{CiValid: true}
	dir := t.TempDir()
	path := filepath.Join(dir, "out.sarif")
	if err := writeSARIFToFile(result, path, "gitlab"); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	raw, _ := os.ReadFile(path)
	var log map[string]any
	_ = json.Unmarshal(raw, &log)
	run := log["runs"].([]any)[0].(map[string]any)
	if _, present := run["versionControlProvenance"]; present {
		t.Error("versionControlProvenance present with no resolved commit; it must be omitted")
	}
}
