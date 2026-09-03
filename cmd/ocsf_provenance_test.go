package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	providerPkg "github.com/getplumber/plumber/provider"
)

// Each OCSF finding names the analyzed commit as a resource, so a consumer
// can attribute the finding to the exact revision (#443).
func TestOCSFCarriesAnalyzedCommitResource(t *testing.T) {
	sha := "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"
	result := &control.AnalysisResult{
		CiValid:           true,
		ProjectPath:       "acme/target",
		ArtifactCommitSHA: sha,
		ArtifactRef:       "release/2.0",
		ArtifactRepoURI:   "https://gitlab.com/acme/target",
	}
	conf := &configuration.Configuration{PlumberConfig: testDefaultPlumberConfig(t)}
	dir := t.TempDir()
	path := filepath.Join(dir, "out.ocsf.json")
	if err := writeOCSFToFile(&providerPkg.GitLabProvider{}, result, conf, path); err != nil {
		t.Fatalf("write ocsf: %v", err)
	}
	raw, _ := os.ReadFile(path)
	var events []map[string]any
	if err := json.Unmarshal(raw, &events); err != nil {
		t.Fatalf("ocsf not JSON: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("no ocsf events")
	}
	res, ok := events[0]["resources"].([]any)
	if !ok || len(res) == 0 {
		t.Fatalf("resources missing on the finding: %v", events[0]["resources"])
	}
	r := res[0].(map[string]any)
	if r["version"] != sha {
		t.Errorf("resource.version = %v, want the resolved commit sha", r["version"])
	}
	if r["uid"] != "https://gitlab.com/acme/target" {
		t.Errorf("resource.uid = %v, want the repo URI", r["uid"])
	}
	labels, ok := r["labels"].([]any)
	if !ok || len(labels) == 0 || labels[0] != "release/2.0" {
		t.Errorf("resource.labels = %v, want the analyzed ref", r["labels"])
	}
}

// The OCSF resource is emitted whenever EITHER a commit or a repo URI resolved,
// so a cross-project scan that named the repo but could not resolve the target
// commit (and the inverse) still carries what it has (#443).
func TestOCSFResourcePartialProvenanceBoundaries(t *testing.T) {
	sha := "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"

	emit := func(t *testing.T, result *control.AnalysisResult) (map[string]any, bool) {
		t.Helper()
		conf := &configuration.Configuration{PlumberConfig: testDefaultPlumberConfig(t)}
		path := filepath.Join(t.TempDir(), "out.ocsf.json")
		if err := writeOCSFToFile(&providerPkg.GitLabProvider{}, result, conf, path); err != nil {
			t.Fatalf("write ocsf: %v", err)
		}
		raw, _ := os.ReadFile(path)
		var events []map[string]any
		_ = json.Unmarshal(raw, &events)
		if len(events) == 0 {
			return nil, false
		}
		res, ok := events[0]["resources"].([]any)
		if !ok || len(res) == 0 {
			return nil, false
		}
		return res[0].(map[string]any), true
	}

	t.Run("commit resolved but no repo URI still emits the commit", func(t *testing.T) {
		r, ok := emit(t, &control.AnalysisResult{CiValid: true, ProjectPath: "acme/target", ArtifactCommitSHA: sha})
		if !ok {
			t.Fatal("resource omitted, want it emitted when a commit resolved")
		}
		if r["version"] != sha {
			t.Errorf("resource.version = %v, want the commit", r["version"])
		}
		if uid, present := r["uid"]; present && uid != "" {
			t.Errorf("resource.uid = %v, want empty when no repo URI resolved", uid)
		}
	})

	t.Run("repo URI resolved but no commit still emits the repo", func(t *testing.T) {
		r, ok := emit(t, &control.AnalysisResult{CiValid: true, ProjectPath: "acme/target", ArtifactRepoURI: "https://gitlab.com/acme/target"})
		if !ok {
			t.Fatal("resource omitted, want it emitted when a repo URI resolved")
		}
		if r["uid"] != "https://gitlab.com/acme/target" {
			t.Errorf("resource.uid = %v, want the repo URI", r["uid"])
		}
		if ver, present := r["version"]; present && ver != "" {
			t.Errorf("resource.version = %v, want empty when no commit resolved", ver)
		}
	})
}

// With no resolved commit and no repo URI, no resource is fabricated.
func TestOCSFOmitsResourceWhenNoProvenance(t *testing.T) {
	result := &control.AnalysisResult{CiValid: true, ProjectPath: "acme/target"}
	conf := &configuration.Configuration{PlumberConfig: testDefaultPlumberConfig(t)}
	dir := t.TempDir()
	path := filepath.Join(dir, "out.ocsf.json")
	if err := writeOCSFToFile(&providerPkg.GitLabProvider{}, result, conf, path); err != nil {
		t.Fatalf("write ocsf: %v", err)
	}
	raw, _ := os.ReadFile(path)
	var events []map[string]any
	_ = json.Unmarshal(raw, &events)
	if len(events) > 0 {
		if _, present := events[0]["resources"]; present {
			t.Error("resources present with no provenance; it must be omitted")
		}
	}
}
