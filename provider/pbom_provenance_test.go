package provider

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
)

// The provider PBOM writers thread the resolved commit/ref (result.Artifact*)
// into the generated PBOM (#443). These lock that wiring end to end: dropping
// the WithCommit chain would ship a PBOM with no commit provenance.
func TestGitLabWritePBOMCarriesCommit(t *testing.T) {
	sha := "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"
	result := &control.AnalysisResult{
		ProjectPath:       "acme/target",
		ProjectID:         42,
		ArtifactCommitSHA: sha,
		ArtifactRef:       "release/2.0",
	}
	conf := &configuration.Configuration{GitlabURL: "https://gitlab.example"}
	p := &GitLabProvider{}

	t.Run("native PBOM stamps project.commitSHA and project.ref", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pbom.json")
		if err := p.WritePBOM(result, conf, path, nil, false); err != nil {
			t.Fatalf("WritePBOM: %v", err)
		}
		raw, _ := os.ReadFile(path)
		var out struct {
			Project struct {
				CommitSHA string `json:"commitSHA"`
				Ref       string `json:"ref"`
			} `json:"project"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("pbom not JSON: %v", err)
		}
		if out.Project.CommitSHA != sha {
			t.Errorf("project.commitSHA = %q, want the resolved commit threaded from the result", out.Project.CommitSHA)
		}
		if out.Project.Ref != "release/2.0" {
			t.Errorf("project.ref = %q, want the resolved ref threaded from the result", out.Project.Ref)
		}
	})

	t.Run("CycloneDX stamps plumber:git:commit and plumber:git:ref", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cdx.json")
		if err := p.WritePBOMCycloneDX(result, conf, path, nil, false); err != nil {
			t.Fatalf("WritePBOMCycloneDX: %v", err)
		}
		raw, _ := os.ReadFile(path)
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("cyclonedx not JSON: %v", err)
		}
		props := map[string]string{}
		if md, ok := out["metadata"].(map[string]any); ok {
			if comp, ok := md["component"].(map[string]any); ok {
				if list, ok := comp["properties"].([]any); ok {
					for _, e := range list {
						if m, ok := e.(map[string]any); ok {
							name, _ := m["name"].(string)
							value, _ := m["value"].(string)
							props[name] = value
						}
					}
				}
			}
		}
		if props["plumber:git:commit"] != sha {
			t.Errorf("plumber:git:commit = %q, want the resolved commit", props["plumber:git:commit"])
		}
		if props["plumber:git:ref"] != "release/2.0" {
			t.Errorf("plumber:git:ref = %q, want the resolved ref", props["plumber:git:ref"])
		}
	})
}

// The GitHub provider threads the same commit provenance into its PBOM, mirror
// of the GitLab twin (#443).
func TestGitHubWritePBOMCarriesCommit(t *testing.T) {
	sha := "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"
	result := &control.AnalysisResult{
		ProjectPath:       "acme/target",
		ArtifactCommitSHA: sha,
		ArtifactRef:       "release/2.0",
	}
	conf := &configuration.Configuration{GithubAPIHost: "github.com"}
	p := &GitHubProvider{}

	t.Run("native PBOM stamps project.commitSHA and project.ref", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pbom.json")
		if err := p.WritePBOM(result, conf, path, nil, false); err != nil {
			t.Fatalf("WritePBOM: %v", err)
		}
		raw, _ := os.ReadFile(path)
		var out struct {
			Project struct {
				CommitSHA string `json:"commitSHA"`
				Ref       string `json:"ref"`
			} `json:"project"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("pbom not JSON: %v", err)
		}
		if out.Project.CommitSHA != sha {
			t.Errorf("project.commitSHA = %q, want the resolved commit on the GitHub path", out.Project.CommitSHA)
		}
		if out.Project.Ref != "release/2.0" {
			t.Errorf("project.ref = %q, want the resolved ref on the GitHub path", out.Project.Ref)
		}
	})

	t.Run("CycloneDX stamps plumber:git:commit and plumber:git:ref", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cdx.json")
		if err := p.WritePBOMCycloneDX(result, conf, path, nil, false); err != nil {
			t.Fatalf("WritePBOMCycloneDX: %v", err)
		}
		raw, _ := os.ReadFile(path)
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("cyclonedx not JSON: %v", err)
		}
		props := map[string]string{}
		if md, ok := out["metadata"].(map[string]any); ok {
			if comp, ok := md["component"].(map[string]any); ok {
				if list, ok := comp["properties"].([]any); ok {
					for _, e := range list {
						if m, ok := e.(map[string]any); ok {
							name, _ := m["name"].(string)
							value, _ := m["value"].(string)
							props[name] = value
						}
					}
				}
			}
		}
		if props["plumber:git:commit"] != sha {
			t.Errorf("plumber:git:commit = %q, want the resolved commit on the GitHub path", props["plumber:git:commit"])
		}
		if props["plumber:git:ref"] != "release/2.0" {
			t.Errorf("plumber:git:ref = %q, want the resolved ref on the GitHub path", props["plumber:git:ref"])
		}
	})
}
