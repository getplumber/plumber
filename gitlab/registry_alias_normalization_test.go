package gitlab

// Tests for Docker Hub registry-host alias normalisation in the image
// parsers (GitLab parseImageLink; the GitHub-side splitImageRef fold is
// unit-tested in the github package) and end-to-end through the
// image_authorized_sources policy. The fix lets a trustedUrls entry
// written against docker.io/* match the same image referenced via any
// Docker Hub alias hostname, without per-alias workaround patterns.

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/getplumber/plumber/github"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
	"github.com/getplumber/plumber/utils"
	"github.com/sirupsen/logrus"
)

func TestCanonicalizeDockerHubRegistry(t *testing.T) {
	cases := map[string]string{
		"registry.hub.docker.com": "docker.io",
		"index.docker.io":         "docker.io",
		"registry-1.docker.io":    "docker.io",
		"docker.io":               "docker.io",
		"ghcr.io":                 "ghcr.io",
		"registry.gitlab.com":     "registry.gitlab.com",
		"":                        "",
		"unknown":                 "unknown",
	}
	for in, want := range cases {
		if got := utils.CanonicalizeDockerHubRegistry(in); got != want {
			t.Errorf("CanonicalizeDockerHubRegistry(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFoldDockerHubAliasInName(t *testing.T) {
	cases := map[string]string{
		"registry.hub.docker.com/library/node": "docker.io/library/node",
		"index.docker.io/foo/bar":              "docker.io/foo/bar",
		"ghcr.io/astral-sh/uv":                 "ghcr.io/astral-sh/uv",
		"alpine":                               "alpine",
		"library/node":                         "library/node",
	}
	for in, want := range cases {
		if got := utils.FoldDockerHubAliasInName(in); got != want {
			t.Errorf("FoldDockerHubAliasInName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseImageLink_FoldsHubAliases(t *testing.T) {
	log := logrus.NewEntry(logrus.New())
	cases := []struct {
		link             string
		wantReg, wantNam string
		wantTag          string
	}{
		{"registry.hub.docker.com/library/node:alpine", "docker.io", "library/node", "alpine"},
		{"index.docker.io/python:3.12", "docker.io", "python", "3.12"},
		{"registry-1.docker.io/library/golang:1.26", "docker.io", "library/golang", "1.26"},
		// non-alias registries are untouched
		{"ghcr.io/astral-sh/uv:latest", "ghcr.io", "astral-sh/uv", "latest"},
	}
	for _, tc := range cases {
		info := GitlabPipelineImageInfo{Link: tc.link, Tag: defaultTag}
		info.parseImageLink(log)
		if info.Registry != tc.wantReg || info.Name != tc.wantNam || info.Tag != tc.wantTag {
			t.Errorf("parseImageLink(%q) = {reg:%q name:%q tag:%q}, want {reg:%q name:%q tag:%q}",
				tc.link, info.Registry, info.Name, info.Tag, tc.wantReg, tc.wantNam, tc.wantTag)
		}
	}
}

// TestAliasNormalization_E2E proves that with ONLY docker.io/library/* trusted
// (no registry.hub.docker.com/* workaround pattern), a Hub-alias reference is
// authorized for both providers — i.e. the collector fix removes the need for
// the alias workaround in .plumber.yaml.
func TestAliasNormalization_E2E(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	cfg := map[string]any{"imageAuthorizedSources": map[string]any{
		"trustedUrls":            []string{"docker.io/library/*"},
		"trustDockerHubOfficial": true,
	}}
	log := logrus.NewEntry(logrus.New())

	eval := func(img ir.Image) bool {
		pipeline := &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, Jobs: []ir.Job{{Name: "build", Image: &img}}}
		findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, f := range findings {
			if f.Code == "ISSUE-101" {
				return false
			}
		}
		return true
	}

	// GitLab path through parseImageLink + imageFromInfo
	info := GitlabPipelineImageInfo{Link: "registry.hub.docker.com/library/node:alpine", Tag: defaultTag}
	info.parseImageLink(log)
	if !eval(imageFromInfo(info)) {
		t.Errorf("GitLab: registry.hub.docker.com/library/node:alpine should be authorized via docker.io/library/* after alias fold")
	}

	// GitHub path through the live collector (splitImageRef via
	// parseGitHubContainer inside ScanGitHubWorkflowsWithProgress)
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wf := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container: registry.hub.docker.com/library/node:alpine
    steps:
      - run: echo hi
`
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(wf), 0o644); err != nil {
		t.Fatal(err)
	}
	ghPipeline, _, err := github.ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, false, nil)
	if err != nil {
		t.Fatalf("scan github workflows: %v", err)
	}
	// Guard against a vacuous pass: the ISSUE-101 absence below only
	// proves the fold if the collector actually extracted the container
	// image. Pin the extracted, folded image first.
	if len(ghPipeline.Jobs) != 1 {
		t.Fatalf("GitHub: expected 1 job from the scanned workflow, got %d", len(ghPipeline.Jobs))
	}
	ghImage := ghPipeline.Jobs[0].Image
	if ghImage == nil {
		t.Fatal("GitHub: collector did not extract the container: image")
	}
	if ghImage.Name != "docker.io/library/node" || ghImage.Tag != "alpine" {
		t.Fatalf("GitHub: collector extracted {name:%q tag:%q}, want {name:%q tag:%q} after alias fold",
			ghImage.Name, ghImage.Tag, "docker.io/library/node", "alpine")
	}
	ghFindings, err := engine.Evaluate(context.Background(), ghPipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate github pipeline: %v", err)
	}
	for _, f := range ghFindings {
		if f.Code == "ISSUE-101" {
			t.Errorf("GitHub: registry.hub.docker.com/library/node:alpine should be authorized via docker.io/library/* after alias fold")
		}
	}

	// Positive control through the same collector path: an untrusted
	// image must fire ISSUE-101, proving extraction + evaluation is live
	// rather than merely producing no findings.
	badTmp := t.TempDir()
	badWfDir := filepath.Join(badTmp, ".github", "workflows")
	if err := os.MkdirAll(badWfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	badWf := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container: ghcr.io/evil/tool:latest
    steps:
      - run: echo hi
`
	if err := os.WriteFile(filepath.Join(badWfDir, "ci.yml"), []byte(badWf), 0o644); err != nil {
		t.Fatal(err)
	}
	badPipeline, _, err := github.ScanGitHubWorkflowsWithProgress("owner/repo", "main", badTmp, "", false, false, nil)
	if err != nil {
		t.Fatalf("scan github workflows (untrusted): %v", err)
	}
	badFindings, err := engine.Evaluate(context.Background(), badPipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate github pipeline (untrusted): %v", err)
	}
	fired := false
	for _, f := range badFindings {
		if f.Code == "ISSUE-101" {
			fired = true
		}
	}
	if !fired {
		t.Error("GitHub: ghcr.io/evil/tool:latest through the live collector must raise ISSUE-101")
	}

	// Negative control: a genuinely untrusted registry stays flagged.
	if eval(ir.Image{Registry: "ghcr.io", Name: "evil/tool", Tag: "latest"}) {
		t.Errorf("ghcr.io/evil/tool:latest must remain unauthorized")
	}
}
