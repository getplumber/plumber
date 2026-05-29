package collector

// Tests for Docker Hub registry-host alias normalisation in the image
// parsers (GitLab parseImageLink + GitHub splitImageRef) and end-to-end
// through the image_authorized_sources policy. The fix lets a trustedUrls
// entry written against docker.io/* match the same image referenced via any
// Docker Hub alias hostname, without per-alias workaround patterns.

import (
	"context"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
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
		if got := canonicalizeDockerHubRegistry(in); got != want {
			t.Errorf("canonicalizeDockerHubRegistry(%q) = %q, want %q", in, got, want)
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
		if got := foldDockerHubAliasInName(in); got != want {
			t.Errorf("foldDockerHubAliasInName(%q) = %q, want %q", in, got, want)
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

func TestSplitImageRef_FoldsHubAliases(t *testing.T) {
	cases := []struct {
		ref      string
		wantName string
		wantTag  string
	}{
		{"registry.hub.docker.com/library/node:alpine", "docker.io/library/node", "alpine"},
		{"index.docker.io/python:3.12", "docker.io/python", "3.12"},
		{"ghcr.io/astral-sh/uv:latest", "ghcr.io/astral-sh/uv", "latest"},
		{"alpine:3.20", "alpine", "3.20"},
	}
	for _, tc := range cases {
		got := splitImageRef(tc.ref)
		if got.Name != tc.wantName || got.Tag != tc.wantTag {
			t.Errorf("splitImageRef(%q) = {name:%q tag:%q}, want {name:%q tag:%q}",
				tc.ref, got.Name, got.Tag, tc.wantName, tc.wantTag)
		}
	}
}

// TestAliasNormalization_E2E proves that with ONLY docker.io/library/* trusted
// (no registry.hub.docker.com/* workaround pattern), a Hub-alias reference is
// authorized for both providers — i.e. the collector fix removes the need for
// the alias workaround in .plumber.yaml.
func TestAliasNormalization_E2E(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFS(policies.FS); err != nil {
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

	// GitHub path through splitImageRef
	if !eval(splitImageRef("registry.hub.docker.com/library/node:alpine")) {
		t.Errorf("GitHub: registry.hub.docker.com/library/node:alpine should be authorized via docker.io/library/* after alias fold")
	}

	// Negative control: a genuinely untrusted registry stays flagged.
	if eval(ir.Image{Registry: "ghcr.io", Name: "evil/tool", Tag: "latest"}) {
		t.Errorf("ghcr.io/evil/tool:latest must remain unauthorized")
	}
}
