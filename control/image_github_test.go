package control

import (
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// imagePath is the path an image not pinned by digest starts in job, read
// from file, in the repository own.
func imagePath(t *testing.T, image, file, own string) AttackPath {
	t.Helper()
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"ci/build": {}}}
	f := opaengine.Finding{Code: string(CodeImageNotPinnedByDigest), Job: "ci/build", File: file, Line: 9, Data: map[string]any{"link": image}}
	paths := AssemblePaths([]opaengine.Finding{f}, sit, own)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	return paths[0]
}

// No image-source control runs on GitHub: an image entry there says its
// source was not checked and reads as possibly malicious, still capped at
// Medium; on GitLab, where the source is checked, it reads as before.
func TestAnImageOnGitHubSaysItsSourceWasNotChecked(t *testing.T) {
	p := imagePath(t, "python:3.11", ".github/workflows/ci.yml", "o/r")
	b := NewPathBlock(p, nil)
	if b.Entry != "python:3.11 (mutable image tag, source not checked on GitHub)" {
		t.Errorf("entry %q", b.Entry)
	}
	if !strings.HasPrefix(b.So, "if this image is compromised or malicious, ") || p.Tier != TierMedium {
		t.Errorf("so %q, tier %s", b.So, p.Tier)
	}
	g := imagePath(t, "python:3.11", ".gitlab-ci.yml", "o/r")
	if b := NewPathBlock(g, nil); b.Entry != "python:3.11 (mutable image tag)" || !strings.HasPrefix(b.So, "if this image is compromised, ") {
		t.Errorf("GitLab: entry %q, so %q", b.Entry, b.So)
	}
}

// An image under the repository owner's own registry namespace is the
// organization's.
func TestAnImageOfTheOwnersNamespaceIsTheOrganizations(t *testing.T) {
	p := imagePath(t, "ghcr.io/Electron/build:latest", ".github/workflows/ci.yml", "electron/electron")
	b := NewPathBlock(p, nil)
	if b.Entry != "ghcr.io/Electron/build:latest (mutable image tag of your organization)" || !strings.HasPrefix(b.So, "if this image is compromised, ") {
		t.Errorf("entry %q, so %q", b.Entry, b.So)
	}
}
