package pbom

import (
	"slices"
	"testing"

	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/internal/ir"
)

const stepImageDigest = "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

// TestGenerateFromGitHubIR_DockerStepsAreImagesNotActions pins the PBOM side
// of #571: a job's `uses: docker://` steps are listed as container images of
// that job next to its container image, and never as action includes (which
// would read `docker:` as the owner).
func TestGenerateFromGitHubIR_DockerStepsAreImagesNotActions(t *testing.T) {
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{{
		Name:  "ci/build",
		Image: &ir.Image{Name: "node", Tag: "20"},
		Uses: []ir.Action{
			{Uses: "actions/checkout@v4"},
			{Uses: "docker://alpine:3.20"},
			{Uses: "docker://ghcr.io/owner/image@" + stepImageDigest},
		},
		StepImages: []ir.Image{
			{Name: "alpine", Tag: "3.20"},
			{Name: "ghcr.io/owner/image", Digest: stepImageDigest},
		},
	}}}
	doc := NewGenerator("acme/app", 0, "", "main").GenerateFromGitHubIR(p)

	images := map[string][]string{}
	for _, img := range doc.ContainerImages {
		images[img.Image] = img.Jobs
	}
	for _, ref := range []string{"node:20", "alpine:3.20", "ghcr.io/owner/image@" + stepImageDigest} {
		if jobs, ok := images[ref]; !ok || !slices.Equal(jobs, []string{"ci/build"}) {
			t.Errorf("container image %s: jobs %v (present %v), want [ci/build]; images %v", ref, jobs, ok, images)
		}
	}
	if len(doc.ContainerImages) != 3 {
		t.Errorf("ContainerImages = %d entries, want 3: %v", len(doc.ContainerImages), images)
	}

	var includes []string
	for _, inc := range doc.Includes {
		includes = append(includes, inc.Type+" "+inc.Location+"@"+inc.Version)
	}
	if want := []string{"action actions/checkout@v4"}; !slices.Equal(includes, want) {
		t.Errorf("Includes = %v, want %v (a docker:// step is no action)", includes, want)
	}
}

// TestBuildGitHubPBOMCompliance_PinnedStepImages: a digest-pinned docker://
// step image is recorded as pinned by digest, like a pinned service, and a
// tag-only one is not.
func TestBuildGitHubPBOMCompliance_PinnedStepImages(t *testing.T) {
	pinned := ir.Image{Name: "alpine", Digest: stepImageDigest}
	tagged := ir.Image{Name: "alpine", Tag: "3.20"}
	service := ir.Image{Name: "redis", Digest: stepImageDigest}
	result := &control.AnalysisResult{GitHubPipeline: &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:       "ci/build",
			StepImages: []ir.Image{pinned, tagged},
			Services:   []ir.Image{service},
		}},
	}}
	got := BuildGitHubPBOMCompliance(result).ImagesPinnedByDigest
	for _, img := range []ir.Image{pinned, service} {
		if !got[normalizeIRImageRef(img)] {
			t.Errorf("%s not recorded as pinned by digest: %v", normalizeIRImageRef(img), got)
		}
	}
	if got[normalizeIRImageRef(tagged)] {
		t.Errorf("%s recorded as pinned by digest: %v", normalizeIRImageRef(tagged), got)
	}
}
