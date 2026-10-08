package situation_test

import (
	"reflect"
	"sort"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// TestArtifactExpressionNamesNeedTheSameLiteralParts pins the artifact
// edge between two names holding expressions: they agree only when their
// literal parts, in order, are the same, since each expression stands for
// a value of its own (a matrix entry, a version) and not for any text. The
// macOS upload `rustdesk-unsigned-macos-${{ matrix.job.arch }}` is not the
// `.deb` download `rustdesk-${{ env.VERSION }}-${{ matrix.job.arch }}.deb`.
// A name that is an expression alone stands for an unknown value: it
// agrees with the same expression only, never with every other name nor
// with a download pattern.
func TestArtifactExpressionNamesNeedTheSameLiteralParts(t *testing.T) {
	jobs := []ir.Job{
		{Name: "macos", Artifacts: []ir.ArtifactRef{{Name: "rustdesk-unsigned-macos-${{ matrix.job.arch }}", Mode: "produce"}}},
		{Name: "linux", Artifacts: []ir.ArtifactRef{{Name: "rustdesk-${{ env.VERSION }}-${{ matrix.job.arch }}.deb", Mode: "produce"}}},
		{Name: "drm", Artifacts: []ir.ArtifactRef{{Name: "${{ env.DRM_DEB }}", Mode: "produce"}}},
		{Name: "xpu", Artifacts: []ir.ArtifactRef{{Name: "manywheel-py3_11-xpu", Mode: "produce"}}},
		{Name: "appimage", Artifacts: []ir.ArtifactRef{{Name: "rustdesk-${{ env.VERSION }}-${{ matrix.job.arch }}.deb", Mode: "consume"}}},
		{Name: "publish-macos", Artifacts: []ir.ArtifactRef{{Name: "rustdesk-unsigned-macos-x86_64", Mode: "consume"}}},
		{Name: "merge", Artifacts: []ir.ArtifactRef{{Pattern: "digest-*", Mode: "consume"}}},
		{Name: "extract", Artifacts: []ir.ArtifactRef{{Name: "${{ matrix.source_wheel_build_name }}", Mode: "consume"}}},
		{Name: "drm-consumer", Artifacts: []ir.ArtifactRef{{Name: "${{ env.DRM_DEB }}", Mode: "consume"}}},
	}
	for producer, want := range map[string][]string{
		"macos": {"publish-macos"},
		"linux": {"appimage"},
		"drm":   {"drm-consumer"},
		"xpu":   nil,
	} {
		got := feedsOf(t, append([]ir.Job{}, jobs...), producer)
		if len(got) == 0 {
			got = nil
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s.feeds = %v, want %v", producer, got, want)
		}
	}
}

// TestCrossRunArtifactDownloadIsAnEdgeAcrossWorkflows pins that artifacts
// cross workflow files only through an explicit read of another run
// (download-artifact with run-id): such a download is fed by an upload of
// that name in any workflow, a plain download by its own workflow's only.
func TestCrossRunArtifactDownloadIsAnEdgeAcrossWorkflows(t *testing.T) {
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{
		{Name: "ci/build", OriginFile: ".github/workflows/ci.yml", Artifacts: []ir.ArtifactRef{{Name: "pr", Mode: "produce"}}},
		{Name: "comment/post", OriginFile: ".github/workflows/comment.yml", Artifacts: []ir.ArtifactRef{{Name: "pr", Mode: "consume", CrossRun: true}}},
		{Name: "other/plain", OriginFile: ".github/workflows/other.yml", Artifacts: []ir.ArtifactRef{{Name: "pr", Mode: "consume"}}},
	}}
	got := append([]string{}, evaluate(t, p, nil).Jobs["ci/build"].Feeds...)
	sort.Strings(got)
	if !reflect.DeepEqual(got, []string{"comment/post"}) {
		t.Errorf("ci/build.feeds = %v, want [comment/post]", got)
	}
}

// TestCrossRunDownloadReadsTheWorkflowRunUpstream pins that a download of
// another run's artifacts in a workflow triggered by workflow_run reads the
// runs of the upstream workflows it names: an upload of any other workflow
// feeds it nothing.
func TestCrossRunDownloadReadsTheWorkflowRunUpstream(t *testing.T) {
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{
		{Name: "docker-builds/build", WorkflowName: "docker-builds", OriginFile: ".github/workflows/docker-builds.yml", Artifacts: []ir.ArtifactRef{{Name: "image", Mode: "produce"}}},
		{Name: "mac/build", WorkflowName: "mac", OriginFile: ".github/workflows/mac.yml", Artifacts: []ir.ArtifactRef{{Name: "wheel", Mode: "produce"}}},
		{Name: "cache/download", OriginFile: ".github/workflows/cache.yml", Triggers: []string{"workflow_run"}, WorkflowRunWorkflows: []string{"docker-builds"},
			Artifacts: []ir.ArtifactRef{{Mode: "consume", CrossRun: true}}},
	}}
	r := evaluate(t, p, nil)
	if got := r.Jobs["docker-builds/build"].Feeds; !reflect.DeepEqual(got, []string{"cache/download"}) {
		t.Errorf("docker-builds/build.feeds = %v, want [cache/download]", got)
	}
	if got := r.Jobs["mac/build"].Feeds; len(got) != 0 {
		t.Errorf("mac/build.feeds = %v, want none", got)
	}
}
