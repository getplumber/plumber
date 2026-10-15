package cmd

import (
	"reflect"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/gitlab"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

func exemptImagesConfig(provider string, tags, exempt []string) *configuration.PlumberConfig {
	pinned := true
	c := &configuration.ImageForbiddenTagsControlConfig{
		Tags:                                tags,
		ContainerImagesMustBePinnedByDigest: &pinned,
		ExemptImages:                        exempt,
	}
	pc := &configuration.PlumberConfig{}
	p := &configuration.ProviderConfig{Controls: configuration.ControlsConfig{ContainerImageMustNotUseForbiddenTags: c}}
	if provider == "github" {
		pc.GitHub = p
	} else {
		pc.GitLab = p
	}
	return pc
}

// TestBuildGitLabControlStats_ExemptImages pins the GitLab stat block of
// containerImageMustNotUseForbiddenTags with exemptImages: an exempt image
// (exemptImages entry on a forbidden tag) leaves "Not Pinned By Digest"
// (ISSUE-103 does not judge it) and is named, once, in its own line.
func TestBuildGitLabControlStats_ExemptImages(t *testing.T) {
	result := &control.AnalysisResult{PipelineImageData: &gitlab.GitlabPipelineImageData{
		Images: []gitlab.GitlabPipelineImageInfo{
			{Link: "ghcr.io/my-org/report-tool:latest", Registry: "ghcr.io", Name: "my-org/report-tool", Tag: "latest", Job: "report"},
			{Link: "ghcr.io/my-org/report-tool:latest", Registry: "ghcr.io", Name: "my-org/report-tool", Tag: "latest", Job: "report-again"},
			// GitLab keeps `@<algo>` in the tag of a tag+digest reference;
			// the digest plays no part in the exemption.
			{Link: "docker.io/debian:latest@sha256:913f6706df59", Registry: "docker.io", Name: "debian", Tag: "latest@sha256", Job: "pinned"},
			{Link: "alpine:latest", Registry: "docker.io", Name: "alpine", Tag: "latest", Job: "deploy"},
			{Link: "$NOPE", Registry: "unknown", Name: "$NOPE", Unresolved: true, Job: "unresolved"},
		},
	}}
	findings := []opaengine.Finding{{Code: "ISSUE-102", Job: "deploy"}, {Code: "ISSUE-103", Job: "deploy"}}
	pc := exemptImagesConfig("gitlab", []string{"latest"}, []string{"ghcr.io/my-org/report-tool", "debian"})

	got := buildGitLabControlStats("containerImageMustNotUseForbiddenTags", result, pc, findings)
	want := []statLine{
		{Label: statTotalImages, Value: "5"},
		{Label: "Pinned By Digest", Value: "1"},
		{Label: "Not Pinned By Digest", Value: "1"},
		{Label: "Using Forbidden Tags", Value: "1"},
		{Label: statUnresolvedImageRefs, Value: "1"},
		{Label: statExemptedImages, Value: "docker.io/debian:latest@sha256:913f6706df59, ghcr.io/my-org/report-tool:latest"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}

// TestBuildGitLabControlStats_ExemptImagesNoForbiddenTag: the exemption
// covers a forbidden tag only, so an exemptImages entry on an allowed tag is
// judged like any image: it counts as "Not Pinned By Digest" and no line
// names it.
func TestBuildGitLabControlStats_ExemptImagesNoForbiddenTag(t *testing.T) {
	result := &control.AnalysisResult{PipelineImageData: &gitlab.GitlabPipelineImageData{
		Images: []gitlab.GitlabPipelineImageInfo{
			{Link: "debian:stable-slim", Registry: "docker.io", Name: "debian", Tag: "stable-slim", Job: "versioned"},
		},
	}}
	pc := exemptImagesConfig("gitlab", []string{"latest"}, []string{"debian"})

	got := buildGitLabControlStats("containerImageMustNotUseForbiddenTags", result, pc, nil)
	want := []statLine{
		{Label: statTotalImages, Value: "1"},
		{Label: "Pinned By Digest", Value: "0"},
		{Label: "Not Pinned By Digest", Value: "1"},
		{Label: "Using Forbidden Tags", Value: "0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}

// TestBuildGitHubControlStats_ExemptImages is the GitHub counterpart: the
// aggregate's exempt counters reach the stat block the same way.
func TestBuildGitHubControlStats_ExemptImages(t *testing.T) {
	stats := &control.GitHubAnalysisStats{
		ImagesTotal:          4,
		ImagesPinnedByDigest: 1,
		ImagesUsingForbidden: 1,
		ImagesExemptUnpinned: 2,
		ImagesExempted:       []string{"ghcr.io/my-org/report-tool:latest", "debian:latest", "ghcr.io/my-org/report-tool:latest"},
	}

	got := buildGitHubControlStats("containerImageMustNotUseForbiddenTags", stats, nil)
	want := []statLine{
		{Label: statTotalImages, Value: "4"},
		{Label: "Pinned By Digest", Value: "1"},
		{Label: "Not Pinned By Digest", Value: "1"},
		{Label: "Using Forbidden Tags", Value: "1"},
		{Label: statExemptedImages, Value: "debian:latest, ghcr.io/my-org/report-tool:latest"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}

// TestRenderFindingGroupsV4_ExemptedImagesNote: the contextual report prints
// no stat block, so the exempted images get their own note after the attack
// paths; without it an exemption would hide an image from the default
// report entirely.
func TestRenderFindingGroupsV4_ExemptedImagesNote(t *testing.T) {
	groups := []findingGroup{{
		Title: "Container images must not use forbidden tags",
		Stats: []statLine{
			{Label: statTotalImages, Value: "3"},
			{Label: statExemptedImages, Value: "debian:latest, ghcr.io/my-org/report-tool:latest"},
		},
		Findings: []detailedFinding{{Code: "ISSUE-102", Message: "alpine:latest", ContextualSeverity: "medium"}},
	}}
	out := captureStdoutAll(t, func() { renderFindingGroupsV4(groups, nil, nil, reportBlock) })

	assertContains(t, out, "Exempted by configuration")
	assertContains(t, out, "Container images must not use forbidden tags: debian:latest, ghcr.io/my-org/report-tool:latest")
	if strings.Contains(out, statTotalImages) {
		t.Errorf("only the exemption line belongs in the note:\n%s", out)
	}
}

// TestRenderPassedControlsSummary_ExemptedImages: a control that passed
// because every flagged image is exempt still names the exempted images
// under its ✓ line, on both profiles.
func TestRenderPassedControlsSummary_ExemptedImages(t *testing.T) {
	groups := []findingGroup{{
		Title: "Container images must not use forbidden tags",
		Stats: []statLine{
			{Label: statTotalImages, Value: "1"},
			{Label: statExemptedImages, Value: "debian:latest"},
		},
	}}
	out := captureStdoutAll(t, func() { renderPassedControlsSummary(groups) })

	assertContains(t, out, "Exempted By Configuration: debian:latest")
	if strings.Contains(out, statTotalImages) {
		t.Errorf("a passed control prints its notes only, not its stats:\n%s", out)
	}
}

// TestRenderFindingGroupsV4_NoExemptionNoNote: nothing exempted, no note.
func TestRenderFindingGroupsV4_NoExemptionNoNote(t *testing.T) {
	groups := []findingGroup{{
		Title:    "Container images must not use forbidden tags",
		Stats:    []statLine{{Label: statTotalImages, Value: "1"}},
		Findings: []detailedFinding{{Code: "ISSUE-102", Message: "alpine:latest", ContextualSeverity: "medium"}},
	}}
	out := captureStdoutAll(t, func() { renderFindingGroupsV4(groups, nil, nil, reportBlock) })
	if strings.Contains(out, "Exempted") {
		t.Errorf("no exemption, no note:\n%s", out)
	}
}
