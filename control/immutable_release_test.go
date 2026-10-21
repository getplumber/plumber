package control

import (
	"context"
	"slices"
	"testing"

	"github.com/getplumber/plumber/configuration"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// immutableReleasePipeline mixes every ISSUE-701 tag shape (#421): an
// immutable-release tag on a step and on a reusable workflow (both
// accepted), and the shapes that keep firing: no metadata, a mutable
// release, a tag shadowed by a same-named branch, a branch.
func immutableReleasePipeline() *ir.NormalizedPipeline {
	immutable := &ir.ActionMetadata{RefKind: "tag", RefExists: true, RefIsImmutableRelease: true}
	return &ir.NormalizedPipeline{
		ProjectPath: "me/repo",
		Jobs: []ir.Job{
			{
				Name: "ci/build",
				Uses: []ir.Action{
					{Uses: "docker/build-push-action@v7.4.0", Line: 12, Metadata: immutable},
					{Uses: "docker/build-push-action@v7"},
					{Uses: "lycheeverse/lychee-action@v2.9.0", Metadata: &ir.ActionMetadata{RefKind: "tag", RefExists: true}},
					{Uses: "octo/shadowed@v1.0.0", Metadata: &ir.ActionMetadata{RefKind: "tag", RefIsImmutableRelease: true, RefIsAmbiguous: true}},
					{Uses: "octo/action@main", Metadata: &ir.ActionMetadata{RefKind: "branch"}},
				},
			},
			{
				Name:                     "ci/call",
				ReusableWorkflowUses:     "octo/shared/.github/workflows/ci.yml@v1.2.0",
				ReusableWorkflowMetadata: immutable,
			},
			{
				Name:                 "ci/call-mutable",
				ReusableWorkflowUses: "octo/shared/.github/workflows/ci.yml@v1",
			},
		},
	}
}

// TestAggregate_ImmutableReleaseTagsArePinned pins the Go mirror of the
// exemption: an immutable-release tag is not counted as unpinned, and it
// is listed with the reason it passed, so the report says why a ref that
// looks unpinned is accepted.
func TestAggregate_ImmutableReleaseTagsArePinned(t *testing.T) {
	pc := &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{}}
	stats := AggregateGitHubStats(immutableReleasePipeline(), pc)

	if stats.ActionRefsUnpinned != 5 {
		t.Errorf("ActionRefsUnpinned = %d, want 5 (every ref but the two immutable-release tags)", stats.ActionRefsUnpinned)
	}
	want := []ImmutableReleaseRef{
		{Job: "ci/build", Uses: "docker/build-push-action@v7.4.0", Line: 12, PinnedVia: PinnedViaImmutableRelease},
		{Job: "ci/call", Uses: "octo/shared/.github/workflows/ci.yml@v1.2.0", PinnedVia: PinnedViaImmutableRelease},
	}
	if !slices.Equal(stats.ActionRefsImmutableRelease, want) {
		t.Errorf("ActionRefsImmutableRelease = %+v, want %+v", stats.ActionRefsImmutableRelease, want)
	}
}

// TestImmutableReleaseRegoAndGoAgree keeps the unpinned counter equal to
// the ISSUE-701 findings: a predicate the Go mirror and the rule read
// differently fails here.
func TestImmutableReleaseRegoAndGoAgree(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	enabled := true
	pc := &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
		ActionsMustBePinnedByCommitSha: &configuration.ActionsPinnedByShaControlConfig{Enabled: &enabled},
	}}}
	pipeline := immutableReleasePipeline()
	findings, err := evaluateStrict(engine, context.Background(), pipeline, buildEngineConfig(pc.ControlsFor("github"), ""))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	flagged := 0
	for _, f := range findings {
		if f.Code == string(CodeActionUnpinned) {
			flagged++
		}
	}
	if got := AggregateGitHubStats(pipeline, pc).ActionRefsUnpinned; got != flagged {
		t.Fatalf("ActionRefsUnpinned = %d, ISSUE-701 findings = %d: the Go mirror drifted from the rule", got, flagged)
	}
}
