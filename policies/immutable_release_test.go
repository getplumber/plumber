package policies_test

import (
	"context"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// TestIssue701_ImmutableReleaseTag pins the #421 exemption: a tag backed
// by an immutable GitHub release can never be moved or deleted, so
// ISSUE-701 treats it as pinned, for a step and for a reusable-workflow
// call alike. Every other shape keeps today's finding: no metadata (no
// token, API disabled), a mutable or missing release, a branch, and a
// tag shadowed by a same-named branch, which could win resolution.
func TestIssue701_ImmutableReleaseTag(t *testing.T) {
	engine := newEngine(t)
	immutable := &ir.ActionMetadata{RefKind: "tag", RefExists: true, RefIsImmutableRelease: true}

	cases := []struct {
		name     string
		job      ir.Job
		wantFire bool
	}{
		{"step on an immutable-release tag", ir.Job{Uses: []ir.Action{{Uses: "docker/build-push-action@v7.4.0", Metadata: immutable}}}, false},
		{"step without metadata", ir.Job{Uses: []ir.Action{{Uses: "docker/build-push-action@v7.4.0"}}}, true},
		{"step on a mutable-release tag", ir.Job{Uses: []ir.Action{{Uses: "lycheeverse/lychee-action@v2.9.0", Metadata: &ir.ActionMetadata{RefKind: "tag", RefExists: true}}}}, true},
		{"step on an ambiguous immutable tag", ir.Job{Uses: []ir.Action{{Uses: "docker/build-push-action@v7.4.0", Metadata: &ir.ActionMetadata{RefKind: "tag", RefIsImmutableRelease: true, RefIsAmbiguous: true}}}}, true},
		{"step on a branch carrying the flag", ir.Job{Uses: []ir.Action{{Uses: "docker/build-push-action@main", Metadata: &ir.ActionMetadata{RefKind: "branch", RefIsImmutableRelease: true}}}}, true},
		{"reusable workflow on an immutable-release tag", ir.Job{ReusableWorkflowUses: "octo/shared/.github/workflows/ci.yml@v1.2.0", ReusableWorkflowMetadata: immutable}, false},
		{"reusable workflow without metadata", ir.Job{ReusableWorkflowUses: "octo/shared/.github/workflows/ci.yml@v1.2.0"}, true},
		{"reusable workflow on a mutable-release tag", ir.Job{ReusableWorkflowUses: "octo/shared/.github/workflows/ci.yml@v1.2.0", ReusableWorkflowMetadata: &ir.ActionMetadata{RefKind: "tag"}}, true},
	}
	cfg := map[string]any{"actionsMustBePinnedByCommitSha": true}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			job := tc.job
			job.Name = "build"
			pipeline := &ir.NormalizedPipeline{ProjectPath: "me/repo", Jobs: []ir.Job{job}}
			findings, err := evaluateStrict(engine, context.Background(), pipeline, cfg)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if got := hasCode(findings, "ISSUE-701"); got != tc.wantFire {
				t.Fatalf("ISSUE-701 fired = %v, want %v (findings %+v)", got, tc.wantFire, findings)
			}
		})
	}
}
