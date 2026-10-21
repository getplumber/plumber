package policies_test

import (
	"context"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// TestIssue701_WorkflowLockfile pins #542: when the scanned branch commits
// .github/workflows/actions.lock, the runner executes the locked commits of
// the repository's own steps, so those no longer fire. Reusable workflows
// are not in the lockfile schema: a reusable-workflow call fires whatever
// the lockfile, and so do the steps of a job appended from another
// repository's reusable workflow (its own lockfile is not read yet).
func TestIssue701_WorkflowLockfile(t *testing.T) {
	engine := newEngine(t)
	jobs := []ir.Job{
		{Name: "ci/build", Uses: []ir.Action{{Uses: "docker/setup-qemu-action@v3.6.0"}, {Uses: "codecov/codecov-action@v5"}}},
		{Name: "ci/shared", ReusableWorkflowUses: "octo/shared/.github/workflows/ci.yml@v1.2.0"},
		{Name: "ci/shared/test", Nested: true, Via: []string{"octo/shared/.github/workflows/ci.yml@v1.2.0"},
			Uses: []ir.Action{{Uses: "docker/setup-buildx-action@v3.11.1", Nested: true, Via: []string{"octo/shared/.github/workflows/ci.yml@v1.2.0"}}}},
	}
	cfg := map[string]any{"actionsMustBePinnedByCommitSha": true}

	cases := []struct {
		name     string
		lockfile string
		want     []string
	}{
		{"no lockfile", "", []string{
			"docker/setup-qemu-action@v3.6.0", "codecov/codecov-action@v5",
			"octo/shared/.github/workflows/ci.yml@v1.2.0", "docker/setup-buildx-action@v3.11.1",
		}},
		{"lockfile present", ".github/workflows/actions.lock", []string{
			"octo/shared/.github/workflows/ci.yml@v1.2.0", "docker/setup-buildx-action@v3.11.1",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pipeline := &ir.NormalizedPipeline{ProjectPath: "me/repo", Jobs: jobs, WorkflowLockfilePath: tc.lockfile}
			findings, err := evaluateStrict(engine, context.Background(), pipeline, cfg)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			got := map[string]string{}
			for _, f := range findings {
				if f.Code == "ISSUE-701" {
					uses, _ := f.Data["uses"].(string)
					got[uses] = f.Message
				}
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ISSUE-701 on %v, want exactly %v", got, tc.want)
			}
			for _, u := range tc.want {
				if _, ok := got[u]; !ok {
					t.Errorf("missing ISSUE-701 on %q (got %v)", u, got)
				}
			}
			call := got["octo/shared/.github/workflows/ci.yml@v1.2.0"]
			names := strings.Contains(call, "workflow lockfiles do not cover")
			if names != (tc.lockfile != "") {
				t.Errorf("reusable-call message names the lockfile gap = %v, want %v: %q", names, tc.lockfile != "", call)
			}
		})
	}
}
