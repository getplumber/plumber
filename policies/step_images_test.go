package policies_test

import (
	"context"
	"sort"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// TestImagePoliciesJudgeDockerSteps pins that the images a job's
// `uses: docker://` steps run (ir.Job.StepImages, #571) are judged by the
// forbidden-tag (ISSUE-102), digest (ISSUE-103) and authorized-source
// (ISSUE-101) rules next to the job's container image, and that a workflow
// lockfile changes none of it: lockfiles pin action commits, not images.
func TestImagePoliciesJudgeDockerSteps(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"imageMutableTag": map[string]any{"forbiddenTags": []any{"latest"}},
		"containerImageMustNotUseForbiddenTags": map[string]any{
			"mustBePinnedByDigest": true,
		},
		"imageAuthorizedSources": map[string]any{
			"trustedUrls":            []any{"ghcr.io/*"},
			"trustDockerHubOfficial": true,
		},
		"actionsMustBePinnedByCommitSha": map[string]any{},
	}
	digest := "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
	pipeline := func(lockfile string) *ir.NormalizedPipeline {
		return &ir.NormalizedPipeline{
			Provider:             ir.ProviderGitHub,
			WorkflowLockfilePath: lockfile,
			Jobs: []ir.Job{{
				Name:  "ci/build",
				Image: &ir.Image{Name: "alpine", Tag: "3.20"},
				Uses: []ir.Action{
					{Uses: "docker://quay.io/org/tool:latest"},
					{Uses: "docker://alpine"},
					{Uses: "docker://alpine:3.20@" + digest},
				},
				StepImages: []ir.Image{
					{Name: "quay.io/org/tool", Tag: "latest"},
					{Name: "alpine", Tag: "latest"},
					{Name: "alpine:3.20", Digest: digest},
				},
			}},
		}
	}
	links := func(lockfile string) map[string][]string {
		findings, err := evaluateStrict(engine, context.Background(), pipeline(lockfile), cfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		out := map[string][]string{}
		for _, f := range findings {
			switch f.Code {
			case "ISSUE-101", "ISSUE-102", "ISSUE-103", "ISSUE-701":
				link, _ := f.Data["link"].(string)
				out[f.Code] = append(out[f.Code], link)
			}
		}
		for _, l := range out {
			sort.Strings(l)
		}
		return out
	}

	want := map[string][]string{
		"ISSUE-101": {"quay.io/org/tool:latest"},
		"ISSUE-102": {"alpine:latest", "quay.io/org/tool:latest"},
		"ISSUE-103": {"alpine:3.20", "alpine:latest", "quay.io/org/tool:latest"},
	}
	for _, lockfile := range []string{"", ".github/workflows/actions.lock"} {
		got := links(lockfile)
		if len(got) != len(want) {
			t.Errorf("lockfile %q: codes %v, want %v (ISSUE-701 never judges docker://)", lockfile, got, want)
		}
		for code, w := range want {
			if !stringSlicesEqual(got[code], w) {
				t.Errorf("lockfile %q: %s got %v, want %v", lockfile, code, got[code], w)
			}
		}
	}
}
