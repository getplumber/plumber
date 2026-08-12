package opa

import (
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// enrichFindingsWithJobLocation is what actually derives Data["step"], by
// matching a finding's Line against the job's actions and copying that action's
// Name. The fingerprint tests set Data["step"] by hand, so they never exercise
// this resolution; without it the step segment would silently never be
// populated and two steps using the same action would collide again.
func TestEnrichFindingsWithJobLocation_ResolvesStepName(t *testing.T) {
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:       "coverage",
			OriginFile: ".github/workflows/cov.yml",
			OriginLine: 5,
			Uses: []ir.Action{
				{Uses: "marocchino/sticky-pull-request-comment@abc", Name: "Delete old comment", Line: 216},
				{Uses: "marocchino/sticky-pull-request-comment@abc", Name: "Post PR comment", Line: 316},
			},
		}},
	}
	// Same action, same job, same message: only the line differs, which is the
	// grafana shape the step discriminator exists for.
	findings := []Finding{
		{Code: "ISSUE-713", Job: "coverage", Line: 216, Message: "same message"},
		{Code: "ISSUE-713", Job: "coverage", Line: 316, Message: "same message"},
	}

	enrichFindingsWithJobLocation(findings, pipeline)

	if got := findings[0].Data["step"]; got != "Delete old comment" {
		t.Errorf("finding[0] step = %v, want %q", got, "Delete old comment")
	}
	if got := findings[1].Data["step"]; got != "Post PR comment" {
		t.Errorf("finding[1] step = %v, want %q", got, "Post PR comment")
	}

	// The point of resolving it: the two findings must not collide.
	StampFingerprints(findings, "")
	if findings[0].Fingerprint == findings[1].Fingerprint {
		t.Errorf("both findings share fingerprint %q; step resolution failed to discriminate", findings[0].Fingerprint)
	}
}

// A job-level finding carries no line of its own, so it must not pick up a step
// from an action, either before the Line fallback runs or after it has assigned
// the job's own OriginLine.
func TestEnrichFindingsWithJobLocation_JobLevelFindingGetsNoStep(t *testing.T) {
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:       "build",
			OriginFile: ".github/workflows/ci.yml",
			OriginLine: 12,
			// An action sitting on the job's own header line: the fallback must
			// not cause a job-level finding to adopt it.
			Uses: []ir.Action{{Uses: "actions/checkout@v4", Name: "Checkout", Line: 12}},
		}},
	}
	findings := []Finding{{Code: "ISSUE-801", Job: "build", Message: "no permissions block"}}

	enrichFindingsWithJobLocation(findings, pipeline)

	if _, has := findings[0].Data["step"]; has {
		t.Errorf("job-level finding picked up step %v, want none", findings[0].Data["step"])
	}
	// It should still inherit the job's file and line for reporting.
	if findings[0].File != ".github/workflows/ci.yml" || findings[0].Line != 12 {
		t.Errorf("job-level finding did not inherit job location: file=%q line=%d", findings[0].File, findings[0].Line)
	}
}

// An action with no `name:` in the workflow leaves no step to resolve.
func TestEnrichFindingsWithJobLocation_UnnamedStepAddsNothing(t *testing.T) {
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:       "build",
			OriginFile: "ci.yml",
			OriginLine: 3,
			Uses:       []ir.Action{{Uses: "actions/checkout@v4", Line: 20}},
		}},
	}
	findings := []Finding{{Code: "ISSUE-701", Job: "build", Line: 20, Message: "unpinned"}}

	enrichFindingsWithJobLocation(findings, pipeline)

	if _, has := findings[0].Data["step"]; has {
		t.Errorf("unnamed step produced a step value %v, want none", findings[0].Data["step"])
	}
}
