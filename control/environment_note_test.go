package control

import (
	"slices"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// environmentJob is a pull_request_target job checking out the pull
// request head, holding a secret, in environment eval-gate whose
// protection reads protected ("true", "false" or "unknown"), the
// environment also listed as a deploy, as an older facts layer did.
func environmentJob(protected string) *Situation {
	js := JobSituation{PrivilegedTriggers: []string{"pull_request_target"}, CacheScopes: defaultScope,
		Impact: []ImpactFact{{Kind: "deploys", State: "proven", Evidence: "environment: eval-gate"}}}
	js.Privilege.Secrets, js.Privilege.SecretsState = []string{"GEMINI_API_KEY"}, "proven"
	js.Privilege.Environment.Name, js.Privilege.Environment.Protected = "eval-gate", protected
	return &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"eval/pr-evaluation": js}}
}

// An environment is never an impact: the path reaches the secret alone.
// The block says the job runs in the environment, and that a review gates
// it when the environment requires one.
func TestAnEnvironmentIsANoteNeverAnImpact(t *testing.T) {
	f := entryFinding("ISSUE-804", "eval/pr-evaluation", "github.event.pull_request.head.sha")
	for protected, gated := range map[string]bool{"true": true, "false": false, "unknown": false} {
		paths := assemblePaths([]opaengine.Finding{f}, environmentJob(protected))
		if len(paths) != 1 || len(paths[0].Reach.Impacts) != 0 {
			t.Fatalf("%s: want one path with no impact, got %+v", protected, paths)
		}
		b := NewPathBlock(paths[0], nil)
		if b.Branches[0].Reach != "1 secret" {
			t.Errorf("%s: reach %q", protected, b.Branches[0].Reach)
		}
		notes := b.Notes()
		if !slices.Contains(notes, "the job runs in environment `eval-gate`") {
			t.Errorf("%s: notes %q lack the environment", protected, notes)
		}
		if slices.Contains(notes, environmentReviewNote) != gated {
			t.Errorf("%s: notes %q, review note expected %v", protected, notes, gated)
		}
	}
}

// The environment's approval fact, when the facts know it, says whether
// an approval gates the job, whatever its protection reads.
func TestEnvironmentOfReadsTheApprovalFactWhenKnown(t *testing.T) {
	for approval, want := range map[string]string{"required": "required", "none": "none", "unknown": "unknown"} {
		js := JobSituation{}
		js.Privilege.Environment.Name, js.Privilege.Environment.Protected, js.Privilege.Environment.Reviewers = "prod", "unknown", approval
		if name, got, ok := environmentOf(js); !ok || name != "prod" || got != want {
			t.Errorf("%s: got %q %q %v", approval, name, got, ok)
		}
	}
	if _, _, ok := environmentOf(JobSituation{}); ok {
		t.Error("a job with no environment reads as running in one")
	}
}
