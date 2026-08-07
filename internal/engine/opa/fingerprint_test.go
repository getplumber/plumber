package opa

import (
	"encoding/json"
	"testing"

	"github.com/getplumber/plumber/finding/identity"
)

// A consumer outside this module reads findings from Plumber's serialized
// output, not from the Go type, and must arrive at the same identity. That only
// holds if every input the recipe reads is flattened into the JSON object, so
// the round trip is pinned here rather than assumed.
func TestFingerprint_SurvivesTheJSONRoundTrip(t *testing.T) {
	findings := []Finding{{
		Code: "ISSUE-701", File: ".github/workflows/ci.yml", Job: "build",
		Message: "prose", Line: 12, URL: "https://example.com/ci.yml#L12",
		Data: map[string]any{"uses": "owner/act@v1", "step": "Check out", "advisories": "GHSA-1"},
	}, {
		Code: "ISSUE-803", File: "ci.yml", Job: "build", Message: "no structured subject here",
	}, {
		Code: "ISSUE-405", File: ".gitlab-ci.yml", Job: "templates/go/go",
		Message: "required template is missing",
		Data:    map[string]any{"templatePath": "templates/go/go"},
	}}
	StampFingerprints(findings)
	for _, f := range findings {
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshal %s: %v", f.Code, err)
		}
		var serialized map[string]any
		if err := json.Unmarshal(b, &serialized); err != nil {
			t.Fatalf("unmarshal %s: %v", f.Code, err)
		}
		if got := identity.Fingerprint(identity.FromMap(serialized)); got != f.Fingerprint {
			t.Errorf("%s: fingerprint from serialized finding = %q, stamped = %q", f.Code, got, f.Fingerprint)
		}
	}
}

// The engine must not keep a second copy of the selection: it computes the
// fingerprint through the public recipe, so a key added there is honoured here
// without an edit. A finding using a subject key the engine never knew about is
// the check that the two are one implementation and not two lists.
func TestFingerprint_ComesFromTheSharedRecipe(t *testing.T) {
	f := Finding{
		Code: "ISSUE-405", File: ".gitlab-ci.yml", Job: "templates/go/go",
		Message: `required template "templates/go/go" is missing from the pipeline (group 0)`,
		Data:    map[string]any{"templatePath": "templates/go/go"},
	}
	want := identity.Fingerprint(identity.Finding{
		Code: f.Code, File: f.File, Job: f.Job, Message: f.Message, Data: f.Data,
	})
	if got := computeFingerprint(f); got != want {
		t.Errorf("computeFingerprint = %q, identity.Fingerprint = %q; the engine is using its own selection", got, want)
	}
}

// The fingerprint must survive line drift: the same finding whose line moved
// (because unrelated code above it was edited) keeps the same identifier, so a
// consumer can follow it across runs.
func TestFingerprint_StableAndLineIndependent(t *testing.T) {
	base := Finding{Code: "ISSUE-701", File: ".github/workflows/ci.yml", Job: "build", Message: "action X unpinned", Line: 12}
	moved := base
	moved.Line = 40
	if computeFingerprint(base) != computeFingerprint(moved) {
		t.Errorf("fingerprint changed when only the line moved; want line-independent")
	}
	if computeFingerprint(base) == "" {
		t.Fatalf("fingerprint empty for a coded finding")
	}
}

// Two findings of the same code in the same file/job but with different subjects
// (different messages) must get different fingerprints, so the 62 ISSUE-701s of
// a big repo are individually trackable.
func TestFingerprint_DiscriminatesBySubject(t *testing.T) {
	a := Finding{Code: "ISSUE-701", File: "ci.yml", Job: "build", Message: "action A unpinned"}
	b := Finding{Code: "ISSUE-701", File: "ci.yml", Job: "build", Message: "action B unpinned"}
	if computeFingerprint(a) == computeFingerprint(b) {
		t.Errorf("same fingerprint for two different subjects; want distinct")
	}
}

// The real collision found on grafana/grafana: the same action referenced twice
// in one job produces an identical code/file/job/message, and only the step name
// tells the two apart (the line does too, but it drifts, so it is excluded).
func TestFingerprint_StepNameBreaksSameActionCollision(t *testing.T) {
	base := Finding{
		Code: "ISSUE-713", File: ".github/workflows/check-frontend-test-coverage.yml", Job: "coverage",
		Message: `job "coverage" references action "marocchino/sticky-pull-request-comment@7737449" from an unauthorized source`,
	}
	a, b := base, base
	a.Data = map[string]any{"step": "Delete old coverage comment if not affected"}
	b.Data = map[string]any{"step": "Post PR comment"}
	if computeFingerprint(a) == computeFingerprint(b) {
		t.Errorf("same fingerprint for two steps of the same action; step name must discriminate")
	}
	// The step name, not the line, is what separates them: moving either line
	// must not change its fingerprint.
	moved := a
	moved.Line = 999
	if computeFingerprint(a) != computeFingerprint(moved) {
		t.Errorf("fingerprint changed on line drift; want line-independent")
	}
}

// Findings with no step name keep the identifier they had before step names
// existed, so adding the discriminator does not churn unrelated fingerprints.
func TestFingerprint_NoStepIsUnchanged(t *testing.T) {
	f := Finding{Code: "ISSUE-505", Job: "main", Message: "Branch 'main' has non-compliant protection settings"}
	withEmpty := f
	withEmpty.Data = map[string]any{"step": ""}
	if computeFingerprint(f) != computeFingerprint(withEmpty) {
		t.Errorf("empty step must not alter the fingerprint")
	}
}

// The point of preferring a structured subject: rewording a rule's prose must
// not change the identifier of every finding that rule ever emitted.
func TestFingerprint_ImmuneToMessageRewordingWhenSubjectPresent(t *testing.T) {
	f := Finding{
		Code: "ISSUE-701", File: "ci.yml", Job: "build",
		Message: `job "build" references action "owner/act@v1" with a mutable ref`,
		Data:    map[string]any{"uses": "owner/act@v1"},
	}
	reworded := f
	reworded.Message = "Pin owner/act@v1 by commit SHA (message reworded in a later release)"
	if computeFingerprint(f) != computeFingerprint(reworded) {
		t.Errorf("fingerprint changed when only the message was reworded; the structured subject should carry identity")
	}
}

// Two different actions in the same job are told apart by the subject alone,
// with no help from the message. This is the grafana shape (two distinct
// unpinned actions in one job).
func TestFingerprint_SubjectDiscriminatesWithoutMessage(t *testing.T) {
	base := Finding{Code: "ISSUE-701", File: "ci.yml", Job: "release", Message: "same prose for both"}
	a, b := base, base
	a.Data = map[string]any{"uses": "grafana/shared-workflows/actions/get-vault-secrets@main"}
	b.Data = map[string]any{"uses": "grafana/grafana-github-actions-go/community-release@main"}
	if computeFingerprint(a) == computeFingerprint(b) {
		t.Errorf("two different actions collided; subject must discriminate")
	}
}

// Rules with no structured subject still fall back to the message, so they keep
// whatever discrimination they had.
func TestFingerprint_FallsBackToMessageWithoutSubject(t *testing.T) {
	a := Finding{Code: "ISSUE-801", File: "ci.yml", Job: "build", Message: "first problem"}
	b := Finding{Code: "ISSUE-801", File: "ci.yml", Job: "build", Message: "second problem"}
	if computeFingerprint(a) == computeFingerprint(b) {
		t.Errorf("message fallback failed to discriminate")
	}
}

// A volatile payload key must not participate: a new CVE landing in advisories
// or an upstream release moving latestVersion cannot make an existing finding
// look like a new one.
func TestFingerprint_IgnoresVolatilePayload(t *testing.T) {
	f := Finding{
		Code: "ISSUE-703", File: "ci.yml", Job: "build", Message: "known CVE",
		Data: map[string]any{"uses": "owner/act@v1", "advisories": "GHSA-1", "latestVersion": "2.2.0"},
	}
	later := f
	later.Data = map[string]any{"uses": "owner/act@v1", "advisories": "GHSA-1,GHSA-2", "latestVersion": "2.3.0"}
	if computeFingerprint(f) != computeFingerprint(later) {
		t.Errorf("fingerprint moved when only volatile payload changed")
	}
}

func TestFingerprint_CodelessIsEmpty(t *testing.T) {
	if computeFingerprint(Finding{Message: "x"}) != "" {
		t.Errorf("codeless finding got a fingerprint; want empty")
	}
}

func TestStampFingerprints_SetsFieldInPlace(t *testing.T) {
	fs := []Finding{
		{Code: "ISSUE-701", File: "ci.yml", Job: "build", Message: "x"},
		{Code: "", Message: "codeless"},
	}
	StampFingerprints(fs)
	if fs[0].Fingerprint == "" {
		t.Errorf("StampFingerprints did not set a fingerprint on a coded finding")
	}
	if fs[1].Fingerprint != "" {
		t.Errorf("codeless finding got a fingerprint; want empty")
	}
	if fs[0].Fingerprint != computeFingerprint(fs[0]) {
		t.Errorf("stamped fingerprint != computeFingerprint")
	}
}
