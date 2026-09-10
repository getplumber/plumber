package control

import (
	"testing"

	"github.com/getplumber/plumber/finding/identity"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/platform"
)

// platformHashOf computes the platform digest via the same identity.PlatformHash the
// production code calls: reusing it here is deliberate, not a shortcut, since the digest's
// bit-for-bit stability is pinned separately by the golden test in
// finding/identity/platformhash_test.go. What the tests in this file exercise is
// MarkDismissed's own matching logic on top of that hash: recipe-version gating, the control
// pre-filter (and its raw-code fallback), and that a codeless finding never matches.
func platformHashOf(t *testing.T, f opaengine.Finding) string {
	t.Helper()
	hash, _, ok := identity.PlatformHash(f.IdentityInput())
	if !ok {
		t.Fatalf("fixture finding %+v must have an identity", f)
	}
	return hash
}

// TestMarkDismissed_MatchesOneEntryAmongDistractors pins #447: MarkDismissed marks exactly the
// findings whose platform identity hash appears in the served list, under the current recipe
// version, under their own control. A version mismatch, a different control's bucket, and a
// codeless finding must never count as a match.
func TestMarkDismissed_MatchesOneEntryAmongDistractors(t *testing.T) {
	findingX := opaengine.Finding{Code: "ISSUE-103", File: ".gitlab-ci.yml", Job: "build"}
	findingY := opaengine.Finding{Code: "ISSUE-701", File: ".github/workflows/ci.yml", Job: "build"}
	codeless := opaengine.Finding{File: "whatever.yml"}

	findings := []opaengine.Finding{findingX, findingY, codeless}

	served := []platform.DismissedIssue{
		// (a) matches findingX: right hash, right recipe version, right control.
		{
			IdentityHash:  platformHashOf(t, findingX),
			RecipeVersion: identity.RecipeVersion,
			ControlType:   "containerImageMustNotUseForbiddenTags",
		},
		// (b) findingY's own hash, but served under an old recipe version: skipped, honest
		// non-suppression, never a cross-version match.
		{
			IdentityHash:  platformHashOf(t, findingY),
			RecipeVersion: identity.RecipeVersion - 1,
			ControlType:   "actionsMustBePinnedByCommitSha",
		},
		// (c) findingX's own hash again, but filed under a different control: control_type is a
		// pre-filter, so this entry sits in another bucket and is never compared against findingX.
		{
			IdentityHash:  platformHashOf(t, findingX),
			RecipeVersion: identity.RecipeVersion,
			ControlType:   "actionsMustBePinnedByCommitSha",
		},
	}

	marked := MarkDismissed(findings, served)
	if marked != 1 {
		t.Fatalf("MarkDismissed returned %d, want 1", marked)
	}
	if !findings[0].Dismissed {
		t.Error("findingX must be marked dismissed")
	}
	if findings[1].Dismissed {
		t.Error("findingY must not be marked dismissed: its only served entry is under an old recipe version")
	}
	if findings[2].Dismissed {
		t.Error("a codeless finding must never be marked dismissed")
	}
}

// A code the registry does not classify is still pushed to the platform, under its raw code
// (platformFindingControlName, cmd/platform_push.go): a dismissed entry served under that same
// raw code as control_type must still match. Without the fallback in controlKeyFor, such a
// finding could never be re-matched after the platform served it back.
func TestMarkDismissed_UnknownCodeMatchesUnderItsRawCode(t *testing.T) {
	unknown := opaengine.Finding{Code: "ISSUE-999999-UNKNOWN", File: "whatever.yml"}
	findings := []opaengine.Finding{unknown}
	served := []platform.DismissedIssue{
		{
			IdentityHash:  platformHashOf(t, unknown),
			RecipeVersion: identity.RecipeVersion,
			ControlType:   "ISSUE-999999-UNKNOWN",
		},
	}

	marked := MarkDismissed(findings, served)
	if marked != 1 {
		t.Fatalf("MarkDismissed returned %d, want 1", marked)
	}
	if !findings[0].Dismissed {
		t.Error("a finding with an unregistered code must still match a served entry filed under its raw code")
	}
}

// An empty served list is the standalone-mode / nothing-cached case: it must mark nothing and
// never panic on a finding with no code.
func TestMarkDismissed_EmptyServedListMarksNothing(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: "ISSUE-103", File: ".gitlab-ci.yml", Job: "build"},
		{File: "whatever.yml"},
	}
	marked := MarkDismissed(findings, nil)
	if marked != 0 {
		t.Fatalf("MarkDismissed returned %d, want 0", marked)
	}
	for i, f := range findings {
		if f.Dismissed {
			t.Errorf("findings[%d] must not be marked dismissed with an empty served list", i)
		}
	}
}
