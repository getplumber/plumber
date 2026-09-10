package cmd

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/finding/identity"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/platform"
)

// untrustedImageFinding is a fail finding a real run of the shipped default
// config produces: ISSUE-101 belongs to
// containerImageMustComeFromAuthorizedSources, which that config enables, and
// it costs the score real points.
func untrustedImageFinding() opaengine.Finding {
	return opaengine.Finding{Code: "ISSUE-101", Severity: "high", Message: "untrusted registry", Job: "build", File: ".gitlab-ci.yml", Line: 4}
}

// servedDismissalFor builds the dismissed entry the platform would serve for
// one finding: the identity hash of the finding as it exists AFTER fingerprint
// stamping, under the current recipe version, keyed by the finding's control.
// Stamping first is the whole point - the identity reads the fields
// fingerprinting canonicalizes, so a hash taken before it matches nothing.
func servedDismissalFor(t *testing.T, f opaengine.Finding) platform.DismissedIssue {
	t.Helper()
	stamped := []opaengine.Finding{f}
	opaengine.StampFingerprints(stamped, "")
	hash, _, ok := identity.PlatformHash(stamped[0].IdentityInput())
	if !ok {
		t.Fatal("the fixture finding has no platform identity, so no served dismissal could ever match it")
	}
	return platform.DismissedIssue{
		IdentityHash:  hash,
		RecipeVersion: identity.RecipeVersion,
		ControlType:   control.ControlKeyFor(stamped[0].Code),
	}
}

// TestFinalizeFindings_MarksServedDismissalsBeforeAnythingReadsThem pins the
// single markPlatformDismissedFindings call inside finalizeFindings, between
// StampFingerprints and buildComplianceSummary. Delete it and the run-level
// result keeps a served dismissal as a live finding - the artifact writers
// (JSON, PBOM, SARIF, CSV, OCSF) all read result.Findings, so every one of
// them would report a dismissed issue as open - and the summary built one line
// later would score it.
//
// This is deliberately a unit test of finalizeFindings rather than of a
// pipeline: since platform mode's push is assembled from the per-policy runs
// (which mark dismissals themselves, inside control.ReEvaluateForConfig), no
// end-to-end test fails any more when this call is removed. It is the only
// thing standing between a served dismissal and the run-level outputs.
func TestFinalizeFindings_MarksServedDismissalsBeforeAnythingReadsThem(t *testing.T) {
	origPrint := printOutput
	printOutput = false // no terminal output is under test
	defer func() { printOutput = origPrint }()

	served := servedDismissalFor(t, untrustedImageFinding())

	// confWith builds the run as production does: a run context whose
	// /context response carries the served dismissed list.
	confWith := func(t *testing.T, dismissed []platform.DismissedIssue) *configuration.Configuration {
		t.Helper()
		conf := configuration.NewDefaultConfiguration()
		conf.PlumberConfig = testDefaultPlumberConfig(t)
		conf.PlatformRun = &platform.RunContext{
			Endpoint: "https://platform.example.com",
			Context:  &platform.ProjectContext{DismissedIssues: dismissed},
		}
		return conf
	}
	resultWith := func(findings ...opaengine.Finding) *control.AnalysisResult {
		return &control.AnalysisResult{CiValid: true, Findings: findings}
	}

	t.Run("the served finding is marked on the run-level result", func(t *testing.T) {
		newGateFlagsCmd(t)
		restore := withPlatformTestEnv(t, "https://platform.example.com", "tok")
		defer restore()

		result := resultWith(untrustedImageFinding())
		_ = finalizeFindings(testProvider(t), confWith(t, []platform.DismissedIssue{served}), result)

		if len(result.Findings) != 1 {
			t.Fatalf("a dismissed finding is never dropped, only marked: got %d findings", len(result.Findings))
		}
		if !result.Findings[0].Dismissed {
			t.Error("the served finding is not marked dismissed: every artifact written from this result would report it as open")
		}
	})

	t.Run("an unserved finding stays live", func(t *testing.T) {
		newGateFlagsCmd(t)
		restore := withPlatformTestEnv(t, "https://platform.example.com", "tok")
		defer restore()

		result := resultWith(untrustedImageFinding())
		_ = finalizeFindings(testProvider(t), confWith(t, nil), result)

		if result.Findings[0].Dismissed {
			t.Error("a finding the platform did not serve was marked dismissed: the marker must come from the served list alone")
		}
	})

	t.Run("the mark precedes the summary, so the score never counts it", func(t *testing.T) {
		// The platform URL is left UNSET on purpose. It is the ordering
		// inside finalizeFindings that is under test - mark, THEN
		// buildComplianceSummary - and platform mode withholds the
		// run-level score entirely, so there would be no score to inspect.
		// markPlatformDismissedFindings keys on conf.PlatformRun.Context
		// alone, never on the flag, so the marking path is the same one.
		score := func(t *testing.T, dismissed []platform.DismissedIssue, findings ...opaengine.Finding) float64 {
			t.Helper()
			newGateFlagsCmd(t)
			s := finalizeFindings(testProvider(t), confWith(t, dismissed), resultWith(findings...))
			if s.score == nil {
				t.Fatal("no score was computed, so this test can say nothing about what it counted")
			}
			return s.score.FinalPoints
		}

		dismissedPoints := score(t, []platform.DismissedIssue{served}, untrustedImageFinding())
		livePoints := score(t, nil, untrustedImageFinding())
		cleanPoints := score(t, nil)

		if dismissedPoints <= livePoints {
			t.Errorf("score = %.1f dismissed vs %.1f live: a dismissed finding must cost nothing (#447: out of the score like not_evaluable)", dismissedPoints, livePoints)
		}
		if dismissedPoints != cleanPoints {
			t.Errorf("score = %.1f with the finding dismissed, %.1f with no such finding at all: the two must agree, or the summary was built before the mark", dismissedPoints, cleanPoints)
		}
	})
}
