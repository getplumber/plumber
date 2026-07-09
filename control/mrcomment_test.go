package control

import (
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// generateMRComment is the user-facing MR verdict: these tests lock the gate
// verdict line (passed/gateLine are threaded in from complianceSummary, no
// longer computed here), the passed/failed/issues Controls table, the hidden
// update-in-place identifier, and the badge-only-with-a-score rule.

// mrCommentPC enables branch protection and Docker-in-Docker; every other
// control is absent from the config and must render as skipped.
func mrCommentPC() *configuration.PlumberConfig {
	enabled := true
	return &configuration.PlumberConfig{
		GitLab: &configuration.ProviderConfig{
			Controls: configuration.ControlsConfig{
				BranchMustBeProtected: &configuration.BranchProtectionControlConfig{
					Enabled: &enabled,
				},
				PipelineMustNotUseDockerInDocker: &configuration.DockerInDockerControlConfig{
					Enabled: &enabled,
				},
			},
		},
	}
}

func TestGenerateMRComment_FailedGate(t *testing.T) {
	result := &AnalysisResult{
		CiValid: true,
		Findings: []opaengine.Finding{
			{Code: string(CodeBranchUnprotected), Message: "branch main is not protected", Severity: "critical"},
		},
	}
	gateLine := "score D — 45.0/100 pts, required ≥ 100 pts"
	body := generateMRComment(result, mrCommentPC(), false, gateLine, &PlumberScoreResult{Score: "D", FinalPoints: 45}, true, false, nil, nil)

	if !strings.Contains(body, ":warning: **Plumber check failed**") {
		t.Fatalf("failed gate must render the failure line, got:\n%s", body)
	}
	if !strings.Contains(body, gateLine) {
		t.Fatalf("body must carry the gate line %q, got:\n%s", gateLine, body)
	}
	if strings.Contains(body, "Plumber check passed") {
		t.Fatalf("failed gate must not render a pass, got:\n%s", body)
	}
	// The finding must appear in the Issues section with its code.
	if !strings.Contains(body, "### Issues") || !strings.Contains(body, string(CodeBranchUnprotected)) {
		t.Fatalf("body must list the finding under Issues, got:\n%s", body)
	}
}

func TestGenerateMRComment_PassedGate(t *testing.T) {
	result := &AnalysisResult{CiValid: true}
	gateLine := "score A — 100.0/100 pts, required ≥ 100 pts"
	body := generateMRComment(result, mrCommentPC(), true, gateLine, &PlumberScoreResult{Score: "A", FinalPoints: 100}, true, false, nil, nil)

	if !strings.Contains(body, ":white_check_mark: **Plumber check passed** ("+gateLine+")") {
		t.Fatalf("passed gate must render the pass line with the gate line, got:\n%s", body)
	}
	if strings.Contains(body, "Plumber check failed") {
		t.Fatalf("passed gate must not render a failure, got:\n%s", body)
	}
	if strings.Contains(body, "### Issues") {
		t.Fatalf("clean run must not render an Issues section, got:\n%s", body)
	}
}

func TestGenerateMRComment_IdentifierStability(t *testing.T) {
	// Update-in-place matches comments posted by older versions against this
	// exact historical wording; the body must start with it, verbatim.
	body := generateMRComment(&AnalysisResult{CiValid: true}, mrCommentPC(), true, "gate", nil, false, false, nil, nil)
	if !strings.HasPrefix(body, MRCommentIdentifier+"\n") {
		t.Fatalf("body must start with the MR comment identifier, got:\n%s", body[:min(len(body), 120)])
	}
	if MRCommentIdentifier != "<!-- Plumber Compliance Comment -->" {
		t.Fatalf("MRCommentIdentifier changed to %q; older comments would stop matching and duplicate", MRCommentIdentifier)
	}
}

func TestGenerateMRComment_ControlsTable(t *testing.T) {
	result := &AnalysisResult{
		CiValid: true,
		Findings: []opaengine.Finding{
			{Code: string(CodeBranchUnprotected), Message: "branch main is not protected", Severity: "critical"},
		},
	}
	body := generateMRComment(result, mrCommentPC(), false, "gate", nil, false, false, nil, nil)

	if !strings.Contains(body, "| :x: Branch must be protected | failed | 1 |") {
		t.Fatalf("control with findings must render a failed row, got:\n%s", body)
	}
	if !strings.Contains(body, "| :white_check_mark: Pipeline must not use Docker-in-Docker | passed | 0 |") {
		t.Fatalf("clean enabled control must render a passed row, got:\n%s", body)
	}
	if !strings.Contains(body, "| _skipped_ | — |") {
		t.Fatalf("controls absent from the config must render as skipped, got:\n%s", body)
	}
}

func TestGenerateMRComment_BadgeOnlyWithScore(t *testing.T) {
	result := &AnalysisResult{CiValid: true}

	withScore := generateMRComment(result, mrCommentPC(), true, "gate", &PlumberScoreResult{Score: "B", FinalPoints: 85}, true, false, nil, nil)
	if !strings.Contains(withScore, ScoreBadgeURL("B")) {
		t.Fatalf("score mode with a score must render the letter badge, got:\n%s", withScore)
	}

	// No score (e.g. score withheld): no badge at all — the old always-badge
	// else branch was removed on purpose.
	withoutScore := generateMRComment(result, mrCommentPC(), true, "gate", nil, true, false, nil, nil)
	if strings.Contains(withoutScore, "img.shields.io") {
		t.Fatalf("no score must render no badge, got:\n%s", withoutScore)
	}
}
