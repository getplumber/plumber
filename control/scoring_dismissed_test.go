package control

import (
	"path/filepath"
	"testing"

	"github.com/getplumber/plumber/configuration"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
	"github.com/getplumber/plumber/finding/identity"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/internal/platform"
)

// TestAggregateIssueCodeCounts_SkipsDismissedFindings pins #447 part 2: a
// finding the platform dismissed is out of the score, the same as
// not_evaluable, never counted toward its code's tally. Two findings of the
// same code, one dismissed, must count as one.
func TestAggregateIssueCodeCounts_SkipsDismissedFindings(t *testing.T) {
	result := &AnalysisResult{
		Findings: []opaengine.Finding{
			{Code: string(CodeImpostorCommit)},
			{Code: string(CodeImpostorCommit), Dismissed: true},
		},
	}
	counts := AggregateIssueCodeCounts(result)
	if got := counts[CodeImpostorCommit]; got != 1 {
		t.Fatalf("counts[%s] = %d, want 1 (the dismissed duplicate must not count)", CodeImpostorCommit, got)
	}
}

// TestCriticalIssueCodesSorted_StillListsCodeWhenLiveFindingRemains documents
// the deliberate asymmetry: forEachIssueCode skips a dismissed finding for
// EVERY reader (AggregateIssueCodeCounts and CriticalIssueCodesSorted alike,
// since both walk through it), so a code stays "present" only because a
// LIVE finding of it survives, not because the dismissed one is still
// silently counted here while excluded from the score elsewhere.
func TestCriticalIssueCodesSorted_StillListsCodeWhenLiveFindingRemains(t *testing.T) {
	result := &AnalysisResult{
		Findings: []opaengine.Finding{
			{Code: string(CodeImpostorCommit)},
			{Code: string(CodeImpostorCommit), Dismissed: true},
		},
	}
	got := CriticalIssueCodesSorted(result)
	if len(got) != 1 || got[0] != string(CodeImpostorCommit) {
		t.Fatalf("CriticalIssueCodesSorted = %v, want [%s]: the live finding must keep the code listed", got, CodeImpostorCommit)
	}
}

// TestCriticalIssueCodesSorted_OmitsCodeWhenAllDismissed is the other half:
// when every finding of a code is dismissed, the code must not appear at
// all: the shared skip in forEachIssueCode is what keeps
// AggregateIssueCodeCounts and CriticalIssueCodesSorted from disagreeing.
func TestCriticalIssueCodesSorted_OmitsCodeWhenAllDismissed(t *testing.T) {
	result := &AnalysisResult{
		Findings: []opaengine.Finding{
			{Code: string(CodeImpostorCommit), Dismissed: true},
		},
	}
	got := CriticalIssueCodesSorted(result)
	if len(got) != 0 {
		t.Fatalf("CriticalIssueCodesSorted = %v, want none: every finding of the code was dismissed", got)
	}
}

// TestReEvaluateForConfig_DismissedFindingExcludedFromScore drives the real
// per-policy path end to end: a served dismissed entry matching one of the
// findings the policy's own re-evaluation produces must make the returned
// score equal the score of the same evaluation with that finding removed
// entirely, not merely reduced.
//
// The fixture job's OriginFile is deliberately an ABSOLUTE path under a temp
// repo root, exactly what evaluatePolicies hands back before any stamping:
// enrichFindingsWithJobLocation fills a codeless-location finding's File
// from job.OriginFile verbatim, unstamped. The served dismissal is hashed
// over the REPO-RELATIVE form instead, matching what the run-level path
// pushes (cmd/analyze_shared.go stamps before MarkDismissed runs there). If
// ReEvaluateForConfig marks against the raw, still-absolute File, the two
// hashes never agree and the finding survives in the score; only stamping
// scopedResult.Findings to repo-relative form BEFORE hashing closes that.
//
// GitHub is used deliberately: markPlatformLaneGapsFor only runs for
// "gitlab", so engaging conf.PlatformRun.Context here (required for the
// MarkDismissed guard) cannot also trip the include-attribution gap marking
// and drop the fixture's own finding as not_evaluable for an unrelated
// reason.
func TestReEvaluateForConfig_DismissedFindingExcludedFromScore(t *testing.T) {
	pc, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "test-default")
	if err != nil {
		t.Fatalf("LoadPlumberConfigFromBytes: %v", err)
	}

	repoRoot := t.TempDir()
	relOriginFile := filepath.Join(".github", "workflows", "release.yml")
	absOriginFile := filepath.Join(repoRoot, relOriginFile)

	// actions/cache on a release-triggered job with an unscoped key: fires
	// releaseWorkflowsMustNotRestoreUntrustedCache (ISSUE-705), pinned by
	// TestCachePoisoningConfigContract as a real rego violation through the
	// same embedded default config. OriginFile is what enrichFindingsWithJobLocation
	// copies onto the finding's own File field when the rule itself sets none,
	// which cache_poisoning.rego does not.
	pipeline := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{{
		Name:       "publish",
		Triggers:   []string{"release"},
		OriginFile: absOriginFile,
		Uses:       []ir.Action{{Uses: "actions/cache@v4", With: map[string]any{"key": "deps-abc", "path": "~/.npm"}}},
	}}}

	// Baseline: no GitRepoRoot, so StampFingerprints' own repoRelative leaves
	// an absolute File exactly as-is (root=="" is its explicit no-op case).
	// This is only used to enumerate the OTHER findings the fixture produces,
	// to build the "same evaluation minus ISSUE-705" expected score below.
	baselineConf := &configuration.Configuration{PlumberConfig: pc}
	baseline, _, ok := ReEvaluateForConfig(&AnalysisResult{CiValid: true, GitHubPipeline: pipeline}, baselineConf, "github", pc)
	if !ok {
		t.Fatal("baseline re-evaluation must succeed")
	}
	var target opaengine.Finding
	found := false
	for _, f := range baseline.Findings {
		if f.Code == "ISSUE-705" {
			target = f
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("fixture must produce ISSUE-705, got %+v", baseline.Findings)
	}
	if target.File != filepath.ToSlash(absOriginFile) {
		t.Fatalf("baseline finding.File = %q, want the unstamped absolute origin %q (fixture assumption broken)", target.File, absOriginFile)
	}

	// Hash the REPO-RELATIVE form: this is what the platform actually
	// hashed for the pushed finding (the run-level path stamps before
	// pushing), not the raw absolute path evaluatePolicies produces.
	relFinding := target
	relFinding.File = filepath.ToSlash(relOriginFile)
	hash, _, ok := identity.PlatformHash(relFinding.IdentityInput())
	if !ok {
		t.Fatal("the ISSUE-705 finding must carry a platform identity")
	}

	// The expected score: the baseline findings with every ISSUE-705 entry
	// removed, scored directly, not merely "one fewer occurrence" but the
	// exact same computation MarkDismissed's skip is meant to reproduce.
	wantCounts := map[ErrorCode]int{}
	for _, f := range baseline.Findings {
		if f.Code == "ISSUE-705" {
			continue
		}
		wantCounts[ErrorCode(f.Code)]++
	}
	want := ComputePlumberScore(wantCounts)

	dismissedConf := &configuration.Configuration{
		PlumberConfig: pc,
		GitRepoRoot:   repoRoot,
		PlatformRun: &platform.RunContext{
			Context: &platform.ProjectContext{
				DismissedIssues: []platform.DismissedIssue{{
					IdentityHash:  hash,
					RecipeVersion: identity.RecipeVersion,
					ControlType:   "releaseWorkflowsMustNotRestoreUntrustedCache",
				}},
			},
		},
	}
	scoped, score, ok := ReEvaluateForConfig(&AnalysisResult{CiValid: true, GitHubPipeline: pipeline}, dismissedConf, "github", pc)
	if !ok {
		t.Fatal("dismissed re-evaluation must succeed")
	}

	if score.FinalPoints != want.FinalPoints || score.Score != want.Score {
		t.Fatalf("score with the finding dismissed = %+v, want %+v (computed with the finding entirely removed): the per-policy path must stamp File to repo-relative form BEFORE hashing against the served dismissal", score, want)
	}
	matched := false
	for _, f := range scoped.Findings {
		if f.Code == "ISSUE-705" {
			if f.File != filepath.ToSlash(relOriginFile) {
				t.Errorf("finding.File = %q, want the repo-relative form %q: the scoped result must be stamped too", f.File, relOriginFile)
			}
			if f.Fingerprint == "" {
				t.Error("finding.Fingerprint must be filled by the stamp, not left empty for a per-policy push")
			}
			if !f.Dismissed {
				t.Errorf("finding %+v must be marked dismissed", f)
			}
			matched = true
		}
	}
	if !matched {
		t.Fatal("the scoped result must still carry the ISSUE-705 finding, marked dismissed (never silently dropped)")
	}
}
