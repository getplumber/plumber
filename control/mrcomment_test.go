package control

import (
	"fmt"
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
	body := generateMRComment(result, mrCommentPC(), false, gateLine, &PlumberScoreResult{Score: "D", FinalPoints: 45}, true, false, nil, nil, nil)

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
	body := generateMRComment(result, mrCommentPC(), true, gateLine, &PlumberScoreResult{Score: "A", FinalPoints: 100}, true, false, nil, nil, nil)

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
	body := generateMRComment(&AnalysisResult{CiValid: true}, mrCommentPC(), true, "gate", nil, false, false, nil, nil, nil)
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
	body := generateMRComment(result, mrCommentPC(), false, "gate", nil, false, false, nil, nil, nil)

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

	withScore := generateMRComment(result, mrCommentPC(), true, "gate", &PlumberScoreResult{Score: "B", FinalPoints: 85}, true, false, nil, nil, nil)
	if !strings.Contains(withScore, ScoreBadgeURL("B")) {
		t.Fatalf("score mode with a score must render the letter badge, got:\n%s", withScore)
	}

	// No score (e.g. score withheld): no badge at all — the old always-badge
	// else branch was removed on purpose.
	withoutScore := generateMRComment(result, mrCommentPC(), true, "gate", nil, true, false, nil, nil, nil)
	if strings.Contains(withoutScore, "img.shields.io") {
		t.Fatalf("no score must render no badge, got:\n%s", withoutScore)
	}
}

// TestMRCommentOrderCoversEveryGitLabControl is the drift guard for
// mrCommentControlOrder. The MR comment builds its controls TABLE from
// GitLabControls, but its per-control DETAIL sections from the hand-written
// mrCommentControlOrder. A control present in the first and missing from the
// second renders as "failed" in the table with no detail lines under it — its
// findings are silently dropped from the body.
//
// That regression shipped three times (the variables controls in #422, the
// approval-rule controls in #423, the approval/MR-settings controls in #426),
// each time unnoticed until a human read a real MR comment. Tying the two
// lists together here makes the next omission a build failure instead.
func TestMRCommentOrderCoversEveryGitLabControl(t *testing.T) {
	listed := make(map[string]bool, len(mrCommentControlOrder))
	for _, g := range mrCommentControlOrder {
		if listed[g.controlName] {
			t.Errorf("mrCommentControlOrder lists %q twice", g.controlName)
		}
		listed[g.controlName] = true
	}

	// An empty config still yields every GitLab control entry (they come back
	// marked Skipped), so this enumerates the full catalogue.
	for _, e := range GitLabControls(&configuration.PlumberConfig{}) {
		if !listed[e.ControlName] {
			t.Errorf("control %q (%q) is in the MR comment's controls table but missing from "+
				"mrCommentControlOrder, so its findings are silently dropped from the comment body; "+
				"add it to the list in mrcomment.go", e.ControlName, e.DisplayName)
		}
	}
}

// TestGenerateMRComment_NotEvaluableRow pins the MR-comment table's third
// state (re-raised #431 review thread): a control whose data lane supplied
// nothing renders as "not evaluated" with a grey question mark, never as a
// green check a reviewer would take for a pass.
func TestGenerateMRComment_NotEvaluableRow(t *testing.T) {
	enabled := true
	pc := &configuration.PlumberConfig{GitLab: &configuration.ProviderConfig{
		Controls: configuration.ControlsConfig{
			BranchMustBeProtected: &configuration.BranchProtectionControlConfig{Enabled: &enabled},
		},
	}}
	result := &AnalysisResult{CiValid: true}
	result.MarkNotEvaluable("branchMustBeProtected", ReasonCollectionFailed)

	body := generateMRComment(result, pc, true, "", nil, false, false, nil, nil, nil)
	if !strings.Contains(body, ":grey_question:") || !strings.Contains(body, "_not evaluated_") {
		t.Fatalf("a not_evaluable control must render its own row, got:\n%s", body)
	}
	if strings.Contains(body, ":white_check_mark: Branch must be protected") {
		t.Fatalf("a not_evaluable control must never render as a green check:\n%s", body)
	}
}

// TestGenerateMRComment_V4ShowsSituationAndAttackPaths pins the scoring-v4
// layout: the score banner is followed by a Situation paragraph and a
// worst-first Attack paths list under the same heading level as the
// comment's other sections, each path numbered with its ordinal and its id
// in parentheses, and the code spans of the path line and of PathSentence
// survive (sanitizeMarkdownKeepCode escapes only the text around them).
func TestGenerateMRComment_V4ShowsSituationAndAttackPaths(t *testing.T) {
	result := &AnalysisResult{
		ProjectPath: "g/p",
		Findings: []opaengine.Finding{
			{Code: "ISSUE-713", Job: "release", Severity: "critical", Data: map[string]any{"role": "Entry of path p1", "pathIds": []string{"p1"}}},
		},
	}
	anchorHash, _ := findingAnchorHash(result.Findings[0])
	result.Paths = []AttackPath{{
		ID: "p1", Tier: TierCritical, EntryKind: EntryMutableDependency,
		Jobs:       []string{"release"},
		Entry:      EntryFact{Subject: "some/action@v1"},
		Reach:      Reach{Executes: true, Secrets: []string{"NPM_TOKEN"}, Impacts: []ImpactFact{{Kind: "publishes"}}},
		AnchorHash: anchorHash,
	}}
	score := &PlumberScoreResult{
		ProfileID: PlumberScoreProfileIDV4, Score: "E", FinalPoints: 30, Paths: result.Paths,
		Situation: "Public repository, 1 job in 1 workflow, 1 publishes or deploys. " +
			"1 attack path: 1 critical, 0 high, 0 medium, 0 low. Nothing to fix.",
	}
	body := generateMRComment(result, nil, false, "gate line", score, true, false, nil, nil, nil)

	for _, want := range []string{
		"### Situation", "1 attack path", "### Attack paths", "**critical** path 1 (`p1`)", "`some/action@v1`", "`release`",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("comment lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "**Situation**") || strings.Contains(body, "**Attack paths**") {
		t.Errorf("v4 sections must be headings, not bold text:\n%s", body)
	}
	// The path's own finding is listed under it, with its role on that
	// path read with the ordinal, never the raw id.
	if !strings.Contains(body, "`ISSUE-713`") || !strings.Contains(body, "Entry of path 1") {
		t.Errorf("the anchor finding and its role line must be listed under its path:\n%s", body)
	}
}

// v4MRResult is a release job whose name the merge-request author chose:
// a link, an image, an @all mention, and quick actions after newlines.
func v4MRResult(job string) (*AnalysisResult, *PlumberScoreResult) {
	result := &AnalysisResult{
		ProjectPath: "g/p",
		Findings: []opaengine.Finding{
			{Code: "ISSUE-713", Job: job, Message: "untrusted action", Data: map[string]any{"uses": "some/action@v1"}},
		},
	}
	h, _ := findingAnchorHash(result.Findings[0])
	result.Paths = []AttackPath{{
		ID: "p1", Tier: TierCritical, BaseTier: TierCritical, EntryKind: EntryMutableDependency,
		Jobs: []string{job}, AnchorHash: h,
		Entry: EntryFact{Subject: "some/action@v1"},
		Reach: Reach{Executes: true, Secrets: []string{"NPM_TOKEN"}, Impacts: []ImpactFact{{Kind: "publishes"}}},
	}}
	fix := &BestFix{Sentence: bestFixSentence("Untrusted action", job, 40, "E", "B")}
	score := &PlumberScoreResult{
		ProfileID: PlumberScoreProfileIDV4, Score: "E", FinalPoints: 30, Paths: result.Paths, BestFix: fix,
		Situation: "Public repository, 1 job in 1 workflow. 1 attack path: 1 critical, 0 high, 0 medium, 0 low. " + fix.Sentence,
	}
	return result, score
}

// A job name is attacker text on a merge-request pipeline and the comment
// is posted with Plumber's token: the link, the image, the @all mention
// and the quick actions it carries must all render inert, in the path
// line, the path sentence, the Situation paragraph and the best fix.
func TestGenerateMRComment_V4JobNameInjectionRendersInert(t *testing.T) {
	evil := "build` [click here](https://evil.example) ![x](https://evil.example/p.png) @all `x\n/approve\n/merge"
	result, score := v4MRResult(evil)
	body := generateMRComment(result, nil, false, "gate line", score, true, false, nil, nil, nil)

	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "/") {
			t.Errorf("a line starts with a quick action: %q", line)
		}
	}
	// Outside a code span, every Markdown-active character of the v4
	// sections is escaped: strip the spans and nothing live may remain (the
	// score badge above them is the comment's own image link).
	v4 := body[strings.Index(body, "### Situation"):strings.Index(body, "### Controls")]
	outside := stripCodeSpans(v4)
	for _, live := range []string{"](https://evil.example", "![", "@all", "[click"} {
		if strings.Contains(outside, live) {
			t.Errorf("live %q outside a code span:\n%s", live, body)
		}
	}
	for _, line := range strings.Split(body, "\n") {
		if strings.Count(line, "`")-strings.Count(line, "\\`") < 0 || (strings.Count(line, "`")-strings.Count(line, "\\`"))%2 != 0 {
			t.Errorf("unpaired code span on line %q", line)
		}
	}
}

// stripCodeSpans drops every unescaped backtick span from s.
func stripCodeSpans(s string) string {
	var b strings.Builder
	in := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			if !in {
				b.WriteByte(c)
				b.WriteByte(s[i+1])
			}
			i++
			continue
		}
		if c == '`' {
			in = !in
			continue
		}
		if !in {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// A benign sentence keeps its words and its code spans; only the escapes
// sanitizeMarkdownInline always applies change outside the spans.
func TestSanitizeMarkdownKeepCodeLeavesSpansIntact(t *testing.T) {
	in := "A new version of `node:latest` runs inside `ci/build`: the runner can be abused (and #1)."
	want := "A new version of `node:latest` runs inside `ci/build`: the runner can be abused \\(and \\#1\\)."
	if got := sanitizeMarkdownKeepCode(in); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	if got := sanitizeMarkdownKeepCode("odd ` backtick"); got != sanitizeMarkdownInline("odd ` backtick") {
		t.Errorf("an unpaired backtick falls back to the plain escaper, got %q", got)
	}
}

// The comment lists at most 20 paths, worst first, then says how many
// more there are.
func TestGenerateMRComment_V4CapsThePathListAt20(t *testing.T) {
	result := &AnalysisResult{ProjectPath: "g/p"}
	for i := 0; i < 23; i++ {
		result.Paths = append(result.Paths, AttackPath{
			ID: fmt.Sprintf("p%02d", i), Tier: TierMedium, BaseTier: TierMedium, EntryKind: EntryMutableDependency,
			Jobs: []string{"build"}, Entry: EntryFact{Subject: "node:latest"},
		})
	}
	score := &PlumberScoreResult{ProfileID: PlumberScoreProfileIDV4, Score: "C", Paths: result.Paths}
	body := generateMRComment(result, nil, false, "gate line", score, true, false, nil, nil, nil)
	if !strings.Contains(body, "path 20 (`p19`)") || strings.Contains(body, "path 21 (") {
		t.Errorf("want exactly the first 20 paths:\n%s", body)
	}
	if !strings.Contains(body, "and 3 more paths") {
		t.Errorf("want the overflow line:\n%s", body)
	}
}

// TestGenerateMRComment_V4OtherFindingsExcludesPathTiedFindings pins the
// renamed, filtered detail section: under v4, the heading below the
// Controls table reads "Other findings" (not "### Issues") and carries only
// the findings the Attack paths list above did not already tell the story
// of (no pathIds in their Data) -- here the gate finding that anchors path
// p1 is dropped, and the unrelated privilege finding on another control
// stays.
func TestGenerateMRComment_V4OtherFindingsExcludesPathTiedFindings(t *testing.T) {
	result := &AnalysisResult{
		CiValid: true,
		Findings: []opaengine.Finding{
			{
				Code: string(CodeBranchUnprotected), Job: "release", Severity: "critical",
				Message: "branch main is not protected",
				Data:    map[string]any{"role": "Entry of path p1", "pathIds": []string{"p1"}},
			},
			{
				Code: string(CodeDockerInDockerUsage), Job: "build", Severity: "high",
				Message: "a Docker-in-Docker service is used",
			},
		},
	}
	result.Paths = []AttackPath{{
		ID: "p1", Tier: TierCritical, EntryKind: EntryUnprotectedPush,
		Jobs:  []string{"release"},
		Entry: EntryFact{Subject: "main"},
	}}
	score := &PlumberScoreResult{
		ProfileID: PlumberScoreProfileIDV4, Score: "E", FinalPoints: 30, Paths: result.Paths,
		Situation: "Public repository, 1 job in 1 workflow, 0 publishes or deploys. " +
			"1 attack path: 1 critical, 0 high, 0 medium, 0 low. Nothing to fix.",
	}
	body := generateMRComment(result, mrCommentPC(), false, "gate line", score, true, false, nil, nil, nil)

	if strings.Contains(body, "### Issues") {
		t.Errorf("v4 must rename the detail section, got ### Issues in:\n%s", body)
	}
	if !strings.Contains(body, "### Other findings") {
		t.Errorf("comment lacks \"### Other findings\":\n%s", body)
	}
	if !strings.Contains(body, string(CodeDockerInDockerUsage)) {
		t.Errorf("the finding with no pathIds must render under Other findings, got:\n%s", body)
	}
	if strings.Contains(body, string(CodeBranchUnprotected)) {
		t.Errorf("the finding already told by the Attack paths list must not also render under Other findings:\n%s", body)
	}
}

// TestGenerateMRComment_V4OtherFindingsKeepsFindingBeyondPathCap pins the
// fix for the asymmetric-omission bug: a finding counts as
// "already told by the Attack paths list" only when EVERY path id in its
// Data carries one that was actually rendered there (the first
// maxCommentPaths, worst-first). A finding anchored on path 1 (rendered)
// still drops out of Other findings; a finding anchored only on path 23
// (beyond the 20-path cap, never rendered) must stay listed, with its role
// line, or it disappears from the comment entirely.
func TestGenerateMRComment_V4OtherFindingsKeepsFindingBeyondPathCap(t *testing.T) {
	result := &AnalysisResult{
		CiValid: true,
		Findings: []opaengine.Finding{
			{
				Code: string(CodeBranchUnprotected), Job: "release", Severity: "critical",
				Message: "branch main is not protected",
				Data:    map[string]any{"role": "Entry of path p00", "pathIds": []string{"p00"}},
			},
			{
				Code: string(CodeDockerInDockerUsage), Job: "build", Severity: "high",
				Message: "a Docker-in-Docker service is used on the orphaned path",
				Data:    map[string]any{"role": "Entry of path p22", "pathIds": []string{"p22"}},
			},
		},
	}
	for i := 0; i < 25; i++ {
		result.Paths = append(result.Paths, AttackPath{
			ID: fmt.Sprintf("p%02d", i), Tier: TierMedium, BaseTier: TierMedium, EntryKind: EntryMutableDependency,
			Jobs: []string{"build"}, Entry: EntryFact{Subject: "node:latest"},
		})
	}
	score := &PlumberScoreResult{ProfileID: PlumberScoreProfileIDV4, Score: "C", Paths: result.Paths}
	body := generateMRComment(result, mrCommentPC(), false, "gate line", score, true, false, nil, nil, nil)

	if !strings.Contains(body, "### Other findings") {
		t.Fatalf("comment lacks \"### Other findings\":\n%s", body)
	}
	if strings.Contains(body, string(CodeBranchUnprotected)) {
		t.Errorf("the finding anchored on a rendered path (path 1) must not also render under Other findings:\n%s", body)
	}
	if !strings.Contains(body, string(CodeDockerInDockerUsage)) {
		t.Errorf("the finding anchored only on path 23 (beyond the 20-path cap) must stay under Other findings:\n%s", body)
	}
}

// TestGenerateMRComment_V4FallbackToV3RendersV3Comment pins a precision on
// the v4 gate: a v4 request whose score fell back to scoring-v3 (no usable
// situation) must render the ordinary v3 comment, even though the
// package-level ScoreProfile variable still says "v4". Gating must read
// score.ProfileID, not that variable.
func TestGenerateMRComment_V4FallbackToV3RendersV3Comment(t *testing.T) {
	ScoreProfile = "v4"
	t.Cleanup(func() { ScoreProfile = "v3" })

	result := &AnalysisResult{
		CiValid: true,
		Findings: []opaengine.Finding{
			{Code: string(CodeBranchUnprotected), Message: "branch main is not protected", Severity: "critical"},
		},
	}
	score := &PlumberScoreResult{ProfileID: "scoring-v3", Score: "D", FinalPoints: 45}
	body := generateMRComment(result, mrCommentPC(), false, "gate line", score, true, false, nil, nil, nil)

	for _, unwanted := range []string{"Situation", "Attack paths", "Other findings"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("fallback to v3 must not render %q:\n%s", unwanted, body)
		}
	}
	if !strings.Contains(body, "### Issues") || !strings.Contains(body, string(CodeBranchUnprotected)) {
		t.Fatalf("fallback to v3 must render the ordinary Issues section, got:\n%s", body)
	}
}

// TestSanitizeMarkdownInline_EscapesBacktickAndAngleBracket documents why
// v4CommentSections routes an attack path line through
// sanitizeMarkdownKeepCode rather than sanitizeMarkdownInline alone: the
// general-purpose escaper escapes the backticks of every code span too.
func TestSanitizeMarkdownInline_EscapesBacktickAndAngleBracket(t *testing.T) {
	in := "`release` -> `deploy`"
	got := sanitizeMarkdownInline(in)
	if got == in {
		t.Fatalf("expected the general escaper to alter backtick/arrow text, got it unchanged: %q", got)
	}
	if !strings.Contains(got, "\\`") || !strings.Contains(got, "\\>") {
		t.Fatalf("expected backtick and > escaped, got %q", got)
	}
}

// House style (CLAUDE.md): no em dash in anything Plumber writes, and a
// comment posted on a merge request is the most public of those. The
// failed-status line is shared by the standalone and the platform-mode
// comment, so pinning it once covers both.
func TestWriteMRStatusLine_FailedLineCarriesNoEmDash(t *testing.T) {
	var b strings.Builder

	writeMRStatusLine(&b, false, "score C - 66/100 pts")

	got := b.String()
	if !strings.Contains(got, ":warning: **Plumber check failed** - score C - 66/100 pts") {
		t.Errorf("status line = %q, want the gate line after a spaced hyphen", got)
	}
	if strings.Contains(got, "\u2014") {
		t.Errorf("status line = %q, want no em dash", got)
	}
}
