package control

import (
	"fmt"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
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

// A poisoned cache's entry line names the job whose run can write it.
func TestGenerateMRComment_CacheEntryNamesTheJobThatCanWriteIt(t *testing.T) {
	preview, entry := privilegedPreview()
	sit := cacheSituation(map[string]JobSituation{"pr-preview/preview": preview})
	findings := []opaengine.Finding{cacheFinding(), entry}
	paths := assemblePaths(findings, sit)
	result := &AnalysisResult{ProjectPath: "o/r", Findings: findings, Paths: paths, Situation: sit,
		Pipeline: &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, DefaultBranch: "main", Jobs: []ir.Job{{Name: "release"}, {Name: "pr-preview/preview"}}}}
	score := ScoreV4WithExplanations(result)
	body := generateMRComment(result, nil, false, "", &score, true, false, nil, nil, nil)
	want := "       Note   a run of job `preview` from workflow `pr-preview` can write the cache\n"
	if !strings.Contains(body, want) {
		t.Errorf("comment lacks %q:\n%s", want, body)
	}
}

// Under the contextual score the comment opens on the summary, read first
// on a web page: the score and the best fix, the other findings in one
// line, the attack paths one line each; then the controls and the
// findings in detail; then each path's details, worst first, the order
// of the terminal report. The arithmetic is for --score-point.
func TestGenerateMRComment_V4SummaryFirstThenDetails(t *testing.T) {
	p, findings := gitlabImagePath()
	result := &AnalysisResult{ProjectPath: "g/p", Findings: findings, Paths: []AttackPath{p},
		Situation: &Situation{Exposure: ir.VisibilityPrivate, Jobs: map[string]JobSituation{"check": {}}},
		Pipeline:  &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, DefaultBranch: "main", Branches: []ir.Branch{{Name: "main", Protected: true}}, Jobs: []ir.Job{{Name: "check"}}},
	}
	score := &PlumberScoreResult{
		ProfileID: PlumberScoreProfileIDV4, Score: "C", RawPoints: 64, FinalPoints: 64, Paths: result.Paths,
		PathLosses:    []PathLoss{{Tier: TierMedium, Count: 1, Weight: 6, Cap: 49, CappedLoss: 6, PathIDs: []string{p.ID}}},
		OtherFindings: &OtherFindingsLoss{Count: 12, Counts: SeverityCounts{Critical: 1, High: 2, Medium: 9}, UncappedLoss: 85, Cap: 30, CappedLoss: 30, CapApplied: true},
		BestFix:       &BestFix{Code: "ISSUE-102", Subject: "docker.io/alpine:latest", PathID: p.ID, PointsGained: 6, NewPoints: 70, NewLetter: "C"},
	}
	body := generateMRComment(result, nil, false, "gate line", score, true, false, nil, nil, nil)
	order := []string{
		"### Plumber Score\n\n- **64 / 100** (C)\n" + `- **Worst case:** if this image is compromised, an attacker can read 7 secrets of the repository \(attack path 1: docker.io/alpine:latest\)` + "\n" + `- **Best fix:** pin the image by digest \(image docker.io/alpine:latest\), +6 pts, 70 / 100 \(C\)` + "\n\n",
		"### Individual findings (12)\n\n- 1 critical, 2 high, 9 medium\n\n### Attack paths (1)\n\n| # | Tier | Entry | Job | Reaches |\n| --- | --- | --- | --- | --- |\n| 1 | Medium | docker.io/alpine:latest \\(mutable image tag\\) | check | 7 secrets |\n",
		"### Controls",
		"### Attack path details", "#### MEDIUM path 1\n\n```text\n MED   path 1\n       Entry  docker.io/alpine:latest (mutable image tag)\n       │\n" +
			"       └──▶ runs in job `check` ─▶ reaches 7 secrets\n",
		"       Fix    pin the image by digest\n```\n\n", "- `ISSUE-102`",
	}
	at := 0
	for _, want := range order {
		i := strings.Index(body[at:], want)
		if i < 0 {
			t.Fatalf("comment lacks %q after offset %d:\n%s", want, at, body)
		}
		at += i + len(want)
	}
	for _, unwanted := range []string{p.ID, "Entry of path", "Profile:", "Raw points", "Situation", "**Repository:**", "(attack paths)", "at most", "apped at"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("comment carries %q:\n%s", unwanted, body)
		}
	}
}

// Under --score-point a nested cap that held is said once under the
// subtraction (nine Medium paths, 54 counted for 49), and an unverified
// path says what could not be checked.
func TestGenerateMRComment_V4NamesTheCapAndWhatCouldNotBeVerified(t *testing.T) {
	medium := func(id string, state PathState) AttackPath {
		return AttackPath{ID: id, Tier: TierMedium, BaseTier: TierMedium, State: state, EntryKind: EntryMutableDependency,
			AnchorCode: "ISSUE-716", Jobs: []string{"build"}, Loss: 5, Entry: EntryFact{Subject: id + "@v1", State: "unresolvable"}}
	}
	result := &AnalysisResult{ProjectPath: "g/p", Paths: []AttackPath{medium("a", PathUnverified)}}
	for _, id := range []string{"b", "c", "d", "e", "f", "g", "h", "i"} {
		result.Paths = append(result.Paths, medium(id, PathProven))
	}
	score := &PlumberScoreResult{ProfileID: PlumberScoreProfileIDV4, Score: "C", RawPoints: 51, FinalPoints: 51, Paths: result.Paths,
		PathLosses: []PathLoss{{Tier: TierMedium, Count: 9, Weight: 6, Cap: 49, CappedLoss: 49}}}
	result.Paths[3].Loss = 6
	body := generateMRComment(result, nil, false, "gate line", score, true, true, nil, nil, nil)
	for _, want := range []string{
		"- 100 - 49 (attack paths) - 0 (individual findings)\n- medium and low items count for 49 at most\n",
		"### Individual findings (0)\n\n### Attack paths (9)\n\n| # | Tier | Entry | Job | Reaches |\n| --- | --- | --- | --- | --- |\n| 1 | Medium |",
		"| 9 | Medium | i\\@v1 \\(external action that downloads code at run time Plumber could not check\\) | build | code execution without secrets |\n\n### Controls",
		"### Attack path details",
		"#### MEDIUM path 1 (unverified)\n", "#### MEDIUM path 4\n", "       └──▶ runs in job `build` (unverified)\n            └─▶ reaches code execution on the runner, no secret and no write token\n", "       Note   Plumber could not check what it runs\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("comment lacks %q:\n%s", want, body)
		}
	}
}

// The comment follows the terminal: a commit SHA shows as 12 characters
// in the path lines and details, under --score-point the best fix says why
// it recovers less than the path's price, and a control split between a
// path and the other findings says where the rest of its findings are.
func TestGenerateMRComment_V4ShortensSHAsAndPointsToThePaths(t *testing.T) {
	sha := "2d756ea4c53f7f6b397767d8723b3a10a9f35bf2"
	uses := "tj-actions/changed-files@" + sha
	findings := []opaengine.Finding{
		{Code: "ISSUE-201", Message: "A is not protected", Data: map[string]any{"variableName": "A", "pathIds": []string{"p1"}}},
		{Code: "ISSUE-201", Message: "B is not protected", Data: map[string]any{"variableName": "B", "pathIds": []string{"p1"}}},
		{Code: "ISSUE-201", Message: "C is not protected", Data: map[string]any{"variableName": "C"}},
	}
	result := &AnalysisResult{ProjectPath: "g/p", Findings: findings, Paths: []AttackPath{{
		ID: "p1", Tier: TierMedium, BaseTier: TierMedium, EntryKind: EntryMutableDependency, AnchorCode: "ISSUE-703",
		Jobs: []string{"build"}, Loss: 6, Entry: EntryFact{Subject: uses},
	}}}
	score := &PlumberScoreResult{ProfileID: PlumberScoreProfileIDV4, Score: "B", RawPoints: 89, FinalPoints: 89, Paths: result.Paths,
		PathLosses:    []PathLoss{{Tier: TierMedium, Count: 1, Weight: 6, Cap: 49, CappedLoss: 6, PathIDs: []string{"p1"}}},
		OtherFindings: &OtherFindingsLoss{Count: 1, Counts: SeverityCounts{Medium: 1}, UncappedLoss: 5, Cap: 30, CappedLoss: 5},
		BestFix:       &BestFix{Code: "ISSUE-703", Subject: uses, PathID: "p1", PointsGained: 4, NewPoints: 93, NewLetter: "A", Reason: "+4 pts: the path's 6, less 2 for a finding that then stands alone"},
	}
	enabled := true
	pc := &configuration.PlumberConfig{GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
		CicdVariablesMustBeProtected: &configuration.EnabledOnlyControlConfig{Enabled: &enabled},
	}}}
	if body := generateMRComment(result, pc, false, "gate line", score, true, false, nil, nil, nil); strings.Contains(body, "less 2") {
		t.Errorf("without --score-point the best fix says why:\n%s", body)
	}
	body := generateMRComment(result, pc, false, "gate line", score, true, true, nil, nil, nil)
	for _, want := range []string{
		"| 1 | Medium | tj-actions/changed-files\\@2d756ea4c53f \\(external action with a known vulnerability\\) | build | code execution without secrets |",
		" MED   path 1\n       Entry  tj-actions/changed-files@2d756ea4c53f (external action with a known vulnerability)\n",
		"+4 pts, 93 / 100 \\(A\\) \\(+4 pts: the path's 6, less 2 for a finding that then stands alone\\)",
		"**CI/CD variables must be protected:**\n_2 more of these are listed under attack path 1._\n- `ISSUE-201` C is not protected",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("comment lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body[:strings.Index(body, "### Controls")]+body[strings.Index(body, "### Attack path details"):], sha) {
		t.Errorf("the summary and the path details carry the full SHA:\n%s", body)
	}
}

// v4MRResult is a release job whose name the merge-request author chose:
// a link, an image, an @all mention, and quick actions after newlines.
func v4MRResult(job string) (*AnalysisResult, *PlumberScoreResult) {
	result := &AnalysisResult{
		ProjectPath: "g/p",
		Findings: []opaengine.Finding{
			{Code: "ISSUE-701", Job: job, Message: "untrusted action", Data: map[string]any{"uses": "some/action@v1"}},
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
	v4 := body[strings.Index(body, "### Plumber Score"):strings.Index(body, "### Controls")] +
		body[strings.Index(body, "### Attack path details"):strings.LastIndex(body, "\n---\n")]
	v4, fenced := stripFencedBlocks(t, v4)
	if fenced == 0 {
		t.Fatalf("no path graph in a code block:\n%s", body)
	}
	outside := stripCodeSpans(v4)
	for _, live := range []string{"](https://evil.example", "![", "@all", "[click"} {
		if strings.Contains(outside, live) {
			t.Errorf("live %q outside a code span:\n%s", live, body)
		}
	}
	for _, line := range strings.Split(v4, "\n") {
		if strings.Count(line, "`")-strings.Count(line, "\\`") < 0 || (strings.Count(line, "`")-strings.Count(line, "\\`"))%2 != 0 {
			t.Errorf("unpaired code span on line %q", line)
		}
	}
}

// stripFencedBlocks drops every fenced code block from s and counts them;
// a block whose fence some line inside could close fails the test.
func stripFencedBlocks(t *testing.T, s string) (string, int) {
	t.Helper()
	var kept []string
	fence, n := "", 0
	for _, line := range strings.Split(s, "\n") {
		switch {
		case fence == "" && strings.HasPrefix(line, "```"):
			fence = strings.TrimRight(line, "abcdefghijklmnopqrstuvwxyz")
			n++
		case fence != "" && line == fence:
			fence = ""
		case fence != "":
			if strings.HasPrefix(strings.TrimSpace(line), fence) {
				t.Errorf("line %q closes the fence %q early", line, fence)
			}
		default:
			kept = append(kept, line)
		}
	}
	if fence != "" {
		t.Errorf("an unclosed fence %q", fence)
	}
	return strings.Join(kept, "\n"), n
}

// stripCodeSpans drops every unescaped backtick span from s, and every
// backslash-escaped character: it renders literally, so it is not live.
func stripCodeSpans(s string) string {
	var b strings.Builder
	in := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
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

// The comment lists at most 20 paths, worst first, then says how many
// more there are; the details stop at the same 20.
func TestGenerateMRComment_V4CapsThePathListAt20(t *testing.T) {
	result := &AnalysisResult{ProjectPath: "g/p"}
	for i := 0; i < 25; i++ {
		result.Paths = append(result.Paths, AttackPath{
			ID: fmt.Sprintf("p%02d", i), Tier: TierMedium, BaseTier: TierMedium, EntryKind: EntryMutableDependency,
			Jobs: []string{"build"}, Entry: EntryFact{Subject: "node:latest"},
		})
	}
	score := &PlumberScoreResult{ProfileID: PlumberScoreProfileIDV4, Score: "C", Paths: result.Paths}
	body := generateMRComment(result, nil, false, "gate line", score, true, false, nil, nil, nil)
	for _, want := range []string{"### Attack paths (25)", "\n| 20 | Medium | ", "|\n\nand 5 more paths\n", "#### MEDIUM path 20\n"} {
		if !strings.Contains(body, want) {
			t.Errorf("comment lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "path 21") {
		t.Errorf("want exactly the first 20 paths:\n%s", body)
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
	i := strings.Index(body, "### Individual findings in detail")
	if i < 0 {
		t.Fatalf("comment lacks \"### Individual findings in detail\":\n%s", body)
	}
	detail := body[i:]
	if !strings.Contains(detail, string(CodeDockerInDockerUsage)) {
		t.Errorf("the finding with no pathIds must render under Other findings, got:\n%s", body)
	}
	if strings.Contains(detail, string(CodeBranchUnprotected)) {
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

	i := strings.Index(body, "### Individual findings in detail")
	if i < 0 {
		t.Fatalf("comment lacks \"### Individual findings in detail\":\n%s", body)
	}
	detail := body[i:]
	if strings.Contains(detail, string(CodeBranchUnprotected)) {
		t.Errorf("the finding anchored on a rendered path (path 1) must not also render under Other findings:\n%s", body)
	}
	if !strings.Contains(detail, string(CodeDockerInDockerUsage)) {
		t.Errorf("the finding anchored only on path 23 (beyond the 20-path cap) must stay under Other findings:\n%s", body)
	}
}

// TestGenerateMRComment_V4FallbackToV3RendersV3Comment pins a precision on
// the v4 gate: a v4 request whose score fell back to scoring-v3 (no usable
// situation) must render the ordinary v3 comment, even though the
// package-level ScoreProfile variable still says "v4". Gating must read
// score.ProfileID, not that variable.
func TestGenerateMRComment_V4FallbackToV3RendersV3Comment(t *testing.T) {
	old := ScoreProfile
	ScoreProfile = "v4"
	t.Cleanup(func() { ScoreProfile = old })

	result := &AnalysisResult{
		CiValid: true,
		Findings: []opaengine.Finding{
			{Code: string(CodeBranchUnprotected), Message: "branch main is not protected", Severity: "critical"},
		},
	}
	score := &PlumberScoreResult{ProfileID: "scoring-v3", Score: "D", FinalPoints: 45}
	body := generateMRComment(result, mrCommentPC(), false, "gate line", score, true, false, nil, nil, nil)

	for _, unwanted := range []string{"Situation", "Attack paths", "Other findings", "Individual findings"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("fallback to v3 must not render %q:\n%s", unwanted, body)
		}
	}
	if !strings.Contains(body, "### Issues") || !strings.Contains(body, string(CodeBranchUnprotected)) {
		t.Fatalf("fallback to v3 must render the ordinary Issues section, got:\n%s", body)
	}
}

// TestSanitizeMarkdownInline_EscapesBacktickAndAngleBracket pins that the
// general-purpose escaper escapes the backticks of every code span too, so
// a name it carries can never open or close a span.
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

// A dependency path the cap held reads as what it is: its branch carries
// no cap marker, and the cap Note, how the score was computed, is printed
// under its details only with --score-point: at Medium for an action that
// is only not pinned, at High when its owner is also outside the
// authorized list.
func TestGenerateMRCommentCapNoteOnlyUnderScorePoint(t *testing.T) {
	uses := map[string]any{"uses": "some/action@v1"}
	for _, tc := range []struct {
		codes []string
		note  string
	}{
		{[]string{"ISSUE-701"}, "       Note   Capped at Medium: it needs a dependency compromise first\n"},
		{[]string{"ISSUE-701", "ISSUE-713"}, "       Note   Capped at High: the source is not authorized, so a compromise is more likely\n"},
	} {
		var findings []opaengine.Finding
		for _, c := range tc.codes {
			findings = append(findings, opaengine.Finding{Code: c, Job: "release", File: ".github/workflows/ci.yml", Line: 3, Data: uses})
		}
		result := &AnalysisResult{CiValid: true, Findings: findings, Situation: releaseSituation(ir.VisibilityPublic)}
		score := ScoreV4WithExplanations(result)
		AnnotateFindingsV4(result)
		body := generateMRComment(result, mrCommentPC(), false, "gate line", &score, true, false, nil, nil, nil)
		if !strings.Contains(body, "       └──▶ runs in job `release`\n            └─▶ reaches 1 secret,") || strings.Contains(body, "apped at") {
			t.Errorf("%v: the details carry a cap marker or Note:\n%s", tc.codes, body)
		}
		body = generateMRComment(result, mrCommentPC(), false, "gate line", &score, true, true, nil, nil, nil)
		if !strings.Contains(body, tc.note) || strings.Contains(body, "(capped at") {
			t.Errorf("%v: --score-point: the details lack the cap Note or carry a marker:\n%s", tc.codes, body)
		}
	}
}

// A merged path lists every anchoring finding under its details.
func TestGenerateMRComment_V4MergedPathListsEveryAnchor(t *testing.T) {
	result := &AnalysisResult{CiValid: true, Findings: pinnedActionFindings(), Situation: pinnedActionSituation()}
	score := ScoreV4WithExplanations(result)
	AnnotateFindingsV4(result)
	body := generateMRComment(result, mrCommentPC(), false, "gate line", &score, true, false, nil, nil, nil)
	start := strings.Index(body, " path 1\n")
	if start < 0 || !strings.HasPrefix(body[strings.LastIndex(body[:start], "\n")+1:], "#### ") {
		t.Fatalf("comment lacks the details of path 1:\n%s", body)
	}
	details := body[start:]
	if end := strings.Index(details, "\n### "); end >= 0 {
		details = details[:end]
	}
	for _, c := range []string{"- `ISSUE-713`", "- `ISSUE-703`"} {
		if !strings.Contains(details, c) {
			t.Errorf("path 1's details lack %s:\n%s", c, details)
		}
	}
}

// Under the contextual score the Critical cap follows a Critical attack
// path, not a Critical issue, so the --score-point line says so, as the
// terminal banner does; the previous formula keeps its own wording.
func TestGenerateMRComment_MalusLineFollowsTheScoreProfile(t *testing.T) {
	result := &AnalysisResult{CiValid: true}
	for _, tc := range []struct {
		profile, want string
	}{
		{PlumberScoreProfileIDV4, "- Capped at 30: a Critical attack path remains.\n"},
		{PlumberScoreProfileID, "- **Critical malus:** final points capped at 30 when any Critical issue exists\n"},
	} {
		score := &PlumberScoreResult{ProfileID: tc.profile, Score: "E", RawPoints: 70, FinalPoints: 30, CriticalMalusApplied: true, CriticalMalusMax: 30}
		body := generateMRComment(result, mrCommentPC(), false, "gate", score, true, true, nil, nil, nil)
		if !strings.Contains(body, tc.want) {
			t.Errorf("%s: comment lacks %q:\n%s", tc.profile, tc.want, body)
		}
	}
}
