package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/provider"
)

// TestRenderAttackPathsWorstFirstWithNestedFindings pins the Attack paths
// section's shape: worst tier first, the anchor/gate findings nested under
// their path with the contextual severity, and the path's own sentence.
// The terminal numbers paths worst-first ("path 1", "path 2", ...) and
// prints the hex id after it in parentheses; a finding's role line
// underneath says "path 1", not the raw id, since the ordinal is this
// renderer's own display concern (control.FindingLine and the JSON output
// keep returning ids).
func TestRenderAttackPathsWorstFirstWithNestedFindings(t *testing.T) {
	paths := []control.AttackPath{
		{ID: "lowpath", Tier: control.TierLow, EntryKind: control.EntryUntrustedExpression, Jobs: []string{"build"}, Entry: control.EntryFact{Subject: "github.event.pull_request.title"}, Reach: control.Reach{Executes: true}, AnchorHash: "h2"},
		{ID: "critpath", Tier: control.TierCritical, EntryKind: control.EntryMutableDependency, Jobs: []string{"release"}, Entry: control.EntryFact{Subject: "some/action@v1"}, Reach: control.Reach{Secrets: []string{"NPM_TOKEN"}, Impacts: []control.ImpactFact{{Kind: "publishes", Evidence: "npm publish"}}, Executes: true}, AnchorHash: "h1"},
	}
	groups := []findingGroup{{Title: "actionsMustComeFromAuthorizedSources", Findings: []detailedFinding{{Code: "ISSUE-713", Message: "some/action@v1 is not trusted", PathIDs: []string{"critpath"}, ContextualSeverity: "critical", Role: "Entry of path critpath"}}}}
	var buf bytes.Buffer
	renderAttackPaths(&buf, paths, groups)
	out := buf.String()
	if strings.Index(out, "critpath") > strings.Index(out, "lowpath") {
		t.Errorf("critical path must come first:\n%s", out)
	}
	if !strings.Contains(out, "[critical] [ISSUE-713]") {
		t.Errorf("anchor finding must be nested under its path with the contextual severity:\n%s", out)
	}
	// The raw id "critpath" is the anchoring path's only path, which is
	// sorted first (Critical), so its ordinal is 1: the role line below
	// the nested finding must read the ordinal, not the raw hex id.
	if !strings.Contains(out, "Entry of path 1") {
		t.Errorf("role line must use the path's ordinal, not its raw id:\n%s", out)
	}
	if strings.Contains(out, "Entry of path critpath") {
		t.Errorf("role line must not leak the raw path id, the ordinal is the display concern:\n%s", out)
	}
	if !strings.Contains(out, "A new version of `some/action@v1` runs inside `release`") {
		t.Errorf("sentence missing:\n%s", out)
	}
}

// TestRenderAttackPathsOwnAnchorPrintsFirst: when a path's nested list has
// both the finding that anchors it and a finding that only gates it (the
// branch-protection eyeball case: ISSUE-501 anchors its own unprotected_push
// path and gates every other path on the same branch), the anchor must
// print first regardless of the groups' own control order, so the reader
// sees "this is the entry" before "this also amplifies it".
func TestRenderAttackPathsOwnAnchorPrintsFirst(t *testing.T) {
	paths := []control.AttackPath{
		{ID: "critpath", Tier: control.TierCritical, EntryKind: control.EntryUnprotectedPush, Jobs: []string{"release"}, Entry: control.EntryFact{Subject: "main"}},
	}
	// The gate finding is listed BEFORE the anchor in the input groups
	// (mirrors the real eyeball run's control order), so a pass with no
	// reordering would print it first.
	groups := []findingGroup{{Findings: []detailedFinding{
		{Code: "ISSUE-307", Message: "persisted credentials", PathIDs: []string{"critpath"}, ContextualSeverity: "critical", Role: "Privilege: on path critpath"},
		{Code: "ISSUE-501", Message: "main is not protected", PathIDs: []string{"critpath"}, ContextualSeverity: "critical", Role: "Entry of path critpath"},
	}}}
	var buf bytes.Buffer
	renderAttackPaths(&buf, paths, groups)
	out := buf.String()
	if idxAnchor, idxGate := strings.Index(out, "ISSUE-501"), strings.Index(out, "ISSUE-307"); idxAnchor > idxGate {
		t.Errorf("the path's own anchor must print before a finding that merely walks it:\n%s", out)
	}
}

// TestRenderAttackPathsOrdinalsMatchSortedOrder exercises the ordinal
// mapping beyond the trivial single-path case: three paths of
// different tiers, each with its own finding referencing it by raw id, and
// every rendered role line must read the path's rank among the sorted
// (worst-first) output, not the id table's own insertion order.
func TestRenderAttackPathsOrdinalsMatchSortedOrder(t *testing.T) {
	paths := []control.AttackPath{
		{ID: "medpath", Tier: control.TierMedium, EntryKind: control.EntryMutableDependency, Jobs: []string{"test"}, Entry: control.EntryFact{Subject: "some/action@v2"}},
		{ID: "critpath", Tier: control.TierCritical, EntryKind: control.EntryMutableDependency, Jobs: []string{"release"}, Entry: control.EntryFact{Subject: "some/action@v1"}},
		{ID: "highpath", Tier: control.TierHigh, EntryKind: control.EntryPRTarget, Jobs: []string{"deploy"}, Entry: control.EntryFact{Subject: "a pull_request_target job"}},
	}
	groups := []findingGroup{{Findings: []detailedFinding{
		{Code: "ISSUE-1", PathIDs: []string{"critpath"}, ContextualSeverity: "critical", Role: "Entry of path critpath"},
		{Code: "ISSUE-2", PathIDs: []string{"highpath"}, ContextualSeverity: "high", Role: "Entry of path highpath"},
		{Code: "ISSUE-3", PathIDs: []string{"medpath"}, ContextualSeverity: "medium", Role: "Entry of path medpath"},
	}}}
	var buf bytes.Buffer
	renderAttackPaths(&buf, paths, groups)
	out := buf.String()
	for _, want := range []string{"Entry of path 1", "Entry of path 2", "Entry of path 3"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in ordinal-mapped output:\n%s", want, out)
		}
	}
	if idx1, idx2, idx3 := strings.Index(out, "Entry of path 1"), strings.Index(out, "Entry of path 2"), strings.Index(out, "Entry of path 3"); idx1 >= idx2 || idx2 >= idx3 {
		t.Errorf("ordinals must print worst tier first (critical=1, high=2, medium=3):\n%s", out)
	}
}

// A finding listed under two paths reads its role relative to each one:
// "Entry of path N" only under the path it anchors, "Gate: amplifies path
// N" under the other. Each nested finding prints the same block the Failed
// Controls listing prints (location, detail lines, doc URL, dismissed tag),
// plus the role line.
func TestRenderAttackPathsRoleIsRelativeToEachPathAndKeepsTheFindingBlock(t *testing.T) {
	paths := []control.AttackPath{
		{ID: "aaaa", Tier: control.TierCritical, EntryKind: control.EntryUnprotectedPush, Jobs: []string{"release"}, Entry: control.EntryFact{Subject: "main"}},
		{ID: "bbbb", Tier: control.TierHigh, EntryKind: control.EntryMutableDependency, Jobs: []string{"build"}, Entry: control.EntryFact{Subject: "node:latest"}},
	}
	groups := []findingGroup{{Findings: []detailedFinding{{
		Code: "ISSUE-501", Message: "Branch `main` is not protected.", PathIDs: []string{"aaaa", "bbbb"},
		ContextualSeverity: "critical", Role: "Entry of path aaaa",
		RoleOnPath:  map[string]string{"aaaa": "Entry of path aaaa", "bbbb": "Gate: amplifies path bbbb"},
		Location:    "https://gitlab.example/g/p/-/settings/repository",
		DocURL:      "https://getplumber.io/docs/cli/issues/ISSUE-501",
		DetailLines: []string{"force push allowed"},
		Dismissed:   true,
	}}}}
	var buf bytes.Buffer
	renderAttackPaths(&buf, paths, groups)
	out := buf.String()
	second := out[strings.Index(out, "path 2 (bbbb)"):]
	first := out[:strings.Index(out, "path 2 (bbbb)")]
	if !strings.Contains(first, "Entry of path 1") || strings.Contains(first, "Gate:") {
		t.Errorf("under its own path the finding is its entry:\n%s", first)
	}
	if !strings.Contains(second, "Gate: amplifies path 2") || strings.Contains(second, "Entry of path") {
		t.Errorf("under the other path the finding is a gate on THAT path:\n%s", second)
	}
	for _, want := range []string{"↳ at https://gitlab.example/g/p/-/settings/repository", "↳ docs: https://getplumber.io/docs/cli/issues/ISSUE-501", "└─ force push allowed", "[dismissed on the platform]"} {
		if strings.Count(out, want) != 2 {
			t.Errorf("want %q once under each path:\n%s", want, out)
		}
	}
}

// Names in the Situation paragraph, the jobs join and the path sentence are
// read off the workflow: an ANSI escape in a job name never reaches the
// terminal, any more than it does through a finding's message.
func TestRenderAttackPathsAndSituationStripTerminalEscapes(t *testing.T) {
	evil := "build\x1b[2J\x1b[31mFAKE PASS"
	paths := []control.AttackPath{{ID: "aaaa", Tier: control.TierMedium, EntryKind: control.EntryMutableDependency, Jobs: []string{evil, evil}, Entry: control.EntryFact{Subject: "node:latest"}}}
	groups := []findingGroup{{Findings: []detailedFinding{{Code: "ISSUE-103", Message: "no digest", PathIDs: []string{"aaaa"}, ContextualSeverity: "medium", Role: "Entry of path aaaa\x1b[2J"}}}}
	var buf bytes.Buffer
	renderAttackPaths(&buf, paths, groups)
	renderSituation(&buf, "Fixing `"+evil+"` recovers 6 points.")
	if strings.Contains(buf.String(), "\x1b[2J") || strings.Contains(buf.String(), "\x1b[31m") {
		t.Errorf("a terminal escape from a name reached the output: %q", buf.String())
	}
}

// v4OutputFixture prices releaseMutableActionResult under v4: ISSUE-713 is
// registered High and rides a Critical path.
func v4OutputFixture(t *testing.T) (*provider.GitHubProvider, *control.AnalysisResult, *configuration.Configuration, complianceSummary) {
	t.Helper()
	newGateFlagsCmd(t)
	withScoreProfile(t, "v4")
	gh := &provider.GitHubProvider{}
	conf := configuration.NewDefaultConfiguration()
	conf.PlumberConfig = defaultGitHubPlumberConfig(t)
	result := releaseMutableActionResult()
	s := buildComplianceSummary(gh, result, conf)
	if !scoreProfileV4(s.score) {
		t.Fatalf("fixture did not price under v4: %+v", s.score)
	}
	s.scorePoint = true
	return gh, result, conf, s
}

// Under v4 the Summary reads the contextual severity: the Controls table
// shows the strongest contextual severity among a control's findings, and
// the "Critical issue codes" line lists the codes whose contextual severity
// is critical (ISSUE-713 is registered High, contextual Critical here).
func TestOutputTextV4SummaryReadsTheContextualSeverity(t *testing.T) {
	gh, result, conf, s := v4OutputFixture(t)
	out := captureStdout(t, func() { _ = outputTextWithProvider(gh, result, conf, s, nil, nil) })
	if !strings.Contains(out, "Critical issue codes:") || !strings.Contains(out, "ISSUE-713") {
		t.Errorf("want ISSUE-713 among the critical issue codes:\n%s", out)
	}
	row := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "ISSUE-713") && strings.Contains(line, "│") {
			row = line
		}
	}
	if !strings.Contains(row, "Critical") {
		t.Errorf("Controls table row = %q, want the contextual Critical", row)
	}
}

// The same run under v3 keeps the registry severity in the Summary.
func TestOutputTextV3SummaryKeepsTheRegistrySeverity(t *testing.T) {
	newGateFlagsCmd(t)
	withScoreProfile(t, "v3")
	gh := &provider.GitHubProvider{}
	conf := configuration.NewDefaultConfiguration()
	conf.PlumberConfig = defaultGitHubPlumberConfig(t)
	result := releaseMutableActionResult()
	s := buildComplianceSummary(gh, result, conf)
	out := captureStdout(t, func() { _ = outputTextWithProvider(gh, result, conf, s, nil, nil) })
	if strings.Contains(out, "Critical issue codes:") {
		t.Errorf("v3 lists no critical code for a registered-High finding:\n%s", out)
	}
}

// A degraded run withholds the score, so it prints none of the v4 blocks
// that state one (the Situation's best fix names a letter, the path tiers
// and the Points breakdown price the run): one condition, the banner's own.
func TestOutputTextV4DegradedRunPrintsNoV4Blocks(t *testing.T) {
	gh, result, conf, s := v4OutputFixture(t)
	result.DataCollectionDegraded = true
	out := captureStdout(t, func() { _ = outputTextWithProvider(gh, result, conf, s, nil, nil) })
	for _, unwanted := range []string{"Situation", "Attack paths", "mutable_dependency"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("a degraded run printed %q:\n%s", unwanted, out)
		}
	}
	if !strings.Contains(out, "Score withheld") {
		t.Fatalf("fixture drifted: the banner did not withhold the score:\n%s", out)
	}
}

// TestRenderAttackPathsNoopOnNoPaths: a nil/empty path slice renders
// nothing, so the section header never appears for a run with zero
// assembled paths.
func TestRenderAttackPathsNoopOnNoPaths(t *testing.T) {
	var buf bytes.Buffer
	renderAttackPaths(&buf, nil, []findingGroup{{Findings: []detailedFinding{{Code: "ISSUE-1"}}}})
	if buf.Len() != 0 {
		t.Errorf("expected no output for zero paths, got:\n%s", buf.String())
	}
}

// TestRenderSituationAndBreakdown pins the Situation paragraph and the
// --score-point breakdown's own shape: the situation paragraph renders
// under its own heading, and the breakdown lists the per-tier path losses,
// the per-code gate losses and the hygiene bucket.
func TestRenderSituationAndBreakdown(t *testing.T) {
	var buf bytes.Buffer
	renderSituation(&buf, "Public repository, 1 job in 1 workflow. 1 attack path: 1 critical, 0 high, 0 medium, 0 low. Nothing to fix.")
	if !strings.Contains(buf.String(), "Situation") || !strings.Contains(buf.String(), "1 attack path") {
		t.Errorf("%s", buf.String())
	}
	buf.Reset()
	renderPathBreakdown(&buf, &control.PlumberScoreResult{
		ProfileID:   control.PlumberScoreProfileIDV4,
		PathLosses:  []control.PathLoss{{Tier: control.TierCritical, EntryKind: control.EntryMutableDependency, Count: 1, Weight: 30, CappedLoss: 30}},
		GateLosses:  []control.CodeLoss{{Code: "ISSUE-501", Severity: control.SeverityCritical, Count: 1, Weight: 25, CappedLoss: 25}},
		HygieneLoss: 2, HygieneCount: 1,
	})
	for _, want := range []string{"critical", "mutable_dependency", "-30", "ISSUE-501", "-25", "hygiene", "-2"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("breakdown lacks %q:\n%s", want, buf.String())
		}
	}
}

// TestRenderSituationNoopOnEmpty: an empty situation string (a v3 score,
// or ScoreV4WithExplanations never having run) renders nothing.
func TestRenderSituationNoopOnEmpty(t *testing.T) {
	var buf bytes.Buffer
	renderSituation(&buf, "")
	if buf.Len() != 0 {
		t.Errorf("expected no output for an empty situation, got:\n%s", buf.String())
	}
}

// TestRenderPathBreakdownNoopUnderV3: a v3-shaped result (or a v4 request
// that fell back to plain v3 pricing because the situation facts never
// evaluated) never
// prints the v4 breakdown. Gating on the score's own ProfileID, not the
// bare --score-profile request, is what keeps this honest on the fallback.
func TestRenderPathBreakdownNoopUnderV3(t *testing.T) {
	var buf bytes.Buffer
	renderPathBreakdown(&buf, &control.PlumberScoreResult{ProfileID: control.PlumberScoreProfileID})
	if buf.Len() != 0 {
		t.Errorf("expected no output for a v3-shaped score, got:\n%s", buf.String())
	}
	buf.Reset()
	renderPathBreakdown(&buf, nil)
	if buf.Len() != 0 {
		t.Errorf("expected no output for a nil score, got:\n%s", buf.String())
	}
}

// TestRenderFindingGroupsV4SplitsAttackPathsProtectionsAndHygiene is the
// end-to-end shape of the v4 report order: an entry finding anchoring
// a path renders once, nested under "Attack paths"; a gate finding on no
// path moves to "Protections missing"; everything else lands in "Hygiene".
// A finding already shown under a path is never repeated in the later
// sections.
func TestRenderFindingGroupsV4SplitsAttackPathsProtectionsAndHygiene(t *testing.T) {
	paths := []control.AttackPath{
		{ID: "critpath", Tier: control.TierCritical, EntryKind: control.EntryMutableDependency, Jobs: []string{"release"}, Entry: control.EntryFact{Subject: "some/action@v1"}},
	}
	groups := []findingGroup{
		{
			Title: "actionsMustComeFromAuthorizedSources",
			Stats: []statLine{{Label: "Action Refs Checked", Value: "3"}},
			Findings: []detailedFinding{
				{Code: "ISSUE-713", Message: "some/action@v1 is not trusted", PathIDs: []string{"critpath"}, ContextualSeverity: "critical", Role: "Entry of path critpath"},
			},
		},
		{
			Title: "branchMustBeProtected",
			Stats: []statLine{{Label: "Total Branches", Value: "1"}},
			Findings: []detailedFinding{
				{Code: "ISSUE-501", Message: "main is not protected", ContextualSeverity: "medium", Role: "Gate: no path to amplify today"},
			},
		},
		{
			Title: "noDangerousCommands",
			Stats: []statLine{{Label: "Script Lines Checked", Value: "10"}},
			Findings: []detailedFinding{
				{Code: "ISSUE-900", Message: "a shell script runs curl | sh", ContextualSeverity: "low", Role: "Hygiene: on no attack path"},
			},
		},
	}
	score := &control.PlumberScoreResult{
		ProfileID: control.PlumberScoreProfileIDV4,
		Paths:     paths,
		Situation: "Public repository, 1 job in 1 workflow. 1 attack path: 1 critical, 0 high, 0 medium, 0 low. Nothing to fix.",
	}
	out := captureStdout(t, func() { renderFindingGroupsV4(groups, score) })

	assertContains(t, out, "Situation")
	assertContains(t, out, "Attack paths (1)")
	assertContains(t, out, "[critical] [ISSUE-713]")
	assertContains(t, out, "Protections missing (1)")
	assertContains(t, out, "ISSUE-501")
	assertContains(t, out, "Hygiene (1)")
	assertContains(t, out, "ISSUE-900")
	if strings.Count(out, "ISSUE-713") != 1 {
		t.Errorf("a finding shown under its path must not repeat in a later section:\n%s", out)
	}
	if strings.Contains(out, "Failed Controls") {
		t.Errorf("the v4 split replaces the plain Failed Controls section entirely:\n%s", out)
	}
}

// TestRenderFindingGroupsV3CallsNoneOfTheNewBlocks pins that v3 stays
// untouched: a plain v3 run (empty Role/ContextualSeverity/PathIDs on every finding, exactly
// what findingsToItems leaves them under v3) never prints a Situation
// paragraph, an Attack paths section, or a bracketed contextual-severity
// tag; it renders through the existing renderFindingGroups/
// renderFailedControl path untouched.
func TestRenderFindingGroupsV3CallsNoneOfTheNewBlocks(t *testing.T) {
	groups := []findingGroup{
		{
			Title:    "branchMustBeProtected",
			Stats:    []statLine{{Label: "Total Branches", Value: "1"}},
			Findings: []detailedFinding{{Code: codeCritical, Message: `branch "main" must be protected`}},
		},
	}
	out := captureStdout(t, func() { renderFindingGroups(groups) })

	assertContains(t, out, "Failed Controls (1)")
	if strings.Contains(out, "Situation") {
		t.Errorf("v3 must never print the Situation block:\n%s", out)
	}
	if strings.Contains(out, "Attack paths") {
		t.Errorf("v3 must never print the Attack paths block:\n%s", out)
	}
	if strings.Contains(out, "Protections missing") || strings.Contains(out, "Hygiene (") {
		t.Errorf("v3 must never split into the v4-only sections:\n%s", out)
	}
}

// Under scoring-v4 the banner's malus line says what the cap means there:
// a Critical attack path remains, not a Critical issue. scoring-v3 keeps
// its own wording.
func TestScoreBadgeMalusLineFollowsTheProfile(t *testing.T) {
	v4 := &control.PlumberScoreResult{ProfileID: control.PlumberScoreProfileIDV4, FinalPoints: 30, Score: "E", CriticalMalusApplied: true, CriticalMalusMax: 30}
	out := captureStdout(t, func() { printScoreBadge(v4) })
	if !strings.Contains(out, "final points capped at 30 while a Critical attack path remains") || strings.Contains(out, "while any Critical remains") {
		t.Errorf("v4 malus line:\n%s", out)
	}
	v3 := &control.PlumberScoreResult{ProfileID: control.PlumberScoreProfileID, FinalPoints: 30, Score: "E", CriticalMalusApplied: true, CriticalMalusMax: 30}
	out = captureStdout(t, func() { printScoreBadge(v3) })
	if !strings.Contains(out, "(final points capped at 30 while any Critical remains)") {
		t.Errorf("v3 malus line must stay unchanged:\n%s", out)
	}
}
