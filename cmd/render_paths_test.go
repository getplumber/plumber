package cmd

import (
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/provider"
)

// v4OutputFixture prices releaseMutableActionResult under v4: ISSUE-701 is
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

// Under the contextual score the Score section is the final screen: no
// Summary, no critical-codes line and no Controls table, whose severities
// the path blocks and the other findings already say. The heading opens on
// the score block. The verdict against the gate is one line of the score
// block, right under the score and above the subtraction.
func TestOutputTextScoreSectionIsTheFinalScreen(t *testing.T) {
	t.Cleanup(func() { useReportColor(colorBasic) })
	useReportColor(colorOff)
	gh, result, conf, s := v4OutputFixture(t)
	out := captureStdout(t, func() { _ = outputTextWithProvider(gh, result, conf, s, nil, nil) })
	for _, unwanted := range []string{"Critical issue codes", "│ Control ", "  Status: FAILED ✗"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("the contextual report printed %q:\n%s", unwanted, out)
		}
	}
	rule := strings.Repeat("─", 20)
	heading := rule + "\nScore\n" + rule + "\n\n"
	if i := strings.Index(out, heading); strings.Contains(out, "Summary") || strings.Count(out, heading) != 1 || i < 0 || !strings.Contains(strings.SplitN(out[i+len(heading):], "\n", 2)[0], "Plumber Score  ") {
		t.Errorf("want one Score heading, opening on the score block:\n%s", out)
	}
	if strings.Contains(out, "\n\n\n"+rule+"\nScore") {
		t.Errorf("want one blank line above the Score heading, as above every section:\n%s", out)
	}
	score, status, sub, fix := strings.Index(out, "Plumber Score  "), strings.Index(out, "  Status: FAILED (gate blocks at 100 pts)\n"), strings.Index(out, "(individual findings)\n"), strings.Index(out, "  Best fix: ")
	if score < 0 || status < 0 || sub < 0 || fix < 0 || score > status || status > sub || sub > fix {
		t.Errorf("want the Status line under the score, above the subtraction:\n%s", out)
	}
}

// The verdict line names the gate in parentheses, "gate blocks at" on a
// failure and "gate at" on a pass, says when no control was evaluated, and
// has no parenthesis when the run has no gate.
func TestGateStatusLine(t *testing.T) {
	for _, c := range []struct {
		s    complianceSummary
		want string
	}{
		{complianceSummary{minPoints: 100, controlCount: 1}, "Status: FAILED (gate blocks at 100 pts)"},
		{complianceSummary{minPoints: 80, minPointsSet: true, controlCount: 1}, "Status: PASSED (gate at 80 pts)"},
		{complianceSummary{minScore: "C", controlCount: 1}, "Status: PASSED (gate at grade C)"},
		{complianceSummary{minScore: "A", controlCount: 1}, "Status: FAILED (gate blocks at grade A)"},
		{complianceSummary{minPoints: 80, minPointsSet: true, minScore: "C", controlCount: 1}, "Status: PASSED (gate at 80 pts and grade C)"},
		{complianceSummary{thresholdSet: true, threshold: 100, compliance: 87.5, controlCount: 1}, "Status: FAILED (gate blocks at 100% of controls passing: 87.5% pass)"},
		{complianceSummary{minPoints: 100}, "Status: FAILED (no control was evaluated)"},
		{complianceSummary{minPoints: 100, controlCount: 1, noControls: true}, "Status: PASSED"},
	} {
		c.s.score = &control.PlumberScoreResult{Score: "B", FinalPoints: 85}
		if got := c.s.gateStatus().line(termCaps{Color: colorOff}); got != c.want {
			t.Errorf("%+v: %q, want %q", c.s, got, c.want)
		}
	}
}

// A control whose findings are split between an attack path and the
// individual findings lists only the ones no path uses, as its code's
// block: no counters, no line pointing to the paths.
func TestIndividualFindingsListOnlyTheRestOfAControl(t *testing.T) {
	t.Cleanup(func() { useReportColor(colorBasic) })
	useReportColor(colorOff)
	paths := []control.AttackPath{
		{ID: "high", Tier: control.TierHigh, BaseTier: control.TierHigh, EntryKind: control.EntryMutableDependency, AnchorCode: "ISSUE-102", Jobs: []string{"build"}, Entry: control.EntryFact{Subject: "alpine:latest"}},
		{ID: "low", Tier: control.TierLow, BaseTier: control.TierLow, EntryKind: control.EntryMutableDependency, AnchorCode: "ISSUE-102", Jobs: []string{"lint"}, Entry: control.EntryFact{Subject: "node:latest"}},
	}
	groups := []findingGroup{{
		Title: "CI/CD variables must be protected",
		Stats: []statLine{{Label: "Unprotected Variables", Value: "4"}},
		Findings: []detailedFinding{
			{Code: "ISSUE-201", Message: "A", PathIDs: []string{"high"}},
			{Code: "ISSUE-201", Message: "B", PathIDs: []string{"high", "low"}},
			{Code: "ISSUE-201", Message: "C", PathIDs: []string{"low"}},
			{Code: "ISSUE-201", Message: "D", ContextualSeverity: "medium"},
		},
	}}
	score := &control.PlumberScoreResult{ProfileID: control.PlumberScoreProfileIDV4, Paths: paths}
	out := captureStdoutAll(t, func() { renderFindingGroupsV4(groups, score, nil, reportBlock) })
	other := out[strings.Index(out, "Individual findings"):strings.Index(out, "Attack paths")]
	assertContains(t, other, " MED   ISSUE-201  ")
	assertContains(t, other, "       └──▶ D\n")
	for _, unwanted := range []string{"more of these", "Unprotected Variables", "CI/CD variables must be protected", "──▶ A", "──▶ B", "──▶ C"} {
		if strings.Contains(other, unwanted) {
			t.Errorf("the individual findings printed %q:\n%s", unwanted, other)
		}
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
	result.Findings = result.Findings[:1] // the registered-High finding alone
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

// TestRenderFindingGroupsV4PrintsFindingsThenBlocks is the shape of
// the contextual report body: the findings no path tells the story of
// under "Other findings", without a role line, then every attack path as
// its labelled block, right before the final screen. A finding shown
// under a path is never repeated with the findings.
func TestRenderFindingGroupsV4PrintsFindingsThenBlocks(t *testing.T) {
	paths := []control.AttackPath{
		{ID: "critpath", Tier: control.TierCritical, BaseTier: control.TierCritical, EntryKind: control.EntryMutableDependency, AnchorCode: "ISSUE-713", Jobs: []string{"release"}, Entry: control.EntryFact{Subject: "some/action@v1"}},
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
				{Code: "ISSUE-501", Message: "main is not protected", ContextualSeverity: "critical", Role: "Gate: no path to amplify today"},
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
	score := &control.PlumberScoreResult{ProfileID: control.PlumberScoreProfileIDV4, Paths: paths}
	out := captureStdoutAll(t, func() { renderFindingGroupsV4(groups, score, nil, reportBlock) })

	block, other := strings.Index(out, "path 1"), strings.Index(out, "Individual findings (2)")
	if block < 0 || other < 0 || other > block {
		t.Fatalf("want the findings before the path block:\n%s", out)
	}
	assertContains(t, out, " Attack path 1\n       Entry  some/action@v1 (untrusted external action)\n       │\n       └──▶ runs in job `release`\n            └─▶ reaches ")
	for _, unwanted := range []string{"Gate:", "Hygiene:", "Entry of path", "Situation", "Protections missing", "Failed Controls", "critpath"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("the contextual report printed %q:\n%s", unwanted, out)
		}
	}
	if strings.Contains(out[other:block], "ISSUE-713") {
		t.Errorf("a finding shown under its path must not repeat under the other findings:\n%s", out)
	}
	if i, j := strings.Index(out, "ISSUE-900"), strings.Index(out, "ISSUE-501"); i < 0 || j < 0 || i > j {
		t.Errorf("the other findings print worst last:\n%s", out)
	}
}

// TestRenderFindingGroupsV4RecomputesDismissedAfterRemoval pins the
// recomputation in removeFindingsShownUnderAPath: a dismissed finding shown
// under a path takes its dismissal with it, so the control's header counts
// only what is left.
func TestRenderFindingGroupsV4RecomputesDismissedAfterRemoval(t *testing.T) {
	paths := []control.AttackPath{
		{ID: "critpath", Tier: control.TierCritical, EntryKind: control.EntryMutableDependency, Jobs: []string{"release"}, Entry: control.EntryFact{Subject: "some/action@v1"}},
	}
	groups := []findingGroup{
		{
			Title: "mixedControl",
			Findings: []detailedFinding{
				{Code: "ISSUE-713", Message: "some/action@v1 is not trusted", PathIDs: []string{"critpath"}, ContextualSeverity: "critical", Dismissed: true},
				{Code: "ISSUE-501", Message: "main is not protected", ContextualSeverity: "medium", Dismissed: true},
				{Code: "ISSUE-900", Message: "a shell script runs curl | sh", ContextualSeverity: "low"},
			},
			Dismissed: 2,
		},
	}
	score := &control.PlumberScoreResult{ProfileID: control.PlumberScoreProfileIDV4, Paths: paths}
	out := captureStdoutAll(t, func() { renderFindingGroupsV4(groups, score, nil, reportBlock) })
	other := out[strings.Index(out, "Individual findings"):]
	if !strings.Contains(other, "Individual findings (1)") || !strings.Contains(other, "ISSUE-501  Branch protection missing (1 dismissed)") || strings.Contains(other, "ISSUE-713") {
		t.Fatalf("want one live finding and one dismissed one left:\n%s", other)
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
	for _, unwanted := range []string{"Other findings", "Individual findings"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("v3 must never print the contextual %s section:\n%s", unwanted, out)
		}
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
