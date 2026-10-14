package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/provider"
)

// The withheld score's glyph is a question mark drawn like the letters:
// six lines of eight cells, in the palette's yellow, and an unknown
// letter still draws E.
func TestWithheldGlyphIsSixLinesOfEightCells(t *testing.T) {
	lines, ok := scoreLetterASCII["?"]
	if !ok {
		t.Fatal("scoreLetterASCII has no ? glyph")
	}
	if len(lines) != 6 {
		t.Fatalf("? glyph: %d lines, want 6", len(lines))
	}
	for i, l := range lines {
		if cells(l) != 8 {
			t.Errorf("? glyph line %d: %d cells, want 8: %q", i, cells(l), l)
		}
	}
	yellow := paletteFor(colorTrue).NewStyle().Foreground(colMedium).Bold(true)
	for i, l := range renderScoreLetter("?", colorTrue) {
		if want := yellow.Render(lines[i]); l != want {
			t.Errorf("? glyph line %d: %q, want yellow %q", i, l, want)
		}
	}
	if got, want := renderScoreLetter("Z", colorOff), renderScoreLetter("E", colorOff); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("an unknown letter no longer draws E:\n%s", strings.Join(got, "\n"))
	}
}

// withheldHeading is the Score heading every final screen opens on.
var withheldHeading = []string{scoreRule, "Score", scoreRule, ""}

// A degraded run closes on the Score block with the score withheld: the
// glyph beside the score line, the yellow INCOMPLETE status, a blank line,
// then why (the degraded reason) and what to do next. No bar, no worst
// case, no best fix, no arithmetic.
func TestWithheldScreenDegraded(t *testing.T) {
	var out bytes.Buffer
	renderWithheldScreen(&out, termCaps{Color: colorOff}, withheldScore{Degraded: true, Reasons: []string{"branch protection fetch failed (403)"}})
	want := strings.Join(append(withheldHeading,
		" ██████╗   Plumber Score  withheld",
		" ╚════██╗  Status: INCOMPLETE (data collection failed)",
		"   ███╔═╝",
		"   ╚══╝    Why: branch protection fetch failed (403)",
		"   ██╗     Next: fix the cause above and re-run; the score and the attack paths need the full",
		"   ╚═╝     picture",
	), "\n") + "\n"
	if out.String() != want {
		t.Errorf("withheld screen:\n%s\nwant:\n%s", out.String(), want)
	}
	for _, unwanted := range []string{"Worst case", "Best fix", "/ 100", "░", "could not be evaluated", "Summary", "Score withheld"} {
		if strings.Contains(out.String(), unwanted) {
			t.Errorf("the withheld screen prints %q:\n%s", unwanted, out.String())
		}
	}
}

// A run that evaluated no control, collection intact, says so: the CI
// errors when there are any, else the one reason left.
func TestWithheldScreenNothingChecked(t *testing.T) {
	var out bytes.Buffer
	renderWithheldScreen(&out, termCaps{Color: colorOff}, withheldScore{})
	want := strings.Join(append(withheldHeading,
		" ██████╗   Plumber Score  withheld",
		" ╚════██╗  Status: NOTHING CHECKED (no control was evaluated)",
		"   ███╔═╝",
		"   ╚══╝    Why: every enabled control needs configuration or was skipped",
		"   ██╗     Next: enable or configure at least one control, then re-run",
		"   ╚═╝",
	), "\n") + "\n"
	if out.String() != want {
		t.Errorf("withheld screen:\n%s\nwant:\n%s", out.String(), want)
	}
	out.Reset()
	renderWithheldScreen(&out, termCaps{Color: colorOff}, withheldScore{CiErrors: []string{"jobs:build config contains unknown keys: scrpt"}})
	if !strings.Contains(out.String(), "    Why: jobs:build config contains unknown keys: scrpt\n") || strings.Contains(out.String(), "needs configuration") {
		t.Errorf("want the CI error as the cause:\n%s", out.String())
	}
}

// The causes stop at three, the rest are counted, and the next step says
// "causes" when there is more than one. A cause is sanitized and wrapped
// like every other line.
func TestWithheldScreenCapsTheCausesAtThree(t *testing.T) {
	var out bytes.Buffer
	reasons := []string{"one", "two", "three\x07", "four", strings.Repeat("five ", 25)}
	renderWithheldScreen(&out, termCaps{Color: colorOff}, withheldScore{Degraded: true, Reasons: reasons})
	got := out.String()
	for _, want := range []string{"    Why: one\n", "    two\n", "    three\n", "    and 2 more\n", "    Next: fix the causes above and re-run;"} {
		if !strings.Contains(got, want) {
			t.Errorf("want %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "four") || strings.Contains(got, "five") || strings.Contains(got, "\x07") {
		t.Errorf("the fourth and fifth causes, or a control character, printed:\n%s", got)
	}
	for _, l := range strings.Split(got, "\n") {
		if cells(l) > defaultReportWidth {
			t.Errorf("line wider than the report: %q", l)
		}
	}
}

// With colour on the status word is bold yellow, the Why label red (the
// worst case's colour), the Next label green (the best fix's colour), and
// the glyph yellow; the rest of each line is plain.
func TestWithheldScreenColours(t *testing.T) {
	var out bytes.Buffer
	renderWithheldScreen(&out, termCaps{Color: colorTrue}, withheldScore{Degraded: true, Reasons: []string{"token lacks api scope"}})
	got := out.String()
	r := paletteFor(colorTrue)
	for _, want := range []string{
		"Status: \x1b[1m\x1b[33mINCOMPLETE\x1b[0m (data collection failed)\n",
		r.NewStyle().Foreground(colCritical).Render("Why:") + " token lacks api scope\n",
		r.NewStyle().Foreground(colAccent).Render("Next:") + " fix the cause above and re-run;",
		r.NewStyle().Foreground(colMedium).Bold(true).Render("██████╗ ") + "  Plumber Score  withheld\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("want %q in:\n%q", want, got)
		}
	}
	out.Reset()
	renderWithheldScreen(&out, termCaps{Color: colorTrue}, withheldScore{})
	if !strings.Contains(out.String(), "Status: \x1b[1m\x1b[33mNOTHING CHECKED\x1b[0m (no control was evaluated)\n") {
		t.Errorf("want the yellow status word:\n%q", out.String())
	}
}

// withheldScoreOf reads the run: degraded with its reasons, or nothing
// checked with the CI errors.
func TestWithheldScoreOf(t *testing.T) {
	degraded := withheldScoreOf(&control.AnalysisResult{DataCollectionDegraded: true, DegradedReasons: []string{"a"}, CiErrors: []string{"b"}})
	if !degraded.Degraded || len(degraded.Reasons) != 1 || degraded.Reasons[0] != "a" || len(degraded.CiErrors) != 1 {
		t.Errorf("degraded: %+v", degraded)
	}
	nothing := withheldScoreOf(&control.AnalysisResult{CiErrors: []string{"b"}})
	if nothing.Degraded || len(nothing.Reasons) != 0 || len(nothing.CiErrors) != 1 {
		t.Errorf("nothing checked: %+v", nothing)
	}
}

// The report closes on the final screen whenever the run was priced under
// scoring-v4 (its score shown or withheld: degraded is not read), and
// when nothing was evaluated under a scoring-v4 request. It keeps the
// previous layout under scoring-v3, under a scoring-v4 request that fell
// back to v3, under --no-controls and in platform mode.
func TestClosesOnFinalScreen(t *testing.T) {
	contextual := &control.PlumberScoreResult{ProfileID: control.PlumberScoreProfileIDV4, Score: "C"}
	legacy := &control.PlumberScoreResult{ProfileID: control.PlumberScoreProfileID, Score: "C"}
	for _, c := range []struct {
		name    string
		profile string
		s       complianceSummary
		want    bool
	}{
		{"scoring-v4 priced", "v4", complianceSummary{score: contextual, scoreMode: true}, true},
		{"scoring-v4 nothing evaluated", "v4", complianceSummary{scoreMode: true}, true},
		{"scoring-v4 fell back to v3", "v4", complianceSummary{score: legacy, scoreMode: true}, false},
		{"scoring-v3 priced", "v3", complianceSummary{score: legacy, scoreMode: true}, false},
		{"scoring-v3 nothing evaluated", "v3", complianceSummary{scoreMode: true}, false},
		{"no controls", "v4", complianceSummary{scoreMode: false, noControls: true}, false},
		{"platform mode", "v4", complianceSummary{scoreMode: true, platformMode: true}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			withScoreProfile(t, c.profile)
			if got := closesOnFinalScreen(c.s); got != c.want {
				t.Errorf("closesOnFinalScreen = %v, want %v", got, c.want)
			}
		})
	}
}

// A degraded run under the contextual score reads like a clean one: the
// caveat under the header, the failing controls as individual findings
// blocks at their registry severity, no attack paths, and the report
// closes on the withheld Score block. No Summary, no Controls table, no
// boxed withheld banner, no previous badge.
func TestOutputTextV4DegradedClosesOnTheWithheldScore(t *testing.T) {
	t.Cleanup(func() { useReportColor(colorBasic) })
	useReportColor(colorOff)
	gh, result, conf, s := v4OutputFixture(t)
	result.DataCollectionDegraded = true
	result.DegradedReasons = []string{"branch protection fetch failed (403)"}
	out := captureStdoutAll(t, func() { _ = outputTextWithProvider(gh, result, conf, s, nil, nil) })
	for _, want := range []string{
		"⚠ Data collection was incomplete, results may be partial:",
		"↳ controls with un-collected data are listed as not evaluated; the score is withheld until the run completes cleanly.",
		"Individual findings (",
		"ISSUE-701",
		scoreRule + "\nScore\n" + scoreRule + "\n\n",
		"Plumber Score  withheld",
		"Status: INCOMPLETE (data collection failed)",
		"Why: branch protection fetch failed (403)",
		"Next: fix the cause above and re-run;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q in:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"Summary", "Score withheld", "/ 100 pts", "│ Control ", "Attack paths", "Situation", "Worst case", "Best fix", "Failed Controls", "Findings Found", "Issues Found", "Passed Controls", "\u2014"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("a degraded run printed %q:\n%s", unwanted, out)
		}
	}
	// ISSUE-701 is registered High and rides a Critical path: with the
	// score withheld it shows at its registry severity.
	if i := strings.Index(out, "ISSUE-701"); i < 0 || !strings.Contains(out[:i], "[HIGH]") && !strings.Contains(out[:i], "HIGH") {
		t.Errorf("want the registry severity beside ISSUE-701:\n%s", out)
	}
	// The withheld block is the last lines of the run.
	tail := "   ██╗     Next: fix the cause above and re-run; the score and the attack paths need the full\n   ╚═╝     picture\n"
	if !strings.HasSuffix(out, tail) {
		t.Errorf("the report does not close on the withheld score block:\n%s", out)
	}
}

// A run that evaluated nothing under the contextual score (every enabled
// control config_required) lists the control as not evaluated and closes
// on the withheld Score block saying nothing was checked.
func TestOutputTextV4NothingCheckedClosesOnTheWithheldScore(t *testing.T) {
	t.Cleanup(func() { useReportColor(colorBasic) })
	useReportColor(colorOff)
	newGateFlagsCmd(t)
	withScoreProfile(t, "v4")
	gh := &provider.GitHubProvider{}
	enabled := true
	conf := configuration.NewDefaultConfiguration()
	conf.PlumberConfig = &configuration.PlumberConfig{
		GitHub: &configuration.ProviderConfig{
			Controls: configuration.ControlsConfig{
				ActionsMustBePinnedByCommitSha: &configuration.ActionsPinnedByShaControlConfig{Enabled: &enabled},
			},
		},
	}
	result := &control.AnalysisResult{
		CiValid:      true,
		ProjectPath:  "group/project",
		NotEvaluable: map[string]string{"actionsMustBePinnedByCommitSha": control.ReasonConfigRequired},
	}
	s := buildComplianceSummary(gh, result, conf)
	if s.score != nil {
		t.Fatalf("fixture drifted: a run that evaluated nothing has a score: %+v", s.score)
	}
	out := captureStdoutAll(t, func() { _ = outputTextWithProvider(gh, result, conf, s, nil, nil) })
	for _, want := range []string{
		"Not Evaluated (1)",
		"Plumber Score  withheld",
		"Status: NOTHING CHECKED (no control was evaluated)",
		"Why: every enabled control needs configuration or was skipped",
		"Next: enable or configure at least one control, then re-run",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q in:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"Summary", "Score withheld", "/ 100 pts", "Status: FAILED", "Status: PASSED", "Individual findings"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("a run that checked nothing printed %q:\n%s", unwanted, out)
		}
	}
}

// Under scoring-v3 a degraded run keeps the previous layout: the Summary
// section, its INCOMPLETE status and the boxed withheld banner.
func TestOutputTextV3DegradedKeepsTheLegacyLayout(t *testing.T) {
	newGateFlagsCmd(t)
	withScoreProfile(t, "v3")
	gh := &provider.GitHubProvider{}
	conf := configuration.NewDefaultConfiguration()
	conf.PlumberConfig = defaultGitHubPlumberConfig(t)
	result := releaseMutableActionResult()
	result.DataCollectionDegraded = true
	result.DegradedReasons = []string{"branch protection fetch failed (403)"}
	s := buildComplianceSummary(gh, result, conf)
	out := captureStdoutAll(t, func() { _ = outputTextWithProvider(gh, result, conf, s, nil, nil) })
	for _, want := range []string{"Summary", "Status: ", "INCOMPLETE", "Score withheld"} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q in the previous layout:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Plumber Score  withheld") {
		t.Errorf("the previous layout printed the contextual withheld block:\n%s", out)
	}
}

// A scoring-v4 request that fell back to v3 (no situation to price) keeps
// the previous layout too, degraded or not.
func TestOutputTextV4FallbackDegradedKeepsTheLegacyLayout(t *testing.T) {
	newGateFlagsCmd(t)
	withScoreProfile(t, "v4")
	gh := &provider.GitHubProvider{}
	conf := configuration.NewDefaultConfiguration()
	conf.PlumberConfig = defaultGitHubPlumberConfig(t)
	result := releaseMutableActionResult()
	result.Situation = nil
	result.DataCollectionDegraded = true
	result.DegradedReasons = []string{"branch protection fetch failed (403)"}
	s := buildComplianceSummary(gh, result, conf)
	if s.score == nil || scoreProfileV4(s.score) {
		t.Fatalf("fixture drifted: want a v3 fallback score, got %+v", s.score)
	}
	out := captureStdoutAll(t, func() { _ = outputTextWithProvider(gh, result, conf, s, nil, nil) })
	if !strings.Contains(out, "Summary") || !strings.Contains(out, "Score withheld") || strings.Contains(out, "Plumber Score  withheld") {
		t.Errorf("the fallback did not keep the previous layout:\n%s", out)
	}
}

// renderFindingGroupsV4 with no score (withheld) prints the findings as
// individual blocks, counted live, and no attack path.
func TestRenderFindingGroupsV4WithoutAScore(t *testing.T) {
	t.Cleanup(func() { useReportColor(colorBasic) })
	useReportColor(colorOff)
	groups := []findingGroup{
		{Title: "Branch must be protected", Findings: []detailedFinding{{Code: control.CodeBranchUnprotected, Message: "branch `main` is not protected"}}},
		{Title: "pass-ctl", Stats: []statLine{{Label: "Total", Value: "3"}}},
	}
	out := captureStdoutAll(t, func() { renderFindingGroupsV4(groups, nil, nil, reportBlock) })
	if !strings.Contains(out, "Individual findings (1)") || !strings.Contains(out, "Passed Controls (1)") || strings.Contains(out, "Attack paths") {
		t.Errorf("want one individual finding and the passed control, no attack path:\n%s", out)
	}
}
