package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/provider"
)

func TestPathBlockRendering(t *testing.T) {
	b := control.PathBlock{
		Tier: control.TierHigh, Loss: 15,
		Entry: "docker.io/alpine:latest (mutable image tag)", EntrySubject: "docker.io/alpine:latest",
		Branches: []control.PathBlockBranch{{Job: "job `est_file`", Reach: "7 secrets"}},
		So:       "if this image is compromised, an attacker can read 7 secrets of the repository and push in your repository", Fix: "pin the image by digest",
		Findings: []control.PathBlockFinding{
			{Code: "ISSUE-102", Title: "Forbidden container image tag", Location: ".gitlab-ci.yml:1"},
			{Code: "ISSUE-103", Title: "Container image not pinned by digest", Location: ".gitlab-ci.yml:1"},
		},
	}
	var out bytes.Buffer
	renderPathBlock(&out, 1, b, termCaps{Color: colorOff}, explainBlock)
	want := strings.Join([]string{
		" HIGH  Attack path 1",
		"       Entry  docker.io/alpine:latest (mutable image tag)",
		"       │",
		"       └──▶ runs in job `est_file` ─▶ reaches 7 secrets",
		"",
		"       So     if this image is compromised, an attacker can read 7 secrets of the repository",
		"              and push in your repository",
		"       Fix    pin the image by digest",
		"       Findings",
		fmt.Sprintf("         ISSUE-102 %-40s   .gitlab-ci.yml:1", "Forbidden container image tag"),
		"                   ↳ docs: https://getplumber.io/docs/cli/issues/ISSUE-102",
		fmt.Sprintf("         ISSUE-103 %-40s   .gitlab-ci.yml:1", "Container image not pinned by digest"),
		"                   ↳ docs: https://getplumber.io/docs/cli/issues/ISSUE-103",
		"",
	}, "\n") + "\n"
	if out.String() != want {
		t.Errorf("block:\n%s\nwant:\n%s", out.String(), want)
	}
}

// With colour on, the documentation line under a finding is dim, as the
// other arrow lines are, and stays under that finding.
func TestPathBlockDocsLineIsDimWithColour(t *testing.T) {
	t.Cleanup(func() { useReportColor(colorBasic) })
	useReportColor(colorBasic)
	b := control.PathBlock{
		Tier: control.TierHigh, Entry: "push to main (not protected)",
		Branches: []control.PathBlockBranch{{Job: "build", Reach: "token: write"}},
		So:       "the token's write permissions can be abused", Fix: "protect the default branch",
		Findings: []control.PathBlockFinding{
			{Code: "ISSUE-501", Title: "Branch protection missing"},
			{Code: "ISSUE-203", Title: "Pipeline enables CI debug trace", Location: ".github/workflows/ci.yml:18", Count: 2},
		},
	}
	var out bytes.Buffer
	renderPathBlock(&out, 1, b, termCaps{Color: colorBasic}, explainBlock)
	docs := func(code string) string {
		return "                   " + colorDim + "↳ docs: https://getplumber.io/docs/cli/issues/" + code + colorReset + "\n"
	}
	got := out.String()
	if colorDim == "" || !strings.Contains(got, "Branch protection missing\n"+docs("ISSUE-501")+"         ISSUE-203") ||
		!strings.HasSuffix(got, docs("ISSUE-203")+"\n") {
		t.Errorf("with colour on, want each docs line dim under its finding:\n%q", got)
	}
}

// In the report a block leaves its findings out and closes, under its
// fix, on one line pointing to the command that prints them.
func TestPathBlockInTheReportClosesOnTheDetailsLine(t *testing.T) {
	b := control.PathBlock{
		Tier: control.TierHigh, Entry: "push to main (not protected)",
		Branches: []control.PathBlockBranch{{Job: "build", Reach: "token: write"}},
		So:       "the token's write permissions can be abused", Fix: "protect the default branch",
		Findings: []control.PathBlockFinding{{Code: "ISSUE-501", Title: "Branch protection missing"}},
	}
	var out bytes.Buffer
	renderPathBlock(&out, 7, b, termCaps{Color: colorOff}, reportBlock)
	got := out.String()
	want := "       Fix    protect the default branch\n       ↳ details: run `plumber explain -a 7`\n\n"
	if !strings.HasSuffix(got, want) {
		t.Errorf("block:\n%s\nwant the end:\n%s", got, want)
	}
	if strings.Contains(got, "Findings") || strings.Contains(got, "ISSUE-501") || strings.Contains(got, "\x1b") {
		t.Errorf("the report block lists findings or prints an escape with colour off:\n%q", got)
	}
	out.Reset()
	renderPathBlock(&out, 7, b, termCaps{Color: colorBasic}, reportBlock)
	// The whole details line is dim, its command no bolder than the rest.
	if want := "       " + colorDim + "↳ details: run `plumber explain -a 7`" + colorReset + "\n\n"; colorDim == "" || !strings.HasSuffix(out.String(), want) {
		t.Errorf("with colour on, want the whole details line dim:\n%q", out.String())
	}
}

// The labels of a block (Entry, So, Note, Fix) are bold with colour on,
// their values plain and in the same column as with colour off; with
// colour off a block prints no escape.
func TestPathBlockLabelsAreBoldWithColour(t *testing.T) {
	t.Cleanup(func() { useReportColor(colorBasic) })
	useReportColor(colorBasic)
	b := control.PathBlock{
		Tier: control.TierHigh, Entry: "main (branch anyone with write access can push to, not protected)", EntrySubject: "main",
		Branches:        []control.PathBlockBranch{{Job: "job `build`", Reach: "an OIDC token"}},
		So:              "as anyone with write access to `main`, an attacker can execute code to request an OIDC token",
		ReachUnverified: "Plumber could not check that the token can write (no permissions block)",
		Fix:             "protect the default branch",
	}
	var plain, coloured bytes.Buffer
	renderPathBlock(&plain, 1, b, termCaps{Color: colorOff}, reportBlock)
	renderPathBlock(&coloured, 1, b, termCaps{Color: colorBasic}, reportBlock)
	if strings.Contains(plain.String(), "\x1b") {
		t.Errorf("colour off printed an escape:\n%q", plain.String())
	}
	for _, label := range []string{"Entry", "So", "Note", "Fix"} {
		pad := strings.Repeat(" ", 7-len(label))
		if !strings.Contains(plain.String(), "\n       "+label+pad) {
			t.Errorf("colour off: %s not in its column:\n%s", label, plain.String())
		}
		if want := "\n       " + colorBold + label + colorReset + pad; colorBold == "" || !strings.Contains(coloured.String(), want) {
			t.Errorf("colour on: want %s bold in its column:\n%q", label, coloured.String())
		}
	}
}

// With colour on, the block opens on the coloured tier badge, the rest of
// its first line unchanged.
func TestPathBlockRenderingColoursTheBadge(t *testing.T) {
	b := control.PathBlock{Tier: control.TierCritical, Entry: "main (branch anyone with write access can push to, not protected)", Branches: []control.PathBlockBranch{{Job: "job `build`", Reach: "a token with write access to pull requests"}}}
	var out bytes.Buffer
	renderPathBlock(&out, 3, b, termCaps{Color: colorBasic}, reportBlock)
	first, _, _ := strings.Cut(out.String(), "\n")
	if !strings.HasPrefix(first, pathTierTag(control.TierCritical)) || !strings.HasSuffix(first, " Attack path 3") {
		t.Errorf("first line = %q", first)
	}
}

// A dependency path the cap held reads as what it is: no marker on its
// branch and, in the report, no cap Note; under --score-point the cap
// Note says why the path stops at its tier, so the points add up.
func TestPathBlockRenderingCapped(t *testing.T) {
	b := control.PathBlock{
		Tier: control.TierMedium, Entry: "o/a@v1 (mutable external action)",
		Branches: []control.PathBlockBranch{{Job: "job `release`", Reach: "1 secret and a step that publishes"}},
		So:       "if this action is compromised, an attacker can read 1 secret of the repository and ship a malicious release",
		Cap:      "Capped at Medium: it needs a dependency compromise first", Fix: "pin the version on the commit SHA",
	}
	var out bytes.Buffer
	renderPathBlock(&out, 1, b, termCaps{Color: colorOff}, reportBlock)
	want := "       └──▶ runs in job `release` ─▶ reaches 1 secret and a step that publishes\n\n" +
		"       So     if this action is compromised, an attacker can read 1 secret of the repository\n" +
		"              and ship a malicious release\n" +
		"       Fix    pin the version on the commit SHA\n"
	if got := out.String(); !strings.Contains(got, want) || strings.Contains(got, "apped at") {
		t.Errorf("block lacks %q or carries the cap:\n%s", want, got)
	}
	out.Reset()
	opts := reportBlock
	opts.ScorePoint = true
	renderPathBlock(&out, 1, b, termCaps{Color: colorOff}, opts)
	if want := "              and ship a malicious release\n" +
		"       Note   Capped at Medium: it needs a dependency compromise first\n       Fix "; !strings.Contains(out.String(), want) {
		t.Errorf("--score-point: block lacks %q:\n%s", want, out.String())
	}
}

// An unverified branch says so after its job, and what could not be
// checked is a note under the consequence.
func TestPathBlockRenderingUnverified(t *testing.T) {
	b := control.PathBlock{
		Tier: control.TierHigh, Unverified: true, Loss: 15, Entry: "o/a@v1 (mutable external action)", EntrySubject: "o/a@v1",
		Branches:        []control.PathBlockBranch{{Job: "job `build`", Reach: "a token with push access (assumed: no permissions block)", Marker: "(unverified)"}},
		ReachUnverified: "Plumber could not check that the token can write (no permissions block)",
		So:              "if this action is compromised or malicious, an attacker can execute code to push in your repository", Fix: "pin the version on the commit SHA",
	}
	var out bytes.Buffer
	renderPathBlock(&out, 2, b, termCaps{Color: colorOff}, explainBlock)
	got := out.String()
	for _, want := range []string{
		" HIGH  Attack path 2 (unverified)\n       Entry  o/a@v1 (mutable external action)\n",
		"       └──▶ runs in job `build` (unverified)\n            └─▶ reaches a token with push access (assumed: no permissions block)\n",
		"       Note   Plumber could not check that the token can write (no permissions block)\n       Fix ",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("block lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Findings") {
		t.Errorf("a block with no finding prints no Findings label:\n%s", got)
	}
}

// A poisoned cache names, in a note, the job whose run can write it.
func TestPathBlockNamesTheJobThatCanWriteTheCache(t *testing.T) {
	b := control.PathBlock{
		Tier: control.TierCritical, Entry: "cache writable by an untrusted run: npm-key",
		Branches:    []control.PathBlockBranch{{Job: "release/publish", Reach: "1 secret; publishing"}},
		EntryWriter: "a run of job pr-preview/preview can write the cache", So: "a compromise here ships a malicious release to your users or into production",
	}
	var out bytes.Buffer
	renderPathBlock(&out, 1, b, termCaps{Color: colorOff}, reportBlock)
	want := "       Note   a run of job pr-preview/preview can write the cache\n"
	if got := out.String(); !strings.Contains(got, want) {
		t.Errorf("block lacks %q:\n%s", want, got)
	}
}

// The findings keep one column for their location whatever the length of
// a title, a folded line says how many findings it holds, and no line
// ends in spaces.
func TestPathBlockFindingsColumn(t *testing.T) {
	long := "Action version carries a published security advisory"
	b := control.PathBlock{Tier: control.TierMedium, Findings: []control.PathBlockFinding{
		{Code: "ISSUE-703", Title: long, Location: "ci.yml:20"},
		{Code: "ISSUE-501", Title: "Branch protection missing"},
		{Code: "ISSUE-201", Title: "CI/CD variable not protected", Count: 5},
	}}
	var out bytes.Buffer
	renderPathBlock(&out, 1, b, termCaps{Color: colorOff}, explainBlock)
	got := out.String()
	for _, want := range []string{
		"       Findings\n         ISSUE-703 " + long + "   ci.yml:20\n",
		"         ISSUE-501 Branch protection missing\n",
		fmt.Sprintf("         ISSUE-201 %-*s   %s\n", len(long), "CI/CD variable not protected", "5 findings"),
	} {
		if !strings.Contains(got, want) {
			t.Errorf("block lacks %q:\n%s", want, got)
		}
	}
	for _, l := range strings.Split(got, "\n") {
		if strings.TrimRight(l, " ") != l {
			t.Errorf("trailing space: %q", l)
		}
	}
}

// Least severe first, so the worst path, path 1, prints last.
func TestPathBlocksPrintTheWorstLast(t *testing.T) {
	paths := []control.AttackPath{
		{ID: "a", Tier: control.TierCritical, BaseTier: control.TierCritical, Jobs: []string{"release"}, Entry: control.EntryFact{Subject: "x@v1"}, AnchorCode: "ISSUE-701", EntryKind: control.EntryMutableDependency},
		{ID: "b", Tier: control.TierLow, BaseTier: control.TierLow, Jobs: []string{"lint"}, Entry: control.EntryFact{Subject: "y@v1"}, AnchorCode: "ISSUE-701", EntryKind: control.EntryMutableDependency},
	}
	var out bytes.Buffer
	renderPathBlocks(&out, paths, nil, termCaps{Color: colorOff}, reportBlock)
	got := out.String()
	low, crit := strings.Index(got, " LOW   Attack path 2"), strings.Index(got, " CRIT  Attack path 1")
	if low < 0 || crit < 0 || low > crit {
		t.Errorf("order:\n%s", got)
	}
}

// A job name is attacker text on a merge request pipeline: it can never
// carry an escape sequence to the terminal.
func TestPathBlockStripsTerminalEscapes(t *testing.T) {
	var out bytes.Buffer
	evil := "a\x1b]8;;http://x\x07b"
	b := control.PathBlock{Tier: control.TierLow, Entry: "push to " + evil, EntrySubject: evil,
		Branches: []control.PathBlockBranch{{Job: evil, Fed: []string{evil, evil}, Reach: evil, Marker: evil}}, So: evil, Fix: evil,
		Findings: []control.PathBlockFinding{{Code: "ISSUE-501", Title: evil, Location: evil}}}
	renderPathBlock(&out, 1, b, termCaps{Color: colorOff}, explainBlock)
	if strings.Contains(out.String(), "\x1b") || strings.Contains(out.String(), "\x07") {
		t.Errorf("escape reached the terminal: %q", out.String())
	}
}

// finalScreenScore is test2's shape: one High path, twelve other
// findings over their cap.
func finalScreenScore() *control.PlumberScoreResult {
	p := control.AttackPath{
		ID: "p1", Tier: control.TierHigh, BaseTier: control.TierHigh, State: control.PathProven,
		EntryKind: control.EntryMutableDependency, AnchorCode: "ISSUE-102",
		Entry: control.EntryFact{Subject: "docker.io/alpine:latest"}, Jobs: []string{"est_file"},
		Reach: control.Reach{Secrets: []string{"A", "B", "C", "D", "E", "F", "G"}, Executes: true}, Loss: 15,
	}
	return &control.PlumberScoreResult{
		ProfileID: control.PlumberScoreProfileIDV4, Score: "C", RawPoints: 55, RawPointsUnclamped: 55, FinalPoints: 55, Paths: []control.AttackPath{p},
		PathLosses:    []control.PathLoss{{Tier: control.TierHigh, Count: 1, Weight: 15, Cap: 69, CappedLoss: 15, PathIDs: []string{"p1"}}},
		OtherFindings: &control.OtherFindingsLoss{Count: 12, Counts: control.SeverityCounts{Critical: 1, High: 2, Medium: 9}, UncappedLoss: 85, Cap: 30, CappedLoss: 30, CapApplied: true},
		BestFix:       &control.BestFix{Code: "ISSUE-102", Subject: "docker.io/alpine:latest", PathID: "p1", PointsGained: 15, NewPoints: 70, NewLetter: "C"},
	}
}

// scoreRule is the rule above and under the final screen's heading.
var scoreRule = strings.Repeat("─", 20)

// The final screen is the Score section: its heading, then the score
// block beside the letter, the bar on the score's line, the verdict right
// under it, a blank line, then the worst case and the best fix right
// under it. The attack paths and the
// individual findings are not repeated there: their counts head their own
// sections above.
func TestFinalScreen(t *testing.T) {
	var out bytes.Buffer
	renderFinalScreen(&out, finalScreenScore(), termCaps{Color: colorOff}, false, finalNotes{Status: &gateStatus{Passed: false, Gate: "100 pts"}})
	want := strings.Join([]string{
		scoreRule,
		"Score",
		scoreRule,
		"",
		"  ██████╗  Plumber Score  55 / 100  " + strings.Repeat("█", 15) + strings.Repeat("░", 13),
		" ██╔════╝  Status: FAILED (gate blocks at 100 pts)",
		" ██║",
		" ██║       Worst case: if this image is compromised, an attacker can read 7 secrets of the",
		" ╚██████╗  repository (attack path 1: docker.io/alpine:latest)",
		"  ╚═════╝  Best fix: pin the image by digest (image docker.io/alpine:latest), +15 pts, 70 / 100 (C)",
	}, "\n") + "\n"
	if out.String() != want {
		t.Errorf("final screen:\n%s\nwant:\n%s", out.String(), want)
	}
	for _, unwanted := range []string{"Summary", "Attack paths", "Individual findings", "╭", "│"} {
		if strings.Contains(out.String(), unwanted) {
			t.Errorf("the final screen prints %q:\n%s", unwanted, out.String())
		}
	}
}

// Every letter's art is six lines tall, so the score block's six lines sit
// beside it whatever the letter; with colour on, a line of the letter with
// nothing beside it ends on the letter, no space left inside its colour.
func TestScoreLettersAreSixLinesTall(t *testing.T) {
	for _, letter := range []string{"A", "B", "C", "D", "E"} {
		if n := len(renderScoreLetter(letter, colorOff)); n != 6 {
			t.Errorf("letter %s: %d lines, want 6", letter, n)
		}
		score := finalScreenScore()
		score.Score = letter
		var out bytes.Buffer
		renderFinalScreen(&out, score, termCaps{Color: colorBasic}, false, finalNotes{Status: &gateStatus{Gate: "100 pts"}})
		for _, l := range strings.Split(out.String(), "\n") {
			if plain := strings.TrimSuffix(l, "\x1b[0m"); strings.TrimRight(plain, " ") != plain {
				t.Errorf("letter %s: trailing space in %q", letter, l)
			}
		}
	}
}

// Under --score-point the score block reads top to bottom: the score and
// its bar, the verdict, the subtraction, the nested cap that held, a blank
// line, the best fix and why it recovers what it does;
// each tier's loss follows the block. Ten Medium paths cost 60, counted
// for 49.
func TestFinalScreenScorePointBlockOrder(t *testing.T) {
	score := finalScreenScore()
	score.FinalPoints, score.RawPoints, score.RawPointsUnclamped = 51, 51, 51
	score.PathLosses = []control.PathLoss{{Tier: control.TierMedium, Count: 10, Weight: 6, Cap: 49, CappedLoss: 49}}
	score.OtherFindings = nil
	score.BestFix.Reason = "+13 pts: the path's 15, less 2 for a finding that then stands alone"
	var out bytes.Buffer
	renderFinalScreen(&out, score, termCaps{Color: colorOff}, true, finalNotes{Status: &gateStatus{Passed: true, Gate: "50 pts"}, NotEvaluated: 2})
	got := out.String()
	at := strings.Index(got, " Plumber Score  51 / 100")
	if at < 0 {
		t.Fatalf("no score line:\n%s", got)
	}
	for _, want := range []string{
		" ██╔════╝  Status: PASSED (gate at 50 pts)\n",
		" ██║       100 - 49 (attack paths) - 0 (individual findings)\n",
		" ██║       medium and low items count for 49 at most\n",
		" ╚██████╗  2 controls could not be evaluated: the score covers the others.\n",
		"  ╚═════╝\n",
		"           Worst case: ",
		"           Best fix: pin the image by digest",
		"\n           +13 pts: the path's 15, less 2 for a finding that then stands alone\n\n",
		"           medium paths        x10  -49\n",
	} {
		i := strings.Index(got[at:], want)
		if i < 0 {
			t.Fatalf("score block lacks %q after the previous line:\n%s", want, got)
		}
		at += i + len(want)
	}
	if at != len(got) {
		t.Errorf("lines after the tier losses:\n%s", got)
	}
	for _, l := range strings.Split(got, "\n") {
		if strings.TrimRight(l, " ") != l {
			t.Errorf("trailing space: %q", l)
		}
	}
}

// A best fix that does not move the score yet is the fix alone; under
// --score-point it says why on the line under it, the way a reason does.
func TestFinalScreenSaysWhyTheBestFixDoesNotMoveTheScore(t *testing.T) {
	score := finalScreenScore()
	score.BestFix = &control.BestFix{Code: "ISSUE-102", Subject: "docker.io/alpine:latest", PathID: "p1", NewPoints: 55, NewLetter: "C",
		Stays: "The score stays at 55 until fewer individual findings remain."}
	var out bytes.Buffer
	renderFinalScreen(&out, score, termCaps{Color: colorOff}, false, finalNotes{})
	if want := "  Best fix: pin the image by digest (image docker.io/alpine:latest).\n"; !strings.Contains(out.String(), want) || strings.Contains(out.String(), "stays at") {
		t.Errorf("want %q alone in:\n%s", want, out.String())
	}
	out.Reset()
	renderFinalScreen(&out, score, termCaps{Color: colorOff}, true, finalNotes{})
	want := "  Best fix: pin the image by digest (image docker.io/alpine:latest).\n"
	if why := "           The score stays at 55 until fewer individual findings remain.\n"; !strings.Contains(out.String(), want+why) {
		t.Errorf("want %q then %q in:\n%s", want, why, out.String())
	}
}

// No line raises the score any more: the nested caps are what keep a run
// with no High item at 51, and the line that says so is the cap's.
func TestFinalScreenNeverRaisesTheScore(t *testing.T) {
	score := &control.PlumberScoreResult{ProfileID: control.PlumberScoreProfileIDV4, Score: "C", RawPoints: 51, RawPointsUnclamped: 51, FinalPoints: 51,
		PathLosses: []control.PathLoss{{Tier: control.TierMedium, Count: 10, Weight: 6, Cap: 49, CappedLoss: 49}}}
	var out bytes.Buffer
	renderFinalScreen(&out, score, termCaps{Color: colorOff}, true, finalNotes{})
	if got := out.String(); strings.Contains(got, "Raised to") || !strings.Contains(got, " ██║       medium and low items count for 49 at most\n") {
		t.Errorf("want the cap line and no raise:\n%s", got)
	}
}

// By default the score block is four lines whatever the arithmetic: the
// score with its bar, the verdict, the worst case and the best fix, a
// blank line before the worst case; what does not fit beside the letter's
// six lines prints under its text column. The
// subtraction, the caps, the force and why the best fix recovers what it
// does are for --score-point.
func TestFinalScreenScoreBlockIsFourLines(t *testing.T) {
	score := finalScreenScore()
	score.FinalPoints, score.RawPoints, score.RawPointsUnclamped = 51, 51, 51
	score.BestFix.Reason = "+13 pts: the path's 15, less 2 for a finding that then stands alone"
	var out bytes.Buffer
	renderFinalScreen(&out, score, termCaps{Color: colorOff}, false, finalNotes{Status: &gateStatus{Gate: "100 pts"}})
	got := out.String()
	block := got[strings.Index(got, "\n\n  ██████╗")+2:]
	want := strings.Join([]string{
		"  ██████╗  Plumber Score  51 / 100  " + strings.Repeat("█", 14) + strings.Repeat("░", 14),
		" ██╔════╝  Status: FAILED (gate blocks at 100 pts)",
		" ██║",
		" ██║       Worst case: if this image is compromised, an attacker can read 7 secrets of the",
		" ╚██████╗  repository (attack path 1: docker.io/alpine:latest)",
		"  ╚═════╝  Best fix: pin the image by digest (image docker.io/alpine:latest), +15 pts, 70 / 100 (C)",
	}, "\n") + "\n"
	if block != want {
		t.Errorf("score block:\n%s\nwant:\n%s", block, want)
	}
}

// --score-point prints the arithmetic: in the score block the
// subtraction, the caps and the line saying how the force or zero changed
// the result, then under the block each code's loss and each
// tier's, in that order.
func TestFinalScreenScorePointPrintsTheArithmetic(t *testing.T) {
	high := func(id string) control.AttackPath {
		return control.AttackPath{ID: id, Tier: control.TierHigh, BaseTier: control.TierHigh, EntryKind: control.EntryMutableDependency,
			AnchorCode: "ISSUE-701", Entry: control.EntryFact{Subject: id + "@v1"}, Jobs: []string{"build"}, Loss: 15}
	}
	crit := high("c")
	crit.Tier, crit.BaseTier, crit.Loss = control.TierCritical, control.TierCritical, 30
	score := &control.PlumberScoreResult{
		ProfileID: control.PlumberScoreProfileIDV4, Score: "E", RawPoints: 0, RawPointsUnclamped: -29, FinalPoints: 0,
		Paths: []control.AttackPath{crit, high("a"), high("b"), high("d"), high("e"), high("f")},
		PathLosses: []control.PathLoss{
			{Tier: control.TierCritical, Count: 1, Weight: 30, CappedLoss: 30},
			{Tier: control.TierHigh, Count: 5, Weight: 15, Cap: 69, CappedLoss: 69},
		},
		OtherFindings: &control.OtherFindingsLoss{Count: 2, Counts: control.SeverityCounts{Critical: 2}, UncappedLoss: 40, Cap: 30, CappedLoss: 30, CapApplied: true},
		CodeLosses:    []control.CodeLoss{{Code: "ISSUE-501", Severity: "critical", Count: 2, Weight: 20, UncappedLoss: 40, CappedLoss: 30}},
		BestFix:       &control.BestFix{Code: "ISSUE-701", Subject: "c@v1", PathID: "c", NewPoints: 0, NewLetter: "E", Stays: "The score stays at 0 while the rest takes it below 0."},
	}
	var out bytes.Buffer
	renderFinalScreen(&out, score, termCaps{Color: colorOff}, true, finalNotes{})
	got := out.String()
	at := 0
	for _, want := range []string{
		scoreRule + "\nScore\n" + scoreRule + "\n\n",
		"Plumber Score  0 / 100  " + strings.Repeat("░", 28) + "\n",
		"  100 - 99 (attack paths) - 30 (individual findings)\n",
		"  high, medium and low items count for 69 at most\n",
		"  individual findings count for 30 at most\n",
		"  The score does not go below 0.\n",
		"  Best fix: ",
		"\n           The score stays at 0 while the rest takes it below 0.\n\n",
		"           ISSUE-501  critical x2   -30\n           critical paths      x1   -30\n           high paths          x5   -69\n",
	} {
		i := strings.Index(got[at:], want)
		if i < 0 {
			t.Fatalf("lacks %q after the previous line:\n%s", want, got)
		}
		at += i + len(want)
	}
	score.CriticalMalusApplied, score.CriticalMalusMax, score.RawPoints, score.RawPointsUnclamped, score.FinalPoints = true, 30, 40, 40, 30
	out.Reset()
	renderFinalScreen(&out, score, termCaps{Color: colorOff}, true, finalNotes{})
	if !strings.Contains(out.String(), "  Capped at 30: a Critical attack path remains.\n") {
		t.Errorf("no force line:\n%s", out.String())
	}
	out.Reset()
	renderFinalScreen(&out, score, termCaps{Color: colorOff}, false, finalNotes{})
	for _, unwanted := range []string{" paths  ", "ISSUE-501", "(attack paths)", "at most", "Capped at", "stays at"} {
		if strings.Contains(out.String(), unwanted) {
			t.Errorf("without --score-point the final screen prints %q:\n%s", unwanted, out.String())
		}
	}
}

// The final screen prices no path: under --score-point the totals are in
// the subtraction, and a nested cap that held says so in one line of the
// score block (one High and nine Medium paths: 54 of Medium counted for
// 49, then the High 15). With no path and no other finding it is the heading and the
// score block alone.
func TestFinalScreenNotesTheCapWithoutPricingThePaths(t *testing.T) {
	path := func(id string, tier control.PathTier, loss float64) control.AttackPath {
		return control.AttackPath{ID: id, Tier: tier, BaseTier: tier, EntryKind: control.EntryMutableDependency,
			AnchorCode: "ISSUE-701", Entry: control.EntryFact{Subject: id + "@v1"}, Jobs: []string{"build"}, Loss: loss}
	}
	score := &control.PlumberScoreResult{
		ProfileID: control.PlumberScoreProfileIDV4, Score: "D", RawPoints: 36, FinalPoints: 36,
		Paths: []control.AttackPath{path("a", control.TierMedium, 6), path("b", control.TierMedium, 6), path("c", control.TierMedium, 6), path("d", control.TierMedium, 6), path("h", control.TierHigh, 15)},
		PathLosses: []control.PathLoss{
			{Tier: control.TierHigh, Count: 1, Weight: 15, Cap: 69, CappedLoss: 15},
			{Tier: control.TierMedium, Count: 9, Weight: 6, Cap: 49, CappedLoss: 49},
		},
	}
	var out bytes.Buffer
	renderFinalScreen(&out, score, termCaps{Color: colorOff}, true, finalNotes{})
	got := out.String()
	for _, want := range []string{
		" 100 - 64 (attack paths) - 0 (individual findings)\n",
		"  medium and low items count for 49 at most\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("final screen lacks %q:\n%s", want, got)
		}
	}
	// The worst case names path 1 alone.
	if strings.Contains(got, "pts") || strings.Count(got, "@v1") != 1 || !strings.Contains(got, "(attack path 1: h@v1)") {
		t.Errorf("the final screen prices or lists the paths:\n%s", got)
	}
	out.Reset()
	renderFinalScreen(&out, &control.PlumberScoreResult{ProfileID: control.PlumberScoreProfileIDV4, Score: "A", RawPoints: 100, FinalPoints: 100}, termCaps{Color: colorOff}, false, finalNotes{})
	if want := scoreRule + "\nScore\n" + scoreRule + "\n\n "; !strings.HasPrefix(out.String(), want) || strings.Count(out.String(), "\n") != 10 {
		t.Errorf("no path, no other finding:\n%s", out.String())
	}
}

// blankTextAbove says whether the score block line holding text has
// nothing in the text column on the line above it, the letter alone.
func blankTextAbove(screen, text string) bool {
	lines := strings.Split(screen, "\n")
	for i, l := range lines {
		if strings.Contains(l, text) {
			above := []rune(lines[max(i-1, 0)])
			return i > 0 && strings.TrimSpace(string(above[min(len(above), 11):])) == ""
		}
	}
	return false
}

// visibleWidth is a line's width in cells, colour off.
func visibleWidth(s string) int { return len([]rune(s)) }

// Nothing on the final screen runs past the terminal width: a commit SHA
// shows as 12 characters, and long lines in the score block wrap under
// their own column, the verdict right under the score and the blank line
// above the worst case kept at every width, the bar shortened to 20 cells
// when 28 do not fit beside the score.
func TestFinalScreenFitsTheWidth(t *testing.T) {
	sha := "2d756ea4c53f7f6b397767d8723b3a10a9f35bf2"
	p := control.AttackPath{ID: "x", Tier: control.TierMedium, BaseTier: control.TierMedium, EntryKind: control.EntryMutableDependency, AnchorCode: "ISSUE-703",
		Entry: control.EntryFact{Subject: "some-organisation/a-rather-long-action-name/sub/dir@" + sha}, Jobs: []string{"build-and-publish"}, Loss: 6}
	score := &control.PlumberScoreResult{
		ProfileID: control.PlumberScoreProfileIDV4, Score: "B", RawPoints: 94, FinalPoints: 94, Paths: []control.AttackPath{p},
		PathLosses:    []control.PathLoss{{Tier: control.TierMedium, Count: 1, Weight: 6, Cap: 49, CappedLoss: 6, PathIDs: []string{"x"}}},
		OtherFindings: &control.OtherFindingsLoss{Count: 4, Counts: control.SeverityCounts{Critical: 1, High: 1, Medium: 1, Low: 1}, UncappedLoss: 37, Cap: 30, CappedLoss: 30, CapApplied: true},
		BestFix:       &control.BestFix{Code: "ISSUE-703", Subject: p.Entry.Subject, PathID: "x", PointsGained: 6, NewPoints: 100, NewLetter: "A", Reason: "+6 pts: a reason long enough to need a second line on a narrow terminal, which it gets"},
	}
	for _, width := range []int{0, 60, 80, 40} {
		for _, scorePoint := range []bool{false, true} {
			var out bytes.Buffer
			renderFinalScreen(&out, score, termCaps{Color: colorOff, Width: width}, scorePoint, finalNotes{Status: &gateStatus{Gate: "100 pts"}})
			got := out.String()
			limit := max(width, 60)
			if width == 0 {
				limit = 100
			}
			for _, l := range strings.Split(got, "\n") {
				if visibleWidth(l) > limit {
					t.Errorf("width %d: line of %d cells: %q", width, visibleWidth(l), l)
				}
				if strings.TrimRight(l, " ") != l {
					t.Errorf("width %d: trailing space: %q", width, l)
				}
			}
			if strings.Contains(got, sha) {
				t.Errorf("width %d: the SHA is not shortened:\n%s", width, got)
			}
			if !blankTextAbove(got, "Worst case: ") || blankTextAbove(got, "Status: ") {
				t.Errorf("width %d: want a blank line above the worst case, none above the verdict:\n%s", width, got)
			}
			bar := strings.Repeat("█", 26) + strings.Repeat("░", 2)
			if width == 40 || width == 60 {
				bar = strings.Repeat("█", 18) + strings.Repeat("░", 2)
			}
			if !strings.Contains(got, "Plumber Score  94 / 100  "+bar+"\n") {
				t.Errorf("width %d: want the bar %q on the score line:\n%s", width, bar, got)
			}
			if !scorePoint {
				continue
			}
			flat := strings.Join(strings.Fields(got), " ")
			for _, want := range []string{"which it gets", "individual findings count for 30 at most", "medium paths x1 -6"} {
				if !strings.Contains(flat, want) {
					t.Errorf("width %d: lost %q:\n%s", width, want, got)
				}
			}
		}
	}
}

// On a narrow screen the best fix wraps between its words, never inside
// "+13 pts" or "78 / 100 (B)".
func TestFinalScreenKeepsFiguresWhole(t *testing.T) {
	score := finalScreenScore()
	score.BestFix = &control.BestFix{Code: "CODE-X", Subject: "abcdefghij/klmnopqrst/uvwxyz-12345", PointsGained: 13, NewPoints: 78, NewLetter: "B"}
	var out bytes.Buffer
	renderFinalScreen(&out, score, termCaps{Color: colorOff, Width: 80}, false, finalNotes{})
	got := out.String()
	if !strings.Contains(got, "78 / 100 (B)") || !strings.Contains(got, "+13 pts,") {
		t.Errorf("the best fix figures broke apart:\n%s", got)
	}
}

// A block whose locations cannot sit in one column beside the titles
// puts every location under its title, not only the long ones.
func TestPathBlockFindingsShareOneLayout(t *testing.T) {
	b := control.PathBlock{Tier: control.TierMedium, Findings: []control.PathBlockFinding{
		{Code: "ISSUE-703", Title: "Action version carries a published security advisory", Location: ".github/workflows/ci.yml:20"},
		{Code: "ISSUE-713", Title: "Action comes from an unauthorized source", Location: ".github/workflows/ci.yml:20"},
	}}
	var out bytes.Buffer
	renderPathBlock(&out, 1, b, termCaps{Color: colorOff, Width: 100}, explainBlock)
	want := "         ISSUE-713 Action comes from an unauthorized source\n                   .github/workflows/ci.yml:20\n"
	if !strings.Contains(out.String(), want) {
		t.Errorf("want %q in:\n%s", want, out.String())
	}
}

// A path block fits the width too: a long value wraps under its column,
// and a finding whose location does not fit beside its title puts it on
// the next line.
func TestPathBlockFitsTheWidth(t *testing.T) {
	b := control.PathBlock{
		Tier: control.TierMedium, Loss: 6,
		Entry:        "some-organisation/a-rather-long-action-name@2d756ea4c53f (external action with a known vulnerability)",
		EntrySubject: "some-organisation/a-rather-long-action-name@2d756ea4c53f",
		Branches:     []control.PathBlockBranch{{Job: "job `build`", Reach: "code execution on the runner, no secret and no write token"}},
		So:           "through the known vulnerability of this action, an attacker can execute code on the runner and poison what it caches or uploads", Fix: "move to a version without the advisory",
		Findings: []control.PathBlockFinding{
			{Code: "ISSUE-703", Title: "Action version carries a published security advisory", Location: ".github/workflows/ci.yml:20"},
			{Code: "ISSUE-713", Title: "Action comes from an unauthorized source", Location: ".github/workflows/ci.yml:20"},
		},
	}
	var out bytes.Buffer
	renderPathBlock(&out, 1, b, termCaps{Color: colorOff, Width: 60}, explainBlock)
	got := out.String()
	for _, l := range strings.Split(got, "\n") {
		if visibleWidth(l) > 60 {
			t.Errorf("line of %d cells: %q", visibleWidth(l), l)
		}
		if strings.TrimRight(l, " ") != l {
			t.Errorf("trailing space: %q", l)
		}
	}
	for _, want := range []string{
		"         ISSUE-703 Action version carries a published\n                   security advisory\n                   .github/workflows/ci.yml:20\n",
		"       So     through the known vulnerability of this\n              action,\n              an attacker can execute code on the runner\n              and poison what it caches or uploads\n",
		" MED   Attack path 1\n       Entry  some-organisation/a-rather-long-action-name@2d\n              756ea4c53f (external action with a known\n",
		"       └──▶ runs in job `build`\n            └─▶ reaches code execution on the runner,\n                        no secret and no write token\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("block lacks %q:\n%s", want, got)
		}
	}
}

// The path details open on a section heading like every other section
// and close on the last block, with no documentation line after it; no
// path, no heading.
func TestPathBlocksOpenOnAHeading(t *testing.T) {
	t.Cleanup(func() { useReportColor(colorBasic) })
	useReportColor(colorOff)
	paths := []control.AttackPath{
		{ID: "a", Tier: control.TierLow, BaseTier: control.TierLow, Jobs: []string{"lint"}, Entry: control.EntryFact{Subject: "y@v1"}, AnchorCode: "ISSUE-701", EntryKind: control.EntryMutableDependency},
		{ID: "b", Tier: control.TierHigh, BaseTier: control.TierHigh, Jobs: []string{"build"}, Entry: control.EntryFact{Subject: "docker.io/alpine:latest"}, AnchorCode: "ISSUE-102", EntryKind: control.EntryMutableDependency},
	}
	var out bytes.Buffer
	renderPathBlocks(&out, paths, nil, termCaps{Color: colorOff}, reportBlock)
	rule := strings.Repeat("─", 20)
	if want := rule + "\n✗ Attack paths (2)\n" + rule + "\n\n LOW   Attack path 2"; !strings.HasPrefix(out.String(), want) {
		t.Errorf("path details:\n%s\nwant the start:\n%s", out.String(), want)
	}
	if want := "       ↳ details: run `plumber explain -a 1`\n\n"; !strings.HasSuffix(out.String(), want) || strings.Contains(out.String(), "↳ docs") {
		t.Errorf("path details:\n%s\nwant the end on the last block, no docs line:\n%s", out.String(), want)
	}
	// A lighter rule, between two blocks only, says where one path ends.
	sep := strings.Repeat("┄", 20)
	if want := "\n\n  " + sep + "\n\n HIGH  Attack path 1"; !strings.Contains(out.String(), want) || strings.Count(out.String(), sep) != 1 {
		t.Errorf("path details:\n%s\nwant one separator, between the blocks:\n%s", out.String(), want)
	}
	out.Reset()
	useReportColor(colorBasic)
	renderPathBlocks(&out, paths, nil, termCaps{Color: colorBasic}, reportBlock)
	if want := "  " + colorDim + sep + colorReset + "\n"; colorDim == "" || !strings.Contains(out.String(), "\n\n"+want+"\n") {
		t.Errorf("with colour on, want the separator dimmed:\n%q", out.String())
	}
	if want := colorDim + "↳ details: run `plumber explain -a 1`" + colorReset + "\n\n"; !strings.HasSuffix(out.String(), want) || strings.Contains(out.String(), "↳ docs") {
		t.Errorf("with colour on, want the end on the last block, no docs line:\n%q", out.String())
	}
	useReportColor(colorOff)
	out.Reset()
	renderPathBlocks(&out, paths[:1], nil, termCaps{Color: colorOff}, reportBlock)
	if strings.Contains(out.String(), "┄") {
		t.Errorf("one path, no separator:\n%s", out.String())
	}
	out.Reset()
	renderPathBlocks(&out, nil, nil, termCaps{Color: colorOff}, reportBlock)
	if out.Len() != 0 {
		t.Errorf("no path printed %q", out.String())
	}
}

// Names from the scanned workflow may hold double-width runes (emoji,
// CJK), whose cell count exceeds their rune count. Every helper that
// fits a name to a width bounds its slices by the runes, so a narrow
// terminal renders such a path instead of panicking.
func TestPathBlocksRenderDoubleWidthNames(t *testing.T) {
	t.Cleanup(func() { useReportColor(colorBasic) })
	useReportColor(colorOff)
	wide := strings.Repeat("🚀", 12) + "/構建構建構建"
	paths := []control.AttackPath{
		{ID: "a", Tier: control.TierHigh, BaseTier: control.TierHigh, Jobs: []string{wide}, Entry: control.EntryFact{Subject: wide + "@v1"}, AnchorCode: "ISSUE-701", EntryKind: control.EntryMutableDependency},
	}
	for width := 0; width <= 40; width++ {
		var out bytes.Buffer
		renderPathBlocks(&out, paths, nil, termCaps{Color: colorOff, Width: width}, reportBlock)
		if !strings.Contains(out.String(), "Attack path 1") {
			t.Fatalf("width %d: no block:\n%s", width, out.String())
		}
		for n := 0; n <= width; n++ {
			_ = wrapCells(wide+" "+wide, n)
		}
	}
}

// The contextual report closes on the final screen: the score block is its
// last lines, nothing prints after it, no situation block, and no badge
// tip, neither with the report nor from the publish leg after it.
func TestOutputTextV4ClosesOnTheScore(t *testing.T) {
	gh, result, conf, s := v4OutputFixture(t)
	defer func(pp bool, pf string) { pushScore, platformURL = pp, pf }(pushScore, platformURL)
	pushScore, platformURL = false, ""
	scorePublishOnce = sync.Once{}
	var out string
	tip := captureStderr(t, func() {
		out = captureStdoutAll(t, func() { _ = outputTextWithProvider(gh, result, conf, s, nil, nil) })
	})
	if tip != "" {
		t.Errorf("the report printed a tip: %q", tip)
	}
	if late := captureStderr(t, func() { handleScorePublishing(gh, conf, result, []byte(`{}`)) }); late != "" {
		t.Errorf("the publish leg printed a tip: %q", late)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if last := lines[len(lines)-1]; !strings.Contains(last, "Best fix: ") && !strings.HasPrefix(last, "           ") {
		t.Errorf("the report does not close on the score block: %q", last)
	}
	if strings.Contains(out, "Situation") || strings.Contains(out, "Default branch ") {
		t.Errorf("the report prints the situation:\n%s", out)
	}
	if !strings.Contains(out, "Plumber Score  ") || strings.Contains(out, "/ 100 pts") {
		t.Errorf("want the final screen's score line, not the previous banner:\n%s", out)
	}
	if i, j := strings.LastIndex(out, "Attack paths ("), strings.Index(out, scoreRule+"\nScore\n"+scoreRule+"\n"); j < 0 || i > j || strings.Contains(out, "Summary") {
		t.Errorf("want the Score section after the path details, no Summary:\n%s", out)
	}
}

// captureOutputInOrder sends stdout and stderr through one pipe, so what
// fn prints keeps the order a terminal shows it in.
func captureOutputInOrder(t *testing.T, fn func()) string {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout, os.Stderr = w, w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	_ = w.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	return <-done
}

// Under the contextual score the artifacts are written before the report,
// so their notices print above it and the score block stays the last
// lines of the run.
func TestContinueRunV4ClosesOnTheScoreWithArtifacts(t *testing.T) {
	gh, result, conf, s := v4OutputFixture(t)
	defer func(pp bool, pf, of string, po bool) {
		pushScore, platformURL, outputFile, printOutput = pp, pf, of, po
	}(pushScore, platformURL, outputFile, printOutput)
	pushScore, platformURL, printOutput = false, "", true
	outputFile = filepath.Join(t.TempDir(), "out.json")
	scorePublishOnce = sync.Once{}
	out := captureOutputInOrder(t, func() { _ = continueRun(gh, nil, conf, result, s, nil, nil) })
	written, final := strings.Index(out, "Results written to: "), strings.Index(out, "\nScore\n")
	if written < 0 || final < 0 || written > final {
		t.Fatalf("want the artifact notice above the final screen:\n%s", out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if last := lines[len(lines)-1]; !strings.Contains(last, "Best fix: ") && !strings.HasPrefix(last, "           ") {
		t.Errorf("the run does not end on the score block, last line %q:\n%s", last, out)
	}
	if _, err := os.Stat(outputFile); err != nil {
		t.Errorf("the JSON report was not written: %v", err)
	}
}

// The previous score keeps its banner as the report's last block.
func TestOutputTextV3KeepsTheBanner(t *testing.T) {
	newGateFlagsCmd(t)
	withScoreProfile(t, "v3")
	gh := &provider.GitHubProvider{}
	conf := configuration.NewDefaultConfiguration()
	conf.PlumberConfig = defaultGitHubPlumberConfig(t)
	result := releaseMutableActionResult()
	s := buildComplianceSummary(gh, result, conf)
	out := captureStdoutAll(t, func() { _ = outputTextWithProvider(gh, result, conf, s, nil, nil) })
	if !strings.Contains(out, "/ 100 pts") || strings.Contains(out, "Situation") || strings.Contains(out, "Attack paths") {
		t.Errorf("the previous score's report changed:\n%s", out)
	}
}

// With colour on, the "Worst case:" label is in the Critical red and the
// "Best fix:" label in the brand green, the rest of their lines plain;
// with colour off, no escape code at all.
func TestFinalScreenColoursTheWorstCaseAndBestFixLabels(t *testing.T) {
	r := paletteFor(colorTrue)
	red := r.NewStyle().Foreground(colCritical).Render("Worst case:")
	green := r.NewStyle().Foreground(colAccent).Render("Best fix:")
	var out bytes.Buffer
	renderFinalScreen(&out, finalScreenScore(), termCaps{Color: colorTrue}, false, finalNotes{Status: &gateStatus{Gate: "100 pts"}})
	got := out.String()
	if !strings.Contains(red, "\x1b[") || !strings.Contains(green, "\x1b[") {
		t.Fatalf("the palette printed no colour: %q %q", red, green)
	}
	worst := red + " if this image is compromised, an attacker can read 7 secrets of the\n"
	fix := green + " pin the image by digest (image docker.io/alpine:latest), +15 pts, 70 / 100 (C)\n"
	if !strings.Contains(got, worst) || !strings.Contains(got, fix) {
		t.Errorf("want %q and %q in:\n%q", worst, fix, got)
	}
	if !strings.Contains(got, "\x1b[0m  repository (attack path 1: docker.io/alpine:latest)\n") {
		t.Errorf("the wrapped worst case carries colour:\n%q", got)
	}
	out.Reset()
	renderFinalScreen(&out, finalScreenScore(), termCaps{Color: colorOff}, false, finalNotes{Status: &gateStatus{Gate: "100 pts"}})
	if strings.Contains(out.String(), "\x1b") || !strings.Contains(out.String(), "  Worst case: if") || !strings.Contains(out.String(), "  Best fix: pin") {
		t.Errorf("colour off:\n%q", out.String())
	}
}
