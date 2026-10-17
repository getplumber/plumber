package cmd

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
)

// The chain of the reproduction (spec 2026-10-16 section 1): E reached
// through B then D.
const (
	chainE    = "thomasboni/nested-actions-e@main"
	chainB    = "thomasboni/nested-actions-b@main"
	chainD    = "thomasboni/nested-actions-d@main"
	chainText = chainB + " > " + chainD
)

var sgr = regexp.MustCompile("\x1b\\[[0-9;]*m")

func nestedBlock(entry, subject string) control.PathBlock {
	return control.PathBlock{
		Tier: control.TierMedium, Entry: entry, EntrySubject: subject,
		Branches: []control.PathBlockBranch{{Job: "job `nested` from workflow `ci.yml`", Reach: "code execution on the runner"}},
		So:       "if this action is compromised, an attacker can execute code on the runner", Fix: "pin the outermost action",
	}
}

// TestTickChain pins the presentation-time wrap (maintainer, round 11):
// the references after " via " go in backticks, a closing punctuation
// stays outside, a chain already in backticks and a " via " that names no
// reference are left alone.
func TestTickChain(t *testing.T) {
	cases := map[string]string{
		chainE + " via " + chainText + " (mutable action)":             chainE + " via `" + chainText + "` (mutable action)",
		"action x, pulled in via " + chainB + ".":                      "action x, pulled in via `" + chainB + "`.",
		"pin it (mutable action " + chainE + " via " + chainText + ")": "pin it (mutable action " + chainE + " via `" + chainText + "`)",
		"pulled in via `" + chainText + "`":                            "pulled in via `" + chainText + "`",
		"local composite via ./.github/actions/x > " + chainB:          "local composite via `./.github/actions/x > " + chainB + "`",
		"secrets passed via env to the step":                           "secrets passed via env to the step",
		"no chain here":                                                "no chain here",
	}
	for in, want := range cases {
		if got := tickChain(in); got != want {
			t.Errorf("tickChain(%q) = %q, want %q", in, got, want)
		}
	}
}

// (a) colour off: the Entry line of a nested path carries the chain in
// backticks and no escape.
func TestPathBlockEntryChainInBackticksWithColourOff(t *testing.T) {
	b := nestedBlock(chainE+" via "+chainText+" (mutable action of your organization)", chainE)
	var out bytes.Buffer
	renderPathBlock(&out, 2, b, termCaps{Color: colorOff, Width: 200}, reportBlock)
	got := out.String()
	if want := "Entry  " + chainE + " via `" + chainText + "` (mutable action of your organization)"; !strings.Contains(got, want) {
		t.Errorf("want the Entry line %q in:\n%s", want, got)
	}
	if strings.Contains(got, "\x1b") {
		t.Errorf("colour off prints an escape:\n%q", got)
	}
}

// (b) colour on: the chain, backticks included, is in the report's dim
// style, on a single line and when the Entry wraps inside the chain, and
// the visible text is the colour off text.
func TestPathBlockEntryChainIsDimWithColour(t *testing.T) {
	t.Cleanup(func() { useReportColor(colorBasic) })
	useReportColor(colorBasic)
	b := nestedBlock(chainE+" via "+chainText+" (mutable action of your organization)", chainE)
	for _, width := range []int{200, 0} {
		var plain, coloured bytes.Buffer
		renderPathBlock(&plain, 2, b, termCaps{Color: colorOff, Width: width}, reportBlock)
		renderPathBlock(&coloured, 2, b, termCaps{Color: colorBasic, Width: width}, reportBlock)
		if got := sgr.ReplaceAllString(coloured.String(), ""); got != plain.String() {
			t.Errorf("width %d: the visible text moved:\n%s\nwant:\n%s", width, got, plain.String())
		}
		got := coloured.String()
		if width == 200 {
			if want := " via " + colorDim + "`" + chainText + "`" + colorReset + " (mutable"; colorDim == "" || !strings.Contains(got, want) {
				t.Errorf("want the chain dim %q in:\n%q", want, got)
			}
			continue
		}
		// The default width breaks the Entry inside the chain (the e2e
		// rendering): each line's part of the chain is dim on its own.
		if want := " via " + colorDim + "`" + chainB + " >" + colorReset + "\n"; !strings.Contains(got, want) {
			t.Errorf("want the first line's part dim %q in:\n%q", want, got)
		}
		if want := colorDim + chainD + "`" + colorReset + " (mutable"; !strings.Contains(got, want) {
			t.Errorf("want the second line's part dim %q in:\n%q", want, got)
		}
	}
}

// (c) a direct entry gains no backticks.
func TestPathBlockDirectEntryHasNoBackticks(t *testing.T) {
	b := nestedBlock(chainB+" (mutable action of your organization)", chainB)
	var out bytes.Buffer
	renderPathBlock(&out, 3, b, termCaps{Color: colorOff, Width: 200}, reportBlock)
	if want := "Entry  " + chainB + " (mutable action of your organization)\n"; !strings.Contains(out.String(), want) {
		t.Errorf("want the direct Entry line %q in:\n%s", want, out.String())
	}
}

// (d) the finding line of explain and of the Individual findings list
// (codeGroupLines) gets the same treatment, the message itself untouched.
func TestFindingLineChainIsIsolated(t *testing.T) {
	t.Cleanup(func() { useReportColor(colorBasic) })
	useReportColor(colorBasic)
	msg := "action " + chainE + " is pinned to a mutable ref, pulled in via " + chainText + consequenceDash + "pin it by commit SHA"
	g := findingCodeGroup{Code: "ISSUE-701", Title: "Action not pinned", Findings: []detailedFinding{{Code: "ISSUE-701", Message: msg}}}
	plain := strings.Join(codeGroupLines(g, "", 200, termCaps{Color: colorOff}), "\n")
	if want := "pulled in via `" + chainText + "`"; !strings.Contains(plain, want) {
		t.Errorf("want %q in:\n%s", want, plain)
	}
	coloured := strings.Join(codeGroupLines(g, "", 200, termCaps{Color: colorBasic}), "\n")
	if want := "pulled in via " + colorDim + "`" + chainText + "`" + colorReset; !strings.Contains(coloured, want) {
		t.Errorf("want %q in:\n%q", want, coloured)
	}
	if g.Findings[0].Message != msg {
		t.Errorf("the message moved: %q", g.Findings[0].Message)
	}
	var out bytes.Buffer
	renderFindingBlock(&out, g.Findings[0], "", "")
	if want := "pulled in via " + colorDim + "`" + chainText + "`" + colorReset; !strings.Contains(out.String(), want) {
		t.Errorf("per-control listing: want %q in:\n%q", want, out.String())
	}
}

// A finding line wrapped right after "via" (the explain rendering of the
// reproduction) opens the next line on the chain: it is dim there too.
func TestDimChainsOpensOnTheLineAfterVia(t *testing.T) {
	lines := []string{
		"     \u2514\u2500\u2500\u25b6 references action x, pulled in via",
		"     \u2502    `" + chainText + "`",
		"     - pulled in by your step via ci.yml",
	}
	got := dimChains(lines, "<d>", "</d>")
	want := []string{lines[0], "     \u2502    <d>`" + chainText + "`</d>", lines[2]}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}
