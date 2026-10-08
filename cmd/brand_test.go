package cmd

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// fakeEnv is a terminal environment for termenv, so the colour decision
// can be read for any set of variables without touching the process's.
type fakeEnv map[string]string

func (e fakeEnv) Environ() []string {
	var out []string
	for k, v := range e {
		out = append(out, k+"="+v)
	}
	return out
}

func (e fakeEnv) Getenv(k string) string { return e[k] }

// The report takes lipgloss's own reading of the output: no colour off a
// terminal or under NO_COLOR, 24-bit colour when the terminal says so,
// basic colour otherwise.
func TestColorLevelFollowsTheRenderer(t *testing.T) {
	cases := []struct {
		name string
		tty  bool
		env  fakeEnv
		want colorLevel
	}{
		{"not a terminal", false, fakeEnv{"TERM": "xterm-256color", "COLORTERM": "truecolor"}, colorOff},
		{"NO_COLOR", true, fakeEnv{"TERM": "xterm-256color", "COLORTERM": "truecolor", "NO_COLOR": "1"}, colorOff},
		{"truecolor", true, fakeEnv{"TERM": "xterm-256color", "COLORTERM": "truecolor"}, colorTrue},
		{"24bit", true, fakeEnv{"TERM": "xterm", "COLORTERM": "24bit"}, colorTrue},
		{"256 colours", true, fakeEnv{"TERM": "xterm-256color"}, colorBasic},
		{"16 colours", true, fakeEnv{"TERM": "xterm"}, colorBasic},
		{"dumb terminal", true, fakeEnv{"TERM": "dumb"}, colorOff},
	}
	for _, tc := range cases {
		r := lipgloss.NewRenderer(&bytes.Buffer{}, termenv.WithTTY(tc.tty), termenv.WithEnvironment(tc.env))
		if got := termCapsOf(r.ColorProfile(), 80); got.Color != tc.want || got.Width != 80 {
			t.Errorf("%s: %+v, want colour %d", tc.name, got, tc.want)
		}
	}
}

// detectTermCaps reads the default renderer, the one every lipgloss style
// of the report prints through.
func TestDetectTermCapsReadsTheDefaultRenderer(t *testing.T) {
	old := lipgloss.ColorProfile()
	t.Cleanup(func() { lipgloss.SetColorProfile(old) })
	for profile, want := range map[termenv.Profile]colorLevel{termenv.Ascii: colorOff, termenv.ANSI: colorBasic, termenv.TrueColor: colorTrue} {
		lipgloss.SetColorProfile(profile)
		if got := detectTermCaps().Color; got != want {
			t.Errorf("profile %d: colour %d, want %d", profile, got, want)
		}
	}
}

// The banner, plain: the wordmark alone, 63 columns with the indent.
func TestBannerPlain(t *testing.T) {
	want := []string{
		"  ██████╗ ██╗     ██╗   ██╗ ███╗   ███╗██████╗ ███████╗██████╗",
		"  ██╔══██╗██║     ██║   ██║ ████╗ ████║██╔══██╗██╔════╝██╔══██╗",
		"  ██████╔╝██║     ██║   ██║ ██╔████╔██║██████╔╝█████╗  ██████╔╝",
		"  ██╔═══╝ ██║     ██║   ██║ ██║╚██╔╝██║██╔══██╗██╔══╝  ██╔══██╗",
		"  ██║     ███████╗╚██████╔╝ ██║ ╚═╝ ██║██████╔╝███████╗██║  ██║",
		"  ╚═╝     ╚══════╝ ╚═════╝  ╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝",
	}
	got := renderBanner(termCaps{Color: colorOff})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("banner:\n%s", strings.Join(got, "\n"))
	}
	if got := renderBanner(termCaps{Color: colorOff, Width: 63}); !reflect.DeepEqual(got, want) {
		t.Errorf("a terminal exactly as wide as the banner gets all of it:\n%s", strings.Join(got, "\n"))
	}
}

// Narrower than the wordmark: the plain bold word.
func TestBannerNarrowTerminal(t *testing.T) {
	want := []string{"  PLUMBER"}
	for _, width := range []int{62, 40, 9} {
		if got := renderBanner(termCaps{Color: colorOff, Width: width}); !reflect.DeepEqual(got, want) {
			t.Errorf("%d columns:\n%s", width, strings.Join(got, "\n"))
		}
	}
	if got := renderBanner(termCaps{Color: colorBasic, Width: 40}); !reflect.DeepEqual(got, []string{"  \x1b[1mPLUMBER\x1b[0m"}) {
		t.Errorf("the narrow name is not bold: %q", got)
	}
}

// In colour, the wordmark is bold green; without truecolor, no 24-bit
// sequence.
func TestBannerColors(t *testing.T) {
	for i, l := range renderBanner(termCaps{Color: colorTrue}) {
		if !strings.Contains(l, "1;38;2;91;201;118") {
			t.Errorf("row %d: the wordmark is not bold green: %q", i, l)
		}
	}
	joined := strings.Join(renderBanner(termCaps{Color: colorBasic}), "\n")
	if strings.Contains(joined, "38;2") || !strings.Contains(joined, "\x1b[") {
		t.Errorf("basic banner: %q", joined)
	}
}

func TestBannerOffHasNoEscape(t *testing.T) {
	for _, width := range []int{0, 79, 40, 20} {
		if joined := strings.Join(renderBanner(termCaps{Color: colorOff, Width: width}), ""); strings.Contains(joined, "\x1b") {
			t.Errorf("escape in a colourless banner %d wide: %q", width, joined)
		}
	}
}

// The score letters in the wordmark's block letters, 6 lines of 8 columns.
func TestScoreLetterBlockArt(t *testing.T) {
	want := map[string][]string{
		"A": {" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"},
		"B": {"██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██████╔╝", "╚═════╝ "},
		"C": {" ██████╗", "██╔════╝", "██║     ", "██║     ", "╚██████╗", " ╚═════╝"},
		"D": {"██████╗ ", "██╔══██╗", "██║  ██║", "██║  ██║", "██████╔╝", "╚═════╝ "},
		"E": {"███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"},
	}
	for letter, lines := range want {
		if got := renderScoreLetter(letter, colorOff); !reflect.DeepEqual(got, lines) {
			t.Errorf("%s = %q", letter, got)
		}
	}
	if got, e := renderScoreLetter("Z", colorOff), renderScoreLetter("E", colorOff); !reflect.DeepEqual(got, e) {
		t.Errorf("an unknown letter draws E: %q", got)
	}
	if got := renderScoreLetter("C", colorTrue); !strings.Contains(got[0], "38;2;242;199;68") {
		t.Errorf("C is not in its colour: %q", got[0])
	}
	if got := strings.Join(renderScoreLetter("C", colorBasic), ""); strings.Contains(got, "38;2") || !strings.Contains(got, "\x1b[") {
		t.Errorf("C without truecolor: %q", got)
	}
}

// The accent is the brand green.
func TestAccentIsTheBrandGreen(t *testing.T) {
	if colAccent != lipgloss.Color("#30D158") {
		t.Errorf("accent %s", colAccent)
	}
}

// With colour off, nothing the report prints carries an escape code: the
// lipgloss styles and the raw sequences follow the same decision.
func TestReportWithoutColorHasNoEscape(t *testing.T) {
	old := lipgloss.ColorProfile()
	t.Cleanup(func() {
		lipgloss.SetColorProfile(old)
		useReportColor(colorBasic)
	})
	lipgloss.SetColorProfile(termenv.Ascii)
	useReportColor(colorOff)

	gh, result, conf, s := v4OutputFixture(t)
	out := captureStdout(t, func() {
		printBanner()
		_ = outputTextWithProvider(gh, result, conf, s, nil, nil)
	})
	if !strings.Contains(out, "Plumber Score") || !strings.Contains(out, "╚═") {
		t.Fatalf("fixture drifted, no report:\n%s", out)
	}
	if i := strings.IndexByte(out, 0x1b); i >= 0 {
		t.Errorf("escape code at byte %d: %q", i, out[max(0, i-40):min(len(out), i+40)])
	}

	withScoreProfile(t, "v3")
	s3 := buildComplianceSummary(gh, result, conf)
	out = captureStdout(t, func() { _ = outputTextWithProvider(gh, result, conf, s3, nil, nil) })
	if i := strings.IndexByte(out, 0x1b); i >= 0 {
		t.Errorf("escape code under the previous score at byte %d: %q", i, out[max(0, i-40):min(len(out), i+40)])
	}

	result.DataCollectionDegraded = true
	out = captureStdout(t, func() { _ = outputTextWithProvider(gh, result, conf, s, nil, nil) })
	if i := strings.IndexByte(out, 0x1b); i >= 0 {
		t.Errorf("escape code on a degraded run at byte %d: %q", i, out[max(0, i-40):min(len(out), i+40)])
	}
}

// The banner closes on the feedback link.
func TestBannerAsksForFeedback(t *testing.T) {
	old := lipgloss.ColorProfile()
	t.Cleanup(func() { lipgloss.SetColorProfile(old) })
	lipgloss.SetColorProfile(termenv.Ascii)
	out := captureStdout(t, printBanner)
	if !strings.Contains(out, "\n  Share your feedback: https://getplumber.io/discord\n") {
		t.Errorf("banner:\n%s", out)
	}
}

// Colour back on, the raw sequences are back.
func TestUseReportColorRestoresTheSequences(t *testing.T) {
	t.Cleanup(func() { useReportColor(colorBasic) })
	useReportColor(colorOff)
	if colorRed != "" || colorReset != "" || colorOrange != "" {
		t.Fatalf("colour off left %q %q %q", colorRed, colorReset, colorOrange)
	}
	useReportColor(colorTrue)
	if colorRed != "\x1b[31m" || colorReset != "\x1b[0m" || colorOrange != "\x1b[38;5;208m" {
		t.Errorf("colour on: %q %q %q", colorRed, colorReset, colorOrange)
	}
}
