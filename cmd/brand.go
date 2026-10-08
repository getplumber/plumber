package cmd

import (
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/term"
)

// colorLevel is how much colour the terminal takes.
type colorLevel int

const (
	colorOff colorLevel = iota
	colorBasic
	colorTrue
)

// termCaps is what the report may assume about where it prints.
type termCaps struct {
	Color colorLevel
	Width int // columns, 0 when unknown
}

// detectTermCaps reads where the report prints: the colour is lipgloss's
// own reading of stdout (none off a terminal or under NO_COLOR, 24-bit
// when the terminal says so), so the art, the raw sequences and every
// style agree; the width is the terminal's, when it reports one.
func detectTermCaps() termCaps {
	width := 0
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
		width = w
	}
	return termCapsOf(lipgloss.ColorProfile(), width)
}

func termCapsOf(profile termenv.Profile, width int) termCaps {
	c := termCaps{Width: width}
	switch profile {
	case termenv.TrueColor:
		c.Color = colorTrue
	case termenv.ANSI256, termenv.ANSI:
		c.Color = colorBasic
	default:
		c.Color = colorOff
	}
	return c
}

// wordmark is PLUMBER in block letters, six rows.
var wordmark = []string{
	"██████╗ ██╗     ██╗   ██╗ ███╗   ███╗██████╗ ███████╗██████╗ ",
	"██╔══██╗██║     ██║   ██║ ████╗ ████║██╔══██╗██╔════╝██╔══██╗",
	"██████╔╝██║     ██║   ██║ ██╔████╔██║██████╔╝█████╗  ██████╔╝",
	"██╔═══╝ ██║     ██║   ██║ ██║╚██╔╝██║██╔══██╗██╔══╝  ██╔══██╗",
	"██║     ███████╗╚██████╔╝ ██║ ╚═╝ ██║██████╔╝███████╗██║  ██║",
	"╚═╝     ╚══════╝ ╚═════╝  ╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝",
}

// paletteFor is a renderer that prints styles at level, whatever stdout
// is, so a caller passing termCaps gets exactly the colour it asked for.
func paletteFor(level colorLevel) *lipgloss.Renderer {
	r := lipgloss.NewRenderer(io.Discard)
	switch level {
	case colorTrue:
		r.SetColorProfile(termenv.TrueColor)
	case colorBasic:
		r.SetColorProfile(termenv.ANSI)
	default:
		r.SetColorProfile(termenv.Ascii)
	}
	return r
}

const (
	bannerIndent = "  "
	// wordmarkWidth is the wordmark's widest row.
	wordmarkWidth = 61
	bannerName    = "PLUMBER"
)

// renderBanner is the start of a run: the wordmark in bold green; on a
// terminal narrower than the wordmark, the plain bold name.
func renderBanner(caps termCaps) []string {
	r := paletteFor(caps.Color)
	if caps.Width > 0 && caps.Width < len(bannerIndent)+wordmarkWidth {
		return []string{bannerIndent + r.NewStyle().Bold(true).Render(bannerName)}
	}
	word := r.NewStyle().Foreground(colPass).Bold(true)
	out := make([]string, len(wordmark))
	for i, l := range wordmark {
		out[i] = bannerIndent + word.Render(strings.TrimRight(l, " "))
	}
	return out
}

// renderScoreLetter is the letter's block-letter art (scoreLetterASCII),
// six lines of 8 columns, in its colour at level; an unknown letter draws
// E.
func renderScoreLetter(letter string, level colorLevel) []string {
	lines, ok := scoreLetterASCII[letter]
	if !ok {
		letter, lines = "E", scoreLetterASCII["E"]
	}
	style := paletteFor(level).NewStyle().Foreground(scoreLetterLipglossColor(letter)).Bold(true)
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = style.Render(l)
	}
	return out
}

// The raw sequences are on until a run reads where it prints
// (runAnalyze).
func init() {
	useReportColor(colorBasic)
}

// useReportColor sets the raw sequences the report prints (colorRed and
// the rest) for level: empty when the report prints without colour, so a
// colourless run carries no escape code.
func useReportColor(level colorLevel) {
	code := func(seq string) string {
		if level == colorOff {
			return ""
		}
		return seq
	}
	colorReset = code("\033[0m")
	colorRed = code("\033[31m")
	colorGreen = code("\033[32m")
	colorYellow = code("\033[33m")
	colorBlue = code("\033[34m")
	colorCyan = code("\033[36m")
	colorGreenBright = code("\033[92m")
	colorOrange = code("\033[38;5;208m")
	colorBold = code("\033[1m")
	colorDim = code("\033[2m")
}
