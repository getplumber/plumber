package cmd

import "github.com/charmbracelet/lipgloss"

// Palette inspired by modern terminal scanners (trivy, semgrep, osc-policy):
// a coherent set of hex colors readable on dark and light backgrounds. The
// semantic styles (title, muted, and so on) compose these colors so they stay
// stable when the palette evolves.

// Palette
var (
	colCritical = lipgloss.Color("#FF4D4F")
	colHigh     = lipgloss.Color("#FF8C42")
	colMedium   = lipgloss.Color("#F2C744")
	colLow      = lipgloss.Color("#4FACF7")
	colPass     = lipgloss.Color("#5BC976")
	colAccent   = lipgloss.Color("#5CCDEF")
	colMuted    = lipgloss.Color("#6C7280")
	colBody     = lipgloss.Color("#D5D8DC")

	// Badge "ink": the foreground used on filled severity badges. These are
	// absolute truecolor values (not the terminal's remappable 16-color
	// ANSI palette), so the badge text stays readable regardless of the
	// user's light/dark theme. See issue #170.
	colInkLight = lipgloss.Color("#FFFFFF") // on saturated/dark badge bg (Critical)
	colInkDark  = lipgloss.Color("#1A1A1A") // on bright badge bg (High)
)

// Semantic styles — prefer these over raw colors to keep call sites
// readable.
var (
	styleTitle  = lipgloss.NewStyle().Foreground(colBody).Bold(true)
	styleAccent = lipgloss.NewStyle().Foreground(colAccent)
	styleMuted  = lipgloss.NewStyle().Foreground(colMuted)
	styleDim    = lipgloss.NewStyle().Faint(true)
	styleError  = lipgloss.NewStyle().Foreground(colCritical)
	styleCell   = lipgloss.NewStyle().Padding(0, 1)
	styleHeader = lipgloss.NewStyle().Foreground(colBody).Bold(true).Padding(0, 1)
	styleRule   = lipgloss.NewStyle().Foreground(colMuted)
	styleFail   = lipgloss.NewStyle().Foreground(colCritical).Bold(true)
)

// hrWidth controls the width of the horizontal separator used by
// section dividers (score banner, etc.).
const hrWidth = 78

// severityColor returns the palette color associated with a severity
// label.
func severityColor(sev string) lipgloss.Color {
	switch sev {
	case "critical":
		return colCritical
	case "high":
		return colHigh
	case "medium":
		return colMedium
	case "low":
		return colLow
	}
	return colMuted
}

// severityIcon returns the emoji icon for a severity label.
func severityIcon(sev string) string {
	switch sev {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🔵"
	}
	return "⚪"
}

// scoreLetterLipglossColor maps a Plumber letter grade (A–E) to the
// palette color used across score banners.
func scoreLetterLipglossColor(letter string) lipgloss.Color {
	switch letter {
	case "A", "B":
		return colPass
	case "C":
		return colMedium
	case "D":
		return colHigh
	}
	return colCritical
}

// Block-letter ASCII art for Plumber letter grades (A–E). Each entry
// is 6 lines tall / 8 columns wide, matching the project's existing
// banner lettering style.
var scoreLetterASCII = map[string][]string{
	"A": {
		" █████╗ ",
		"██╔══██╗",
		"███████║",
		"██╔══██║",
		"██║  ██║",
		"╚═╝  ╚═╝",
	},
	"B": {
		"██████╗ ",
		"██╔══██╗",
		"██████╔╝",
		"██╔══██╗",
		"██████╔╝",
		"╚═════╝ ",
	},
	"C": {
		" ██████╗",
		"██╔════╝",
		"██║     ",
		"██║     ",
		"╚██████╗",
		" ╚═════╝",
	},
	"D": {
		"██████╗ ",
		"██╔══██╗",
		"██║  ██║",
		"██║  ██║",
		"██████╔╝",
		"╚═════╝ ",
	},
	"E": {
		"███████╗",
		"██╔════╝",
		"█████╗  ",
		"██╔══╝  ",
		"███████╗",
		"╚══════╝",
	},
}

// scoreLetterASCIIArt returns the block-letter art for the given
// grade, ready-rendered with its tier color. Unknown letters fall
// back to the E badge.
func scoreLetterASCIIArt(letter string) string {
	lines, ok := scoreLetterASCII[letter]
	if !ok {
		lines = scoreLetterASCII["E"]
	}
	style := lipgloss.NewStyle().Foreground(scoreLetterLipglossColor(letter)).Bold(true)
	joined := ""
	for i, l := range lines {
		if i > 0 {
			joined += "\n"
		}
		joined += l
	}
	return style.Render(joined)
}
