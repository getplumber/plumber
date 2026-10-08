package cmd

import (
	"cmp"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/charmbracelet/lipgloss"

	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// fmtPoints is a point figure at one decimal, without a trailing ".0".
func fmtPoints(p float64) string {
	return strconv.FormatFloat(math.Round(p*10)/10, 'f', -1, 64)
}

const (
	// defaultReportWidth is the width the report fits when the output is
	// not a terminal or the terminal does not say.
	defaultReportWidth = 100
	// minReportWidth is the narrowest width the report fits.
	minReportWidth = 60
)

// reportWidth is the width the contextual report fits: the terminal's,
// defaultReportWidth when unknown, never below minReportWidth.
func reportWidth(caps termCaps) int {
	if caps.Width <= 0 {
		return defaultReportWidth
	}
	return max(caps.Width, minReportWidth)
}

// cells is the width of s on screen, escape sequences left out.
func cells(s string) int {
	return lipgloss.Width(s)
}

// shortenMiddle cuts s to n cells by replacing its middle with "...", so
// both the start and the end of a name stay readable.
func shortenMiddle(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 3 {
		return string(r[:max(n, 0)])
	}
	keep := n - 3
	head := (keep + 1) / 2
	return string(r[:head]) + "..." + string(r[len(r)-(keep-head):])
}

// glue is a space wrapCells never breaks at, printed as a space.
const glue = " "

// wrapCells breaks s into lines of at most width cells at spaces (never
// at glue); a word wider than a line is shortened in the middle.
func wrapCells(s string, width int) []string {
	return wrapCellsWith(s, width, shortenMiddle)
}

// wrapCellsWith is wrapCells shortening a word too wide for a line with
// shorten.
func wrapCellsWith(s string, width int, shorten func(string, int) string) []string {
	lines := wrapWords(s, width, shorten)
	for i := range lines {
		lines[i] = strings.ReplaceAll(lines[i], glue, " ")
	}
	return lines
}

func wrapWords(s string, width int, shorten func(string, int) string) []string {
	var lines []string
	line := ""
	for _, w := range strings.FieldsFunc(s, func(r rune) bool { return r == ' ' }) {
		w = shorten(w, width)
		switch {
		case line == "":
			line = w
		case cells(line)+1+cells(w) <= width:
			line += " " + w
		default:
			lines = append(lines, line)
			line = w
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// pathBlockOptions says what a path block prints after its graph: its
// findings, a documentation line under the first finding of each code,
// and the line pointing to `plumber explain -a` for them.
type pathBlockOptions struct {
	Findings bool
	Docs     bool
	Hint     bool
	// ScorePoint prints the cap Note (control.PathBlock.ShowCap), how the
	// path's points were computed, as --score-point asks.
	ScorePoint bool
	// Details, when set, replaces the one line per code of the Findings
	// list by every finding in full (detailedFindingLines), one group per
	// line of the block's list: what `explain -a` prints.
	Details []findingCodeGroup
}

var (
	// reportBlock is a block in the report: the graph, then the details
	// line.
	reportBlock = pathBlockOptions{Hint: true}
	// explainBlock is a block under `plumber explain -a`: the graph, then
	// the findings, each code with its documentation.
	explainBlock = pathBlockOptions{Findings: true, Docs: true}
	// platformBlock is a block of a policy section in platform mode, which
	// the run cache does not hold: the graph and the findings.
	platformBlock = pathBlockOptions{Findings: true}
)

// blockIndent is where the labelled lines of a path block start.
const blockIndent = "       "

// findingIndent is where a finding's code starts in the Findings list,
// findingUnder where the lines under its code start.
const (
	findingIndent = blockIndent + "  "
	findingUnder  = findingIndent + "          "
)

// renderPathBlock prints one attack path as its graph
// (control.ReportPathGraph), then what opts asks for, fitting the report
// width. Every value is read off the workflow and goes through
// sanitizeTerminal first; with colour on, the tier badge is the coloured
// one, the labels (Entry, So, Note, Fix) are bold, and the documentation
// lines and the whole details line are dim.
func renderPathBlock(out io.Writer, n int, b control.PathBlock, caps termCaps, opts pathBlockOptions) {
	width := reportWidth(caps)
	b = b.Clean(sanitizeTerminal)
	b.ShowCap = opts.ScorePoint
	lines := control.ReportPathGraph(n, b, width)
	if caps.Color != colorOff {
		lines[0] = pathTierTag(b.Tier) + strings.TrimPrefix(lines[0], control.PathTierBadge(b.Tier))
		for i, l := range lines {
			lines[i] = boldLabel(l)
		}
	}
	// pad is indent before a line of s: a URL or a command never wraps,
	// the indent gives way first.
	pad := func(indent, s string) string {
		return indent[:max(0, min(len(indent), width-cells(s)))]
	}
	switch {
	case opts.Findings && len(opts.Details) > 0:
		lines = append(lines, detailedFindingLines(opts.Details, width, caps)...)
	case opts.Findings:
		lines = append(lines, findingLines(b.Findings, width, caps, opts.Docs, pad)...)
	}
	if opts.Hint {
		// The whole line is dim, the command in backticks no bolder than
		// the rest.
		hint := fmt.Sprintf("↳ details: run `plumber explain -a %d`", n)
		lines = append(lines, pad(blockIndent, hint)+colorIf(caps, colorDim)+hint+colorIf(caps, colorReset))
	}
	// Errors discarded: out is the terminal or a test buffer.
	for _, l := range lines {
		_, _ = fmt.Fprintln(out, l)
	}
	_, _ = fmt.Fprintln(out)
}

// boldLabel is a graph line with the label it opens on (control.BlockLabels,
// in the column under the badge) in bold, the padding after it and the
// value unchanged, so the columns hold as with colour off; any other line
// comes back as it is.
func boldLabel(line string) string {
	rest, ok := strings.CutPrefix(line, blockIndent)
	if !ok {
		return line
	}
	for _, label := range control.BlockLabels {
		if after, ok := strings.CutPrefix(rest, label+" "); ok {
			return blockIndent + colorBold + label + colorReset + " " + after
		}
	}
	return line
}

// findingLines is the Findings list of a block (control.PathGraphFindings)
// with, when docs is set, the documentation line of a code as the last
// line of its first finding, aligned with the lines under the code and
// dim with colour on.
func findingLines(findings []control.PathBlockFinding, width int, caps termCaps, docs bool, pad func(indent, s string) string) []string {
	list := control.PathGraphFindings(findings, width)
	if !docs || len(list) == 0 {
		return list
	}
	out := []string{list[0]}
	seen := map[control.ErrorCode]bool{}
	k := -1
	closeFinding := func() {
		if k < 0 || k >= len(findings) || seen[findings[k].Code] {
			return
		}
		seen[findings[k].Code] = true
		s := "↳ docs: https://getplumber.io/docs/cli/issues/" + string(findings[k].Code)
		out = append(out, pad(findingUnder, s)+colorIf(caps, colorDim)+s+colorIf(caps, colorReset))
	}
	for _, l := range list[1:] {
		// A finding opens on the line carrying its code; the lines under it
		// start further right.
		if len(l) > len(findingIndent) && strings.HasPrefix(l, findingIndent) && l[len(findingIndent)] != ' ' {
			closeFinding()
			k++
		}
		out = append(out, l)
	}
	closeFinding()
	return out
}

// detailedFindingLines is the Findings list of `plumber explain -a`: one
// group per line of the block's list, a blank line before each, each laid
// out as an individual finding's block (codeGroupLines) indented under the
// label.
func detailedFindingLines(groups []findingCodeGroup, width int, caps termCaps) []string {
	out := []string{blockIndent + "Findings"}
	for _, g := range groups {
		out = append(out, "")
		out = append(out, codeGroupLines(g, findingIndent, width, caps)...)
	}
	return out
}

// findingCodeGroup is the findings of one issue code as a block lays them
// out: its title, its fix when the block prints one, and every finding.
type findingCodeGroup struct {
	Code     control.ErrorCode
	Title    string
	Fix      string
	Findings []detailedFinding
}

// consequenceDash is the dash a policy message sets what it found apart
// from what it means with; never printed.
const consequenceDash = " \u2014 "

// jobLead is the job reference a policy message opens on, quoted or in a
// code span (`job "x" `, "Job `x` ").
var jobLead = regexp.MustCompile("^[Jj]ob (?:\"([^\"]*)\"|`([^`]*)`) ")

// findingBranch is what a finding's branch says and what it means: the
// message up to its consequence, opened on where it runs (the job phrase
// the path graph uses, in place of the job reference the message opens
// on, unless the message already names the job), and the consequence
// after the dash, empty when the message has none. No dash is left in
// either.
func findingBranch(f detailedFinding) (what, so string) {
	what, so, _ = strings.Cut(sanitizeTerminal(f.Message), consequenceDash)
	job := f.Job
	if m := jobLead.FindStringSubmatch(what); m != nil {
		what = what[len(m[0]):]
		if job == "" {
			job = m[1] + m[2]
		}
		what = control.JobPhraseOf(job, f.File) + ": " + what
	} else if job != "" && !strings.Contains(what, job) {
		what = control.JobPhraseOf(job, f.File) + ": " + what
	}
	if f.Dismissed {
		what += " [dismissed on the platform]"
	}
	return noDash(what), noDash(so)
}

// noDash is s with the dash a policy message may carry replaced.
func noDash(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, consequenceDash, ", "), "\u2014", "-")
}

// groupSeverity is the most serious contextual severity of the group's
// findings, the registry's for a finding without one.
func groupSeverity(g findingCodeGroup) control.IssueSeverity {
	rank := map[control.IssueSeverity]int{control.SeverityLow: 1, control.SeverityMedium: 2, control.SeverityHigh: 3, control.SeverityCritical: 4}
	worst := control.SeverityLow
	for _, f := range g.Findings {
		sev := control.IssueSeverity(f.ContextualSeverity)
		if rank[sev] == 0 {
			sev = control.SeverityForCode(f.Code)
		}
		if rank[sev] > rank[worst] {
			worst = sev
		}
	}
	return worst
}

// codeGroupLines lays one code's findings out at indent, fitting width:
// the severity badge, the code, the title and how many findings; one
// branch per finding, saying where it runs and what it found, its
// location (and its consequence, when the findings do not share one)
// under it; then the shared consequence (So), the fix (Fix) and the
// documentation line. With colour on, the badge is the coloured one, the
// labels are bold and the lines starting with an arrow are dim.
func codeGroupLines(g findingCodeGroup, indent string, width int, caps termCaps) []string {
	sev := groupSeverity(g)
	badge := control.PathTierBadge(control.PathTier(sev))
	if caps.Color != colorOff {
		badge = pathTierTag(control.PathTier(sev))
	}
	keep := func(w string, _ int) string { return w }
	dim := func(s string) string { return colorIf(caps, colorDim) + s + colorIf(caps, colorReset) }

	live, dismissed := 0, 0
	for _, f := range g.Findings {
		if f.Dismissed {
			dismissed++
			continue
		}
		live++
	}
	var count []string
	if live > 1 || live == 1 && dismissed > 0 {
		count = append(count, plural(live, "finding", "findings"))
	}
	if dismissed > 0 {
		count = append(count, fmt.Sprintf("%d dismissed", dismissed))
	}
	title := strings.TrimSpace(sanitizeTerminal(g.Title) + " ")
	if len(count) > 0 {
		title = strings.TrimSpace(title + " (" + strings.Join(count, ", ") + ")")
	}
	head := string(g.Code) + "  "
	lead := cells(control.PathTierBadge(control.TierLow)) + 1 + cells(head)
	var out []string
	for k, l := range wrapCellsWith(title, max(width-cells(indent)-lead, minGraphText), keep) {
		if k == 0 {
			out = append(out, indent+badge+" "+head+l)
			continue
		}
		out = append(out, indent+strings.Repeat(" ", lead)+l)
	}
	if len(out) == 0 {
		out = append(out, strings.TrimRight(indent+badge+" "+string(g.Code), " "))
	}

	pad := indent + strings.Repeat(" ", len(blockIndent))
	type branch struct{ what, so string }
	branches := make([]branch, 0, len(g.Findings))
	shared := ""
	for i, f := range g.Findings {
		what, so := findingBranch(f)
		branches = append(branches, branch{what, so})
		switch {
		case i == 0:
			shared = so
		case so != shared:
			shared = ""
		}
	}
	room := max(width-cells(pad)-5, minGraphText)
	out = append(out, pad+"│")
	for i, f := range g.Findings {
		fork, stem := "├──▶ ", "│    "
		if i == len(g.Findings)-1 {
			fork, stem = "└──▶ ", "     "
		}
		for k, l := range wrapCellsWith(branches[i].what, room, keep) {
			if k == 0 {
				out = append(out, pad+fork+l)
				continue
			}
			out = append(out, pad+stem+l)
		}
		for _, d := range f.DetailLines {
			for k, l := range wrapCellsWith("- "+sanitizeTerminal(d), room, keep) {
				if k > 0 {
					l = "  " + l
				}
				out = append(out, pad+stem+l)
			}
		}
		if so := branches[i].so; so != "" && shared == "" {
			for k, l := range wrapCellsWith("so "+so, room, keep) {
				if k > 0 {
					l = "   " + l
				}
				out = append(out, pad+stem+l)
			}
		}
		if f.Location != "" {
			out = append(out, pad+stem+dim("↳ at "+sanitizeTerminal(f.Location)))
		}
	}
	out = append(out, "")
	valueWidth := max(width-cells(pad)-7, minGraphText)
	labelled := func(label, value string) {
		for k, l := range wrapCellsWith(value, valueWidth, keep) {
			if k == 0 {
				out = append(out, pad+colorIf(caps, colorBold)+label+colorIf(caps, colorReset)+strings.Repeat(" ", 7-len(label))+l)
				continue
			}
			out = append(out, pad+strings.Repeat(" ", 7)+l)
		}
	}
	labelled("So", shared)
	labelled("Fix", sanitizeTerminal(g.Fix))
	out = append(out, pad+dim("↳ docs: "+g.Code.DocURL()))
	return out
}

// codeFix is the fix of a code read on its own: its entry in the fix
// table the best fix reads, else the first sentence of its remediation.
func codeFix(code control.ErrorCode) string {
	if do, ok := control.FindingFixFor(code); ok {
		return do
	}
	if info := control.LookupCode(code); info != nil {
		return remediationFix(info.Remediation)
	}
	return ""
}

// remediationFix is the first sentence of a remediation as something to
// do: up to its first period that ends a sentence (one a space or the end
// follows), its first letter lower-cased.
func remediationFix(remediation string) string {
	s := strings.TrimSpace(remediation)
	if i := strings.Index(s, ". "); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	r := []rune(s)
	if len(r) > 0 {
		r[0] = unicode.ToLower(r[0])
	}
	return string(r)
}

// minGraphText is the narrowest a finding's message wraps to.
const minGraphText = 20

// fprintPathRule prints the lighter rule between two path blocks.
func fprintPathRule(out io.Writer, caps termCaps) {
	_, _ = fmt.Fprintf(out, "  "+fmtColored+"\n", colorIf(caps, colorDim), strings.Repeat("┄", 20), colorIf(caps, colorReset))
}

// fprintStatusSectionHeader is printStatusSectionHeader on out.
func fprintStatusSectionHeader(out io.Writer, name, glyph, color string) {
	line := strings.Repeat("─", 20)
	_, _ = fmt.Fprintf(out, fmtColored, colorDim, line, colorReset)
	_, _ = fmt.Fprintf(out, "%s%s%s %s%s%s\n", color, glyph, colorReset, colorBold+color, name, colorReset)
	_, _ = fmt.Fprintf(out, fmtColored, colorDim, line, colorReset)
}

// renderPathBlocks prints the attack path details under their section
// heading, every path least severe first, numbered worst first, so the
// worst path, path 1, sits closest to the score below, a lighter rule
// between two blocks, the last block closing the section. No path, no
// heading.
func renderPathBlocks(out io.Writer, paths []control.AttackPath, findings []opaengine.Finding, caps termCaps, opts pathBlockOptions) {
	if len(paths) == 0 {
		return
	}
	fprintStatusSectionHeader(out, fmt.Sprintf("Attack paths (%d)", len(paths)), "✗", colorRed)
	_, _ = fmt.Fprintln(out)
	ordered := control.PathsWorstFirst(paths)
	for i := len(ordered) - 1; i >= 0; i-- {
		renderPathBlock(out, i+1, control.NewPathBlock(ordered[i], findings), caps, opts)
		if i > 0 {
			fprintPathRule(out, caps)
		}
	}
}

// plainBar is the score bar without colour: filled then empty cells.
func plainBar(points float64, width int) string {
	filled := min(max(int(points/100*float64(width)), 0), width)
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

// gateStatus is the run's verdict against its gate: whether it passed,
// and what the gate required ("100 pts required").
type gateStatus struct {
	Passed   bool
	Required string
}

// gateStatus reads the verdict the exit code follows (gateErr) and says
// what the active gate required, in gateErr's own precedence.
func (s complianceSummary) gateStatus() gateStatus {
	st := gateStatus{Passed: s.passed()}
	switch {
	case s.thresholdSet:
		st.Required = fmt.Sprintf("%.1f%% of controls passing, %.0f%% required", s.compliance, s.threshold)
	case s.controlCount == 0 || s.score == nil:
		st.Required = "no control was evaluated"
	default:
		var req []string
		if s.pointsGateActive() {
			req = append(req, fmt.Sprintf("%.0f pts", s.minPoints))
		}
		if s.minScore != "" {
			req = append(req, s.minScore+" or better")
		}
		st.Required = strings.Join(req, " and ") + " required"
	}
	return st
}

// finalNotes is what the final screen says beyond the score: the verdict
// against the gate when the run shows one, and how many controls could
// not be evaluated.
type finalNotes struct {
	Status       *gateStatus
	NotEvaluated int
}

// renderFinalScreen closes the contextual score's report, the part a user
// sees first: the Score heading, then the score block as the last lines.
// The attack paths and the individual findings are not repeated: their
// counts head their own sections above. Under scorePoint the figures add
// up by hand: the score block's arithmetic (see renderScoreBlock), then
// each code's loss and each tier's under it. Nothing runs past the report
// width.
func renderFinalScreen(out io.Writer, score *control.PlumberScoreResult, caps termCaps, scorePoint bool, notes finalNotes) {
	width := reportWidth(caps)
	pathsLoss, otherLoss := control.BucketLosses(score)

	// Errors discarded: out is the terminal or a test buffer.
	rule := strings.Repeat("─", 20)
	_, _ = fmt.Fprintf(out, fmtColored, colorIf(caps, colorDim), rule, colorIf(caps, colorReset))
	_, _ = fmt.Fprintf(out, fmtColored, colorIf(caps, colorBold), "Score", colorIf(caps, colorReset))
	_, _ = fmt.Fprintf(out, fmtColored, colorIf(caps, colorDim), rule, colorIf(caps, colorReset))
	renderScoreBlock(out, score, caps, notes, width, scorePoint, pathsLoss, otherLoss)
	if !scorePoint || len(score.CodeLosses)+len(score.PathLosses) == 0 {
		return
	}
	pad := strings.Repeat(" ", scoreTextIndent)
	_, _ = fmt.Fprintln(out)
	for _, cl := range score.CodeLosses {
		_, _ = fmt.Fprintf(out, "%s%-10s %-8s x%-3d -%s\n", pad, cl.Code, cl.Severity, cl.Count, fmtPoints(cl.CappedLoss))
	}
	for _, pl := range score.PathLosses {
		_, _ = fmt.Fprintf(out, "%s%-19s x%-3d -%s\n", pad, string(pl.Tier)+" paths", pl.Count, fmtPoints(pl.CappedLoss))
	}
}

// scoreTextIndent is where the score block's text starts: after the
// letter's eight columns, a space before and two after.
const scoreTextIndent = 11

// colorIf is a raw sequence when the report prints in colour, "" when not.
func colorIf(caps termCaps, seq string) string {
	if caps.Color == colorOff {
		return ""
	}
	return seq
}

// renderScoreBlock prints the block letter beside the score, the bar, the
// verdict, the controls that could not be evaluated, the worst case (what
// attack path 1 means, when there is a path) and the best fix.
// Under scorePoint it adds the arithmetic: the subtraction, the caps that
// kept less than the prices add up to and the adjustment line under the
// bar, and why the best fix recovers what it does under it. A blank line
// sets the verdict apart from what is above it, and another the best fix,
// so the letter's six lines carry the score, the bar, the verdict and the
// best fix. Lines past the letter's six continue under the text column; a
// line of the letter with no text beside it prints alone.
func renderScoreBlock(out io.Writer, score *control.PlumberScoreResult, caps termCaps, notes finalNotes, width int, scorePoint bool, pathsLoss, otherLoss float64) {
	bar := plainBar(score.FinalPoints, 28)
	if caps.Color != colorOff {
		bar = scoreBar(score.FinalPoints, 28)
	}
	textWidth := width - scoreTextIndent
	right := []string{fmt.Sprintf("Plumber Score  %s / 100", fmtPoints(score.FinalPoints)), bar}
	wrap := func(s string) { right = append(right, wrapCells(s, textWidth)...) }
	if scorePoint {
		wrap(fmt.Sprintf("100 - %s (attack paths) - %s (individual findings)", fmtPoints(pathsLoss), fmtPoints(otherLoss)))
		for _, note := range control.CapNotes(score) {
			wrap(note)
		}
		if line := control.ScoreAdjustment(score); line != "" {
			wrap(line)
		}
	}
	if notes.Status != nil || notes.NotEvaluated > 0 {
		right = append(right, "")
	}
	if st := notes.Status; st != nil {
		word, color := "FAILED", colorRed
		if st.Passed {
			word, color = "PASSED", colorGreen
		}
		right = append(right, fmt.Sprintf("Status: %s%s%s, %s", colorIf(caps, colorBold+color), word, colorIf(caps, colorReset), st.Required))
	}
	if n := notes.NotEvaluated; n > 0 {
		wrap(fmt.Sprintf("%s could not be evaluated: the score covers the others.", plural(n, "control", "controls")))
	}
	// "+13 pts" and "78 / 100 (B)" never break across lines.
	fix := sanitizeTerminal(control.BestFixSummary(score))
	if i := strings.LastIndex(fix, ", +"); i >= 0 {
		gain, result, _ := strings.Cut(fix[i+2:], ", ")
		fix = fix[:i+2] + strings.ReplaceAll(gain, " ", glue) + ", " + strings.ReplaceAll(result, " ", glue)
	}
	// A fix that does not move the score yet is the fix alone; under
	// scorePoint it says why on the next line.
	var why string
	if score.BestFix != nil && score.BestFix.Stays != "" {
		fix, why = strings.TrimSuffix(fix, " "+score.BestFix.Stays), score.BestFix.Stays
	}
	right = append(right, "")
	if worst := control.WorstCase(score.Paths); worst != "" {
		wrap("Worst case: " + sanitizeTerminal(worst))
	}
	wrap("Best fix: " + fix)
	if scorePoint {
		if score.BestFix != nil && score.BestFix.Reason != "" {
			wrap(score.BestFix.Reason)
		}
		if why != "" {
			wrap(why)
		}
	}
	letter := renderScoreLetter(score.Score, caps.Color)
	_, _ = fmt.Fprintln(out)
	for i := range max(len(right), len(letter)) {
		l, r := "        ", ""
		if i < len(letter) {
			l = letter[i]
		}
		if i < len(right) {
			r = right[i]
		}
		_, _ = fmt.Fprintln(out, trimRightStyled(fmt.Sprintf(" %s  %s", l, r)))
	}
}

// trimRightStyled is s without its trailing spaces, those inside the colour
// sequences that close it included: a line of the letter with nothing
// beside it ends on the letter.
func trimRightStyled(s string) string {
	tail := ""
	for {
		s = strings.TrimRight(s, " ")
		i := strings.LastIndex(s, "\x1b[")
		if i < 0 || !strings.HasSuffix(s, "m") || strings.Trim(s[i+2:len(s)-1], "0123456789;") != "" {
			return s + tail
		}
		s, tail = s[:i], s[i:]+tail
	}
}

// plural is n and the noun for n ("1 control", "2 controls").
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// renderIndividualFindings prints the findings no path told the story of,
// one block per issue code (codeGroupLines), the least severe first and
// the worst last, closest to the attack paths, by code within a severity,
// a lighter rule between two blocks. The heading counts distinct
// findings, the count the summary prints (distinct, the score's other
// findings), or the live findings listed when the score has none
// (distinct below 0).
func renderIndividualFindings(out io.Writer, groups []findingGroup, distinct int, caps termCaps) {
	byCode := map[control.ErrorCode]*findingCodeGroup{}
	var blocks []*findingCodeGroup
	n := 0
	for _, g := range groups {
		for _, f := range g.Findings {
			if !f.Dismissed {
				n++
			}
			b := byCode[f.Code]
			if b == nil {
				b = &findingCodeGroup{Code: f.Code, Fix: codeFix(f.Code)}
				byCode[f.Code] = b
				blocks = append(blocks, b)
			}
			b.Findings = append(b.Findings, f)
		}
	}
	if len(blocks) == 0 {
		return
	}
	rank := map[control.IssueSeverity]int{control.SeverityLow: 1, control.SeverityMedium: 2, control.SeverityHigh: 3, control.SeverityCritical: 4}
	slices.SortStableFunc(blocks, func(a, b *findingCodeGroup) int {
		if c := cmp.Compare(rank[groupSeverity(*a)], rank[groupSeverity(*b)]); c != 0 {
			return c
		}
		return cmp.Compare(a.Code, b.Code)
	})
	if distinct >= 0 {
		n = distinct
	}
	width := reportWidth(caps)
	fprintStatusSectionHeader(out, fmt.Sprintf("Individual findings (%d)", n), "✗", colorRed)
	_, _ = fmt.Fprintln(out)
	for i, b := range blocks {
		b.Title = codeTitle(*b)
		for _, l := range codeGroupLines(*b, "", width, caps) {
			_, _ = fmt.Fprintln(out, l)
		}
		_, _ = fmt.Fprintln(out)
		if i < len(blocks)-1 {
			fprintPathRule(out, caps)
		}
	}
}

// codeTitle is the registry title of the group's code, the one its
// provider reads (a GitHub workflow file says GitHub); the code alone
// when the registry has none.
func codeTitle(g findingCodeGroup) string {
	info := control.LookupCode(g.Code)
	if info == nil {
		return ""
	}
	provider := "gitlab"
	if slices.ContainsFunc(g.Findings, func(f detailedFinding) bool { return strings.Contains(f.File, ".github/") }) {
		provider = "github"
	}
	return info.TitleFor(provider)
}
