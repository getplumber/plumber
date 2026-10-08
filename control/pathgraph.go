package control

import (
	"fmt"
	"path"
	"slices"
	"strings"
	"unicode"

	"github.com/charmbracelet/lipgloss"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// PathBlockBranch is one branch of a path block: the entry job, the jobs it
// feeds and, beside each (FedVia, in Fed order), what it hands them
// (shownFeedKinds), what an attacker there reaches in a few words (the
// table's phrase), and a marker saying the trigger it runs on or that it
// is unverified, never how the score was computed (a cap that held it).
type PathBlockBranch struct {
	Job    string
	Fed    []string
	FedVia [][]string
	Reach  string
	Marker string // "(on pull_request_target)", "(unverified)", both, or empty
}

// jobFiles is the file each job of the run is in, read off the findings
// that name both, then off the path's own entry fact for its first job.
// A GitHub workflow file also stands for its workflow (the part of a job
// name before the slash, keyed "workflow/"), so a job no finding names
// still reads its workflow's file.
func jobFiles(p AttackPath, findings []opaengine.Finding) map[string]string {
	files := map[string]string{}
	add := func(job, file string) {
		if job == "" || file == "" {
			return
		}
		if files[job] == "" {
			files[job] = file
		}
		if workflow, _, ok := strings.Cut(job, "/"); ok && strings.Contains(file, githubWorkflowDir) && workflowOf(file) == workflow && files[workflow+"/"] == "" {
			files[workflow+"/"] = file
		}
	}
	for _, f := range findings {
		add(f.Job, f.File)
	}
	if len(p.Jobs) > 0 {
		add(p.Jobs[0], p.Entry.File)
	}
	return files
}

// workflowOf is the workflow a GitHub workflow file names its jobs after:
// its base name without the extension.
func workflowOf(file string) string {
	base := path.Base(file)
	return strings.TrimSuffix(strings.TrimSuffix(base, ".yml"), ".yaml")
}

// githubWorkflowDir is the directory every GitHub workflow file is in.
const githubWorkflowDir = ".github/workflows/"

// onGitHub reports whether the jobs are GitHub workflow jobs: a file of
// theirs is a workflow file, or, with no file known, a name carries the
// workflow before a slash, as only a GitHub job name does once collected.
func onGitHub(files map[string]string, jobs []string) bool {
	known := false
	for _, f := range files {
		if strings.Contains(f, githubWorkflowDir) {
			return true
		}
		known = known || f != ""
	}
	return !known && slices.ContainsFunc(jobs, func(j string) bool { return strings.Contains(j, "/") })
}

// jobPhrase says where a job runs, after "runs in": on GitHub the job and
// the workflow file it is in ("job `triage` from workflow `labeler.yml`"),
// the workflow's name when no file of it is known; on GitLab the job
// alone. The names are code spans: a job name is the workflow author's
// text.
func jobPhrase(job string, files map[string]string, github bool) string {
	id, workflow := jobAndWorkflow(job, files, github)
	if workflow == "" {
		return "job " + code(id)
	}
	return "job " + code(id) + " from workflow " + code(workflow)
}

// JobPhraseOf is jobPhrase for a job read off one finding, its file the
// finding's own: "job `triage` from workflow `labeler.yml`" on GitHub,
// "job `build`" on GitLab.
func JobPhraseOf(job, file string) string {
	files := map[string]string{}
	if file != "" {
		files[job] = file
	}
	return jobPhrase(job, files, onGitHub(files, []string{job}))
}

// jobAndWorkflow splits a job into its own name and the workflow it is in
// as jobPhrase names them: the workflow file's base name, else the
// workflow's name; no workflow off GitHub or for a name without one.
func jobAndWorkflow(job string, files map[string]string, github bool) (id, workflow string) {
	workflow, id, ok := strings.Cut(job, "/")
	if !github || !ok {
		return job, ""
	}
	for _, f := range []string{files[job], files[workflow+"/"]} {
		if strings.Contains(f, githubWorkflowDir) && workflowOf(f) == workflow {
			return id, path.Base(f)
		}
	}
	return id, workflow
}

// fedJobPhrase is jobPhrase for a job entry feeds: a job of another
// workflow reads through that workflow, since what it is handed crosses
// from one workflow run to another ("job `publish` through workflow
// `release.yml`").
func fedJobPhrase(entry, job string, files map[string]string, github bool) string {
	id, workflow := jobAndWorkflow(job, files, github)
	_, entryWorkflow := jobAndWorkflow(entry, files, github)
	if workflow == "" || workflow == entryWorkflow {
		return jobPhrase(job, files, github)
	}
	return "job " + code(id) + " through workflow " + code(workflow)
}

// blockBranches reads every branch of p out for its block, in p's order,
// each job said where it runs (jobPhrase, its file read off findings); a
// path built without branches reads as one, its own.
func blockBranches(p AttackPath, findings []opaengine.Finding) []PathBlockBranch {
	files := jobFiles(p, findings)
	github := onGitHub(files, p.Jobs)
	branches := p.Branches
	if len(branches) == 0 && len(p.Jobs) > 0 {
		branches = []PathBranch{{Job: p.Jobs[0], Jobs: p.Jobs, Reach: p.Reach, Tier: p.Tier, State: p.State, Modifiers: p.Modifiers, cause: p.cause}}
	}
	// A job shows once: every entry job on its own branch, a fed job under
	// the first (strongest) branch that feeds it.
	shown := map[string]bool{}
	for _, b := range branches {
		shown[b.Job] = true
	}
	out := make([]PathBlockBranch, 0, len(branches))
	for _, b := range branches {
		var marks []string
		if len(b.triggers) > 0 {
			marks = append(marks, "on "+strings.Join(b.triggers, " or "))
		}
		if b.State == PathUnverified {
			marks = append(marks, "unverified")
		}
		marker := ""
		if len(marks) > 0 {
			marker = "(" + strings.Join(marks, ", ") + ")"
		}
		var fed []string
		var fedVia [][]string
		for _, j := range b.Jobs[min(len(b.Jobs), 1):] {
			if !shown[j] {
				shown[j] = true
				fed = append(fed, fedJobPhrase(b.Job, j, files, github))
				fedVia = append(fedVia, shownFeedKinds(b.FeedsVia[j]))
			}
		}
		// A hop into a job of another workflow names that workflow, a job
		// name being unique only within its workflow.
		hopName := func(job string) string {
			id, workflow := jobAndWorkflow(job, files, github)
			if _, entryWorkflow := jobAndWorkflow(b.Job, files, github); workflow != entryWorkflow {
				return jobPhrase(job, files, github)
			}
			return "job " + code(id)
		}
		out = append(out, PathBlockBranch{Job: jobPhrase(b.Job, files, github), Fed: fed, FedVia: fedVia, Reach: reachFragment(b.Reach, b.cause, hopName), Marker: marker})
	}
	return out
}

// shownFeedKinds is what a fed job's line names the entry job hands it:
// its artifact and cache kinds, and the job outputs of a needs dependency
// only when nothing else links the two, a needs being how an artifact
// download waits for its upload too.
func shownFeedKinds(kinds []string) []string {
	var shown []string
	for _, k := range kinds {
		if k != FeedOutput {
			shown = append(shown, k)
		}
	}
	if len(shown) == 0 && slices.Contains(kinds, FeedOutput) {
		return []string{FeedOutput}
	}
	return shown
}

// fedLine is a fed job's line: "feeds artifact and cache to job ...", or
// "feeds job ..." when the kinds are not known.
func fedLine(job string, kinds []string) string {
	if len(kinds) == 0 {
		return "feeds " + job
	}
	return "feeds " + strings.Join(kinds, " and ") + " to " + job
}

// maxSameReach is how many branches reaching the same thing a graph draws
// before it folds the rest into one line.
const maxSameReach = 6

// foldBranches keeps, of the branches sharing one reach and marker, the
// first maxSameReach, and folds the rest into one branch at the end
// ("12 more jobs with the same reach") reaching the same; folded is the
// entry jobs it folded, in order.
func foldBranches(branches []PathBlockBranch) (kept []PathBlockBranch, folded []string) {
	type group struct {
		first PathBlockBranch
		n     int
	}
	count := map[string]int{}
	var order []string
	groups := map[string]*group{}
	for _, br := range branches {
		key := br.Reach + "|" + br.Marker
		count[key]++
		if count[key] <= maxSameReach {
			kept = append(kept, br)
			continue
		}
		if groups[key] == nil {
			groups[key] = &group{first: br}
			order = append(order, key)
		}
		groups[key].n++
		folded = append(folded, br.Job)
	}
	for _, key := range order {
		g := groups[key]
		kept = append(kept, PathBlockBranch{Job: fmt.Sprintf("%d more jobs with the same reach", g.n), Reach: g.first.Reach, Marker: g.first.Marker})
	}
	return kept, folded
}

// Clean returns the block with every text passed through clean: a
// renderer strips what its output must never carry (an escape sequence on
// a terminal) before laying the block out.
func (b PathBlock) Clean(clean func(string) string) PathBlock {
	for _, s := range []*string{&b.Entry, &b.EntrySubject, &b.EntryWriter, &b.EntryUnverified, &b.RunsIn, &b.ReachesShort, &b.ReachUnverified, &b.So, &b.Cap, &b.Fix} {
		*s = clean(*s)
	}
	env := make([]string, len(b.Environment))
	for i, e := range b.Environment {
		env[i] = clean(e)
	}
	b.Environment = env
	branches := make([]PathBlockBranch, len(b.Branches))
	for i, br := range b.Branches {
		fed := make([]string, len(br.Fed))
		for j, f := range br.Fed {
			fed[j] = clean(f)
		}
		var fedVia [][]string
		for _, kinds := range br.FedVia {
			fedVia = append(fedVia, slices.Clone(kinds))
		}
		branches[i] = PathBlockBranch{Job: clean(br.Job), Fed: fed, FedVia: fedVia, Reach: clean(br.Reach), Marker: clean(br.Marker)}
	}
	b.Branches = branches
	findings := make([]PathBlockFinding, len(b.Findings))
	for i, f := range b.Findings {
		findings[i] = PathBlockFinding{Code: ErrorCode(clean(string(f.Code))), Title: clean(f.Title), Location: clean(f.Location), Count: f.Count}
	}
	b.Findings = findings
	return b
}

// Notes is what the block says under its consequence: what could not be
// checked about the entry, the job that can write a cache, what could not
// be checked about the reach, the environment the job runs in, then, only
// when ShowCap is set (the points are printed), why the path stops at its
// cap.
func (b PathBlock) Notes() []string {
	notes := append([]string{b.EntryUnverified, b.EntryWriter, b.ReachUnverified}, b.Environment...)
	if b.ShowCap {
		notes = append(notes, b.Cap)
	}
	var out []string
	for _, n := range notes {
		if n != "" {
			out = append(out, n)
		}
	}
	return out
}

// PathTierBadge is a tier as the plain badge a path block opens on, six
// cells wide.
func PathTierBadge(t PathTier) string {
	switch t {
	case TierCritical:
		return " CRIT "
	case TierHigh:
		return " HIGH "
	case TierMedium:
		return " MED  "
	}
	return " LOW  "
}

const (
	// graphIndent is where a block's graph and labels start: under the
	// badge and one space.
	graphIndent = 7
	// graphLabel is the width of a label column ("So", "Note", "Fix").
	graphLabel = 7
	// graphFork is the width of a branch's fork ("├──▶ ") and of the stem
	// under it ("│    ").
	graphFork = 5
	// minGraphReach is the narrowest a branch's reach wraps to.
	minGraphReach = 16
	// findingGap is the space between a finding's title column and its
	// location.
	findingGap = 3
)

// PathGraph lays a path block out as lines at most width cells wide (a
// value that cannot fit wraps under itself, never cut): the plain tier
// badge and the path number, alone on the title line; the Entry line; one
// branch per entry job, saying where it runs and what it reaches, the
// jobs it feeds hanging off it; then what the path means, the notes and
// the fix. The findings are PathGraphFindings, which a renderer prints
// after it. Every value is printed as given: the caller cleans the block
// first (PathBlock.Clean). This is the merge request comment's layout,
// titled "path"; the terminal's is ReportPathGraph, the same lines titled
// "Attack path".
func PathGraph(n int, b PathBlock, width int) []string {
	return pathGraph(n, b, width, "path")
}

// ReportPathGraph is PathGraph as the terminal report titles it: "Attack
// path" and its number.
func ReportPathGraph(n int, b PathBlock, width int) []string {
	return pathGraph(n, b, width, "Attack path")
}

// BlockLabels are the labels a path graph opens its labelled lines on, in
// the column under the badge: a renderer can set them apart.
var BlockLabels = []string{"Entry", "So", "Note", "Fix", "Also"}

func pathGraph(n int, b PathBlock, width int, title string) []string {
	head := fmt.Sprintf("%s %s %d", PathTierBadge(b.Tier), title, n)
	if b.Unverified {
		head += " (unverified)"
	}
	out := []string{head}
	pad := strings.Repeat(" ", graphIndent)
	valueWidth := max(width-graphIndent-graphLabel, minGraphReach)
	labelledLines := func(label string, lines []string) {
		for i, l := range lines {
			if i == 0 {
				out = append(out, pad+fmt.Sprintf("%-*s", graphLabel, label)+l)
				continue
			}
			out = append(out, pad+strings.Repeat(" ", graphLabel)+l)
		}
	}
	labelled := func(label, value string) {
		if value != "" {
			labelledLines(label, wrapHard(value, valueWidth))
		}
	}
	if b.Entry != "" {
		labelledLines("Entry", wrapEntryPhrase(b.Entry, b.EntrySubject, valueWidth))
	}
	branches, folded := foldBranches(b.Branches)
	if len(branches) > 0 {
		out = append(out, pad+"│")
		out = append(out, branchLines(branches, width)...)
	}
	out = append(out, "")
	if b.So != "" {
		labelledLines("So", wrapSentence(b.So, valueWidth))
	}
	for _, note := range b.Notes() {
		labelled("Note", note)
	}
	labelled("Fix", b.Fix)
	labelled("Also", strings.Join(folded, ", "))
	return out
}

// phraseUnits splits a sentence at its phrase boundaries: after each ", "
// (the comma kept), before each " and " and before each " (", never inside
// a parenthesised phrase or a code span.
func phraseUnits(s string) []string {
	var units []string
	depth, inCode, start := 0, false, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '`':
			inCode = !inCode
		case inCode:
		case c == '(':
			if depth == 0 && i > start && s[i-1] == ' ' {
				units = append(units, s[start:i-1])
				start = i
			}
			depth++
		case c == ')':
			depth = max(depth-1, 0)
		case depth > 0:
		case strings.HasPrefix(s[i:], ", "):
			units = append(units, s[start:i+1])
			start = i + 2
			i++
		case strings.HasPrefix(s[i:], " and "):
			units = append(units, s[start:i])
			start = i + 1
		}
	}
	return append(units, s[start:])
}

// tokenLead opens the token's phrase in a reach fragment.
const tokenLead = "a token with "

// reachUnits splits a reach fragment at its phrase boundaries
// (phraseUnits), the token's phrase held as one unit ("a token with push,
// publish and deploy access", "a token with write access to pull requests
// and issues"): what follows it up to the next part of the reach (an
// article, a parenthesis) is its verbs or its scopes. Each unit's words
// are glued so it wraps whole.
func reachUnits(reach string) []string {
	var units []string
	inToken := false
	for _, u := range phraseUnits(reach) {
		bare := strings.TrimPrefix(u, "and ")
		part := strings.HasPrefix(bare, "a ") || strings.HasPrefix(bare, "an ") || strings.HasPrefix(bare, "(")
		if inToken && !part && len(units) > 0 {
			units[len(units)-1] += " " + u
			continue
		}
		inToken = strings.HasPrefix(bare, tokenLead)
		units = append(units, u)
	}
	for i, u := range units {
		units[i] = strings.ReplaceAll(u, " ", string(glueRune))
	}
	return units
}

// wrapPhrases fills lines of at most width cells with the phrases of s
// (units, glued), breaking at the last boundary that fits; a phrase wider
// than a line alone breaks between its own words, never inside one.
func wrapPhrases(units []string, width int) []string {
	lines := wrapUnits(units, width)
	for i := range lines {
		lines[i] = strings.ReplaceAll(lines[i], string(glueRune), " ")
	}
	return lines
}

// wrapReach breaks a reach fragment into lines of at most width cells at
// its phrase boundaries (reachUnits).
func wrapReach(reach string, width int) []string {
	return wrapPhrases(reachUnits(reach), width)
}

// wrapSentence breaks a sentence into lines of at most width cells at its
// phrase boundaries (phraseUnits).
func wrapSentence(s string, width int) []string {
	units := phraseUnits(s)
	for i, u := range units {
		units[i] = strings.ReplaceAll(u, " ", string(glueRune))
	}
	return wrapPhrases(units, width)
}

// fitsBeside reports whether every phrase of reach fits in width cells, so
// the reach can wrap beside its job without breaking a phrase.
func fitsBeside(reach string, width int) bool {
	if cellWidth(reach) <= width {
		return true
	}
	if width < minGraphReach {
		return false
	}
	for _, u := range reachUnits(reach) {
		if cellWidth(u) > width {
			return false
		}
	}
	return true
}

// reachLead is what opens the reach of a branch beside its job.
const reachLead = "─▶ reaches "

// droppedLead opens a reach on the line under its job, its corner under
// the job's first word; droppedFedLead does when the branch feeds jobs, so
// the tree runs on down to them. droppedBar carries that tree past the
// reach's continuation lines.
const (
	droppedLead    = "└─▶ reaches "
	droppedFedLead = "├─▶ reaches "
	droppedBar     = "│"
)

// branchLines draws the branches: "├──▶ runs in job ... ─▶ reaches ...",
// the last one with "└──▶". The marker follows the job when it fits beside
// it, else takes the line under it. The reach follows on the same line
// when its phrases fit there in fewer lines than under the job, wrapping
// under its first word; else it takes the line under the job (and the
// marker) on a corner under the job's first word ("└─▶ reaches ...", or
// "├─▶ reaches ..." when the branch feeds jobs), wrapping under its first
// word. The jobs a branch feeds hang one per line under it, each naming
// what the entry job hands it ("└──▶ feeds artifact to job ...").
func branchLines(branches []PathBlockBranch, width int) []string {
	room := max(width-graphIndent-graphFork, minGraphReach)
	pad := strings.Repeat(" ", graphIndent)
	var out []string
	for i, br := range branches {
		fork, stem := "├──▶ ", "│    "
		if i == len(branches)-1 {
			fork, stem = "└──▶ ", "     "
		}
		label, marker := "runs in "+br.Job, br.Marker
		if marker != "" && cellWidth(label+" "+marker) <= room {
			label, marker = label+" "+marker, ""
		}
		lines := wrapHard(label, room)
		for j, l := range lines {
			lead := pad + stem
			if j == 0 {
				lead = pad + fork
			}
			lines[j] = lead + l
		}
		last := len(lines) - 1
		if marker != "" {
			for _, l := range wrapHard(marker, room) {
				lines = append(lines, pad+stem+l)
			}
		}
		if br.Reach != "" {
			// Beside the job, in the room left after " ─▶ reaches ", when
			// that takes fewer lines than the reach on the lines under the
			// job does.
			beside := room - cellWidth(lines[last]) + graphIndent + graphFork - 1 - cellWidth(reachLead)
			under := wrapReach(br.Reach, max(room-cellWidth(droppedLead), minGraphReach))
			if besideLines := wrapReach(br.Reach, max(beside, 1)); marker == "" && fitsBeside(br.Reach, beside) && len(besideLines) < 1+len(under) {
				col := cellWidth(lines[last]) + 1 + cellWidth(reachLead)
				lines[last] += " " + reachLead + besideLines[0]
				for _, l := range besideLines[1:] {
					lines = append(lines, pad+stem+strings.Repeat(" ", col-graphIndent-graphFork)+l)
				}
			} else {
				lead, cont := droppedLead, strings.Repeat(" ", cellWidth(droppedLead))
				if len(br.Fed) > 0 {
					lead, cont = droppedFedLead, droppedBar+cont[cellWidth(droppedBar):]
				}
				lines = append(lines, pad+stem+lead+under[0])
				for _, l := range under[1:] {
					lines = append(lines, pad+stem+cont+l)
				}
			}
		}
		out = append(out, lines...)
		for j, f := range br.Fed {
			hang := "├──▶ "
			if j == len(br.Fed)-1 {
				hang = "└──▶ "
			}
			var kinds []string
			if j < len(br.FedVia) {
				kinds = br.FedVia[j]
			}
			for k, l := range wrapHard(fedLine(f, kinds), max(room-cellWidth(hang), minGraphReach)) {
				if k == 0 {
					out = append(out, pad+stem+hang+l)
					continue
				}
				out = append(out, pad+stem+strings.Repeat(" ", cellWidth(hang))+l)
			}
		}
	}
	return out
}

// PathGraphFindings lists a block's findings under a "Findings" label, one
// per line with its code, its title and its location, the locations in
// one column: beside the titles when the width holds them, else each on
// the line under its title.
func PathGraphFindings(findings []PathBlockFinding, width int) []string {
	if len(findings) == 0 {
		return nil
	}
	where := func(f PathBlockFinding) string {
		if f.Count > 1 && f.Location != "" {
			return fmt.Sprintf("%d findings, first %s", f.Count, f.Location)
		}
		if f.Count > 1 {
			return fmt.Sprintf("%d findings", f.Count)
		}
		return f.Location
	}
	longest, whereWidth := 0, 0
	for _, f := range findings {
		longest = max(longest, cellWidth(f.Title))
		whereWidth = max(whereWidth, cellWidth(where(f)))
	}
	indent := strings.Repeat(" ", graphIndent+2)
	under := indent + strings.Repeat(" ", len("ISSUE-000 "))
	avail := max(width-cellWidth(under), minGraphReach)
	titleCol := max(longest, min(40, avail-findingGap-whereWidth))
	column := titleCol+findingGap+whereWidth <= avail
	out := []string{strings.Repeat(" ", graphIndent) + "Findings"}
	for _, f := range findings {
		at := where(f)
		if column {
			line := indent + string(f.Code) + " " + f.Title
			if at != "" {
				line += strings.Repeat(" ", titleCol-cellWidth(f.Title)+findingGap) + at
			}
			out = append(out, line)
			continue
		}
		for j, l := range wrapHard(f.Title, avail) {
			if j == 0 {
				out = append(out, indent+string(f.Code)+" "+l)
				continue
			}
			out = append(out, under+l)
		}
		for _, l := range wrapHard(at, avail) {
			out = append(out, under+l)
		}
	}
	return out
}

func cellWidth(s string) int {
	return lipgloss.Width(s)
}

// wrapHard breaks s into lines of at most width cells at spaces; a word
// wider than a line is split across lines, never cut.
func wrapHard(s string, width int) []string {
	return wrapUnits(strings.Fields(s), width)
}

// glueRune holds a subject's words together while an entry phrase wraps.
const glueRune = ' '

// wrapEntryPhrase wraps an entry phrase between its words, its subject
// kept on one line when a line can hold it, else broken between its own
// words, never cut.
func wrapEntryPhrase(entry, subject string, width int) []string {
	glued := entry
	if subject != "" && strings.Contains(entry, subject) {
		glued = strings.Replace(entry, subject, strings.ReplaceAll(subject, " ", string(glueRune)), 1)
	}
	lines := wrapUnits(strings.FieldsFunc(glued, func(r rune) bool { return r == ' ' }), width)
	for i := range lines {
		lines[i] = strings.ReplaceAll(lines[i], string(glueRune), " ")
	}
	return lines
}

// wrapUnits fills lines of at most width cells with units, a space
// between two; a glued unit wider than a line starts a line and breaks
// between its own words, and a word wider than a line is split.
func wrapUnits(units []string, width int) []string {
	width = max(width, 1)
	var lines []string
	line := ""
	add := func(u string) {
		switch {
		case line == "":
			line = u
		case cellWidth(line)+1+cellWidth(u) <= width:
			line += " " + u
		default:
			lines = append(lines, line)
			line = u
		}
	}
	for _, u := range units {
		if cellWidth(u) <= width {
			add(u)
			continue
		}
		if strings.ContainsRune(u, glueRune) {
			if line != "" {
				lines = append(lines, line)
				line = ""
			}
			for _, l := range wrapUnits(strings.FieldsFunc(u, func(r rune) bool { return r == glueRune }), width) {
				add(l)
			}
			continue
		}
		for _, piece := range splitCells(u, width) {
			add(piece)
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// splitCells splits a word into pieces of at most width cells.
func splitCells(w string, width int) []string {
	var out []string
	piece := ""
	for _, r := range w {
		if piece != "" && cellWidth(piece+string(r)) > width {
			out = append(out, piece)
			piece = ""
		}
		piece += string(r)
	}
	return append(out, piece)
}

// codeBlockText is s with what a code block must not carry dropped: a
// control character, a tab read as a space.
func codeBlockText(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			return ' '
		case unicode.IsControl(r):
			return -1
		}
		return r
	}, s)
}

// codeFence is a Markdown fence longer than any run of backticks in
// lines, so nothing inside can close it.
func codeFence(lines []string) string {
	longest, run := 0, 0
	for _, l := range lines {
		run = 0
		for _, r := range l {
			if r == '`' {
				run++
				longest = max(longest, run)
				continue
			}
			run = 0
		}
	}
	return strings.Repeat("`", max(3, longest+1))
}
