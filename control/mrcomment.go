package control

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/sirupsen/logrus"
)

const (
	// MRCommentIdentifier is an invisible HTML comment used to find the Plumber
	// comment in the merge request notes so it can be updated on subsequent
	// runs. The historical wording is kept on purpose: changing it would stop
	// matching comments posted by older versions and create duplicates.
	MRCommentIdentifier = "<!-- Plumber Compliance Comment -->"
)

// ManageMergeRequestComment creates or updates the Plumber comment on the
// given merge request. projectID and gitlabURL come from the already-resolved
// configuration/result; only mrIID is CI-specific. passed is the run's gate
// verdict and gateLine its human-readable rendering.
func ManageMergeRequestComment(
	projectID int,
	mrIID int,
	result *AnalysisResult,
	pc *configuration.PlumberConfig,
	passed bool,
	gateLine string,
	conf *configuration.Configuration,
	score *PlumberScoreResult,
	scoreMode bool,
	scorePointMode bool,
	platform *PlatformPostSummary,
) error {
	l := logrus.WithFields(logrus.Fields{
		"action":          "ManageMergeRequestComment",
		"projectID":       projectID,
		"mergeRequestIID": mrIID,
	})

	// Generate comment body
	commentBody := generateMRComment(result, pc, passed, gateLine, score, scoreMode, scorePointMode, conf.ControlsFilter, conf.SkipControlsFilter, platform)

	// List existing notes to find our comment
	notes, err := gitlab.ListMergeRequestNotes(
		projectID,
		mrIID,
		conf.GitlabToken,
		conf.GitlabURL,
		conf,
	)
	if err != nil {
		l.WithError(err).Error("Unable to list merge request notes")
		return err
	}

	// Look for an existing Plumber comment
	var existingNoteID int64
	for _, note := range notes {
		if strings.Contains(note.Body, MRCommentIdentifier) {
			existingNoteID = note.ID
			break
		}
	}

	if existingNoteID != 0 {
		// Update the existing comment
		_, err = gitlab.UpdateMergeRequestNote(
			projectID,
			mrIID,
			int(existingNoteID),
			commentBody,
			conf.GitlabToken,
			conf.GitlabURL,
			conf,
		)
		if err != nil {
			l.WithError(err).Error("Failed to update MR comment")
			return err
		}
		l.Info("Updated Plumber comment on merge request")
	} else {
		// Create a new comment
		_, err = gitlab.CreateMergeRequestNote(
			projectID,
			mrIID,
			commentBody,
			conf.GitlabToken,
			conf.GitlabURL,
			conf,
		)
		if err != nil {
			l.WithError(err).Error("Failed to create MR comment")
			return err
		}
		l.Info("Created Plumber comment on merge request")
	}

	return nil
}

// ScoreBadgeURL builds a Shields.io badge URL showing the Plumber letter score (A–E).
func ScoreBadgeURL(letter string) string {
	color := "red"
	switch letter {
	case "A":
		color = "brightgreen"
	case "B":
		color = "green"
	case "C":
		color = "yellow"
	case "D":
		color = "orange"
	case "E":
		color = "red"
	}
	return fmt.Sprintf("https://img.shields.io/badge/plumber-%s-%s", letter, color)
}

// generateMRComment builds the Markdown body for the merge request comment
// based on the analysis result.
//
// platform is set only in platform mode and then owns the whole body (spec
// s5): what a reviewer must see there is the platform's verdict per policy,
// not the local configuration's evaluation of the same pipeline.
func generateMRComment(result *AnalysisResult, pc *configuration.PlumberConfig, passed bool, gateLine string, score *PlumberScoreResult, scoreMode, scorePointMode bool, controlsFilterList, skipControlsList []string, platform *PlatformPostSummary) string {
	if platform != nil {
		return generatePlatformMRComment(platform, passed, gateLine)
	}
	var b strings.Builder

	// Hidden identifier so we can find this comment later
	b.WriteString(MRCommentIdentifier + "\n")

	// Letter-score badge linking to the score documentation
	if scoreMode && score != nil {
		fmt.Fprintf(&b, "[![Plumber](%s)](%s)\n\n", ScoreBadgeURL(score.Score), PlumberScoreDocURL)
	}

	b.WriteString("*If this merge request is merged, the expected Plumber Score will be as shown above.*\n\n")

	// isV4 gates on the computed score's own ProfileID, never on the
	// package-level ScoreProfile variable: a --score-profile v4 request
	// that fell back to scoring-v3 for lack of a usable situation must
	// still render the ordinary v3 comment below. Under the contextual
	// score the comment opens on its summary; the path details close it,
	// after the controls and the other findings in detail.
	isV4 := score != nil && score.ProfileID == PlumberScoreProfileIDV4
	switch {
	case isV4:
		b.WriteString(v4CommentSummary(result, score, scorePointMode))
	case scorePointMode && score != nil:
		b.WriteString("### Plumber Score\n\n")
		fmt.Fprintf(&b, "- **Profile:** `%s`\n", score.ProfileID)
		fmt.Fprintf(&b, "- **Issues by severity:** critical %d, high %d, medium %d, low %d\n",
			score.Counts.Critical, score.Counts.High, score.Counts.Medium, score.Counts.Low)
		fmt.Fprintf(&b, "- **Raw points (before Critical malus):** %.1f / 100\n", score.RawPoints)
		fmt.Fprintf(&b, "- **Final points:** %.1f / 100\n", score.FinalPoints)
		if score.CriticalMalusApplied {
			fmt.Fprintf(&b, "- **Critical malus:** final points capped at %.0f when any Critical issue exists\n", score.CriticalMalusMax)
		}
		fmt.Fprintf(&b, "- **Score (letter):** **%s**\n", score.Score)
		b.WriteString("\n")
	case scoreMode && score != nil:
		b.WriteString("### Plumber Score\n\n")
		fmt.Fprintf(&b, "- **Score:** **%s**\n\n", score.Score)
	}

	// renderedPaths is the id set of the attack paths the path details
	// at the end of the comment print (the first maxCommentPaths, worst first);
	// computed once here and threaded into both the otherIssues tally
	// below and writeIssueDetails, so a finding riding a path beyond the
	// cap is judged against the same set in both places.
	renderedPaths := renderedPathIDs(result.Paths)

	// Gather controls from the config-driven catalog joined with the
	// Rego Findings list. An empty findings list is not automatically a
	// pass: a control whose data lane supplied nothing has no findings
	// either, and a green check beside it on a merge request is the most
	// consequential place to get that wrong.
	type controlEntry struct {
		name         string
		issues       int
		skipped      bool
		notEvaluable bool
	}

	findingsByControl := FindingsByControl(result.Findings)
	var controls []controlEntry
	var totalIssues int
	// otherIssues counts, under v4 only, the findings the Attack paths
	// list does not tell the story of (no pathIds in their
	// Data): what is left to show under "Individual findings". Unused, and so
	// always zero, under v3.
	var otherIssues int

	mrEntries := GitLabControls(pc)
	MarkSkippedByFilter(mrEntries, controlsFilterList, skipControlsList)
	for _, e := range mrEntries {
		findings := findingsByControl[e.ControlName]
		count := len(findings)
		// Keyed on result.NotEvaluable, not StatusFor: StatusFor also
		// returns StatusError for the older run-wide degradation signals,
		// and re-bucketing those would change what a STANDALONE run posts.
		_, unevaluated := result.NotEvaluable[e.ControlName]
		controls = append(controls, controlEntry{
			name:         e.DisplayName,
			issues:       count,
			skipped:      e.Skipped,
			notEvaluable: !e.Skipped && unevaluated,
		})
		if !e.Skipped {
			totalIssues += count
			if isV4 {
				otherIssues += countWithoutPathIDs(findings, renderedPaths)
			}
		}
	}

	// Controls summary table
	b.WriteString("### Controls\n\n")
	b.WriteString("| Control | Status | Issues |\n")
	b.WriteString("|---------|--------|--------|\n")
	for _, c := range controls {
		switch {
		case c.skipped:
			fmt.Fprintf(&b, "| %s | _skipped_ | — |\n", c.name)
		case c.notEvaluable:
			// Never a green check: this control was not checked at all, and
			// a reviewer reading the MR must not take it for a pass.
			fmt.Fprintf(&b, "| :grey_question: %s | _not evaluated_ | — |\n", c.name)
		case c.issues > 0:
			fmt.Fprintf(&b, "| :x: %s | failed | %d |\n", c.name, c.issues)
		default:
			fmt.Fprintf(&b, "| :white_check_mark: %s | passed | 0 |\n", c.name)
		}
	}
	b.WriteString("\n")

	// Status line after the table
	writeMRStatusLine(&b, passed, gateLine)

	// Issue details. Under the contextual score the path details below tell the
	// story of every finding that anchors or walks a path; this section is
	// renamed "Individual findings in detail" and carries only what is left, so
	// nothing is told twice. Under v3 nothing changes: the heading, and
	// every finding able to reach it, are exactly what they were before v4
	// existed.
	switch {
	case isV4 && otherIssues > 0:
		b.WriteString("### Individual findings in detail\n\n")
		writeIssueDetails(&b, result, renderedPaths)
	case !isV4 && totalIssues > 0:
		b.WriteString("### Issues\n\n")
		writeIssueDetails(&b, result, nil)
	}
	if isV4 {
		b.WriteString(v4CommentPathDetails(result, scorePointMode))
	}

	writeMRFooter(&b)

	return b.String()
}

// writeMRStatusLine and writeMRFooter are the two blocks every Plumber
// comment ends with, standalone or platform mode. They are shared rather than
// repeated so the two bodies cannot drift on the wording a reader uses to
// recognise a Plumber comment; the strings are the existing ones, moved
// verbatim, so a standalone comment is byte-for-byte what it was.
func writeMRStatusLine(b *strings.Builder, passed bool, gateLine string) {
	if passed {
		fmt.Fprintf(b, ":white_check_mark: **Plumber check passed** (%s)\n\n", gateLine)
	} else {
		fmt.Fprintf(b, ":warning: **Plumber check failed** - %s\n\n", gateLine)
	}
}

func writeMRFooter(b *strings.Builder) {
	b.WriteString("---\n")
	b.WriteString("*Automatically posted by [Plumber](https://getplumber.io) — do not edit manually.*\n")
}

// generatePlatformMRComment builds the merge-request comment of a
// platform-mode run (spec s5): the platform's global score as the headline,
// then one row per resolved policy.
//
// It deliberately does NOT carry the controls table or the issue details the
// standalone comment ends with. Both are rendered from the run-level result,
// which in platform mode is the LOCAL configuration's evaluation - the one
// thing this mode exists to stop publishing (QUESTIONS row 44). The per-policy
// findings live in the report artifacts and on the platform, where they carry
// the policy they belong to.
//
// A missing global score is stated, never filled in: an unavailable verdict
// and a bad one must not look the same to a reviewer.
func generatePlatformMRComment(platform *PlatformPostSummary, passed bool, gateLine string) string {
	var b strings.Builder

	hasGlobal := platform.hasPublishableGlobal()

	b.WriteString(MRCommentIdentifier + "\n")
	if hasGlobal {
		fmt.Fprintf(&b, "[![Plumber](%s)](%s)\n\n", ScoreBadgeURL(platform.GlobalLetter), PlumberScoreDocURL)
	}
	b.WriteString("*Enforcement comes from the platform's policies; the scores below are this run's.*\n\n")

	b.WriteString("### Plumber Score\n\n")
	if hasGlobal {
		fmt.Fprintf(&b, "- **Global score (platform):** **%s** - %d / 100 pts\n\n",
			sanitizeMarkdownInline(platform.GlobalLetter), platform.GlobalPoints)
	} else {
		b.WriteString("- **Global score (platform):** _score unavailable_ - the platform returned none for this run\n\n")
	}

	b.WriteString("### Policies\n\n")
	b.WriteString("| Policy | Enforcement | Score | Blocking |\n")
	b.WriteString("|--------|-------------|-------|----------|\n")
	for _, p := range platform.Policies {
		// A policy the CLI could not evaluate has no letter. Rendering the
		// zero it carries would read as a policy that scored nothing rather
		// than one that ran nothing.
		scoreCell := "_not evaluated_"
		if p.Letter != "" {
			scoreCell = fmt.Sprintf("%s - %d / 100", sanitizeMarkdownInline(p.Letter), p.FinalPoints)
		}
		blocking := "no"
		if p.Blocking {
			blocking = "**yes**"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
			sanitizeMarkdownInline(p.Name), sanitizeMarkdownInline(p.Enforcement), scoreCell, blocking)
	}
	b.WriteString("\n")

	writeMRStatusLine(&b, passed, gateLine)
	writeMRFooter(&b)

	return b.String()
}

// sanitizeMarkdownInline neutralizes repo-controlled text placed inline in the
// merge-request comment. Finding messages embed data from the scanned
// repository (job names, image refs, script lines); left raw they could inject
// Markdown links/images or — via a newline — whole new lines into a comment
// posted with Plumber's identity. Control characters are removed (newlines and
// tabs become spaces) and Markdown-active characters are backslash-escaped so
// the text renders literally.
func sanitizeMarkdownInline(s string) string {
	const escaped = "\\`*_[]()<>|~@#!%$"
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case unicode.IsControl(r):
			// drop other control characters
		default:
			if strings.ContainsRune(escaped, r) {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

// writeIssueDetails appends per-control issue details into the builder.
// Findings are grouped by the ControlName declared in the issue-code
// registry so the section headings line up with the controls table.
// Order within each group follows the Rego evaluation order so repeated
// runs produce stable output.
//
// rendered is non-nil only for the contextual score's "Individual findings
// in detail" section: it drops every finding whose pathIds are all within
// the path details (rendered there in full), leaving the findings no rendered path
// reached. A finding riding at least one path beyond the cap is kept,
// since the path details never told its story. Under v3
// rendered is always nil and nothing here changes.
func writeIssueDetails(b *strings.Builder, result *AnalysisResult, rendered map[string]bool) {
	findingsByControl := FindingsByControl(result.Findings)
	numbers := map[string]int{}
	for i, p := range PathsWorstFirst(result.Paths) {
		numbers[p.ID] = i + 1
	}
	for _, g := range mrCommentControlOrder {
		all := findingsByControl[g.controlName]
		findings := all
		if rendered != nil {
			findings = withoutPathIDs(all, rendered)
		}
		if len(findings) == 0 {
			continue
		}
		fmt.Fprintf(b, "**%s:**\n", g.heading)
		if note := elsewhereNote(all, rendered, numbers); note != "" {
			fmt.Fprintf(b, "_%s._\n", note)
		}
		for _, f := range findings {
			docURL := ErrorCode(f.Code).DocURL()
			fmt.Fprintf(b, "- `%s` %s ([docs](%s))\n", f.Code, sanitizeMarkdownInline(f.Message), docURL)
		}
		b.WriteString("\n")
	}
}

// maxCommentPaths bounds the attack paths of one comment; the rest are
// counted on one line, worst-first order keeping the ones that matter.
const maxCommentPaths = 20

// v4CommentSummary is the top of the contextual score's comment, read
// first on a web page: the score and the best fix, the other findings in
// one line, and the attack paths as a table. Under scorePoint the score
// section adds the arithmetic: the subtraction, the caps, the adjustment
// line, and why the best fix recovers what it does. Every name is
// attacker text on a merge request pipeline and goes through
// sanitizeMarkdownInline.
func v4CommentSummary(result *AnalysisResult, score *PlumberScoreResult, scorePoint bool) string {
	var b strings.Builder
	b.WriteString("### Plumber Score\n\n")
	fmt.Fprintf(&b, "- **%s / 100** (%s)\n", formatPoints(score.FinalPoints), score.Score)
	fix := BestFixSummary(score)
	if scorePoint {
		pathsLoss, otherLoss := BucketLosses(score)
		fmt.Fprintf(&b, "- 100 - %s (attack paths) - %s (individual findings)\n", formatPoints(pathsLoss), formatPoints(otherLoss))
		for _, note := range CapNotes(score) {
			fmt.Fprintf(&b, "- %s\n", note)
		}
		if line := ScoreAdjustment(score); line != "" {
			fmt.Fprintf(&b, "- %s\n", line)
		}
		if score.BestFix != nil && score.BestFix.Reason != "" {
			fix += " (" + score.BestFix.Reason + ")"
		}
	} else if score.BestFix != nil && score.BestFix.Stays != "" {
		fix = strings.TrimSuffix(fix, " "+score.BestFix.Stays)
	}
	if worst := WorstCase(result.Paths); worst != "" {
		fmt.Fprintf(&b, "- **Worst case:** %s\n", sanitizeMarkdownInline(worst))
	}
	fmt.Fprintf(&b, "- **Best fix:** %s\n", sanitizeMarkdownInline(fix))

	count := 0
	if score.OtherFindings != nil {
		count = score.OtherFindings.Count
	}
	if count == 0 {
		b.WriteString("\n### Individual findings (0)\n")
	} else {
		fmt.Fprintf(&b, "\n### Individual findings (%d)\n\n- %s\n", count, OtherFindingsSummary(score))
	}

	ordered := PathsWorstFirst(result.Paths)
	fmt.Fprintf(&b, "\n### Attack paths (%d)\n", len(ordered))
	if len(ordered) > 0 {
		b.WriteString("\n| # | Tier | Entry | Job | Reaches |\n| --- | --- | --- | --- | --- |\n")
	}
	for i, p := range ordered {
		if i == maxCommentPaths {
			fmt.Fprintf(&b, "\nand %s\n", plural(len(ordered)-maxCommentPaths, "more path", "more paths"))
			break
		}
		row := PathRowOf(p)
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %s |\n", i+1, tierTitle(p.Tier), sanitizeMarkdownInline(row.Entry), sanitizeMarkdownInline(row.Jobs), sanitizeMarkdownInline(row.Reaches))
	}
	b.WriteString("\n")
	return b.String()
}

// v4CommentPathDetails is one block per attack path, worst first, at most
// maxCommentPaths of them: the same graph as the terminal, in a code
// block, then its findings with their documentation links. Under
// scorePoint each block also says why its path stops at a cap.
func v4CommentPathDetails(result *AnalysisResult, scorePoint bool) string {
	ordered := PathsWorstFirst(result.Paths)
	if len(ordered) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("### Attack path details\n\n")
	for i, p := range ordered {
		if i == maxCommentPaths {
			break
		}
		blk := NewPathBlock(p, result.Findings)
		blk.ShowCap = scorePoint
		state := ""
		if blk.Unverified {
			state = " (unverified)"
		}
		fmt.Fprintf(&b, "#### %s path %d%s\n\n", strings.ToUpper(string(p.Tier)), i+1, state)
		// Inside a code block nothing is read as Markdown; a fence longer
		// than any backtick run of the block keeps attacker text inside it.
		graph := PathGraph(i+1, blk.Clean(codeBlockText), commentGraphWidth)
		fence := codeFence(graph)
		fmt.Fprintf(&b, "%stext\n%s\n%s\n\n", fence, strings.Join(graph, "\n"), fence)
		for _, f := range blk.Findings {
			where := sanitizeMarkdownInline(f.Location)
			if f.Count > 1 {
				where = fmt.Sprintf("%d findings", f.Count)
			}
			if where != "" {
				where += ", "
			}
			fmt.Fprintf(&b, "- `%s` %s (%s[docs](%s))\n", f.Code, f.Title, where, f.Code.DocURL())
		}
		b.WriteString("\n")
	}
	return b.String()
}

// commentGraphWidth is the width a path graph is laid out at in a
// comment: a code block on a merge request page scrolls, but the terminal's
// default width reads without it.
const commentGraphWidth = 100

// renderedPathIDs is the id set of the attack paths v4CommentPathDetails
// actually prints: the first maxCommentPaths of result.Paths, worst first
// (AssemblePaths's own order, the one PathsWorstFirst keeps). A path beyond the cap is only ever
// summarized on the "and N more paths" line, never told on its own, so its
// id does not belong in this set.
func renderedPathIDs(paths []AttackPath) map[string]bool {
	n := len(paths)
	if n > maxCommentPaths {
		n = maxCommentPaths
	}
	ids := make(map[string]bool, n)
	for _, p := range paths[:n] {
		ids[p.ID] = true
	}
	return ids
}

// findingHasPathIDs reports whether a finding is already told IN FULL by
// the path details: AnnotateFindingsV4 writes Data["pathIds"] only
// when PathIDsFor returned at least one id, and omits the key otherwise.
// A finding with every one of its path ids in rendered was shown there; a
// finding with even one id beyond the maxCommentPaths cap was not, and
// must stay visible somewhere, or it disappears from the comment entirely.
func findingHasPathIDs(f opaengine.Finding, rendered map[string]bool) bool {
	ids, ok := f.Data["pathIds"].([]string)
	if !ok || len(ids) == 0 {
		return false
	}
	for _, id := range ids {
		if !rendered[id] {
			return false
		}
	}
	return true
}

// elsewhereNote says how many of a control's findings the path details
// list instead ("2 more of these are listed under attack path 1"), ""
// when none: numbers is each path's number, worst first.
func elsewhereNote(findings []opaengine.Finding, rendered map[string]bool, numbers map[string]int) string {
	if rendered == nil {
		return ""
	}
	n := 0
	var on []int
	seen := map[int]bool{}
	for _, f := range findings {
		if !findingHasPathIDs(f, rendered) {
			continue
		}
		n++
		ids, _ := f.Data["pathIds"].([]string)
		for _, id := range ids {
			if k := numbers[id]; k > 0 && !seen[k] {
				seen[k] = true
				on = append(on, k)
			}
		}
	}
	return ElsewhereNote(n, on)
}

// ElsewhereNote is the line a control split between attack paths and the
// other findings carries under the other findings: n more of its findings
// are listed under the paths numbered on. "" when n is 0.
func ElsewhereNote(n int, on []int) string {
	if n == 0 {
		return ""
	}
	sort.Ints(on)
	nums := make([]string, len(on))
	for i, k := range on {
		nums[i] = strconv.Itoa(k)
	}
	where := "the attack paths"
	switch len(nums) {
	case 0:
	case 1:
		where = "attack path " + nums[0]
	default:
		where = "attack paths " + strings.Join(nums[:len(nums)-1], ", ") + " and " + nums[len(nums)-1]
	}
	verb := "are"
	if n == 1 {
		verb = "is"
	}
	return fmt.Sprintf("%d more of these %s listed under %s", n, verb, where)
}

// withoutPathIDs filters out every finding findingHasPathIDs reports true
// for against rendered, preserving the input order (the Rego evaluation
// order FindingsByControl already produced).
func withoutPathIDs(findings []opaengine.Finding, rendered map[string]bool) []opaengine.Finding {
	out := make([]opaengine.Finding, 0, len(findings))
	for _, f := range findings {
		if !findingHasPathIDs(f, rendered) {
			out = append(out, f)
		}
	}
	return out
}

// countWithoutPathIDs is withoutPathIDs without the allocation, for the
// otherIssues tally that decides whether the "Individual findings" heading
// renders at all.
func countWithoutPathIDs(findings []opaengine.Finding, rendered map[string]bool) int {
	n := 0
	for _, f := range findings {
		if !findingHasPathIDs(f, rendered) {
			n++
		}
	}
	return n
}

// mrCommentControlOrder drives the per-control detail sections of the MR
// comment, in the same order as the controls table above so the two sections
// align visually.
//
// This list is hand-maintained and a control missing from it has its findings
// SILENTLY dropped from the comment body — the control still shows as failed in
// the table, but with no detail lines under it. That has now happened three
// times (#422, #423, #426), so TestMRCommentOrderCoversEveryGitLabControl
// fails the build when a GitLab control is added without an entry here.
var mrCommentControlOrder = []struct {
	controlName string
	heading     string
}{
	{"containerImageMustNotUseForbiddenTags", "Container images must not use forbidden reference"},
	{"containerImageMustComeFromAuthorizedSources", "Container images must come from authorized sources"},
	{"branchMustBeProtected", "Branch must be protected"},
	{"projectMustHaveSecurityPolicySource", "Project must have a security policy source"},
	{"mergeRequestApprovalRulesMustRequireMinimumApprovals", "MR approval rules must require a minimum number of approvals"},
	{"mergeRequestApprovalRulesMustCoverAllProtectedBranches", "MR approval rules must cover all protected branches"},
	{"mergeRequestApprovalSettingsMustBeCompliant", "MR approval settings must be compliant"},
	{"mergeRequestSettingsMustBeCompliant", "MR settings must be compliant"},
	{"cicdVariablesMustBeProtected", "CI/CD variables must be protected"},
	{"cicdVariablesMustBeMasked", "CI/CD variables must be masked"},
	{"pipelineMustNotIncludeHardcodedJobs", "Pipeline must not include hardcoded jobs"},
	{"externalRefsMustNotCollide", "Includes must not use ambiguous tag/branch refs"},
	{"includesMustBeUpToDate", "Includes must be up to date"},
	{"includesMustNotUseForbiddenVersions", "Includes must not use forbidden versions"},
	{"pipelineMustIncludeComponent", "Pipeline must include required components"},
	{"pipelineMustIncludeTemplate", "Pipeline must include required templates"},
	{"pipelineMustNotEnableDebugTrace", "Pipeline must not enable debug trace"},
	{"pipelineMustNotUseUnsafeVariableExpansion", "Pipeline must not use unsafe variable expansion"},
	{"pipelineMustNotOverrideJobVariables", "Pipeline must not override job variables"},
	{"securityJobsMustNotBeWeakened", "Security jobs must not be weakened"},
	{"pipelineMustNotExecuteUnverifiedScripts", "Pipeline must not execute unverified scripts"},
	{"pipelineMustNotUseDockerInDocker", "Pipeline must not use Docker-in-Docker"},
	{"workflowMustNotInjectUserInputInScripts", "Workflows must not inject user input in scripts"},
	{"workflowMustNotReEnableInsecureCommands", "Workflows must not re-enable insecure commands"},
	{"checkoutMustNotPersistCredentials", "Checkout must not persist credentials"},
	{"workflowMustNotUseDangerousTriggers", "Workflows must not use dangerous triggers"},
	{"pullRequestTargetMustNotCheckoutHead", "pull_request_target workflows must not check out the PR head"},
	{"workflowMustNotGrantPermissionsWriteAll", "Workflow must not grant write-all permissions"},
	{"githubActionMustComeFromAuthorizedSources", "Actions must come from authorized sources"},
}
