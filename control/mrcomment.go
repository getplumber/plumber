package control

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	"github.com/sirupsen/logrus"
)

const (
	// MRCommentIdentifier is an invisible HTML comment used to find the Plumber
	// comment in the merge request notes so it can be updated on subsequent runs.
	MRCommentIdentifier = "<!-- Plumber Compliance Comment -->"
)

// ManageMergeRequestComment creates or updates the Plumber compliance comment
// on the given merge request. projectID and gitlabURL come from the already-
// resolved configuration/result; only mrIID is CI-specific.
func ManageMergeRequestComment(
	projectID int,
	mrIID int,
	result *AnalysisResult,
	pc *configuration.PlumberConfig,
	compliance float64,
	threshold float64,
	conf *configuration.Configuration,
	score *PlumberScoreResult,
	scoreMode bool,
	scorePointMode bool,
) error {
	l := logrus.WithFields(logrus.Fields{
		"action":          "ManageMergeRequestComment",
		"projectID":       projectID,
		"mergeRequestIID": mrIID,
	})

	// Generate comment body
	commentBody := generateMRComment(result, pc, compliance, threshold, score, scoreMode, scorePointMode, conf.ControlsFilter, conf.SkipControlsFilter)

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

// ComplianceBadgeURL builds a Shields.io badge URL for the given compliance %.
// Color is green if compliance meets threshold, red otherwise.
// Exported so it can be used by the project badge feature.
func ComplianceBadgeURL(compliance, threshold float64) string {
	pct := fmt.Sprintf("%.1f%%", compliance)
	color := "red"
	if compliance >= threshold {
		color = "brightgreen"
	}
	message := strings.ReplaceAll(pct, "%", "%25")
	return fmt.Sprintf("https://img.shields.io/badge/Plumber-%s-%s", message, color)
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
func generateMRComment(result *AnalysisResult, pc *configuration.PlumberConfig, compliance, threshold float64, score *PlumberScoreResult, scoreMode, scorePointMode bool, controlsFilterList, skipControlsList []string) string {
	var b strings.Builder

	// Hidden identifier so we can find this comment later
	b.WriteString(MRCommentIdentifier + "\n")

	// Compliance badge (green if passed, red if failed)
	passed := compliance >= threshold
	badgeURL := ComplianceBadgeURL(compliance, threshold)
	if scoreMode && score != nil {
		badgeURL = ScoreBadgeURL(score.Score)
		fmt.Fprintf(&b, "[![Plumber](%s)](%s)\n\n", badgeURL, PlumberScoreDocURL)
	} else {
		fmt.Fprintf(&b, "![Plumber](%s)\n\n", badgeURL)
	}

	b.WriteString("*If this merge request is merged, the expected pipeline compliance will be as shown above.*\n\n")

	if scorePointMode && score != nil {
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
	} else if scoreMode && score != nil {
		b.WriteString("### Plumber Score\n\n")
		fmt.Fprintf(&b, "- **Score:** **%s**\n\n", score.Score)
	}

	// Gather controls from the config-driven catalog joined with the
	// Rego Findings list. Compliance is binary per control (100% when
	// no finding matches, 0% otherwise); skipped status comes from
	// .plumber.yaml.
	type controlEntry struct {
		name       string
		compliance float64
		issues     int
		skipped    bool
	}

	findingsByControl := FindingsByControl(result.Findings)
	var controls []controlEntry
	var totalIssues int

	mrEntries := GitLabControls(pc)
	MarkSkippedByFilter(mrEntries, controlsFilterList, skipControlsList)
	for _, e := range mrEntries {
		count := len(findingsByControl[e.ControlName])
		ctrlCompliance := 100.0
		if !e.Skipped && count > 0 {
			ctrlCompliance = 0.0
		}
		controls = append(controls, controlEntry{e.DisplayName, ctrlCompliance, count, e.Skipped})
		if !e.Skipped {
			totalIssues += count
		}
	}

	// Controls summary table
	b.WriteString("### Controls\n\n")
	b.WriteString("| Control | Compliance | Issues |\n")
	b.WriteString("|---------|-----------|--------|\n")
	for _, c := range controls {
		if c.skipped {
			fmt.Fprintf(&b, "| %s | _skipped_ | — |\n", c.name)
		} else {
			icon := ":white_check_mark:"
			if c.compliance < 100 {
				icon = ":x:"
			}
			fmt.Fprintf(&b, "| %s %s | %.1f%% | %d |\n", icon, c.name, c.compliance, c.issues)
		}
	}
	b.WriteString("\n")

	// Status line after the table
	if passed {
		fmt.Fprintf(&b, ":white_check_mark: **Compliance: %.1f%%** meets threshold (%.0f%%)\n\n", compliance, threshold)
	} else {
		fmt.Fprintf(&b, ":warning: **Compliance: %.1f%%** is below threshold (%.0f%%)\n\n", compliance, threshold)
	}

	// Issue details as a normal section
	if totalIssues > 0 {
		b.WriteString("### Issues\n\n")
		writeIssueDetails(&b, result)
	}

	// Footer
	b.WriteString("---\n")
	b.WriteString("*Automatically posted by [Plumber](https://getplumber.io) — do not edit manually.*\n")

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
	const escaped = "\\`*_[]()<>|~"
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
func writeIssueDetails(b *strings.Builder, result *AnalysisResult) {
	findingsByControl := FindingsByControl(result.Findings)
	// Emit groups in the registry order (the same order used by the
	// controls table above) so the two sections align visually.
	order := []struct {
		controlName string
		heading     string
	}{
		{"containerImageMustNotUseForbiddenTags", "Container images must not use forbidden tags"},
		{"containerImageMustComeFromAuthorizedSources", "Container images must come from authorized sources"},
		{"branchMustBeProtected", "Branch must be protected"},
		{"pipelineMustNotIncludeHardcodedJobs", "Pipeline must not include hardcoded jobs"},
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
		{"workflowMustNotInjectUserInputInScripts", "Workflow must not inject user input in scripts"},
		{"workflowMustNotReEnableInsecureCommands", "Workflow must not re-enable insecure commands"},
		{"checkoutMustNotPersistCredentials", "actions/checkout must not persist credentials"},
		{"workflowMustNotUseDangerousTriggers", "Workflow must not use dangerous triggers"},
		{"pullRequestTargetMustNotCheckoutHead", "pull_request_target must not check out the PR head"},
		{"workflowMustNotGrantPermissionsWriteAll", "Workflow must not grant write-all permissions"},
		{"githubActionMustComeFromAuthorizedSources", "Actions must come from authorized sources"},
	}
	for _, g := range order {
		findings := findingsByControl[g.controlName]
		if len(findings) == 0 {
			continue
		}
		fmt.Fprintf(b, "**%s:**\n", g.heading)
		for _, f := range findings {
			docURL := ErrorCode(f.Code).DocURL()
			fmt.Fprintf(b, "- `%s` %s ([docs](%s))\n", f.Code, sanitizeMarkdownInline(f.Message), docURL)
		}
		b.WriteString("\n")
	}
}
