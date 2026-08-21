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
) error {
	l := logrus.WithFields(logrus.Fields{
		"action":          "ManageMergeRequestComment",
		"projectID":       projectID,
		"mergeRequestIID": mrIID,
	})

	// Generate comment body
	commentBody := generateMRComment(result, pc, passed, gateLine, score, scoreMode, scorePointMode, conf.ControlsFilter, conf.SkipControlsFilter)

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
func generateMRComment(result *AnalysisResult, pc *configuration.PlumberConfig, passed bool, gateLine string, score *PlumberScoreResult, scoreMode, scorePointMode bool, controlsFilterList, skipControlsList []string) string {
	var b strings.Builder

	// Hidden identifier so we can find this comment later
	b.WriteString(MRCommentIdentifier + "\n")

	// Letter-score badge linking to the score documentation
	if scoreMode && score != nil {
		fmt.Fprintf(&b, "[![Plumber](%s)](%s)\n\n", ScoreBadgeURL(score.Score), PlumberScoreDocURL)
	}

	b.WriteString("*If this merge request is merged, the expected Plumber Score will be as shown above.*\n\n")

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
	// Rego Findings list. A control passes when no finding matches;
	// skipped status comes from .plumber.yaml.
	type controlEntry struct {
		name    string
		issues  int
		skipped bool
	}

	findingsByControl := FindingsByControl(result.Findings)
	var controls []controlEntry
	var totalIssues int

	mrEntries := GitLabControls(pc)
	MarkSkippedByFilter(mrEntries, controlsFilterList, skipControlsList)
	for _, e := range mrEntries {
		count := len(findingsByControl[e.ControlName])
		controls = append(controls, controlEntry{e.DisplayName, count, e.Skipped})
		if !e.Skipped {
			totalIssues += count
		}
	}

	// Controls summary table
	b.WriteString("### Controls\n\n")
	b.WriteString("| Control | Status | Issues |\n")
	b.WriteString("|---------|--------|--------|\n")
	for _, c := range controls {
		if c.skipped {
			fmt.Fprintf(&b, "| %s | _skipped_ | — |\n", c.name)
		} else if c.issues > 0 {
			fmt.Fprintf(&b, "| :x: %s | failed | %d |\n", c.name, c.issues)
		} else {
			fmt.Fprintf(&b, "| :white_check_mark: %s | passed | 0 |\n", c.name)
		}
	}
	b.WriteString("\n")

	// Status line after the table
	if passed {
		fmt.Fprintf(&b, ":white_check_mark: **Plumber check passed** (%s)\n\n", gateLine)
	} else {
		fmt.Fprintf(&b, ":warning: **Plumber check failed** — %s\n\n", gateLine)
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
func writeIssueDetails(b *strings.Builder, result *AnalysisResult) {
	findingsByControl := FindingsByControl(result.Findings)
	for _, g := range mrCommentControlOrder {
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
	{"containerImageMustNotUseForbiddenTags", "Container images must not use forbidden tags"},
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
	{"workflowMustNotInjectUserInputInScripts", "Workflow must not inject user input in scripts"},
	{"workflowMustNotReEnableInsecureCommands", "Workflow must not re-enable insecure commands"},
	{"checkoutMustNotPersistCredentials", "actions/checkout must not persist credentials"},
	{"workflowMustNotUseDangerousTriggers", "Workflow must not use dangerous triggers"},
	{"pullRequestTargetMustNotCheckoutHead", "pull_request_target must not check out the PR head"},
	{"workflowMustNotGrantPermissionsWriteAll", "Workflow must not grant write-all permissions"},
	{"githubActionMustComeFromAuthorizedSources", "Actions must come from authorized sources"},
}
