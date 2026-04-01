package control

import (
	"fmt"
	"strings"

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
	compliance float64,
	threshold float64,
	conf *configuration.Configuration,
) error {
	l := logrus.WithFields(logrus.Fields{
		"action":          "ManageMergeRequestComment",
		"projectID":       projectID,
		"mergeRequestIID": mrIID,
	})

	// Generate comment body
	commentBody := generateMRComment(result, compliance, threshold)

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

// generateMRComment builds the Markdown body for the merge request comment
// based on the analysis result.
func generateMRComment(result *AnalysisResult, compliance, threshold float64) string {
	var b strings.Builder

	// Hidden identifier so we can find this comment later
	b.WriteString(MRCommentIdentifier + "\n")

	// Compliance badge (green if passed, red if failed)
	passed := compliance >= threshold
	badgeURL := ComplianceBadgeURL(compliance, threshold)
	fmt.Fprintf(&b, "![Plumber](%s)\n\n", badgeURL)

	b.WriteString("*If this merge request is merged, the expected pipeline compliance will be as shown above.*\n\n")

	// Gather controls
	type controlEntry struct {
		name       string
		compliance float64
		issues     int
		skipped    bool
	}

	var controls []controlEntry
	var totalIssues int

	if r := result.ImageForbiddenTagsResult; r != nil {
		name := "Container images must not use forbidden tags"
		if r.MustBePinnedByDigest {
			name = "Container images must be pinned by digest"
		}
		controls = append(controls, controlEntry{name, r.Compliance, len(r.Issues), r.Skipped})
		if !r.Skipped {
			totalIssues += len(r.Issues)
		}
	}
	if r := result.ImageAuthorizedSourcesResult; r != nil {
		controls = append(controls, controlEntry{"Container images must come from authorized sources", r.Compliance, len(r.Issues), r.Skipped})
		if !r.Skipped {
			totalIssues += len(r.Issues)
		}
	}
	if r := result.BranchProtectionResult; r != nil {
		controls = append(controls, controlEntry{"Branch must be protected", r.Compliance, len(r.Issues), r.Skipped})
		if !r.Skipped {
			totalIssues += len(r.Issues)
		}
	}
	if r := result.HardcodedJobsResult; r != nil {
		controls = append(controls, controlEntry{"Pipeline must not include hardcoded jobs", r.Compliance, len(r.Issues), r.Skipped})
		if !r.Skipped {
			totalIssues += len(r.Issues)
		}
	}
	if r := result.OutdatedIncludesResult; r != nil {
		controls = append(controls, controlEntry{"Includes must be up to date", r.Compliance, len(r.Issues), r.Skipped})
		if !r.Skipped {
			totalIssues += len(r.Issues)
		}
	}
	if r := result.ForbiddenVersionsIncludesResult; r != nil {
		controls = append(controls, controlEntry{"Includes must not use forbidden versions", r.Compliance, len(r.Issues), r.Skipped})
		if !r.Skipped {
			totalIssues += len(r.Issues)
		}
	}
	if r := result.RequiredComponentsResult; r != nil {
		issueCount := len(r.Issues) + len(r.OverriddenIssues)
		controls = append(controls, controlEntry{"Pipeline must include required components", r.Compliance, issueCount, r.Skipped})
		if !r.Skipped {
			totalIssues += issueCount
		}
	}
	if r := result.RequiredTemplatesResult; r != nil {
		issueCount := len(r.Issues) + len(r.OverriddenIssues)
		controls = append(controls, controlEntry{"Pipeline must include required templates", r.Compliance, issueCount, r.Skipped})
		if !r.Skipped {
			totalIssues += issueCount
		}
	}
	if r := result.DebugTraceResult; r != nil {
		controls = append(controls, controlEntry{"Pipeline must not enable debug trace", r.Compliance, len(r.Issues), r.Skipped})
		if !r.Skipped {
			totalIssues += len(r.Issues)
		}
	}
	if r := result.VariableInjectionResult; r != nil {
		controls = append(controls, controlEntry{"Pipeline must not use unsafe variable expansion", r.Compliance, len(r.Issues), r.Skipped})
		if !r.Skipped {
			totalIssues += len(r.Issues)
		}
	}
	if r := result.SecurityJobsWeakenedResult; r != nil {
		controls = append(controls, controlEntry{"Security jobs must not be weakened", r.Compliance, len(r.Issues), r.Skipped})
		if !r.Skipped {
			totalIssues += len(r.Issues)
		}
	}
	if r := result.UnverifiedScriptsResult; r != nil {
		controls = append(controls, controlEntry{"Pipeline must not execute unverified scripts", r.Compliance, len(r.Issues), r.Skipped})
		if !r.Skipped {
			totalIssues += len(r.Issues)
		}
	}
	if r := result.JobVariablesOverrideResult; r != nil {
		controls = append(controls, controlEntry{"Pipeline must not override job variables", r.Compliance, len(r.Issues), r.Skipped})
		if !r.Skipped {
			totalIssues += len(r.Issues)
		}
	}
	if r := result.DockerInDockerResult; r != nil {
		controls = append(controls, controlEntry{"Pipeline must not use Docker-in-Docker", r.Compliance, len(r.Issues), r.Skipped})
		if !r.Skipped {
			totalIssues += len(r.Issues)
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

// writeIssueDetails appends per-control issue details into the builder.
func writeIssueDetails(b *strings.Builder, result *AnalysisResult) {
	// Forbidden tags / digest pinning
	if r := result.ImageForbiddenTagsResult; r != nil && !r.Skipped && len(r.Issues) > 0 {
		if r.MustBePinnedByDigest {
			b.WriteString("**Container images must be pinned by digest:**\n")
			for _, issue := range r.Issues {
				fmt.Fprintf(b, "- `%s` Job `%s`: image `%s` is not pinned by digest ([docs](%s))\n", issue.Code, issue.Job, issue.Link, issue.DocURL)
			}
		} else {
			b.WriteString("**Container images must not use forbidden tags:**\n")
			for _, issue := range r.Issues {
				fmt.Fprintf(b, "- `%s` Job `%s`: image `%s` uses forbidden tag `%s` ([docs](%s))\n", issue.Code, issue.Job, issue.Link, issue.Tag, issue.DocURL)
			}
		}
		b.WriteString("\n")
	}

	// Unauthorized images
	if r := result.ImageAuthorizedSourcesResult; r != nil && !r.Skipped && len(r.Issues) > 0 {
		b.WriteString("**Container images must come from authorized sources:**\n")
		for _, issue := range r.Issues {
			fmt.Fprintf(b, "- `%s` Job `%s`: unauthorized image `%s` ([docs](%s))\n", issue.Code, issue.Job, issue.Link, issue.DocURL)
		}
		b.WriteString("\n")
	}

	// Branch protection
	if r := result.BranchProtectionResult; r != nil && !r.Skipped && len(r.Issues) > 0 {
		b.WriteString("**Branch must be protected:**\n")
		for _, issue := range r.Issues {
			if issue.Type == "unprotected" {
				fmt.Fprintf(b, "- `%s` Branch `%s` is not protected ([docs](%s))\n", issue.Code, issue.BranchName, issue.DocURL)
			} else {
				fmt.Fprintf(b, "- `%s` Branch `%s` has non-compliant protection settings ([docs](%s))\n", issue.Code, issue.BranchName, issue.DocURL)
			}
		}
		b.WriteString("\n")
	}

	// Hardcoded jobs
	if r := result.HardcodedJobsResult; r != nil && !r.Skipped && len(r.Issues) > 0 {
		b.WriteString("**Pipeline must not include hardcoded jobs:**\n")
		for _, issue := range r.Issues {
			fmt.Fprintf(b, "- `%s` Job `%s` is hardcoded (not from include/component) ([docs](%s))\n", issue.Code, issue.JobName, issue.DocURL)
		}
		b.WriteString("\n")
	}

	// Outdated includes
	if r := result.OutdatedIncludesResult; r != nil && !r.Skipped && len(r.Issues) > 0 {
		b.WriteString("**Includes must be up to date:**\n")
		for _, issue := range r.Issues {
			fmt.Fprintf(b, "- `%s` `%s` uses version `%s` (latest: `%s`) ([docs](%s))\n", issue.Code, issue.GitlabIncludeLocation, issue.Version, issue.LatestVersion, issue.DocURL)
		}
		b.WriteString("\n")
	}

	// Forbidden versions
	if r := result.ForbiddenVersionsIncludesResult; r != nil && !r.Skipped && len(r.Issues) > 0 {
		b.WriteString("**Includes must not use forbidden versions:**\n")
		for _, issue := range r.Issues {
			fmt.Fprintf(b, "- `%s` `%s` uses forbidden version `%s` ([docs](%s))\n", issue.Code, issue.GitlabIncludeLocation, issue.Version, issue.DocURL)
		}
		b.WriteString("\n")
	}

	// Required components
	if r := result.RequiredComponentsResult; r != nil && !r.Skipped && (len(r.Issues) > 0 || len(r.OverriddenIssues) > 0) {
		b.WriteString("**Pipeline must include required components:**\n")
		for _, issue := range r.Issues {
			fmt.Fprintf(b, "- `%s` Missing component `%s` (group %d) ([docs](%s))\n", issue.Code, issue.ComponentPath, issue.GroupIndex+1, issue.DocURL)
		}
		for _, issue := range r.OverriddenIssues {
			fmt.Fprintf(b, "- `%s` Overridden component `%s` (group %d) ([docs](%s))\n", issue.Code, issue.ComponentPath, issue.GroupIndex+1, issue.DocURL)
			for _, job := range issue.OverriddenJobs {
				fmt.Fprintf(b, "  - job `%s` overrides: `%s`\n", job.JobName, strings.Join(job.OverriddenKeys, "`, `"))
			}
		}
		b.WriteString("\n")
	}

	// Required templates
	if r := result.RequiredTemplatesResult; r != nil && !r.Skipped && (len(r.Issues) > 0 || len(r.OverriddenIssues) > 0) {
		b.WriteString("**Pipeline must include required templates:**\n")
		for _, issue := range r.Issues {
			fmt.Fprintf(b, "- `%s` Missing template `%s` (group %d) ([docs](%s))\n", issue.Code, issue.TemplatePath, issue.GroupIndex+1, issue.DocURL)
		}
		for _, issue := range r.OverriddenIssues {
			fmt.Fprintf(b, "- `%s` Overridden template `%s` (group %d) ([docs](%s))\n", issue.Code, issue.TemplatePath, issue.GroupIndex+1, issue.DocURL)
			for _, job := range issue.OverriddenJobs {
				fmt.Fprintf(b, "  - job `%s` overrides: `%s`\n", job.JobName, strings.Join(job.OverriddenKeys, "`, `"))
			}
		}
		b.WriteString("\n")
	}

	// Debug trace
	if r := result.DebugTraceResult; r != nil && !r.Skipped && len(r.Issues) > 0 {
		b.WriteString("**Pipeline must not enable debug trace:**\n")
		for _, issue := range r.Issues {
			if issue.Location == "global" {
				fmt.Fprintf(b, "- `%s` `%s` = `%s` in global variables ([docs](%s))\n", issue.Code, issue.VariableName, issue.Value, issue.DocURL)
			} else {
				fmt.Fprintf(b, "- `%s` `%s` = `%s` in job `%s` ([docs](%s))\n", issue.Code, issue.VariableName, issue.Value, issue.Location, issue.DocURL)
			}
		}
		b.WriteString("\n")
	}

	// Variable injection
	if r := result.VariableInjectionResult; r != nil && !r.Skipped && len(r.Issues) > 0 {
		b.WriteString("**Pipeline must not use unsafe variable expansion:**\n")
		for _, issue := range r.Issues {
			if issue.JobName == "(global)" {
				fmt.Fprintf(b, "- `$%s` used in global `%s`: `%s`\n", issue.VariableName, issue.ScriptBlock, issue.ScriptLine)
			} else {
				fmt.Fprintf(b, "- `$%s` used in job `%s` `%s`: `%s`\n", issue.VariableName, issue.JobName, issue.ScriptBlock, issue.ScriptLine)
			}
		}
		b.WriteString("\n")
	}

	// Security jobs weakened
	if r := result.SecurityJobsWeakenedResult; r != nil && !r.Skipped && len(r.Issues) > 0 {
		b.WriteString("**Security jobs must not be weakened:**\n")
		for _, issue := range r.Issues {
			fmt.Fprintf(b, "- `%s` Job `%s`: %s ([docs](%s))\n", issue.Code, issue.JobName, issue.Detail, issue.DocURL)
		}
		b.WriteString("\n")
	}

	// Unverified script execution
	if r := result.UnverifiedScriptsResult; r != nil && !r.Skipped && len(r.Issues) > 0 {
		b.WriteString("**Pipeline must not execute unverified scripts:**\n")
		for _, issue := range r.Issues {
			if issue.JobName == "(global)" {
				fmt.Fprintf(b, "- `%s` Global `%s`: `%s` ([docs](%s))\n", issue.Code, issue.ScriptBlock, issue.ScriptLine, issue.DocURL)
			} else {
				fmt.Fprintf(b, "- `%s` Job `%s` `%s`: `%s` ([docs](%s))\n", issue.Code, issue.JobName, issue.ScriptBlock, issue.ScriptLine, issue.DocURL)
			}
		}
		b.WriteString("\n")
	}

	// Docker-in-Docker
	if r := result.DockerInDockerResult; r != nil && !r.Skipped && len(r.Issues) > 0 {
		b.WriteString("**Pipeline must not use Docker-in-Docker:**\n")
		for _, issue := range r.Issues {
			if issue.Code == CodeDockerInDockerUsage {
				fmt.Fprintf(b, "- `%s` Job `%s` uses DinD service: `%s` ([docs](%s))\n", issue.Code, issue.JobName, issue.ServiceImage, issue.DocURL)
			} else {
				fmt.Fprintf(b, "- `%s` Job `%s`: %s ([docs](%s))\n", issue.Code, issue.JobName, issue.Detail, issue.DocURL)
			}
		}
		b.WriteString("\n")
	}

	// Job variable overrides
	if r := result.JobVariablesOverrideResult; r != nil && !r.Skipped && len(r.Issues) > 0 {
		b.WriteString("**Pipeline must not override job variables:**\n")
		for _, issue := range r.Issues {
			if issue.Location == "global" {
				fmt.Fprintf(b, "- `%s` `%s` = `%s` in global variables ([docs](%s))\n", issue.Code, issue.VariableName, issue.Value, issue.DocURL)
			} else {
				fmt.Fprintf(b, "- `%s` `%s` = `%s` in job `%s` ([docs](%s))\n", issue.Code, issue.VariableName, issue.Value, issue.Location, issue.DocURL)
			}
		}
		b.WriteString("\n")
	}
}
