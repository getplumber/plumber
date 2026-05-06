package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// runGitHubAnalyze handles `plumber analyze` for GitHub-hosted projects.
// Local-only MVP: walks .github/workflows/*.{yml,yaml} under the detected
// git repo root, evaluates the embedded Rego policies, and prints /
// writes the resulting findings. No GitHub API call, no token required.
//
// Returns an error (exit code 1) when at least one finding is reported,
// so the command can gate CI pipelines without any threshold flag.
func runGitHubAnalyze(cmd *cobra.Command, info *utils.GitRemoteInfo) error {
	fmt.Fprintf(os.Stderr, "Auto-detected GitHub project: %s\n", info.ProjectPath)

	plumberConfig, configPath, configWarnings, err := configuration.LoadPlumberConfig(configFile)
	if err != nil {
		if strings.Contains(err.Error(), "config file not found") {
			return fmt.Errorf("configuration file not found: %w. Create one with `plumber config generate` or `plumber config init`", err)
		}
		return fmt.Errorf("configuration error: %w", err)
	}
	if len(configWarnings) > 0 {
		fmt.Fprintf(os.Stderr, "Configuration validation warnings:\n")
		for _, w := range configWarnings {
			fmt.Fprintf(os.Stderr, "  - %s\n", w)
		}
		if failWarnings {
			return fmt.Errorf("configuration has %d warning(s) and --fail-warnings is set", len(configWarnings))
		}
	}
	fmt.Fprintf(os.Stderr, "Using configuration: %s\n", configPath)

	if printOutput {
		printBanner()
	}

	conf := configuration.NewDefaultConfiguration()
	conf.ProjectPath = info.ProjectPath
	conf.GitRepoRoot = info.RepoRoot
	conf.Branch = defaultBranch
	conf.PlumberConfig = plumberConfig
	// Optional GHES override. Empty = default api.github.com.
	conf.GithubAPIHost = strings.TrimPrefix(strings.TrimPrefix(githubURL, "https://"), "http://")
	if verbose {
		conf.LogLevel = logrus.DebugLevel
	}

	fmt.Fprintf(os.Stderr, "Scanning workflows under: %s\n", info.RepoRoot)

	// Progress spinner — mirrors the GitLab path. Only installed
	// when we are printing to stdout and not running verbose (the
	// spinner races with log lines in verbose mode).
	sp := newSpinner()
	if printOutput && !verbose {
		conf.ProgressFunc = func(step, total int, message string) {
			sp.Update(step, total, message)
		}
		sp.InstallLogHook()
		sp.Start()
	}

	result, err := control.RunGitHubAnalysis(conf)
	sp.Stop()
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Compute the Plumber letter score on demand. The pipeline
	// (AggregateSeverityCounts → ComputePlumberScore) is the same one
	// used on GitLab, so the letter is definition-compatible across
	// providers.
	scoreMode := showScore || showScorePoint
	var scoreResult *control.PlumberScoreResult
	if scoreMode {
		counts := control.AggregateSeverityCounts(result)
		s := control.ComputePlumberScore(counts)
		scoreResult = &s
	}

	// Per-control compliance averaging — same model as GitLab. The
	// overall percentage is the mean of every shipping control's own
	// compliance (skipped controls don't count toward the denominator).
	findingsByControl := control.FindingsByControl(result.Findings)
	entries := control.GitHubControls(plumberConfig)
	totalPct := 0.0
	considered := 0
	for _, e := range entries {
		if e.Skipped {
			continue
		}
		comp := gitHubControlCompliance(e.ControlName, result.GitHubStats, len(findingsByControl[e.ControlName]))
		totalPct += comp
		considered++
	}
	compliance := 100.0
	if considered > 0 {
		compliance = totalPct / float64(considered)
	}

	if outputFile != "" {
		if err := writeJSONToFile(result, conf.PlumberConfig, threshold, compliance, outputFile, scoreResult, scoreMode); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Results written to: %s\n", outputFile)
	}

	if printOutput {
		printGitHubFindings(result, plumberConfig, compliance)
		printSummaryScoreBanner(scoreResult, scoreMode)
		if showScorePoint {
			printScoreBreakdown(scoreResult)
		}
	}

	if len(result.Findings) > 0 {
		return &ComplianceError{Compliance: compliance, Threshold: threshold}
	}
	return nil
}

// printGitHubFindings writes the GitHub analyze output in the same
// visual style as the GitLab path: project header, a per-rule detail
// block for each rule that produced findings, a controls summary
// table, a compliance table with a total line. Detail rendering is
// delegated to the shared renderFindingGroups so the visual contract
// is identical across providers.
func printGitHubFindings(result *control.AnalysisResult, pc *configuration.PlumberConfig, overallCompliance float64) {
	fmt.Printf("\n%s %s\n\n", styleTitle.Render("Project:"), result.ProjectPath)

	if !result.CiValid {
		fmt.Printf("  %s\n", styleDim.Render("No GitHub Actions workflows discovered."))
		return
	}

	// Same shape as GitLab: build an ordered list of (catalog entry,
	// findings, stats) tuples so renderFindingGroups + the Issues +
	// Compliance tables all see the full set of shipping controls,
	// not just the ones with findings.
	findingsByControl := control.FindingsByControl(result.Findings)
	entries := control.GitHubControls(pc)
	groups := make([]findingGroup, 0, len(entries))
	summaries := make([]controlSummary, 0, len(entries))
	for _, e := range entries {
		findings := findingsByControl[e.ControlName]
		codes := make([]control.ErrorCode, 0, len(findings))
		items := make([]detailedFinding, 0, len(findings))
		for _, f := range findings {
			code := control.ErrorCode(f.Code)
			codes = append(codes, code)
			items = append(items, detailedFinding{
				Code:        code,
				Message:     f.Message,
				DocURL:      code.DocURL(),
				Location:    formatFindingLocation(f),
				DetailLines: detailLinesFromFinding(f),
			})
		}
		comp := gitHubControlCompliance(e.ControlName, result.GitHubStats, len(items))
		if e.Skipped {
			comp = 100
		}
		summaries = append(summaries, controlSummary{
			name:       e.DisplayName,
			compliance: comp,
			issues:     len(items),
			skipped:    e.Skipped,
			codes:      uniqueSortedIssueCodeStrings(codes),
			bySeverity: control.SeverityCountsFromIssueCodes(codes),
		})
		groups = append(groups, findingGroup{
			Title:      e.DisplayName,
			Compliance: comp,
			Skipped:    e.Skipped,
			Stats:      buildGitHubControlStats(e.ControlName, result.GitHubStats),
			Findings:   items,
		})
	}
	renderFindingGroups(groups)

	if len(result.Findings) == 0 {
		fmt.Printf("  %s\n\n", styleSuccess.Render("✓ No findings. All policies pass."))
	}

	printIssuesTable(summaries)
	fmt.Println()
	printComplianceTable(summaries, overallCompliance, 100)
}


