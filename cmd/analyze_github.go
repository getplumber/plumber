package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
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

	// Binary compliance on the GitHub path for now: pass when there is no
	// finding, fail otherwise. A per-rule compliance model matching the
	// GitLab controls (each control averages its own compliance) will come
	// alongside the CLI threshold flag work.
	compliance := 100.0
	if len(result.Findings) > 0 {
		compliance = 0.0
	}

	if outputFile != "" {
		if err := writeJSONToFile(result, conf.PlumberConfig, threshold, compliance, outputFile, scoreResult, scoreMode); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Results written to: %s\n", outputFile)
	}

	if printOutput {
		printGitHubFindings(result, compliance)
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
func printGitHubFindings(result *control.AnalysisResult, overallCompliance float64) {
	fmt.Printf("\n%s %s\n\n", styleTitle.Render("Project:"), result.ProjectPath)

	if !result.CiValid {
		fmt.Printf("  %s\n", styleDim.Render("No GitHub Actions workflows discovered."))
		return
	}

	renderFindingGroups(findingGroupsFromRegoFindings(result.Findings))

	summaries := summariesFromFindings(result.Findings)
	if len(summaries) == 0 {
		fmt.Printf("  %s\n\n", styleSuccess.Render("✓ No findings. All policies pass."))
		return
	}

	printIssuesTable(summaries)
	fmt.Println()
	printComplianceTable(summaries, overallCompliance, 100)
}

// summariesFromFindings projects the Rego engine's flat list of
// findings onto the same []controlSummary shape the GitLab path builds
// from its legacy Go controls. Findings are grouped by the ControlName
// advertised in the issue-code registry; each summary reports one
// entry per policy that produced at least one finding, with a
// per-policy compliance of 0 (binary model on the GitHub side).
func summariesFromFindings(findings []opaengine.Finding) []controlSummary {
	byControl := map[string]*controlSummary{}
	for _, f := range findings {
		info := control.LookupCode(control.ErrorCode(f.Code))
		name := f.Code
		if info != nil && info.ControlName != "" {
			name = info.ControlName
		}
		sum, ok := byControl[name]
		if !ok {
			sum = &controlSummary{name: name, compliance: 0}
			byControl[name] = sum
		}
		sum.issues++
		if !containsString(sum.codes, f.Code) {
			sum.codes = append(sum.codes, f.Code)
		}
		switch control.SeverityForCode(control.ErrorCode(f.Code)) {
		case control.SeverityCritical:
			sum.bySeverity.Critical++
		case control.SeverityHigh:
			sum.bySeverity.High++
		case control.SeverityMedium:
			sum.bySeverity.Medium++
		case control.SeverityLow:
			sum.bySeverity.Low++
		}
	}

	out := make([]controlSummary, 0, len(byControl))
	for _, s := range byControl {
		sort.Strings(s.codes)
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func containsString(s []string, v string) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}
	return false
}
