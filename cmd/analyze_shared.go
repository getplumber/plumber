package cmd

import (
	"fmt"
	"os"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/provider"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func init() {
	// Register provider stats builders here to avoid import cycles:
	// provider/ cannot import cmd/, so cmd/ pushes the builders in.
	provider.RegisterStatsBuilder("gitlab", func(controlName string, result *control.AnalysisResult, pc *configuration.PlumberConfig, findings []opaengine.Finding) []control.StatLine {
		return buildGitLabControlStats(controlName, result, pc, findings)
	})
	provider.RegisterStatsBuilder("github", func(controlName string, result *control.AnalysisResult, pc *configuration.PlumberConfig, findings []opaengine.Finding) []control.StatLine {
		return buildGitHubControlStats(controlName, result.GitHubStats, findings)
	})
}

// runWithProvider executes the full analysis + output pipeline for any registered
// provider, replacing the per-provider if/switch chains in runAnalyze.
func runWithProvider(p provider.Provider, cmd *cobra.Command, conf *configuration.Configuration, controlsFilterList, skipControlsList []string) error {
	sp := installSpinner(conf)
	result, err := p.Run(conf)
	sp.Stop()
	if err != nil {
		return err
	}

	newLocationLinker(conf, result, p.Name()).Annotate(result.Findings)

	summary := buildComplianceSummary(p, result, conf)

	if printOutput {
		if err := outputTextWithProvider(p, result, conf, summary, controlsFilterList, skipControlsList); err != nil {
			return err
		}
	}

	if err := writeOutputsWithProvider(p, result, conf, summary); err != nil {
		return err
	}

	handleScorePublishing(p, conf, result, summary)

	pas := provider.PostActionSummary{
		Passed:     summary.passed(),
		GateLine:   summary.gateLine(),
		Score:      summary.score,
		ScoreMode:  summary.scoreMode,
		ScorePoint: summary.scorePoint,
	}
	if err := p.PostAnalysisActions(cmd, result, conf, pas); err != nil {
		return err
	}

	return finalizeRun(result, summary)
}

// buildComplianceSummary assembles the gate inputs for a run: the Plumber
// Score (the default gate), the score-gate flags, and — only to serve the
// deprecated --threshold gate — the legacy passing-controls percentage.
func buildComplianceSummary(p provider.Provider, result *control.AnalysisResult, conf *configuration.Configuration) complianceSummary {
	compliance, controlCount := p.ComputeCompliance(result, conf)
	scoreMode := true // the score banner is shown by default (#218); --score is a no-op
	return complianceSummary{
		compliance:   compliance,
		controlCount: controlCount,
		threshold:    threshold,
		thresholdSet: thresholdSet,
		minPoints:    minPoints,
		minPointsSet: minPointsSet,
		minScore:     minScore,
		score:        computeScoreResult(result, scoreMode),
		scoreMode:    scoreMode,
		scorePoint:   showScorePoint,
	}
}

// outputTextWithProvider renders terminal output using the provider's catalog
// and stats builder — the shared path for both GitLab and GitHub.
func outputTextWithProvider(p provider.Provider, result *control.AnalysisResult, conf *configuration.Configuration, s complianceSummary, controlsFilterList, skipControlsList []string) error {
	renderRunHeader(p, result, conf)

	if s.controlCount == 0 {
		printNoControlsWarning(result)
	}
	if result.DataCollectionDegraded {
		renderDegradedCaveat(result.DegradedReasons)
	}

	controls, groups := buildProviderControlSummariesAndGroups(p, result, conf, controlsFilterList, skipControlsList)
	// On a degraded run the per-control verdict is untrustworthy; render only
	// the findings we DID surface (a real violation on partial data is still
	// real) and drop the green stat blocks (#220).
	renderFindingGroups(filterGroupsForDegraded(groups, result.DataCollectionDegraded))
	renderWarnings(result.Warnings)

	printSectionHeader("Summary")
	fmt.Println()

	if crit := control.CriticalIssueCodesSorted(result); len(crit) > 0 {
		fmt.Printf("  %s▶ Critical issue codes:%s %s\n", colorRed, colorReset, joinStrings(crit))
		fmt.Println()
	}

	switch {
	case result.DataCollectionDegraded:
		fmt.Printf("  Status: %s%sINCOMPLETE — data collection failed%s\n\n", colorBold, colorYellow, colorReset)
	case s.passed():
		fmt.Printf("  Status: %s%sPASSED ✓%s %s(%s)%s\n\n", colorBold, colorGreen, colorReset, colorDim, s.gateLine(), colorReset)
	default:
		fmt.Printf("  Status: %s%sFAILED ✗%s %s(%s)%s\n\n", colorBold, colorRed, colorReset, colorDim, s.gateLine(), colorReset)
	}

	// On a degraded run suppress the issues table when empty (it would imply a
	// clean pipeline we never evaluated) and the score, which would present
	// partial data as a verdict (#220).
	if !result.DataCollectionDegraded || len(result.Findings) > 0 {
		printIssuesTable(controls)
		fmt.Println()
	}

	printSummaryScoreBanner(s.score, s.scoreMode, result.DataCollectionDegraded)
	if s.scorePoint && s.score != nil && !result.DataCollectionDegraded {
		printScoreBreakdown(s.score)
	}
	return nil
}

// buildProviderControlSummariesAndGroups builds the control summary and finding
// group slices for any provider using the provider's catalog and registered
// stats builder.
func buildProviderControlSummariesAndGroups(p provider.Provider, result *control.AnalysisResult, conf *configuration.Configuration, controlsFilterList, skipControlsList []string) ([]controlSummary, []findingGroup) {
	findingsByControl := control.FindingsByControl(result.Findings)
	entries := p.Controls(conf.PlumberConfig)
	control.MarkSkippedByFilter(entries, controlsFilterList, skipControlsList)
	dataCollectionFailed := !result.CiValid && !result.CiMissing

	controls := make([]controlSummary, 0, len(entries))
	groups := make([]findingGroup, 0, len(entries))
	for _, e := range entries {
		findings := findingsByControl[e.ControlName]
		if e.ControlName == "branchMustBeProtected" {
			sortBranchProtectionFindingsForDisplay(findings)
		}
		codes, items := findingsToItems(findings)
		skipped := e.Skipped || dataCollectionFailed
		stats := provider.BuildControlStats(p.Name(), e.ControlName, result, conf.PlumberConfig, findings)
		controls = append(controls, controlSummary{
			name:       e.DisplayName,
			issues:     len(items),
			skipped:    skipped,
			codes:      uniqueSortedIssueCodeStrings(codes),
			bySeverity: control.SeverityCountsFromIssueCodes(codes),
		})
		groups = append(groups, findingGroup{
			Title:      e.DisplayName,
			Skipped:    skipped,
			SkipReason: e.SkipReason,
			Stats:      stats,
			Findings:   items,
		})
	}
	return controls, groups
}

// writeOutputsWithProvider writes all requested artifact files (JSON, PBOM,
// CycloneDX, SARIF, GitLab SAST) using the provider's writers.
func writeOutputsWithProvider(p provider.Provider, result *control.AnalysisResult, conf *configuration.Configuration, s complianceSummary) error {
	// Artifacts are still written on a degraded run (they are files the user
	// asked for, and the exit-3 gate, not the file's absence, protects CI).
	// Each format stamps itself degraded; warn so a partial report is not
	// mistaken for authoritative (#220).
	if result.DataCollectionDegraded && (outputFile != "" || pbomFile != "" || pbomCycloneDXFile != "" || sarifFile != "" || glsastFile != "" || csvFile != "") {
		fmt.Fprintf(os.Stderr, "Note: data collection was incomplete — artifacts are written but marked degraded; treat them as partial.\n")
	}
	if outputFile != "" {
		params := jsonOutputParams{filePath: outputFile, provider: p.Name(), includeOnly: conf.ControlsFilter, skip: conf.SkipControlsFilter}
		if err := writeJSONToFile(result, conf.PlumberConfig, s, params); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Results written to: %s\n", outputFile)
	}
	if pbomFile != "" {
		if err := p.WritePBOM(result, conf, pbomFile, s.score, s.scoreMode); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "PBOM written to: %s\n", pbomFile)
	}
	if pbomCycloneDXFile != "" {
		if err := p.WritePBOMCycloneDX(result, conf, pbomCycloneDXFile, s.score, s.scoreMode); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "PBOM (CycloneDX) written to: %s\n", pbomCycloneDXFile)
	}
	if sarifFile != "" {
		if err := writeSARIFToFile(result, sarifFile, p.Name()); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "SARIF written to: %s\n", sarifFile)
	}
	if glsastFile != "" {
		if err := writeGLSASTToFile(result, glsastFile, p.Name()); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "GitLab SAST report written to: %s\n", glsastFile)
	}
	if csvFile != "" {
		if err := writeCSVToFile(p, result, conf, csvFile); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "CSV written to: %s\n", csvFile)
	}
	return nil
}

// presentResultWithProvider runs the compliance + output pipeline for an
// already-obtained AnalysisResult. Used by GitHub paths that run their own
// analysis call (local scan, remote fetch) before handing off to the shared
// pipeline.
func presentResultWithProvider(p provider.Provider, cmd *cobra.Command, result *control.AnalysisResult, conf *configuration.Configuration) error {
	newLocationLinker(conf, result, p.Name()).Annotate(result.Findings)
	summary := buildComplianceSummary(p, result, conf)
	if printOutput {
		if err := outputTextWithProvider(p, result, conf, summary, conf.ControlsFilter, conf.SkipControlsFilter); err != nil {
			return err
		}
	}
	if err := writeOutputsWithProvider(p, result, conf, summary); err != nil {
		return err
	}
	handleScorePublishing(p, conf, result, summary)
	pas := provider.PostActionSummary{
		Passed:     summary.passed(),
		GateLine:   summary.gateLine(),
		Score:      summary.score,
		ScoreMode:  summary.scoreMode,
		ScorePoint: summary.scorePoint,
	}
	if cmd != nil {
		if err := p.PostAnalysisActions(cmd, result, conf, pas); err != nil {
			return err
		}
	}
	return finalizeRun(result, summary)
}

func joinStrings(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += ", "
		}
		result += s
	}
	return result
}

// installSpinner attaches a progress spinner to conf when output is enabled and
// not in verbose mode, starts it, and returns it so the caller can stop it.
// The spinner is skipped when stderr is not a terminal (CI logs, redirects):
// its \r-based redraws would land as garbled progress lines in the captured
// output.
func installSpinner(conf *configuration.Configuration) *progressSpinner {
	sp := newSpinner()
	if shouldShowProgress(printOutput, verbose, term.IsTerminal(int(os.Stderr.Fd()))) {
		conf.ProgressFunc = func(step, total int, message string) {
			sp.Update(step, total, message)
		}
		sp.InstallLogHook()
		sp.Start()
	}
	return sp
}

// shouldShowProgress decides whether the interactive progress bar is
// rendered. It requires a real terminal on stderr: the bar redraws
// in place with `\r`, and a non-TTY consumer (CI job logs, a file, a
// pipe) renders every redraw as its own line — hundreds of junk
// lines per run (#309). CI runs therefore get no progress frames at
// all; --verbose replaces the bar with debug logs; --print=false
// disables all human-oriented output.
func shouldShowProgress(printOutput, verbose, stderrIsTerminal bool) bool {
	return printOutput && !verbose && stderrIsTerminal
}

// computeScoreResult computes the Plumber score when score mode is active.
// Returns nil when scoreMode is false.
func computeScoreResult(result *control.AnalysisResult, scoreMode bool) *control.PlumberScoreResult {
	if !scoreMode {
		return nil
	}
	s := control.ComputePlumberScore(control.AggregateIssueCodeCounts(result))
	return &s
}

// finalizeRun applies the exit-code gates in priority order: a degraded run
// (incomplete data) fails at exit 3 regardless of the gate (#220); then
// --fail-warnings fails at exit 3 when "could not verify" warnings exist;
// otherwise the score gate (or the deprecated --threshold gate) governs.
func finalizeRun(result *control.AnalysisResult, s complianceSummary) error {
	if result.DataCollectionDegraded {
		return &IncompleteDataError{Reasons: result.DegradedReasons}
	}
	if failWarnings && len(result.Warnings) > 0 {
		return &DegradedError{Count: len(result.Warnings)}
	}
	return s.gateErr()
}
