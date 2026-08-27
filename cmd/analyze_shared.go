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
	opaengine.StampFingerprints(result.Findings, conf.GitRepoRoot)

	summary := buildComplianceSummary(p, result, conf)

	if printOutput {
		if err := outputTextWithProvider(p, result, conf, summary, controlsFilterList, skipControlsList); err != nil {
			return err
		}
	}

	if err := writeOutputsWithProvider(p, result, conf, summary); err != nil {
		return err
	}

	return publishAndFinalize(p, cmd, result, conf, summary)
}

// publishAndFinalize is the tail both analyze entry points share: publish the
// run (badge, score service, platform), let the provider run its post-analysis
// actions, then map the outcome onto the exit code. Keeping it in one place is
// what stops the two paths from drifting on things like the --no-controls
// guard below.
func publishAndFinalize(p provider.Provider, cmd *cobra.Command, result *control.AnalysisResult, conf *configuration.Configuration, summary complianceSummary) error {
	// Everything here publishes or comments on a verdict. Under
	// --no-controls there is no verdict: a badge, a score push, a platform
	// push or an MR comment built from a run that evaluated nothing would
	// assert a clean pipeline nobody checked. Skip them and say which flags
	// were ignored, rather than erroring, because CI templates set these
	// globally and a hard failure would make --no-controls unusable in
	// exactly the templated pipeline that wants it.
	if conf.NoControls {
		warnInertFlagsUnderNoControls()
		// A CI config that was fetched but does not parse is not a
		// successful collection: the collector sets LimitedAnalysis and
		// returns early, so the inventory is empty. It is deliberately not
		// marked DataCollectionDegraded (it is a user-fixable finding), so
		// on a normal run the zero-control gate is what catches it.
		// --no-controls removes that gate, and exiting 0 here would ship an
		// empty PBOM as if it were complete and swallow the errors.
		if len(result.CiErrors) > 0 {
			return &IncompleteDataError{Reasons: result.CiErrors}
		}
		// A CI config that is absent, or unusable without producing error
		// strings (the collector's INVALID-status branch), leaves nothing to
		// inventory, so an empty PBOM is not a result.
		//
		// The condition is GitLabProvider.ComputeCompliance's own, verbatim,
		// so the two cannot drift apart about what "no usable pipeline"
		// means. It is scoped to GitLab because the providers disagree here
		// on purpose: GitLab zeroes the control count on a missing or
		// invalid CI (so a normal run fails the gate), while GitHub keeps
		// its count for a repo with no workflows, restored in 0.4.0 so
		// fleet scanners do not fail on CI-less repositories. --no-controls
		// removes the gate, so it must not quietly reverse either stance.
		//
		// Note the ordering: the publish suppression above is unconditional,
		// so an unusable collection cannot reach the score service either.
		// A --no-controls run never publishes, whether it ends in success
		// or in one of the failures below.
		if p.Name() == "gitlab" && (result.CiMissing || !result.CiValid) {
			return &IncompleteDataError{Reasons: []string{"no usable CI configuration found in the project, nothing to inventory"}}
		}
		return finalizeRun(result, summary, nil)
	}

	jsonPayload := buildPublishPayload(p, conf, result, summary)
	handleScorePublishing(p, conf, result, summary, jsonPayload)
	platformErr := maybePushPlatform(p, conf, result, summary.score)

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

	return finalizeRun(result, summary, platformErr)
}

// inertFlagsUnderNoControls lists the flags that read or publish a score and
// are therefore no-ops on a --no-controls run, so the user is told once
// instead of quietly getting less than they asked for.
func inertFlagsUnderNoControls() []string {
	var ignored []string
	for _, f := range []struct {
		name string
		set  bool
	}{
		{"--min-points", minPointsSet},
		{"--min-score", minScore != ""},
		{"--threshold", thresholdSet},
		{"--score", showScore},
		{"--score-point", showScorePoint},
		{"--badge", badge},
		{"--score-push", pushScore},
		{"--mr-comment", mrComment},
		{"--platform", platformURL != ""},
		{"--sarif", sarifFile != ""},
		{"--glsast", glsastFile != ""},
	} {
		if f.set {
			ignored = append(ignored, f.name)
		}
	}
	return ignored
}

// warnInertFlagsUnderNoControls prints that one-time notice.
func warnInertFlagsUnderNoControls() {
	if ignored := inertFlagsUnderNoControls(); len(ignored) > 0 {
		fmt.Fprintf(os.Stderr, "Note: --no-controls evaluated nothing, so there is no score to gate or publish; ignored: %s\n", joinStrings(ignored))
	}
}

// applyControlScope copies the run's control-scope flags onto conf: which
// controls to run (--controls / --skip-controls) and whether to run any at
// all (--no-controls).
//
// The three analyze entry points all go through here rather than assigning
// the fields themselves. The whole --no-controls safety chain (score
// withholding, MarkAllSkipped, publish suppression, the gate no-op) keys off
// conf.NoControls, so one provider path quietly losing the assignment would
// evaluate everything, score it and publish it for a user who asked for no
// verdict at all.
func applyControlScope(conf *configuration.Configuration, includeOnly, skip []string) {
	conf.ControlsFilter = includeOnly
	conf.SkipControlsFilter = skip
	conf.NoControls = noControls
}

// providerControlEntries returns the provider's catalog with this run's skip
// semantics already applied: --no-controls marks every entry skipped, so no
// artifact can stamp a verdict on a control that never ran; otherwise the
// --controls / --skip-controls filter applies as usual.
//
// Every artifact writer that reports a PER-CONTROL status must go through
// here. control.StatusFor returns "passed" for an unskipped control with
// zero findings on a valid run, and under --no-controls the two filters are
// empty by construction (they are mutually exclusive with the flag), so a
// writer calling MarkSkippedByFilter directly marks nothing and reports a
// clean posture for a run that evaluated nothing.
func providerControlEntries(p provider.Provider, conf *configuration.Configuration) []control.ControlEntry {
	entries := p.Controls(conf.PlumberConfig)
	if conf.NoControls {
		control.MarkAllSkipped(entries, noControlsSkipReason)
		return entries
	}
	control.MarkSkippedByFilter(entries, conf.ControlsFilter, conf.SkipControlsFilter)
	return entries
}

// buildComplianceSummary assembles the gate inputs for a run: the Plumber
// Score (the default gate), the score-gate flags, and — only to serve the
// deprecated --threshold gate — the legacy passing-controls percentage.
func buildComplianceSummary(p provider.Provider, result *control.AnalysisResult, conf *configuration.Configuration) complianceSummary {
	compliance, controlCount := p.ComputeCompliance(result, conf)
	// The score banner is shown by default (#218); --score is a no-op.
	// Under --no-controls nothing was evaluated, so zero findings would
	// otherwise compute a perfect 100/100 and stamp it on the banner, the
	// JSON report, the PBOM and the CycloneDX output. scoreMode=false is
	// the existing withhold-the-score path (every consumer already guards
	// on a nil score), so the outputs carry no score instead of a fake one.
	scoreMode := !conf.NoControls
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
		noControls:   conf.NoControls,
	}
}

// outputTextWithProvider renders terminal output using the provider's catalog
// and stats builder — the shared path for both GitLab and GitHub.
func outputTextWithProvider(p provider.Provider, result *control.AnalysisResult, conf *configuration.Configuration, s complianceSummary, controlsFilterList, skipControlsList []string) error {
	renderRunHeader(p, result, conf)

	// The zero-control warning describes a run that meant to check something
	// and could not. Under --no-controls that is the request, not a failure;
	// the header already says so. CI errors are the exception: they are why
	// the artifacts are empty, so they stay visible.
	switch {
	case s.controlCount == 0 && !s.noControls:
		printNoControlsWarning(result)
	case s.noControls && len(result.CiErrors) > 0:
		printCIErrors(result)
	}
	if result.DataCollectionDegraded {
		renderDegradedCaveat(result.DegradedReasons)
	}

	controls, groups := buildProviderControlSummariesAndGroups(p, result, conf, controlsFilterList, skipControlsList)
	// Nothing was selected, so listing every control as "skipped" is noise
	// that reads like a misconfiguration.
	if s.noControls {
		controls, groups = nil, nil
	}
	// On a degraded run the per-control verdict is untrustworthy; render only
	// the findings we DID surface (a real violation on partial data is still
	// real) and drop the green stat blocks (#220).
	renderFindingGroups(filterGroupsForDegraded(groups, result.DataCollectionDegraded))
	renderWarnings(result.Warnings)
	renderApprovalRulesTierCaveat(result)
	renderMRApprovalSettingsTierCaveat(result)
	renderMRSettingsPremiumCaveat(result)
	renderSecurityPolicyTierCaveat(result)

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
	// Under --no-controls there are no controls to tabulate, and an empty
	// "(none with open issues)" table reads like a clean scan.
	if (!result.DataCollectionDegraded || len(result.Findings) > 0) && !s.noControls {
		printIssuesTable(controls)
		fmt.Println()
	}

	if s.noControls {
		printNoControlsSummary()
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
// CycloneDX, SARIF, GitLab SAST, CSV, OCSF) using the provider's writers.
func writeOutputsWithProvider(p provider.Provider, result *control.AnalysisResult, conf *configuration.Configuration, s complianceSummary) error {
	// Artifacts are still written on a degraded run (they are files the user
	// asked for, and the exit-3 gate, not the file's absence, protects CI).
	// Each format stamps itself degraded; warn so a partial report is not
	// mistaken for authoritative (#220).
	if result.DataCollectionDegraded && (outputFile != "" || pbomFile != "" || pbomCycloneDXFile != "" || sarifFile != "" || glsastFile != "" || csvFile != "" || ocsfFile != "") {
		fmt.Fprintf(os.Stderr, "Note: data collection was incomplete — artifacts are written but marked degraded; treat them as partial.\n")
	}
	if outputFile != "" {
		params := jsonOutputParams{filePath: outputFile, provider: p.Name(), includeOnly: conf.ControlsFilter, skip: conf.SkipControlsFilter, noControls: conf.NoControls}
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
	// SARIF and the GitLab SAST report have no honest empty form. An
	// empty SARIF is the documented signal that makes Code Scanning clear
	// previously-reported alerts, and buildGLSAST leaves Scan.Status at
	// "success", so uploading either from a run that evaluated nothing
	// dismisses real alerts and shows a clean dashboard for a pipeline
	// nobody checked. There is no field that fixes that, so they are not
	// written at all; warnInertFlagsUnderNoControls names them.
	if sarifFile != "" && !conf.NoControls {
		if err := writeSARIFToFile(result, sarifFile, p.Name()); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "SARIF written to: %s\n", sarifFile)
	}
	if glsastFile != "" && !conf.NoControls {
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
	if ocsfFile != "" {
		if err := writeOCSFToFile(p, result, conf, ocsfFile); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "OCSF report written to: %s\n", ocsfFile)
	}
	return nil
}

// presentResultWithProvider runs the compliance + output pipeline for an
// already-obtained AnalysisResult. Used by GitHub paths that run their own
// analysis call (local scan, remote fetch) before handing off to the shared
// pipeline.
func presentResultWithProvider(p provider.Provider, cmd *cobra.Command, result *control.AnalysisResult, conf *configuration.Configuration) error {
	newLocationLinker(conf, result, p.Name()).Annotate(result.Findings)
	opaengine.StampFingerprints(result.Findings, conf.GitRepoRoot)
	summary := buildComplianceSummary(p, result, conf)
	if printOutput {
		if err := outputTextWithProvider(p, result, conf, summary, conf.ControlsFilter, conf.SkipControlsFilter); err != nil {
			return err
		}
	}
	if err := writeOutputsWithProvider(p, result, conf, summary); err != nil {
		return err
	}
	return publishAndFinalize(p, cmd, result, conf, summary)
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

// buildPublishPayload builds the analysis JSON payload for the score badge
// push (handleScorePublishing): the exact bytes buildAnalysisJSONReport
// produced for --output, so the badge record and the file on disk can never
// diverge. The platform push does NOT consume this payload — maybePushPlatform
// builds its own structured envelope directly from result/conf/score — so the
// gate below is scorePush alone; skipped (nil) when the badge push is not
// configured, so a plain local run (or a --platform-only run) pays no
// marshal/hash cost for a payload nobody sends.
func buildPublishPayload(p provider.Provider, conf *configuration.Configuration, result *control.AnalysisResult, summary complianceSummary) []byte {
	scorePush, _ := effectiveScorePush()
	if !scorePush {
		return nil
	}
	var pc *configuration.PlumberConfig
	var includeOnly, skip []string
	if conf != nil {
		pc = conf.PlumberConfig
		includeOnly, skip = conf.ControlsFilter, conf.SkipControlsFilter
	}
	payload, err := buildAnalysisJSONReport(result, pc, summary, jsonOutputParams{
		provider: p.Name(), includeOnly: includeOnly, skip: skip,
	})
	if err != nil {
		scoreWarn(fmt.Sprintf("could not build the publish payload: %v", err))
		return nil
	}
	return payload
}

// finalizeRun applies the exit-code gates in priority order: a degraded run
// (incomplete data) fails at exit 3 regardless of the gate (#220); then
// --fail-warnings fails at exit 3 when "could not verify" warnings exist; then
// the score gate (or the deprecated --threshold gate). A platform token failure
// is evaluated LAST so a broken id-token grant can never mask a security
// finding the scan just made.
func finalizeRun(result *control.AnalysisResult, s complianceSummary, platformErr error) error {
	if result.DataCollectionDegraded {
		return &IncompleteDataError{Reasons: result.DegradedReasons}
	}
	if failWarnings && len(result.Warnings) > 0 {
		return &DegradedError{Count: len(result.Warnings)}
	}
	if err := s.gateErr(); err != nil {
		return err
	}
	return platformErr
}
