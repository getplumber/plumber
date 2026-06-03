package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	ghauth "github.com/cli/go-gh/v2/pkg/auth"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/pbom"
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
func runGitHubAnalyze(cmd *cobra.Command, info *utils.GitRemoteInfo, controlsFilterList, skipControlsList []string) error {
	fmt.Fprintf(os.Stderr, "GitHub project: %s (local clone)\n", info.ProjectPath)

	plumberConfig, configPath, configWarnings, err := loadConfigOrOffer(configFile)
	if err != nil {
		return err
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
	// This command is the local-clone GitHub flow: the working tree
	// at info.RepoRoot is, by construction, the project we are about
	// to analyse. Flag it so downstream code (e.g. the source-link
	// builder) emits absolute local paths instead of remote blob URLs.
	conf.IsLocalProject = true
	conf.Branch = defaultBranch
	conf.PlumberConfig = plumberConfig
	conf.ControlsFilter = controlsFilterList
	conf.SkipControlsFilter = skipControlsList
	// API host for the settings/metadata controls. Precedence:
	//   1. --github-url, if the user passed it explicitly;
	//   2. otherwise the git remote host, when it is not github.com — this
	//      is a GitHub Enterprise Server clone, so target its API directly
	//      (mirrors how the GitLab path auto-uses the remote URL). go-gh
	//      resolves the matching token (GH_ENTERPRISE_TOKEN / gh auth login
	//      for that host);
	//   3. empty -> api.github.com.
	apiHost := strings.TrimPrefix(strings.TrimPrefix(githubURL, "https://"), "http://")
	if apiHost == "" && info.Host != "" && !strings.EqualFold(info.Host, "github.com") {
		apiHost = info.Host
	}
	conf.GithubAPIHost = apiHost
	if verbose {
		conf.LogLevel = logrus.DebugLevel
	}

	fmt.Fprintf(os.Stderr, "Scanning workflows under: %s\n", info.RepoRoot)
	printGitHubAuthBanner(apiHost, false)

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

	return presentGitHubResult(result, conf)
}

// runGitHubAnalyzeRemote is the upstream-fetch counterpart of
// runGitHubAnalyze. Triggered by `plumber analyze --github-url X
// --project owner/repo [--branch Y]` when the user has not checked
// out the target repo locally. Symmetric to the GitLab path that
// fetches the merged CI YAML via API.
func runGitHubAnalyzeRemote(cmd *cobra.Command, host, project, ref string, controlsFilterList, skipControlsList []string) error {
	parts := strings.SplitN(project, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("--project must be of the form owner/repo (got %q)", project)
	}
	owner, repo := parts[0], parts[1]

	plumberConfig, configPath, configWarnings, err := loadConfigOrOffer(configFile)
	if err != nil {
		return err
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

	apiHost := strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	if apiHost == "github.com" || apiHost == "" {
		fmt.Fprintf(os.Stderr, "Analyzing GitHub project: %s/%s (remote fetch)\n", owner, repo)
	} else {
		fmt.Fprintf(os.Stderr, "Analyzing GitHub project: %s/%s on %s (remote fetch)\n", owner, repo, apiHost)
	}
	printGitHubAuthBanner(apiHost, true)

	conf := configuration.NewDefaultConfiguration()
	conf.ProjectPath = owner + "/" + repo
	conf.Branch = ref
	conf.PlumberConfig = plumberConfig
	conf.GithubAPIHost = apiHost
	conf.ControlsFilter = controlsFilterList
	conf.SkipControlsFilter = skipControlsList
	if verbose {
		conf.LogLevel = logrus.DebugLevel
	}

	sp := newSpinner()
	if printOutput && !verbose {
		conf.ProgressFunc = func(step, total int, message string) {
			sp.Update(step, total, message)
		}
		sp.InstallLogHook()
		sp.Start()
	}

	result, err := control.RunGitHubAnalysisRemote(conf, owner, repo, ref)
	sp.Stop()
	if err != nil {
		// Pass the auth-required sentinel through verbatim — wrapping
		// it with "analysis failed:" prefixes a frame onto the
		// actionable message and gives the user three layers of context
		// they don't need. Cobra's "Error:" prefix is sufficient.
		if errors.Is(err, collector.ErrAuthRequired) {
			return err
		}
		return fmt.Errorf("analysis failed: %w", err)
	}

	return presentGitHubResult(result, conf)
}

// printGitHubAuthBanner emits a one-line stderr banner naming which
// auth source go-gh will use for this run. Cheap (no network) — pure
// env-var inspection — and complementary to the postflight skipped-
// control markers: tells the user up front "this is the credential
// I'm running with", so a later "ISSUE-505 was skipped because the
// token lacks Administration:Read" message lands with context.
//
// upstreamFetch=true means the run will fail outright if no auth is
// resolvable (ErrAuthRequired path). For local-clone runs, "no auth"
// is a degraded mode rather than a hard error, and the banner says so.
func printGitHubAuthBanner(apiHost string, upstreamFetch bool) {
	source := detectGitHubAuthSource(apiHost)
	switch source {
	case "":
		if upstreamFetch {
			// runGitHubAnalyzeRemote will surface ErrAuthRequired
			// almost immediately; banner here would just be noise
			// before the actionable error.
			return
		}
		fmt.Fprintf(os.Stderr, "GitHub auth: none — running in degraded mode (workflow-content controls only).\n")
	case "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN":
		fmt.Fprintf(os.Stderr, "GitHub auth: %s env var\n", source)
	case "gh":
		fmt.Fprintf(os.Stderr, "GitHub auth: gh CLI (~/.config/gh)\n")
	}
}

// detectGitHubAuthSource returns the highest-priority source go-gh
// would use, mirroring its resolution chain. Returns "" when no
// source is configured. Uses go-gh's auth package so the answer
// matches what the REST client actually picks up at request time.
//
// apiHost is the host the run will talk to (a GHES host, or "" /
// github.com for the SaaS default). The gh-CLI credential lookup is
// per-host, so a GHES clone authenticated only via `gh auth login` to
// its own host is correctly reported instead of falsely "degraded".
func detectGitHubAuthSource(apiHost string) string {
	if v := os.Getenv("GH_TOKEN"); v != "" {
		return "GH_TOKEN"
	}
	if v := os.Getenv("GITHUB_TOKEN"); v != "" {
		return "GITHUB_TOKEN"
	}
	if v := os.Getenv("GH_ENTERPRISE_TOKEN"); v != "" {
		return "GH_ENTERPRISE_TOKEN"
	}
	// Fall back to gh CLI's stored credential for the host we will hit.
	// auth.TokenForHost returns ("", "") when none is configured, so we
	// get an honest "" instead of pretending gh exists when it doesn't.
	host := apiHost
	if host == "" {
		host = "github.com"
	}
	if token, _ := ghauth.TokenForHost(host); token != "" {
		return "gh"
	}
	return ""
}

// presentGitHubResult is the shared post-analysis flow used by both
// the local-clone and remote-fetch GitHub paths: per-control
// compliance averaging, JSON output, terminal rendering, and the
// non-zero exit when findings are present.
func presentGitHubResult(result *control.AnalysisResult, conf *configuration.Configuration) error {
	plumberConfig := conf.PlumberConfig
	scoreMode := showScore || showScorePoint
	var scoreResult *control.PlumberScoreResult
	if scoreMode {
		codeCounts := control.AggregateIssueCodeCounts(result)
		s := control.ComputePlumberScore(codeCounts)
		scoreResult = &s
	}

	// Decorate every finding with a clickable link. In CI this is the
	// host forge's web URL anchored to the analysed commit; locally
	// it falls back to an absolute `<path>:<line>` reference that
	// editors and terminals turn into a jump-to-source action.
	newLocationLinker(conf, result, "github").Annotate(result.Findings)

	findingsByControl := control.FindingsByControl(result.Findings)
	entries := control.GitHubControls(plumberConfig)
	control.MarkSkippedByFilter(entries, conf.ControlsFilter, conf.SkipControlsFilter)
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

	// Terminal rendering FIRST, then file-writes — mirrors the
	// GitLab path (cmd/analyze.go) so the trailing "Results / PBOM
	// / PBOM (CycloneDX) written to:" lines sit right before the
	// compliance error in the terminal, where the user actually
	// looks. Writing first would push those confirmations above the
	// per-control output and out of the visible scrollback.
	if printOutput {
		printGitHubFindings(result, conf, compliance)
		printSummaryScoreBanner(scoreResult, scoreMode)
		if showScorePoint {
			printScoreBreakdown(scoreResult)
		}
	}

	if outputFile != "" {
		if err := writeJSONToFile(result, plumberConfig, threshold, compliance, outputFile, scoreResult, scoreMode, "github", conf.ControlsFilter, conf.SkipControlsFilter); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Results written to: %s\n", outputFile)
	}

	if pbomFile != "" {
		if err := writeGitHubPBOMToFile(result, conf.GithubAPIHost, conf.Branch, pbomFile, scoreResult, scoreMode); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "PBOM written to: %s\n", pbomFile)
	}

	if pbomCycloneDXFile != "" {
		if err := writeGitHubPBOMCycloneDXToFile(result, conf.GithubAPIHost, conf.Branch, pbomCycloneDXFile, scoreResult, scoreMode); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "PBOM (CycloneDX) written to: %s\n", pbomCycloneDXFile)
	}

	if sarifFile != "" {
		if err := writeSARIFToFile(result, sarifFile, "github"); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "SARIF written to: %s\n", sarifFile)
	}

	if glsastFile != "" {
		if err := writeGLSASTToFile(result, glsastFile, "github"); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "GitLab SAST report written to: %s\n", glsastFile)
	}

	// Check compliance against threshold (mirrors the GitLab path). The
	// threshold is the gate, not the mere presence of findings, so a run
	// above the configured threshold passes even with some findings.
	if compliance < threshold {
		return &ComplianceError{Compliance: compliance, Threshold: threshold}
	}
	return nil
}

// writeGitHubPBOMToFile writes a Pipeline Bill of Materials for the
// GitHub run to filePath. Mirrors writePBOMToFile on the GitLab side
// but builds from the normalized IR (third-party actions, reusable
// workflows, container images) instead of GitLab collector outputs.
func writeGitHubPBOMToFile(result *control.AnalysisResult, host, branch, filePath string, score *control.PlumberScoreResult, scoreMode bool) error {
	if host == "" {
		host = "github.com"
	}
	gen := pbom.NewGitHubGenerator(result.ProjectPath, host, branch).
		WithGitHubComplianceData(buildGitHubPBOMCompliance(result))
	bom := gen.GenerateFromGitHubIR(result.GitHubPipeline)
	bom.PlumberScore = pbomPlumberScoreSummary(score, scoreMode)

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create PBOM file: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(bom)
}

// writeGitHubPBOMCycloneDXToFile writes the same PBOM in CycloneDX
// format. Reuses the PBOM builder so both files describe the same
// inventory at the same instant.
func writeGitHubPBOMCycloneDXToFile(result *control.AnalysisResult, host, branch, filePath string, score *control.PlumberScoreResult, scoreMode bool) error {
	if host == "" {
		host = "github.com"
	}
	gen := pbom.NewGitHubGenerator(result.ProjectPath, host, branch).
		WithGitHubComplianceData(buildGitHubPBOMCompliance(result))
	bom := gen.GenerateFromGitHubIR(result.GitHubPipeline)
	bom.PlumberScore = pbomPlumberScoreSummary(score, scoreMode)

	cdx := bom.ToCycloneDX(Version)

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create CycloneDX PBOM file: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(cdx)
}

// buildGitHubPBOMCompliance walks Findings and the IR to assemble
// the per-image / per-action compliance lookup the PBOM generator
// uses to enrich entries. Returns nil when there is nothing to enrich.
func buildGitHubPBOMCompliance(result *control.AnalysisResult) *pbom.GitHubComplianceData {
	if result == nil {
		return nil
	}
	out := &pbom.GitHubComplianceData{
		ForbiddenTagImages:   map[string]bool{},
		ImagesPinnedByDigest: map[string]bool{},
		UnpinnedActions:      map[string]bool{},
		ArchivedActions:      map[string]bool{},
		VulnerableActions:    map[string]bool{},
		ActionAdvisories:     map[string][]string{},
	}
	for _, f := range result.Findings {
		switch f.Code {
		case string(control.CodeImageForbiddenTag):
			if v, ok := f.Data["link"].(string); ok && v != "" {
				out.ForbiddenTagImages[v] = true
			}
		case string(control.CodeActionUnpinned):
			if v, ok := f.Data["uses"].(string); ok && v != "" {
				out.UnpinnedActions[v] = true
			}
		case string(control.CodeActionArchivedRepo):
			if v, ok := f.Data["uses"].(string); ok && v != "" {
				out.ArchivedActions[v] = true
			}
		case string(control.CodeKnownVulnerableAction):
			if v, ok := f.Data["uses"].(string); ok && v != "" {
				out.VulnerableActions[v] = true
				if advRaw, ok := f.Data["advisories"].([]any); ok {
					ids := make([]string, 0, len(advRaw))
					for _, a := range advRaw {
						if s, ok := a.(string); ok && s != "" {
							ids = append(ids, s)
						}
					}
					if len(ids) > 0 {
						out.ActionAdvisories[v] = ids
					}
				}
			}
		}
	}
	if result.GitHubPipeline != nil {
		for _, j := range result.GitHubPipeline.Jobs {
			if j.Image != nil && j.Image.Digest != "" {
				out.ImagesPinnedByDigest[normalizeIRImageRef(*j.Image)] = true
			}
			for _, s := range j.Services {
				if s.Digest != "" {
					out.ImagesPinnedByDigest[normalizeIRImageRef(s)] = true
				}
			}
		}
	}
	return out
}

// normalizeIRImageRef mirrors pbom.normalizeImageRef so the keys we
// stamp into the compliance lookup match the ones the PBOM emits.
// Kept private to cmd/ to avoid leaking pbom internals.
func normalizeIRImageRef(img ir.Image) string {
	if img.Name == "" {
		return ""
	}
	ref := img.Name
	if img.Registry != "" && !strings.HasPrefix(ref, img.Registry+"/") {
		ref = img.Registry + "/" + ref
	}
	if img.Digest != "" {
		return ref + "@" + img.Digest
	}
	if img.Tag != "" {
		return ref + ":" + img.Tag
	}
	return ref
}

// printGitHubFindings writes the GitHub analyze output in the same
// visual style as the GitLab path: project header, a per-rule detail
// block for each rule that produced findings, a controls summary
// table, a compliance table with a total line. Detail rendering is
// delegated to the shared renderFindingGroups so the visual contract
// is identical across providers.
func printGitHubFindings(result *control.AnalysisResult, conf *configuration.Configuration, overallCompliance float64) {
	pc := conf.PlumberConfig
	fmt.Printf("\n%s %s\n\n", styleTitle.Render("Project:"), result.ProjectPath)

	// "No workflows" is informational, not a short-circuit. API-driven
	// controls (branchMustBeProtected today, more later) are evaluated
	// regardless of whether any workflow files exist, so the per-control
	// sections + compliance table must still render — otherwise a repo
	// whose repository-settings controls all *pass* (no findings) would
	// show only this note and look as if nothing was analyzed.
	if !result.CiValid {
		fmt.Printf("  %s\n", styleDim.Render("No GitHub Actions workflows discovered."))
	}

	// Same shape as GitLab: build an ordered list of (catalog entry,
	// findings, stats) tuples so renderFindingGroups + the Issues +
	// Compliance tables all see the full set of shipping controls,
	// not just the ones with findings.
	findingsByControl := control.FindingsByControl(result.Findings)
	entries := control.GitHubControls(pc)
	control.MarkSkippedByFilter(entries, conf.ControlsFilter, conf.SkipControlsFilter)
	// gitleaks may have been configured-enabled but unable to run
	// (binary missing on a sealed CI host, custom path misresolved,
	// scan timeout). The collector signals that on the pipeline IR;
	// route it through the normal "skipped" lane so the summary row
	// goes to "-" / SKIPPED rather than a misleading 100% green.
	if result.GitleaksAbstainReason != "" {
		for i := range entries {
			if entries[i].ControlName == "pipelineMustNotLeakSecretsInConfig" && !entries[i].Skipped {
				entries[i].Skipped = true
				entries[i].SkipReason = result.GitleaksAbstainReason
				break
			}
		}
	}
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
			SkipReason: e.SkipReason,
			Stats:      buildGitHubControlStats(e.ControlName, result.GitHubStats, findings),
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

