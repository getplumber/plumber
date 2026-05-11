package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	glabCI "github.com/getplumber/plumber/gitlab"
	"github.com/getplumber/plumber/pbom"
	"github.com/getplumber/plumber/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	// Flags for analyze command
	gitlabURL         string
	githubURL         string
	projectPath       string
	defaultBranch     string
	outputFile        string
	printOutput       bool
	configFile        string
	threshold         float64
	pbomFile          string
	pbomCycloneDXFile string
	mrComment         bool
	badge             bool
	showScore         bool
	showScorePoint    bool
	controlsFilter    string
	skipControls      string
	ciConfigPath      string
)

var analyzeCmd = &cobra.Command{
	Use:          "analyze",
	Short:        "Analyze CI/CD configuration (GitLab via API, or local GitHub Actions when origin is GitHub)",
	SilenceUsage: true, // Don't print usage on errors (e.g., threshold failures)
	Long: `Analyze CI/CD configuration for compliance issues.

GitLab path (when the git remote is GitLab, or when you pass --gitlab-url and --project):
  Connects to GitLab, retrieves CI/CD configuration and project settings, and runs
  checks including pipeline origins, images, tags, and branch protection.
  Required environment variable: GITLAB_TOKEN

GitHub path (when origin is GitHub and --gitlab-url / --project are not set):
  Scans local .github/workflows only (Rego). No GitLab token. Some flags apply only
  to the GitLab API path (see README).

Flags (auto-detected from git remote if not specified):
  --gitlab-url    GitLab instance URL (auto-detected from git remote)
  --project       Full path of the project (auto-detected from git remote)

Optional flags:
  --config           Path to .plumber.yaml config file (default: .plumber.yaml)
  --threshold        Minimum compliance percentage to pass, 0-100 (default: 100)
  --branch           Branch to analyze (defaults to project's default branch)
  --print            Print text output to stdout (default: true)
  --output           Write JSON results to file (optional)
  --pbom             Write PBOM (Pipeline Bill of Materials) to file (optional)
  --pbom-cyclonedx   Write PBOM in CycloneDX format for integration with security tools
  --mr-comment       Post/update a compliance comment on the merge request (requires api scope, merge request pipeline only)
  --badge            Create/update a Plumber compliance badge on the project (requires api scope; only runs on default branch)
  --score            Letter score, points, bar, and counts in stdout (banner only); points + score in JSON/PBOM/CycloneDX; badge/MR use letter when set (optional)
  --score-point      Same as --score plus full points breakdown in stdout and MR comment (optional; wins if both set)
  --controls         Run only listed controls (comma-separated)
  --skip-controls    Skip listed controls (comma-separated)
  --fail-warnings    Treat configuration warnings as errors (exit 2)
  --ci-config-path   Override the CI configuration file path (default: auto-detected from GitLab project settings, usually .gitlab-ci.yml)

Exit codes:
  0  Analysis passed (compliance >= threshold)
  1  Compliance failure (compliance < threshold)
  2  Runtime error (configuration error, network failure, missing token, etc.)

Examples:
  # Set token via environment variable
  export GITLAB_TOKEN=glpat-xxxx

  # Analyze current repo (auto-detects GitLab URL and project from git remote)
  plumber analyze

  # Analyze a specific project
  plumber analyze --gitlab-url https://gitlab.com --project mygroup/myproject

  # Analyze with custom config and threshold
  plumber analyze --gitlab-url https://gitlab.com --project mygroup/myproject --config custom.yaml --threshold 80

  # Analyze and save JSON to file (no stdout)
  plumber analyze --gitlab-url https://gitlab.com --project mygroup/myproject --print=false --output results.json

  # Analyze a project that uses a custom CI configuration file path
  plumber analyze --ci-config-path my-custom-ci.yml
`,
	RunE: runAnalyze,
}

func init() {
	rootCmd.AddCommand(analyzeCmd)

	// GitLab connection flags (auto-detected from git remote if not specified)
	analyzeCmd.Flags().StringVar(&gitlabURL, "gitlab-url", "", "GitLab instance URL (auto-detected from git remote, required otherwise)")
	analyzeCmd.Flags().StringVar(&projectPath, "project", "", "Project path (auto-detected from git remote, required otherwise)")

	// GitHub Enterprise Server: override the GitHub API host. Default
	// (empty) targets api.github.com. Set to your GHES API host (e.g.
	// "ghes.example.com" or "ghes.example.com/api/v3") to scan a
	// self-hosted instance. Auth via GH_TOKEN / GH_ENTERPRISE_TOKEN.
	analyzeCmd.Flags().StringVar(&githubURL, "github-url", "", "GitHub Enterprise Server API host (empty = api.github.com)")

	// Optional flags with defaults
	analyzeCmd.Flags().StringVar(&configFile, "config", ".plumber.yaml", "Path to .plumber.yaml config file")
	analyzeCmd.Flags().Float64Var(&threshold, "threshold", 100, "Minimum compliance percentage to pass, 0-100")
	analyzeCmd.Flags().StringVar(&defaultBranch, "branch", "", "Branch to analyze (defaults to project's default branch)")
	analyzeCmd.Flags().BoolVar(&printOutput, "print", true, "Print text output to stdout")
	analyzeCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write JSON results to file")
	analyzeCmd.Flags().StringVar(&pbomFile, "pbom", "", "Write PBOM (Pipeline Bill of Materials) to file")
	analyzeCmd.Flags().StringVar(&pbomCycloneDXFile, "pbom-cyclonedx", "", "Write PBOM in CycloneDX format (for security tool integration)")
	analyzeCmd.Flags().BoolVar(&mrComment, "mr-comment", false, "Post/update a compliance comment on the merge request (requires api scope token; only works in merge request pipelines)")
	analyzeCmd.Flags().BoolVar(&badge, "badge", false, "Create/update a Plumber compliance badge on the project (requires api scope; only runs on default branch)")
	analyzeCmd.Flags().BoolVar(&showScore, "score", false, "Banner: letter score, points, bar, severity counts on stdout; points + score in JSON, PBOM, CycloneDX; badge shows letter when set")
	analyzeCmd.Flags().BoolVar(&showScorePoint, "score-point", false, "Like --score plus full points breakdown in stdout and MR comment; overrides --score when both are set")
	analyzeCmd.Flags().StringVar(&controlsFilter, "controls", "", "Run only listed controls (comma-separated)")
	analyzeCmd.Flags().StringVar(&skipControls, "skip-controls", "", "Skip listed controls (comma-separated)")
	analyzeCmd.Flags().BoolVar(&failWarnings, "fail-warnings", false, "Treat configuration warnings as errors (exit 2)")
	analyzeCmd.Flags().StringVar(&ciConfigPath, "ci-config-path", "", "Override the CI configuration file path (default: auto-detected from GitLab project settings, usually .gitlab-ci.yml)")
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	// Set log level based on verbose flag
	// Default: WarnLevel (quiet output, only show warnings/errors)
	// Verbose: DebugLevel (show all logs for troubleshooting)
	if verbose {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.WarnLevel)
	}

	// Detect git remote info (used for auto-detection AND local CI file matching)
	gitlabURLFromFlag := cmd.Flags().Changed("gitlab-url")
	githubURLFromFlag := cmd.Flags().Changed("github-url")
	projectFromFlag := cmd.Flags().Changed("project")
	branchFromFlag := cmd.Flags().Changed("branch")

	if gitlabURLFromFlag && githubURLFromFlag {
		return fmt.Errorf("--gitlab-url and --github-url are mutually exclusive; pass one to select the provider explicitly")
	}

	// Validate + parse --controls / --skip-controls before any provider
	// dispatch — both providers honour the filter, so the lists must
	// be available no matter which path runs. (Previously these were
	// computed only on the GitLab branch, leaving the GitHub paths
	// blind to the flags.)
	if controlsFilter != "" && skipControls != "" {
		return fmt.Errorf("--controls and --skip-controls cannot be used together")
	}
	controlsFilterList, err := parseControlsFilter(controlsFilter)
	if err != nil {
		return err
	}
	skipControlsList, err := parseControlsFilter(skipControls)
	if err != nil {
		return err
	}

	// Explicit GitHub remote-fetch: when both --github-url and
	// --project are set, the user wants to scan an upstream GitHub
	// project they have not checked out locally. Symmetric to
	// --gitlab-url + --project on the GitLab side. --github-url
	// alone (no project) keeps its existing meaning: GHES API host
	// for the local-clone scan.
	if githubURLFromFlag && projectFromFlag {
		ref := ""
		if branchFromFlag {
			ref = defaultBranch
		}
		return runGitHubAnalyzeRemote(cmd, githubURL, projectPath, ref, controlsFilterList, skipControlsList)
	}

	var gitRepoRoot string
	var gitRemoteURL string
	var gitRemoteProjectPath string

	if remoteInfo := utils.DetectGitRemote(); remoteInfo != nil {
		gitRepoRoot = remoteInfo.RepoRoot
		gitRemoteURL = remoteInfo.URL
		gitRemoteProjectPath = remoteInfo.ProjectPath

		// Multi-provider dispatch: GitHub projects take the Rego-only,
		// local-file path. GitLab (and self-hosted) continue to use the
		// full legacy analyzer below.
		//
		// Explicit --gitlab-url / --project flags always win over
		// auto-detection: a user inside a GitHub clone may legitimately
		// want to analyse a GitLab project they passed by hand
		// (cross-checks, demos, scripted regression runs). Only
		// dispatch to the GitHub path when the caller did not override.
		if remoteInfo.Provider == "github" && !gitlabURLFromFlag && !projectFromFlag {
			return runGitHubAnalyze(cmd, remoteInfo, controlsFilterList, skipControlsList)
		}

		if !gitlabURLFromFlag {
			gitlabURL = remoteInfo.URL
			fmt.Fprintf(os.Stderr, "Auto-detected GitLab URL: %s\n", gitlabURL)
		}
		if !projectFromFlag {
			projectPath = remoteInfo.ProjectPath
			fmt.Fprintf(os.Stderr, "Auto-detected project: %s\n", projectPath)
		}
	}

	// Validate required values (either from flags or auto-detected).
	// At this point either --gitlab-url has been set / auto-detected,
	// or the GitHub-remote-fetch path above has already returned. So
	// reaching here without a gitlab URL means neither auto-detection
	// nor an explicit flag landed — surface both providers in the
	// error so the user knows the symmetric option exists.
	if gitlabURL == "" {
		return fmt.Errorf("could not auto-detect provider from git remote — pass --gitlab-url + --project (GitLab) or --github-url + --project (GitHub)")
	}
	if projectPath == "" {
		return fmt.Errorf("--project is required (could not auto-detect from git remote)")
	}

	// Validate threshold
	if threshold < 0 || threshold > 100 {
		return fmt.Errorf("threshold must be between 0 and 100")
	}

	// --score-point implies score output; if both --score and --score-point are set, points mode wins for breakdown/MR text.
	scoreMode := showScore || showScorePoint
	scorePointMode := showScorePoint

	// controlsFilterList / skipControlsList were parsed earlier so the
	// GitHub dispatch sees them too — see the "Validate + parse" block
	// above the dispatch.

	// Get token from environment variable (required)
	gitlabToken := os.Getenv("GITLAB_TOKEN")
	if gitlabToken == "" {
		return fmt.Errorf("GITLAB_TOKEN environment variable is required")
	}

	// Clean up URL
	cleanGitlabURL := strings.TrimSuffix(gitlabURL, "/")

	// Load Plumber configuration (required)
	plumberConfig, configPath, configWarnings, err := configuration.LoadPlumberConfig(configFile)
	if err != nil {
		if strings.Contains(err.Error(), "config file not found") {
			return fmt.Errorf("configuration file not found: %w. Create one with `plumber config generate` or `plumber config init`", err)
		}
		return fmt.Errorf("configuration error: %w", err)
	}

	if len(configWarnings) > 0 {
		fmt.Fprintf(os.Stderr, "Configuration validation warnings:\n")
		for _, warning := range configWarnings {
			fmt.Fprintf(os.Stderr, "  - %s\n", warning)
		}
		if failWarnings {
			return fmt.Errorf("configuration has %d warning(s) and --fail-warnings is set", len(configWarnings))
		}
		fmt.Fprintf(os.Stderr, "Please fix the warnings above for best results.\n\n")
	}

	// Print banner if output is enabled
	if printOutput {
		printBanner()
	}

	fmt.Fprintf(os.Stderr, "Using configuration: %s\n", configPath)

	// Create configuration
	conf := configuration.NewDefaultConfiguration()
	conf.GitlabURL = cleanGitlabURL
	conf.GitlabToken = gitlabToken
	conf.ProjectPath = projectPath
	conf.Branch = defaultBranch
	conf.PlumberConfig = plumberConfig
	conf.GitRepoRoot = gitRepoRoot
	conf.ControlsFilter = controlsFilterList
	conf.SkipControlsFilter = skipControlsList
	conf.CIConfigPathOverride = ciConfigPath

	// Determine if the local git repo matches the project being analyzed.
	// Local CI file support only applies when the local repo IS the analyzed project.
	if gitRepoRoot != "" && gitRemoteURL != "" {
		sameURL := strings.TrimSuffix(gitRemoteURL, "/") == cleanGitlabURL
		samePath := gitRemoteProjectPath == projectPath
		conf.IsLocalProject = sameURL && samePath
	}

	if verbose {
		conf.LogLevel = logrus.DebugLevel
	}

	// Run analysis
	fmt.Fprintf(os.Stderr, "Analyzing project: %s on %s\n", projectPath, cleanGitlabURL)

	// Start progress spinner (only when printing output and not in verbose mode)
	sp := newSpinner()
	if printOutput && !verbose {
		conf.ProgressFunc = func(step, total int, message string) {
			sp.Update(step, total, message)
		}
		sp.InstallLogHook()
		sp.Start()
	}

	result, err := control.RunAnalysis(conf)
	sp.Stop()
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Overall compliance is the share of enabled controls that emitted
	// no finding. One control = one unit, regardless of how many
	// findings it produces. Skipped controls are excluded from both
	// sides of the ratio so disabling a control does not change the
	// score. When no controls are enabled the score falls back to 0 —
	// same semantic as the legacy averaging loop: if nothing can be
	// verified, nothing can be trusted.
	//
	// A missing or invalid CI configuration short-circuits to 0:
	// the absence of findings under those conditions is evidence that
	// nothing could be analysed, not that the project is compliant.
	// Without this guard a project with no .gitlab-ci.yml or a
	// syntactically broken one would score 100% — letting attackers
	// pass the gate by deleting or breaking the CI file.
	compliance := 0.0
	controlCount := 0
	if !result.CiMissing && result.CiValid {
		findingCountsByControl := map[string]int{}
		for _, f := range result.Findings {
			if info := control.LookupCode(control.ErrorCode(f.Code)); info != nil {
				findingCountsByControl[info.ControlName]++
			}
		}
		passed := 0
		entries := control.GitLabControls(conf.PlumberConfig)
		control.MarkSkippedByFilter(entries, conf.ControlsFilter, conf.SkipControlsFilter)
		for _, e := range entries {
			if e.Skipped {
				continue
			}
			controlCount++
			if findingCountsByControl[e.ControlName] == 0 {
				passed++
			}
		}
		if controlCount > 0 {
			compliance = float64(passed) * 100.0 / float64(controlCount)
		}
	}

	var scoreResult *control.PlumberScoreResult
	if scoreMode {
		codeCounts := control.AggregateIssueCodeCounts(result)
		s := control.ComputePlumberScore(codeCounts)
		scoreResult = &s
	}

	// Print text output to stdout if enabled
	if printOutput {
		if err := outputText(result, conf.PlumberConfig, threshold, compliance, controlCount, scoreResult, scoreMode, scorePointMode, conf.ControlsFilter, conf.SkipControlsFilter); err != nil {
			return err
		}
	}

	// Write JSON to file if specified
	if outputFile != "" {
		if err := writeJSONToFile(result, conf.PlumberConfig, threshold, compliance, outputFile, scoreResult, scoreMode, "gitlab"); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Results written to: %s\n", outputFile)
	}

	// Write PBOM to file if specified
	if pbomFile != "" {
		if err := writePBOMToFile(result, cleanGitlabURL, defaultBranch, pbomFile, scoreResult, scoreMode); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "PBOM written to: %s\n", pbomFile)
	}

	// Write CycloneDX PBOM to file if specified
	if pbomCycloneDXFile != "" {
		if err := writePBOMCycloneDXToFile(result, cleanGitlabURL, defaultBranch, pbomCycloneDXFile, scoreResult, scoreMode); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "PBOM (CycloneDX) written to: %s\n", pbomCycloneDXFile)
	}

	// Post merge request comment if explicitly enabled and in a CI merge request pipeline
	if mrComment {
		if mrIID := glabCI.DetectMergeRequestIID(); mrIID != 0 {
			fmt.Fprintf(os.Stderr, "Merge request pipeline detected (MR !%d), posting compliance comment...\n", mrIID)
			if err := control.ManageMergeRequestComment(result.ProjectID, mrIID, result, conf.PlumberConfig, compliance, threshold, conf, scoreResult, scoreMode, scorePointMode); err != nil {
				// Log but don't fail the analysis for a comment error
				fmt.Fprintf(os.Stderr, "Warning: failed to post merge request comment: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "Merge request comment posted successfully\n")
			}
		}
	}

	// Create/update project badge if explicitly enabled AND on default branch
	// Badge should only reflect compliance of the default branch, not MRs or feature branches
	if badge {
		shouldUpdateBadge := false
		skipReason := ""

		if glabCI.IsRunningInCI() {
			// In CI: use environment variables
			if glabCI.IsOnDefaultBranchCI() {
				shouldUpdateBadge = true
			} else {
				skipReason = "not on default branch in CI"
			}
		} else {
			// Locally: check various conditions
			if result.CIConfigSource == "local" {
				// Using local CI files - don't update badge (user is testing locally)
				skipReason = "using local CI files (testing mode)"
			} else if !cmd.Flags().Changed("branch") {
				// --branch not specified = analyzing default branch
				shouldUpdateBadge = true
			} else if conf.Branch == result.DefaultBranch {
				// --branch specified and matches default branch
				shouldUpdateBadge = true
			} else {
				skipReason = fmt.Sprintf("analyzing branch '%s', not default branch '%s'", conf.Branch, result.DefaultBranch)
			}
		}

		if shouldUpdateBadge {
			fmt.Fprintf(os.Stderr, "Updating project compliance badge...\n")
			if err := control.ManageProjectBadge(result.ProjectID, compliance, threshold, conf, scoreResult, scoreMode); err != nil {
				// Log but don't fail the analysis for a badge error
				fmt.Fprintf(os.Stderr, "Warning: failed to update project badge: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "Project badge updated successfully\n")
			}
		} else {
			fmt.Fprintf(os.Stderr, "Skipping badge update (%s)\n", skipReason)
		}
	}

	// Check compliance against threshold
	if compliance < threshold {
		return &ComplianceError{Compliance: compliance, Threshold: threshold}
	}

	return nil
}

// parseControlsFilter parses and validates a comma separated control list.
func parseControlsFilter(raw string) ([]string, error) {
	// Empty flag means that no filter,
	// so keep current behavior (all controls run).
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	// Resolve valid names from the same schema used by .plumber.yaml validation.
	validControls := configuration.ValidControlNames()
	validSet := make(map[string]struct{}, len(validControls))
	for _, control := range validControls {
		validSet[control] = struct{}{}
	}

	controls := make([]string, 0)
	controlsSet := make(map[string]struct{})
	unknown := make([]string, 0)
	unknownSet := make(map[string]struct{})

	for _, part := range strings.Split(raw, ",") {
		control := strings.TrimSpace(part)
		if control == "" {
			continue
		}

		// Collecting unknown names so it can return one actionable error.
		if _, ok := validSet[control]; !ok {
			if _, seen := unknownSet[control]; !seen {
				unknownSet[control] = struct{}{}
				unknown = append(unknown, control)
			}
			continue
		}

		// Keeps the first occurrence only,
		// it will avoid duplicate work downstream.
		if _, seen := controlsSet[control]; seen {
			continue
		}
		controlsSet[control] = struct{}{}
		controls = append(controls, control)
	}

	if len(unknown) > 0 {
		sort.Strings(unknown)
		sort.Strings(validControls)
		var b strings.Builder
		b.WriteString("unknown control names: ")
		b.WriteString(strings.Join(unknown, ", "))
		b.WriteString("\n\nValid controls:\n")
		for _, name := range validControls {
			b.WriteString("  - ")
			b.WriteString(name)
			b.WriteString("\n")
		}
		return nil, fmt.Errorf("%s", b.String())
	}

	return controls, nil
}

func writeJSONToFile(result *control.AnalysisResult, pc *configuration.PlumberConfig, threshold, compliance float64, filePath string, score *control.PlumberScoreResult, scoreMode bool, provider string) error {
	// Marshal AnalysisResult into a generic map so the per-control
	// `*Result` legacy blocks can sit alongside its existing fields
	// without forcing every consumer to follow the dev's flat-findings
	// shape. The legacy keys (imageForbiddenTagsResult, …) carry the
	// same issues + metrics + compliance triplet v0.2.x emitted, so
	// downstream tooling parses the dev output unchanged.
	raw, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	output := map[string]any{}
	if err := json.Unmarshal(raw, &output); err != nil {
		return fmt.Errorf("unmarshal result: %w", err)
	}
	output["threshold"] = threshold
	output["compliance"] = compliance
	output["passed"] = compliance >= threshold
	if scoreMode && score != nil {
		output["plumberScore"] = score
	}
	// `partialControls` surfaces the postflight-skipped story so CI
	// consumers can detect "we couldn't fully evaluate X" without
	// scraping the rendered terminal output. Today the only entry
	// is `branchMustBeProtected` when GitHub /branches/{name}/
	// protection 403'd; future controls with similar partial-data
	// modes can append here.
	if partial := partialControlEntries(result); len(partial) > 0 {
		output["partialControls"] = partial
	}
	for k, v := range legacyResultsByName(result, pc, provider) {
		output[k] = v
	}

	// Top-level aggregate blocks (pipelineOriginMetrics +
	// pipelineImageMetrics) are populated by the GitLab task path
	// and serialised straight from AnalysisResult. The GitHub path
	// doesn't fill those fields, so inject GitHub-shaped equivalents
	// here from result.GitHubStats — same top-level key slots, GitHub-
	// native counters ("originAction" / "originReusableWorkflow"
	// instead of "originComponent" / "originTemplate"). Keeps the
	// "scroll to the top of analysis.json" experience symmetric
	// across providers.
	if provider == "github" && result.GitHubStats != nil {
		s := result.GitHubStats
		output["pipelineOriginMetrics"] = map[string]any{
			"jobTotal":                             s.JobsTotal,
			"workflowsTotal":                       s.WorkflowsTotal,
			"originAction":                         s.ActionRefsTotal,
			"originActionUnpinned":                 s.ActionRefsUnpinned,
			"originActionTrustedExempt":            s.ActionRefsExempt,
			"originReusableWorkflow":               s.ReusableCalls,
			"originReusableWorkflowSecretsInherit": s.ReusableCallsSecretsInherit,
			"originTotal":                          s.ActionRefsTotal + s.ReusableCalls,
		}
		output["pipelineImageMetrics"] = map[string]any{
			"total": s.ImagesTotal,
		}
	}

	// Drop the flat Rego findings list from the file on both
	// providers. Legacy GitLab consumers parse the per-control
	// *Result blocks (issues/metrics/compliance) and never read
	// `findings`. The GitHub side now ships per-control *Result
	// blocks for every shipping control (the 4 cross-provider ones
	// + 5 GitHub-only added in this session), so the flat array is
	// no longer needed as an escape hatch — keeping it would just
	// duplicate every issue between the top level and the *Result
	// blocks. Cross-provider structural parity > flat-jq convenience.
	delete(output, "findings")

	// Encode with intentional key order so readers see project/context first,
	// scoring next, then per-control *Result blocks (not Go map lexical order).
	payload, err := marshalLegacyAnalysisJSONObject(output)
	if err != nil {
		return fmt.Errorf("marshal ordered analysis JSON: %w", err)
	}
	if err := os.WriteFile(filePath, payload, 0o644); err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	return nil
}

// partialControlEntries lists controls whose evaluation was partial —
// some inputs reachable, others not. CI gates parse this to decide
// whether to fail loud ("we never actually checked your protection
// rules") even when compliance is 100%.
func partialControlEntries(result *control.AnalysisResult) []map[string]any {
	if result == nil || result.GitHubStats == nil {
		return nil
	}
	var out []map[string]any
	if n := result.GitHubStats.BranchesProtectionDetailsUnknown; n > 0 {
		out = append(out, map[string]any{
			"control":          "branchMustBeProtected",
			"reason":           "Token lacks Administration:Read scope; force-push and code-owner-approval rules (ISSUE-505) not evaluated.",
			"affectedBranches": n,
			"remediation":      "Re-run with a token carrying Administration:Read (fine-grained PAT) or `repo` scope (classic PAT).",
		})
	}
	return out
}

// analysisJSONLegacyKeyHead is the canonical top-level key order before any
// *Result control blocks so analysis.json reads: project → CI context →
// outcome/score → findings (per-control).
var analysisJSONLegacyKeyHead = []string{
	"projectPath", "projectId", "defaultBranch",
	"ciConfigSource", "ciValid", "ciMissing", "ciErrors",
	"pipelineOriginMetrics", "pipelineImageMetrics",
	"compliance", "threshold", "passed", "plumberScore",
}

func legacyAnalysisJSONKeyOrder(m map[string]any) []string {
	seen := make(map[string]bool, len(m))
	order := make([]string, 0, len(m))
	for _, k := range analysisJSONLegacyKeyHead {
		if _, ok := m[k]; ok {
			order = append(order, k)
			seen[k] = true
		}
	}
	var suffixResult []string
	for k := range m {
		if seen[k] {
			continue
		}
		if strings.HasSuffix(k, "Result") {
			suffixResult = append(suffixResult, k)
		}
	}
	sort.Strings(suffixResult)
	for _, k := range suffixResult {
		order = append(order, k)
		seen[k] = true
	}
	var rest []string
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	order = append(order, rest...)
	return order
}

func marshalLegacyAnalysisJSONObject(output map[string]any) ([]byte, error) {
	keys := legacyAnalysisJSONKeyOrder(output)
	step := "  "
	var buf bytes.Buffer
	buf.WriteString("{\n")
	first := true
	for _, k := range keys {
		v, ok := output[k]
		if !ok {
			continue
		}
		if !first {
			buf.WriteString(",\n")
		}
		first = false

		keyBytes, err := json.Marshal(k)
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", k, err)
		}
		rawVal, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("%s value: %w", k, err)
		}

		buf.WriteString(step)
		buf.Write(keyBytes)
		buf.WriteString(": ")
		if len(rawVal) > 0 && (rawVal[0] == '{' || rawVal[0] == '[') {
			rawIndented, err := json.MarshalIndent(v, "", step)
			if err != nil {
				return nil, fmt.Errorf("%s indentation: %w", k, err)
			}
			trimmed := bytes.TrimSpace(rawIndented)
			lines := bytes.Split(trimmed, []byte("\n"))
			if len(lines) == 1 {
				buf.Write(lines[0])
				continue
			}
			// Opening bracket on the same line as the key; body lines indented.
			buf.Write(lines[0])
			buf.WriteByte('\n')
			for i := 1; i < len(lines)-1; i++ {
				buf.WriteString(step)
				buf.Write(lines[i])
				buf.WriteByte('\n')
			}
			buf.WriteString(step)
			buf.Write(lines[len(lines)-1])
			continue
		}
		buf.Write(rawVal)
	}
	buf.WriteString("\n}\n")
	return buf.Bytes(), nil
}

// buildImageComplianceData extracts compliance results into a lookup map for the PBOM generator
func buildImageComplianceData(result *control.AnalysisResult) *pbom.ImageComplianceData {
	data := &pbom.ImageComplianceData{
		ForbiddenTagImages: make(map[string]bool),
		UnauthorizedImages: make(map[string]bool),
	}
	if result.PipelineImageData == nil {
		return data
	}
	imagesByJob := make(map[string]string, len(result.PipelineImageData.Images))
	for _, img := range result.PipelineImageData.Images {
		imagesByJob[img.Job] = img.Link
		data.ForbiddenTagImages[img.Link] = false
		data.UnauthorizedImages[img.Link] = false
	}
	// Flip flags based on Rego findings. Image-pinning codes
	// (ISSUE-102/103) mark forbidden-tag; ISSUE-101 marks unauthorized.
	for _, f := range result.Findings {
		link, ok := imagesByJob[f.Job]
		if !ok {
			continue
		}
		switch control.ErrorCode(f.Code) {
		case control.CodeImageForbiddenTag, control.CodeImageNotPinnedByDigest:
			data.ForbiddenTagImages[link] = true
		case control.CodeImageUnauthorizedSource:
			data.UnauthorizedImages[link] = true
		}
	}
	return data
}

// buildIncludeOverrideData extracts override detection results into a lookup map for the PBOM generator.
// Keys are clean include paths (without version/instance prefix). The data
// now comes directly from the collector-enriched IR that the Rego engine
// already uses — no dependency on the legacy Go controls.
func buildIncludeOverrideData(result *control.AnalysisResult) *pbom.IncludeOverrideData {
	data := &pbom.IncludeOverrideData{
		Overrides: make(map[string][]utils.OverriddenJobDetail),
	}
	if result.PipelineOriginData == nil {
		return data
	}
	for idx := range result.PipelineOriginData.Origins {
		o := &result.PipelineOriginData.Origins[idx]
		location := o.GitlabIncludeOrigin.Location
		if location == "" {
			location = o.GitlabComponent.ComponentIncludePath
		}
		if location == "" {
			continue
		}
		key := utils.CleanOriginPath(location)
		irJobs := collector.CollectOverriddenJobs(o, result.PipelineOriginData)
		if len(irJobs) == 0 {
			continue
		}
		details := make([]utils.OverriddenJobDetail, 0, len(irJobs))
		for _, j := range irJobs {
			details = append(details, utils.OverriddenJobDetail{JobName: j.Name, OverriddenKeys: j.Keys})
		}
		data.Overrides[key] = details
	}
	return data
}

func pbomPlumberScoreSummary(score *control.PlumberScoreResult, scoreMode bool) *pbom.PlumberScoreSummary {
	if score == nil || !scoreMode {
		return nil
	}
	return &pbom.PlumberScoreSummary{
		ProfileID:            score.ProfileID,
		RawPoints:            score.RawPoints,
		FinalPoints:          score.FinalPoints,
		Score:                score.Score,
		CriticalMalusApplied: score.CriticalMalusApplied,
		CriticalMalusMax:     score.CriticalMalusMax,
		Counts: pbom.PlumberScoreCounts{
			Critical: score.Counts.Critical,
			High:     score.Counts.High,
			Medium:   score.Counts.Medium,
			Low:      score.Counts.Low,
		},
	}
}

func writePBOMToFile(result *control.AnalysisResult, gitlabURL, branch, filePath string, score *control.PlumberScoreResult, scoreMode bool) error {
	complianceData := buildImageComplianceData(result)
	overrideData := buildIncludeOverrideData(result)
	generator := pbom.NewGenerator(result.ProjectPath, result.ProjectID, gitlabURL, branch).
		WithComplianceData(complianceData).
		WithIncludeOverrideData(overrideData)
	pipelineBOM := generator.Generate(result.PipelineImageData, result.PipelineOriginData)
	pipelineBOM.PlumberScore = pbomPlumberScoreSummary(score, scoreMode)

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create PBOM file: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(pipelineBOM)
}

func writePBOMCycloneDXToFile(result *control.AnalysisResult, gitlabURL, branch, filePath string, score *control.PlumberScoreResult, scoreMode bool) error {
	complianceData := buildImageComplianceData(result)
	overrideData := buildIncludeOverrideData(result)
	generator := pbom.NewGenerator(result.ProjectPath, result.ProjectID, gitlabURL, branch).
		WithComplianceData(complianceData).
		WithIncludeOverrideData(overrideData)
	pipelineBOM := generator.Generate(result.PipelineImageData, result.PipelineOriginData)
	pipelineBOM.PlumberScore = pbomPlumberScoreSummary(score, scoreMode)

	cycloneDX := pipelineBOM.ToCycloneDX(Version)

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create CycloneDX PBOM file: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(cycloneDX)
}

// ANSI color codes
const (
	colorReset       = "\033[0m"
	colorRed         = "\033[31m"
	colorGreen       = "\033[32m"
	colorYellow      = "\033[33m"
	colorBlue        = "\033[34m"
	colorCyan        = "\033[36m"
	colorGreenBright = "\033[92m"
	colorBold        = "\033[1m"
	colorDim         = "\033[2m"
	colorBgRed       = "\033[41m"
	colorBgYellow    = "\033[43m"
	colorBlack       = "\033[30m"
	colorWhite       = "\033[97m"
)

func severityTag(code control.ErrorCode) string {
	switch control.SeverityForCode(code) {
	case control.SeverityCritical:
		return fmt.Sprintf("%s%s CRIT %s", colorBgRed, colorWhite, colorReset)
	case control.SeverityHigh:
		return fmt.Sprintf("%s%s HIGH %s", colorBgYellow, colorBlack, colorReset)
	case control.SeverityMedium:
		return fmt.Sprintf("%s MED  %s", colorCyan, colorReset)
	case control.SeverityLow:
		return fmt.Sprintf("%s LOW  %s", colorBlue, colorReset)
	default:
		return fmt.Sprintf("%s MED  %s", colorCyan, colorReset)
	}
}

func highestSeverityLabel(c control.SeverityCounts, visibleWidth int) string {
	pad := func(label string) string {
		w := utf8.RuneCountInString(label)
		if w < visibleWidth {
			return label + strings.Repeat(" ", visibleWidth-w)
		}
		return label
	}
	switch {
	case c.Critical > 0:
		return fmt.Sprintf("%s%s%s%s", colorBgRed, colorWhite, pad("Critical"), colorReset)
	case c.High > 0:
		return fmt.Sprintf("%s%s%s%s", colorBgYellow, colorBlack, pad("High"), colorReset)
	case c.Medium > 0:
		return fmt.Sprintf("%s%s%s", colorCyan, pad("Medium"), colorReset)
	case c.Low > 0:
		return fmt.Sprintf("%s%s%s", colorBlue, pad("Low"), colorReset)
	default:
		return fmt.Sprintf("%s%s%s", colorDim, pad("-"), colorReset)
	}
}

func scoreLetterColor(letter string) string {
	switch letter {
	case "A":
		return colorGreen
	case "B":
		return colorGreenBright
	case "C":
		return colorYellow
	case "D":
		return "\033[38;5;208m" // orange
	default:
		return colorRed
	}
}

func scoreBar(finalPoints float64, width int) string {
	filled := int(finalPoints / 100.0 * float64(width))
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	var barColor string
	switch {
	case finalPoints >= 90:
		barColor = colorGreen
	case finalPoints >= 71:
		barColor = colorGreenBright
	case finalPoints >= 51:
		barColor = colorYellow
	case finalPoints >= 31:
		barColor = "\033[38;5;208m"
	default:
		barColor = colorRed
	}
	return barColor + strings.Repeat("█", filled) + colorDim + strings.Repeat("░", width-filled) + colorReset
}

// controlSummary holds summary data for a control
type controlSummary struct {
	name       string
	compliance float64
	issues     int
	skipped    bool
	codes      []string
	bySeverity control.SeverityCounts // tallies from actual findings (C/H/M/L)
}

func uniqueSortedIssueCodeStrings(codes []control.ErrorCode) []string {
	seen := make(map[string]bool)
	var out []string
	for _, c := range codes {
		s := string(c)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// compareSeverityWorstFirst compares severity tallies for "which is worse".
// Returns negative if a is worse than b, positive if a is better, zero if equal.
func compareSeverityWorstFirst(a, b control.SeverityCounts) int {
	if a.Critical != b.Critical {
		if a.Critical > b.Critical {
			return -1
		}
		return 1
	}
	if a.High != b.High {
		if a.High > b.High {
			return -1
		}
		return 1
	}
	if a.Medium != b.Medium {
		if a.Medium > b.Medium {
			return -1
		}
		return 1
	}
	if a.Low != b.Low {
		if a.Low > b.Low {
			return -1
		}
		return 1
	}
	return 0
}

func sortControlSummariesForComplianceTable(s []controlSummary) {
	sort.SliceStable(s, func(i, j int) bool {
		a, b := s[i], s[j]
		if a.skipped != b.skipped {
			return !a.skipped && b.skipped
		}
		if a.skipped {
			return a.name < b.name
		}
		if a.compliance != b.compliance {
			return a.compliance < b.compliance
		}
		if cmp := compareSeverityWorstFirst(a.bySeverity, b.bySeverity); cmp != 0 {
			return cmp < 0
		}
		if a.issues != b.issues {
			return a.issues > b.issues
		}
		return a.name < b.name
	})
}

func sortControlSummariesForIssuesTable(s []controlSummary) {
	sort.SliceStable(s, func(i, j int) bool {
		a, b := s[i], s[j]
		if cmp := compareSeverityWorstFirst(a.bySeverity, b.bySeverity); cmp != 0 {
			return cmp < 0
		}
		if a.issues != b.issues {
			return a.issues > b.issues
		}
		return a.name < b.name
	})
}

// printBanner renders the Plumber ASCII-art banner followed by the
// tagline and community link. The banner keeps Plumber's signature
// green color for brand recognition.
func printBanner() {
	asciiArt := lipgloss.NewStyle().Foreground(colPass).Bold(true).Render(
		"  ██████╗ ██╗     ██╗   ██╗ ███╗   ███╗██████╗ ███████╗██████╗ \n" +
			"  ██╔══██╗██║     ██║   ██║ ████╗ ████║██╔══██╗██╔════╝██╔══██╗\n" +
			"  ██████╔╝██║     ██║   ██║ ██╔████╔██║██████╔╝█████╗  ██████╔╝\n" +
			"  ██╔═══╝ ██║     ██║   ██║ ██║╚██╔╝██║██╔══██╗██╔══╝  ██╔══██╗\n" +
			"  ██║     ███████╗╚██████╔╝ ██║ ╚═╝ ██║██████╔╝███████╗██║  ██║\n" +
			"  ╚═╝     ╚══════╝ ╚═════╝  ╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝",
	)
	fmt.Println()
	fmt.Println(asciiArt)
	fmt.Printf("  %s  %s\n",
		styleTitle.Render("CI/CD Compliance Scanner for GitLab & GitHub Actions"),
		styleMuted.Render("v"+Version),
	)
	fmt.Printf("  %s %s\n\n",
		styleMuted.Render("Join our community:"),
		styleAccent.Render("https://getplumber.io/discord"),
	)
}

func outputText(result *control.AnalysisResult, pc *configuration.PlumberConfig, threshold, compliance float64, controlCount int, score *control.PlumberScoreResult, scoreMode, scorePointMode bool, controlsFilterList, skipControlsList []string) error {
	// Collect control summaries for tables
	var controls []controlSummary

	// Header
	fmt.Printf("\n%s %s\n\n", styleTitle.Render("Project:"), result.ProjectPath)

	// Warning if no controls could be evaluated
	if controlCount == 0 {
		fmt.Printf("  %s\n", styleError.Render("⚠ WARNING: No controls could be evaluated!"))

		if len(result.CiErrors) > 0 {
			fmt.Printf("  %s\n", styleError.Render("CI configuration errors:"))
			bullet := styleError.Render("•")
			for _, e := range result.CiErrors {
				fmt.Printf("    %s %s\n", bullet, e)
			}
			fmt.Println()
		} else if result.CiMissing {
			fmt.Printf("  %s\n\n", styleDim.Render("CI configuration file is missing from the project."))
		} else {
			fmt.Printf("  %s\n", styleDim.Render("Data collection failed - compliance defaults to 0%."))
			fmt.Printf("  %s\n\n", styleDim.Render("Use --verbose for more info."))
		}
	}

	// CI config source info
	if result.CIConfigSource == "local" {
		fmt.Printf("  %s\n\n", styleAccent.Render("CI Config Source: local file"))
	}

	// Build control summaries and detailed-finding groups from the
	// config-driven catalog (one entry per configured .plumber.yaml
	// section) joined with the Rego Findings list. Compliance is
	// binary: 100 when no finding matches the control, 0 otherwise.
	// The unified renderer in render_details.go handles the printing
	// (shared with the GitHub analyze path).
	findingsByControl := control.FindingsByControl(result.Findings)
	entries := control.GitLabControls(pc)
	control.MarkSkippedByFilter(entries, controlsFilterList, skipControlsList)
	groups := make([]findingGroup, 0, len(entries))
	for _, e := range entries {
		findings := findingsByControl[e.ControlName]
		if e.ControlName == "branchMustBeProtected" {
			sortBranchProtectionFindingsForDisplay(findings)
		}
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
		compliance := 100.0
		if !e.Skipped && len(items) > 0 {
			compliance = 0.0
		}
		controls = append(controls, controlSummary{
			name:       e.DisplayName,
			compliance: compliance,
			issues:     len(items),
			skipped:    e.Skipped,
			codes:      uniqueSortedIssueCodeStrings(codes),
			bySeverity: control.SeverityCountsFromIssueCodes(codes),
		})
		groups = append(groups, findingGroup{
			Title:      e.DisplayName,
			Compliance: compliance,
			Skipped:    e.Skipped,
			Stats:      buildGitLabControlStats(e.ControlName, result, pc, findings),
			Findings:   items,
		})
	}
	renderFindingGroups(groups)

	// Summary Section
	printSectionHeader("Summary")
	fmt.Println()

	if crit := control.CriticalIssueCodesSorted(result); len(crit) > 0 {
		fmt.Printf("  %s▶ Critical issue codes:%s %s\n", colorRed, colorReset, strings.Join(crit, ", "))
		fmt.Println()
	}

	// Status
	if compliance >= threshold {
		fmt.Printf("  Status: %s%sPASSED ✓%s\n\n", colorBold, colorGreen, colorReset)
	} else {
		fmt.Printf("  Status: %s%sFAILED ✗%s\n\n", colorBold, colorRed, colorReset)
	}

	// Issues Table
	printIssuesTable(controls)
	fmt.Println()

	// Compliance Table (issues/compliance summary before Plumber score output)
	printComplianceTable(controls, compliance, threshold)
	fmt.Println()

	// Letter score + points breakdown last on stdout (--score / --score-point)
	printSummaryScoreBanner(score, scoreMode)
	if scorePointMode && score != nil {
		printScoreBreakdown(score)
	}

	return nil
}

// scoreBreakdownWidths are inner text widths (padding applied after; borders use w+2 dashes per column).
const (
	sbWCode = 11
	sbWSev  = 10
	sbWCnt  = 5
	sbWWgt  = 6
	sbWCap  = 5
	sbWLoss = 8
)

func padRunesRight(s string, w int) string {
	n := utf8.RuneCountInString(s)
	if n >= w {
		return s
	}
	return s + strings.Repeat(" ", w-n)
}

func padRunesLeft(s string, w int) string {
	n := utf8.RuneCountInString(s)
	if n >= w {
		return s
	}
	return strings.Repeat(" ", w-n) + s
}

func scoreBreakdownBorderTop() string {
	parts := []int{sbWCode, sbWSev, sbWCnt, sbWWgt, sbWCap, sbWLoss}
	var segs []string
	for _, w := range parts {
		segs = append(segs, strings.Repeat("─", w+2))
	}
	return "┌" + strings.Join(segs, "┬") + "┐"
}

func scoreBreakdownBorderMid() string {
	parts := []int{sbWCode, sbWSev, sbWCnt, sbWWgt, sbWCap, sbWLoss}
	var segs []string
	for _, w := range parts {
		segs = append(segs, strings.Repeat("─", w+2))
	}
	return "├" + strings.Join(segs, "┼") + "┤"
}

func scoreBreakdownBorderMidFooter() string {
	parts := []int{sbWCode, sbWSev, sbWCnt, sbWWgt, sbWCap, sbWLoss}
	var segs []string
	for _, w := range parts {
		segs = append(segs, strings.Repeat("─", w+2))
	}
	// Merge the first five columns into a single "Total loss" cell, leaving the Loss column.
	return "├" + strings.Join(segs[:5], "┴") + "┼" + segs[5] + "┤"
}

func scoreBreakdownBorderBottom() string {
	parts := []int{sbWCode, sbWSev, sbWCnt, sbWWgt, sbWCap, sbWLoss}
	var segs []string
	for _, w := range parts {
		segs = append(segs, strings.Repeat("─", w+2))
	}
	return "└" + strings.Join(segs, "┴") + "┘"
}

func scoreBreakdownSevColor(sev control.IssueSeverity) string {
	switch sev {
	case control.SeverityCritical:
		return colorRed
	case control.SeverityHigh:
		return colorYellow
	case control.SeverityMedium:
		return colorCyan
	default:
		return colorBlue
	}
}

func printScoreBreakdown(score *control.PlumberScoreResult) {
	printSectionHeader("Points breakdown (beta)")
	fmt.Println()
	fmt.Printf("  %sProfile:%s %s\n\n", colorDim, colorReset, score.ProfileID)

	var totalLoss float64
	if len(score.CodeLosses) > 0 {
		fmt.Printf("  %s%s%s\n", colorDim, scoreBreakdownBorderTop(), colorReset)
		fmt.Printf("  %s│ %s │ %s │ %s │ %s │ %s │ %s │%s\n", colorDim,
			padRunesRight("Code", sbWCode),
			padRunesRight("Severity", sbWSev),
			padRunesLeft("Count", sbWCnt),
			padRunesLeft("Weight", sbWWgt),
			padRunesLeft("Cap", sbWCap),
			padRunesLeft("Loss", sbWLoss),
			colorReset)
		fmt.Printf("  %s%s%s\n", colorDim, scoreBreakdownBorderMid(), colorReset)

		for _, l := range score.CodeLosses {
			capPlain := "inf"
			if l.Severity != control.SeverityCritical {
				capPlain = fmt.Sprintf("%.0f", l.Cap)
			}
			sc := scoreBreakdownSevColor(l.Severity)
			lossStr := fmt.Sprintf("-%.1f", l.CappedLoss)
			fmt.Printf("  %s│ %s%s%s │ %s%s%s │ %s%s%s │ %s%s%s │ %s%s%s │ %s%s%s │%s\n", colorDim,
				colorDim, padRunesRight(string(l.Code), sbWCode), colorReset,
				sc, padRunesRight(string(l.Severity), sbWSev), colorReset,
				colorDim, padRunesLeft(fmt.Sprintf("%d", l.Count), sbWCnt), colorReset,
				colorDim, padRunesLeft(fmt.Sprintf("%.0f", l.Weight), sbWWgt), colorReset,
				colorDim, padRunesLeft(capPlain, sbWCap), colorReset,
				colorRed, padRunesLeft(lossStr, sbWLoss), colorReset,
				colorReset)
			totalLoss += l.CappedLoss
		}
		fmt.Printf("  %s%s%s\n", colorDim, scoreBreakdownBorderMidFooter(), colorReset)

		// Merge first five columns ("Code", "Severity", "Count", "Weight", "Cap") for the Total row.
		mergedW := sbWCode + 3 + sbWSev + 3 + sbWCnt + 3 + sbWWgt + 3 + sbWCap // " │ " between five columns
		tl := "Total loss"
		tlPad := mergedW - utf8.RuneCountInString(tl)
		if tlPad < 0 {
			tlPad = 0
		}
		leftCell := colorBold + tl + colorReset + strings.Repeat(" ", tlPad)
		totalStr := fmt.Sprintf("-%.1f", totalLoss)
		fmt.Printf("  %s│ %s │ %s%s%s │%s\n", colorDim,
			leftCell,
			colorRed, padRunesLeft(totalStr, sbWLoss), colorReset,
			colorReset)
		fmt.Printf("  %s%s%s\n", colorDim, scoreBreakdownBorderBottom(), colorReset)
		fmt.Println()

		fmt.Printf("  Base points: %s100%s\n", colorGreen, colorReset)
		fmt.Printf("  Total loss:  %s-%.1f%s\n", colorRed, totalLoss, colorReset)
		fmt.Printf("  Raw points:  %.1f\n", score.RawPoints)
	} else {
		fmt.Printf("  Base points: %s100%s\n", colorGreen, colorReset)
		fmt.Printf("  Raw points:  %.1f\n", score.RawPoints)
	}
	if score.CriticalMalusApplied {
		fmt.Printf("  %sCritical malus: final points capped at %.0f%s\n", colorRed, score.CriticalMalusMax, colorReset)
	}
	gc := scoreLetterColor(score.Score)
	fmt.Printf("  %sFinal points:%s %s%s%.1f / 100%s\n", colorBold, colorReset, colorBold, gc, score.FinalPoints, colorReset)
	fmt.Printf("  %sScore:%s       %s%s%s%s\n", colorBold, colorReset, gc, colorBold, score.Score, colorReset)
	fmt.Println()
	fmt.Printf("  %sLetter score (from points):%s  %sA%s >=90  %s│%s  %sB%s >=71  %s│%s  %sC%s >=51  %s│%s  %sD%s >=31  %s│%s  %sE%s <31\n",
		colorDim, colorReset,
		colorGreen, colorReset, colorDim, colorReset,
		colorGreenBright, colorReset, colorDim, colorReset,
		colorYellow, colorReset, colorDim, colorReset,
		"\033[38;5;208m", colorReset, colorDim, colorReset,
		colorRed, colorReset)
	fmt.Println()
}

func printControlHeader(name string, compliance float64, skipped bool) {
	line := strings.Repeat("─", 50)
	fmt.Printf("%s%s%s\n", colorDim, line, colorReset)
	if skipped {
		fmt.Printf("%s%s%s %s(skipped)%s\n", colorBold, name, colorReset, colorDim, colorReset)
	} else {
		compColor := colorGreen
		if compliance < 100 {
			compColor = colorYellow
		}
		if compliance == 0 {
			compColor = colorRed
		}
		fmt.Printf("%s%s%s %s(%.1f%% compliant)%s\n", colorBold, name, colorReset, compColor, compliance, colorReset)
	}
	fmt.Printf("%s%s%s\n", colorDim, line, colorReset)
}

func printSectionHeader(name string) {
	line := strings.Repeat("─", 20)
	fmt.Printf("%s%s%s\n", colorDim, line, colorReset)
	fmt.Printf("%s%s%s\n", colorBold, name, colorReset)
	fmt.Printf("%s%s%s\n", colorDim, line, colorReset)
}

// scoreLetterBadgeLines returns 5 pre-colored lines drawing a double-bordered badge
// around the letter score (A–E), e.g.
//
//	╔═══════╗
//	║       ║
//	║   E   ║
//	║       ║
//	╚═══════╝
//
// The whole badge (borders + letter) is rendered in bold, using the letter's
// tier color so it reads as a single coherent visual token.
// printSummaryScoreBanner renders the Plumber letter score in a
// modernised two-column layout: a large grade badge on the left, and
// a side panel on the right with points, progress bar, meaning text,
// severity chips, and any Critical malus warning.
func printSummaryScoreBanner(score *control.PlumberScoreResult, scoreMode bool) {
	if score == nil || !scoreMode {
		return
	}

	letterColor := scoreLetterLipglossColor(score.Score)

	// Block-letter ASCII badge — six lines tall, matches the project
	// banner lettering style.
	badge := scoreLetterAsciiArt(score.Score)

	letterStyle := lipgloss.NewStyle().Foreground(letterColor).Bold(true)
	pointsLine := letterStyle.Render(fmt.Sprintf("%.0f / 100 pts", score.FinalPoints))
	bar := scoreBar(score.FinalPoints, 28)
	meaning := ""
	if m := control.ScoreLetterMeaning(score.Score); m != "" {
		meaning = styleMuted.Render(m)
	}
	chips := fmt.Sprintf("%s   %s   %s   %s",
		severityChip("critical", "Critical", score.Counts.Critical),
		severityChip("high", "High", score.Counts.High),
		severityChip("medium", "Medium", score.Counts.Medium),
		severityChip("low", "Low", score.Counts.Low))

	// Six-line side panel matching the block-letter badge height:
	// blank line, points, bar, meaning, blank, chips.
	side := lipgloss.JoinVertical(lipgloss.Left,
		"",
		pointsLine,
		bar,
		meaning,
		"",
		chips,
	)
	// lipgloss.JoinHorizontal vertically centers the two blocks; the
	// side panel gets a small left gutter.
	body := lipgloss.JoinHorizontal(lipgloss.Center,
		badge,
		lipgloss.NewStyle().PaddingLeft(2).Render(side),
	)

	sep := styleRule.Render(strings.Repeat("─", hrWidth))

	fmt.Println()
	fmt.Println(" " + sep)
	fmt.Println(" " + styleMuted.Render("Plumber Score"))
	fmt.Println()
	fmt.Println(indentBlock(body, " "))

	if score.CriticalMalusApplied {
		fmt.Println()
		fmt.Printf(" %s  %s\n",
			styleFail.Render("▲ Critical malus applied"),
			styleMuted.Render(fmt.Sprintf("(final points capped at %.0f while any Critical remains)", score.CriticalMalusMax)))
	}

	fmt.Println()
	fmt.Println(" " + sep)
	fmt.Println()
}

// severityChip renders a single severity count as an emoji + label +
// colored count, used by the modern score banner.
func severityChip(sev, label string, n int) string {
	countStyle := lipgloss.NewStyle().Foreground(severityColor(sev)).Bold(true)
	return severityIcon(sev) + " " + styleMuted.Render(label) + " " + countStyle.Render(fmt.Sprintf("%d", n))
}

func printIssuesTable(controls []controlSummary) {
	var rows []controlSummary
	for _, c := range controls {
		if c.issues > 0 {
			rows = append(rows, c)
		}
	}

	fmt.Printf("  %s\n", styleTitle.Render("Controls"))
	if len(rows) == 0 {
		fmt.Printf("  %s\n", styleDim.Render("(none with open issues)"))
		return
	}

	sortControlSummariesForIssuesTable(rows)

	tbl := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(styleAccent).
		Headers("Control", "Codes", "Severity", "#").
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return styleHeader
			}
			if col == 3 && row >= 0 && row < len(rows) && rows[row].issues > 0 {
				return styleCell.Inherit(styleError)
			}
			return styleCell
		})

	for _, ctrl := range rows {
		issueStr := "-"
		if !ctrl.skipped {
			issueStr = fmt.Sprintf("%d", ctrl.issues)
		}
		codesStr := strings.Join(ctrl.codes, ", ")
		if ctrl.skipped {
			codesStr = "-"
		}
		sevLabel := highestSeverityLabel(ctrl.bySeverity, 10)
		if ctrl.skipped || ctrl.bySeverity.Critical+ctrl.bySeverity.High+ctrl.bySeverity.Medium+ctrl.bySeverity.Low == 0 {
			sevLabel = highestSeverityLabel(control.SeverityCounts{}, 10)
		}
		tbl.Row(ctrl.name, codesStr, sevLabel, issueStr)
	}

	fmt.Println(indentBlock(tbl.String(), "  "))
	fmt.Printf("  %s\n", styleDim.Render("↳ docs: https://getplumber.io/docs/use-plumber/issues/<code>"))
}

// indentBlock prefixes every line of s with prefix. Used because
// lipgloss tables render flush-left and we want a little left margin.
func indentBlock(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

func printComplianceTable(controls []controlSummary, overallCompliance, threshold float64) {
	fmt.Printf("  %s\n", styleTitle.Render("Compliance"))

	sorted := append([]controlSummary(nil), controls...)
	sortControlSummariesForComplianceTable(sorted)

	// Total line rendered as an extra row at the bottom. We remember its
	// index so StyleFunc can make it bold.
	type rowKind int
	const (
		rowControl rowKind = iota
		rowTotal
	)
	type tblRow struct {
		kind    rowKind
		name    string
		compStr string
		status  string
		compOK  bool
	}

	var rows []tblRow
	for _, ctrl := range sorted {
		r := tblRow{kind: rowControl, name: ctrl.name, compStr: "-", status: "-"}
		if !ctrl.skipped {
			r.compStr = fmt.Sprintf("%.1f%%", ctrl.compliance)
			r.compOK = ctrl.compliance >= 100
			if r.compOK {
				r.status = "🟢"
			} else {
				r.status = "🔴"
			}
		}
		rows = append(rows, r)
	}
	totalRow := tblRow{
		kind:    rowTotal,
		name:    fmt.Sprintf("Total (required: %.0f%%)", threshold),
		compStr: fmt.Sprintf("%.1f%%", overallCompliance),
		compOK:  overallCompliance >= threshold,
	}
	if totalRow.compOK {
		totalRow.status = "🟢"
	} else {
		totalRow.status = "🔴"
	}
	rows = append(rows, totalRow)

	tbl := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(styleAccent).
		Headers("Control", "Compliance", "Status").
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return styleHeader
			}
			if row < 0 || row >= len(rows) {
				return styleCell
			}
			r := rows[row]
			style := styleCell
			if r.kind == rowTotal {
				style = style.Bold(true)
			}
			if col == 1 || col == 2 {
				if r.compStr == "-" {
					return style.Faint(true)
				}
				if r.compOK {
					return style.Inherit(styleSuccess)
				}
				return style.Inherit(styleError)
			}
			return style
		})

	for _, r := range rows {
		tbl.Row(r.name, r.compStr, r.status)
	}

	fmt.Println(indentBlock(tbl.String(), "  "))
}
