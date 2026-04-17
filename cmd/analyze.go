package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

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
	showScore        bool
	showScorePoint   bool
	controlsFilter    string
	skipControls      string
	ciConfigPath      string
)

var analyzeCmd = &cobra.Command{
	Use:          "analyze",
	Short:        "Analyze a GitLab project's CI/CD pipeline",
	SilenceUsage: true, // Don't print usage on errors (e.g., threshold failures)
	Long: `Analyze a GitLab project's CI/CD pipeline for compliance issues.

This command connects to a GitLab instance, retrieves the project's CI/CD
configuration, and runs various checks including:
- Pipeline origin analysis (components, templates, local files)
- Pipeline image analysis (registries, tags)
- Mutable image tag detection
- Image digest pinning enforcement

Required environment variables:
  GITLAB_TOKEN    GitLab API token (required)

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
	projectFromFlag := cmd.Flags().Changed("project")

	var gitRepoRoot string
	var gitRemoteURL string
	var gitRemoteProjectPath string

	if remoteInfo := utils.DetectGitRemote(); remoteInfo != nil {
		gitRepoRoot = remoteInfo.RepoRoot
		gitRemoteURL = remoteInfo.URL
		gitRemoteProjectPath = remoteInfo.ProjectPath

		if !gitlabURLFromFlag {
			gitlabURL = remoteInfo.URL
			fmt.Fprintf(os.Stderr, "Auto-detected GitLab URL: %s\n", gitlabURL)
		}
		if !projectFromFlag {
			projectPath = remoteInfo.ProjectPath
			fmt.Fprintf(os.Stderr, "Auto-detected project: %s\n", projectPath)
		}
	}

	// Validate required values (either from flags or auto-detected)
	if gitlabURL == "" {
		return fmt.Errorf("--gitlab-url is required (could not auto-detect from git remote)")
	}
	if projectPath == "" {
		return fmt.Errorf("--project is required (could not auto-detect from git remote)")
	}

	// Validate threshold
	if threshold < 0 || threshold > 100 {
		return fmt.Errorf("threshold must be between 0 and 100")
	}
	if controlsFilter != "" && skipControls != "" {
		return fmt.Errorf("--controls and --skip-controls cannot be used together")
	}

	// --score-point implies score output; if both --score and --score-point are set, points mode wins for breakdown/MR text.
	scoreMode := showScore || showScorePoint
	scorePointMode := showScorePoint

	controlsFilterList, err := parseControlsFilter(controlsFilter)
	if err != nil {
		return err
	}

	skipControlsList, err := parseControlsFilter(skipControls)
	if err != nil {
		return err
	}

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

	// Calculate overall compliance (average of all enabled controls)
	var complianceSum float64 = 0
	controlCount := 0

	if result.ImageForbiddenTagsResult != nil && !result.ImageForbiddenTagsResult.Skipped {
		complianceSum += result.ImageForbiddenTagsResult.Compliance
		controlCount++
	}

	if result.ImageAuthorizedSourcesResult != nil && !result.ImageAuthorizedSourcesResult.Skipped {
		complianceSum += result.ImageAuthorizedSourcesResult.Compliance
		controlCount++
	}

	if result.BranchProtectionResult != nil && !result.BranchProtectionResult.Skipped {
		complianceSum += result.BranchProtectionResult.Compliance
		controlCount++
	}

	if result.HardcodedJobsResult != nil && !result.HardcodedJobsResult.Skipped {
		complianceSum += result.HardcodedJobsResult.Compliance
		controlCount++
	}

	if result.OutdatedIncludesResult != nil && !result.OutdatedIncludesResult.Skipped {
		complianceSum += result.OutdatedIncludesResult.Compliance
		controlCount++
	}

	if result.ForbiddenVersionsIncludesResult != nil && !result.ForbiddenVersionsIncludesResult.Skipped {
		complianceSum += result.ForbiddenVersionsIncludesResult.Compliance
		controlCount++
	}

	if result.RequiredComponentsResult != nil && !result.RequiredComponentsResult.Skipped {
		complianceSum += result.RequiredComponentsResult.Compliance
		controlCount++
	}

	if result.RequiredTemplatesResult != nil && !result.RequiredTemplatesResult.Skipped {
		complianceSum += result.RequiredTemplatesResult.Compliance
		controlCount++
	}

	if result.DebugTraceResult != nil && !result.DebugTraceResult.Skipped {
		complianceSum += result.DebugTraceResult.Compliance
		controlCount++
	}

	if result.VariableInjectionResult != nil && !result.VariableInjectionResult.Skipped {
		complianceSum += result.VariableInjectionResult.Compliance
		controlCount++
	}

	if result.SecurityJobsWeakenedResult != nil && !result.SecurityJobsWeakenedResult.Skipped {
		complianceSum += result.SecurityJobsWeakenedResult.Compliance
		controlCount++
	}

	if result.UnverifiedScriptsResult != nil && !result.UnverifiedScriptsResult.Skipped {
		complianceSum += result.UnverifiedScriptsResult.Compliance
		controlCount++
	}

	if result.JobVariablesOverrideResult != nil && !result.JobVariablesOverrideResult.Skipped {
		complianceSum += result.JobVariablesOverrideResult.Compliance
		controlCount++
	}

	if result.DockerInDockerResult != nil && !result.DockerInDockerResult.Skipped {
		complianceSum += result.DockerInDockerResult.Compliance
		controlCount++
	}

	// Calculate average compliance
	// If no controls ran (e.g., data collection failed), compliance is 0% - we can't verify anything
	var compliance float64 = 0
	if controlCount > 0 {
		compliance = complianceSum / float64(controlCount)
	}

	var scoreResult *control.PlumberScoreResult
	if scoreMode {
		counts := control.AggregateSeverityCounts(result)
		s := control.ComputePlumberScore(counts)
		scoreResult = &s
	}

	// Print text output to stdout if enabled
	if printOutput {
		if err := outputText(result, threshold, compliance, controlCount, scoreResult, scoreMode, scorePointMode); err != nil {
			return err
		}
	}

	// Write JSON to file if specified
	if outputFile != "" {
		if err := writeJSONToFile(result, threshold, compliance, outputFile, scoreResult, scoreMode); err != nil {
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
			if err := control.ManageMergeRequestComment(result.ProjectID, mrIID, result, compliance, threshold, conf, scoreResult, scoreMode, scorePointMode); err != nil {
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

func writeJSONToFile(result *control.AnalysisResult, threshold, compliance float64, filePath string, score *control.PlumberScoreResult, scoreMode bool) error {
	// Create output with threshold info
	output := struct {
		*control.AnalysisResult
		Threshold    float64                     `json:"threshold"`
		Compliance   float64                     `json:"compliance"`
		Passed       bool                        `json:"passed"`
		PlumberScore *control.PlumberScoreResult `json:"plumberScore,omitempty"`
	}{
		AnalysisResult: result,
		Threshold:      threshold,
		Compliance:     compliance,
		Passed:         compliance >= threshold,
	}
	if scoreMode && score != nil {
		s := *score
		output.PlumberScore = &s
	}

	// Create/overwrite the file
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// buildImageComplianceData extracts compliance results into a lookup map for the PBOM generator
func buildImageComplianceData(result *control.AnalysisResult) *pbom.ImageComplianceData {
	data := &pbom.ImageComplianceData{
		ForbiddenTagImages: make(map[string]bool),
		UnauthorizedImages: make(map[string]bool),
	}

	// Build set of images with forbidden tags from control results
	if result.ImageForbiddenTagsResult != nil && !result.ImageForbiddenTagsResult.Skipped {
		// Mark all images as NOT having forbidden tags first
		if result.PipelineImageData != nil {
			for _, img := range result.PipelineImageData.Images {
				data.ForbiddenTagImages[img.Link] = false
			}
		}
		// Then mark the ones that do
		for _, issue := range result.ImageForbiddenTagsResult.Issues {
			data.ForbiddenTagImages[issue.Link] = true
		}
	}

	// Build set of unauthorized images from control results
	if result.ImageAuthorizedSourcesResult != nil && !result.ImageAuthorizedSourcesResult.Skipped {
		// Mark all images as authorized first
		if result.PipelineImageData != nil {
			for _, img := range result.PipelineImageData.Images {
				data.UnauthorizedImages[img.Link] = false
			}
		}
		// Then mark the ones that aren't
		for _, issue := range result.ImageAuthorizedSourcesResult.Issues {
			data.UnauthorizedImages[issue.Link] = true
		}
	}

	return data
}

// buildIncludeOverrideData extracts override detection results into a lookup map for the PBOM generator.
// Keys are clean include paths (without version/instance prefix).
func buildIncludeOverrideData(result *control.AnalysisResult) *pbom.IncludeOverrideData {
	data := &pbom.IncludeOverrideData{
		Overrides: make(map[string][]utils.OverriddenJobDetail),
	}

	if r := result.RequiredComponentsResult; r != nil && !r.Skipped {
		for _, issue := range r.OverriddenIssues {
			data.Overrides[issue.ComponentPath] = issue.OverriddenJobs
		}
	}

	if r := result.RequiredTemplatesResult; r != nil && !r.Skipped {
		for _, issue := range r.OverriddenIssues {
			data.Overrides[issue.TemplatePath] = issue.OverriddenJobs
		}
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

func printBanner() {
	fmt.Printf("\n")
	fmt.Printf("%s", colorGreenBright)
	fmt.Printf("  ██████╗ ██╗     ██╗   ██╗ ███╗   ███╗██████╗ ███████╗██████╗ \n")
	fmt.Printf("  ██╔══██╗██║     ██║   ██║ ████╗ ████║██╔══██╗██╔════╝██╔══██╗\n")
	fmt.Printf("  ██████╔╝██║     ██║   ██║ ██╔████╔██║██████╔╝█████╗  ██████╔╝\n")
	fmt.Printf("  ██╔═══╝ ██║     ██║   ██║ ██║╚██╔╝██║██╔══██╗██╔══╝  ██╔══██╗\n")
	fmt.Printf("  ██║     ███████╗╚██████╔╝ ██║ ╚═╝ ██║██████╔╝███████╗██║  ██║\n")
	fmt.Printf("  ╚═╝     ╚══════╝ ╚═════╝  ╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝\n")
	fmt.Printf("%s", colorReset)
	fmt.Printf("  %sCI/CD Compliance Scanner for GitLab Pipelines%s\n", colorBold, colorReset)
	fmt.Printf("  %sJoin our community: %shttps://getplumber.io/discord%s\n\n", colorDim, colorCyan, colorReset)
}

func outputText(result *control.AnalysisResult, threshold, compliance float64, controlCount int, score *control.PlumberScoreResult, scoreMode, scorePointMode bool) error {
	// Collect control summaries for tables
	var controls []controlSummary

	// Header
	fmt.Printf("\n%sProject: %s%s\n\n", colorBold, result.ProjectPath, colorReset)

	// Warning if no controls could be evaluated
	if controlCount == 0 {
		fmt.Printf("  %s⚠ WARNING: No controls could be evaluated!%s\n", colorRed, colorReset)

		if len(result.CiErrors) > 0 {
			fmt.Printf("  %sCI configuration errors:%s\n", colorRed, colorReset)
			for _, e := range result.CiErrors {
				fmt.Printf("    %s•%s %s\n", colorRed, colorReset, e)
			}
			fmt.Println()
		} else if result.CiMissing {
			fmt.Printf("  %sCI configuration file is missing from the project.%s\n\n", colorDim, colorReset)
		} else {
			fmt.Printf("  %sData collection failed - compliance defaults to 0%%.%s\n", colorDim, colorReset)
			fmt.Printf("  %sUse --verbose for more info.%s\n\n", colorDim, colorReset)
		}
	}

	// CI config source info
	if result.CIConfigSource == "local" {
		fmt.Printf("  %sCI Config Source: local file%s\n\n", colorCyan, colorReset)
	}

	// Control 1: Container images must not use forbidden tags
	if result.ImageForbiddenTagsResult != nil {
		controlName := "Container images must not use forbidden tags"
		if result.ImageForbiddenTagsResult.MustBePinnedByDigest {
			controlName = "Container images must not use forbidden tags (pinned by digest)"
		}

		ftIssueCodes := make([]control.ErrorCode, 0, len(result.ImageForbiddenTagsResult.Issues))
		for _, issue := range result.ImageForbiddenTagsResult.Issues {
			ftIssueCodes = append(ftIssueCodes, issue.Code)
		}
		ctrl := controlSummary{
			name:       controlName,
			compliance: result.ImageForbiddenTagsResult.Compliance,
			issues:     len(result.ImageForbiddenTagsResult.Issues),
			skipped:    result.ImageForbiddenTagsResult.Skipped,
			codes:      uniqueSortedIssueCodeStrings(ftIssueCodes),
			bySeverity: control.SeverityCountsFromIssueCodes(ftIssueCodes),
		}
		controls = append(controls, ctrl)

		printControlHeader(controlName, result.ImageForbiddenTagsResult.Compliance, result.ImageForbiddenTagsResult.Skipped)

		if result.ImageForbiddenTagsResult.Skipped {
			fmt.Printf("  %sStatus: SKIPPED (disabled in configuration)%s\n", colorDim, colorReset)
		} else if result.ImageForbiddenTagsResult.MustBePinnedByDigest {
			// Digest pinning mode
			fmt.Printf("  Total Images: %d\n", result.ImageForbiddenTagsResult.Metrics.Total)
			fmt.Printf("  Pinned By Digest: %d\n", result.ImageForbiddenTagsResult.Metrics.PinnedByDigest)
			fmt.Printf("  Not Pinned By Digest: %d\n", result.ImageForbiddenTagsResult.Metrics.NotPinnedByDigest)

			if len(result.ImageForbiddenTagsResult.Issues) > 0 {
				fmt.Printf("\n  %sImages Not Pinned By Digest Found:%s\n", colorYellow, colorReset)
				for _, issue := range result.ImageForbiddenTagsResult.Issues {
					fmt.Printf("    %s [%s] Job '%s' uses image without digest pinning: %s\n", severityTag(issue.Code), issue.Code, issue.Job, issue.Link)
					fmt.Printf("      %s↳ docs: %s%s\n", colorDim, issue.DocURL, colorReset)
				}
			}
		} else {
			// Standard forbidden tags mode
			fmt.Printf("  Total Images: %d\n", result.ImageForbiddenTagsResult.Metrics.Total)
			fmt.Printf("  Using Forbidden Tags: %d\n", result.ImageForbiddenTagsResult.Metrics.UsingForbiddenTags)

			if len(result.ImageForbiddenTagsResult.Issues) > 0 {
				fmt.Printf("\n  %sForbidden Tags Found:%s\n", colorYellow, colorReset)
				for _, issue := range result.ImageForbiddenTagsResult.Issues {
					fmt.Printf("    %s [%s] Job '%s' uses forbidden tag '%s' (image: %s)\n", severityTag(issue.Code), issue.Code, issue.Job, issue.Tag, issue.Link)
					fmt.Printf("      %s↳ docs: %s%s\n", colorDim, issue.DocURL, colorReset)
				}
			}
		}
		fmt.Println()
	}

	// Control 2: Container images must come from authorized sources
	if result.ImageAuthorizedSourcesResult != nil {
		authCodes := make([]control.ErrorCode, 0, len(result.ImageAuthorizedSourcesResult.Issues))
		for _, issue := range result.ImageAuthorizedSourcesResult.Issues {
			authCodes = append(authCodes, issue.Code)
		}
		ctrl := controlSummary{
			name:       "Container images must come from authorized sources",
			compliance: result.ImageAuthorizedSourcesResult.Compliance,
			issues:     len(result.ImageAuthorizedSourcesResult.Issues),
			skipped:    result.ImageAuthorizedSourcesResult.Skipped,
			codes:      uniqueSortedIssueCodeStrings(authCodes),
			bySeverity: control.SeverityCountsFromIssueCodes(authCodes),
		}
		controls = append(controls, ctrl)

		printControlHeader("Container images must come from authorized sources", result.ImageAuthorizedSourcesResult.Compliance, result.ImageAuthorizedSourcesResult.Skipped)

		if result.ImageAuthorizedSourcesResult.Skipped {
			fmt.Printf("  %sStatus: SKIPPED (disabled in configuration)%s\n", colorDim, colorReset)
		} else {
			fmt.Printf("  Total Images: %d\n", result.ImageAuthorizedSourcesResult.Metrics.Total)
			fmt.Printf("  Authorized: %d\n", result.ImageAuthorizedSourcesResult.Metrics.Authorized)
			fmt.Printf("  Unauthorized: %d\n", result.ImageAuthorizedSourcesResult.Metrics.Unauthorized)

			if len(result.ImageAuthorizedSourcesResult.Issues) > 0 {
				fmt.Printf("\n  %sUnauthorized Images Found:%s\n", colorYellow, colorReset)
				for _, issue := range result.ImageAuthorizedSourcesResult.Issues {
					fmt.Printf("    %s [%s] Job '%s' uses unauthorized image: %s\n", severityTag(issue.Code), issue.Code, issue.Job, issue.Link)
					fmt.Printf("      %s↳ docs: %s%s\n", colorDim, issue.DocURL, colorReset)
				}
			}
		}
		fmt.Println()
	}

	// Control 3: Branch must be protected
	if result.BranchProtectionResult != nil {
		bpCodes := make([]control.ErrorCode, 0, len(result.BranchProtectionResult.Issues))
		for _, issue := range result.BranchProtectionResult.Issues {
			bpCodes = append(bpCodes, issue.Code)
		}
		ctrl := controlSummary{
			name:       "Branch must be protected",
			compliance: result.BranchProtectionResult.Compliance,
			issues:     len(result.BranchProtectionResult.Issues),
			skipped:    result.BranchProtectionResult.Skipped,
			codes:      uniqueSortedIssueCodeStrings(bpCodes),
			bySeverity: control.SeverityCountsFromIssueCodes(bpCodes),
		}
		controls = append(controls, ctrl)

		printControlHeader("Branch must be protected", result.BranchProtectionResult.Compliance, result.BranchProtectionResult.Skipped)

		if result.BranchProtectionResult.Skipped {
			fmt.Printf("  %sStatus: SKIPPED (disabled in configuration)%s\n", colorDim, colorReset)
		} else {
			if result.BranchProtectionResult.Metrics != nil {
				fmt.Printf("  Total Branches: %d\n", result.BranchProtectionResult.Metrics.Branches)
				fmt.Printf("  Branches to Protect: %d\n", result.BranchProtectionResult.Metrics.BranchesToProtect)
				fmt.Printf("  Protected Branches: %d\n", result.BranchProtectionResult.Metrics.TotalProtectedBranches)
				fmt.Printf("  Unprotected: %d\n", result.BranchProtectionResult.Metrics.UnprotectedBranches)
				fmt.Printf("  Non-Compliant: %d\n", result.BranchProtectionResult.Metrics.NonCompliantBranches)
			}

			if len(result.BranchProtectionResult.Issues) > 0 {
				fmt.Printf("\n  %sIssues Found:%s\n", colorYellow, colorReset)
				for _, issue := range result.BranchProtectionResult.Issues {
					if issue.Type == "unprotected" {
						fmt.Printf("    %s [%s] Branch '%s' is not protected\n", severityTag(issue.Code), issue.Code, issue.BranchName)
						fmt.Printf("      %s↳ docs: %s%s\n", colorDim, issue.DocURL, colorReset)
					} else {
						fmt.Printf("    %s [%s] Branch '%s' has non-compliant protection settings\n", severityTag(issue.Code), issue.Code, issue.BranchName)
						if issue.AllowForcePushDisplay {
							fmt.Printf("      └─ Force push is allowed (should be disabled)\n")
						}
						if issue.CodeOwnerApprovalRequiredDisplay {
							fmt.Printf("      └─ Code owner approval is not required\n")
						}
						if issue.MinMergeAccessLevelDisplay {
							fmt.Printf("      └─ Merge access level is too low (%d, minimum: %d)\n", issue.MinMergeAccessLevel, issue.AuthorizedMinMergeAccessLevel)
						}
						if issue.MinPushAccessLevelDisplay {
							fmt.Printf("      └─ Push access level is too low (%d, minimum: %d)\n", issue.MinPushAccessLevel, issue.AuthorizedMinPushAccessLevel)
						}
						fmt.Printf("      %s↳ docs: %s%s\n", colorDim, issue.DocURL, colorReset)
					}
				}
			}
		}
		fmt.Println()
	}

	// Control 4: Pipeline must not include hardcoded jobs
	if result.HardcodedJobsResult != nil {
		hjCodes := make([]control.ErrorCode, 0, len(result.HardcodedJobsResult.Issues))
		for _, issue := range result.HardcodedJobsResult.Issues {
			hjCodes = append(hjCodes, issue.Code)
		}
		ctrl := controlSummary{
			name:       "Pipeline must not include hardcoded jobs",
			compliance: result.HardcodedJobsResult.Compliance,
			issues:     len(result.HardcodedJobsResult.Issues),
			skipped:    result.HardcodedJobsResult.Skipped,
			codes:      uniqueSortedIssueCodeStrings(hjCodes),
			bySeverity: control.SeverityCountsFromIssueCodes(hjCodes),
		}
		controls = append(controls, ctrl)

		printControlHeader("Pipeline must not include hardcoded jobs", result.HardcodedJobsResult.Compliance, result.HardcodedJobsResult.Skipped)

		if result.HardcodedJobsResult.Skipped {
			fmt.Printf("  %sStatus: SKIPPED (disabled in configuration)%s\n", colorDim, colorReset)
		} else {
			fmt.Printf("  Total Jobs: %d\n", result.HardcodedJobsResult.Metrics.Total)
			fmt.Printf("  Hardcoded Jobs: %d\n", result.HardcodedJobsResult.Metrics.HardcodedJobs)

			if len(result.HardcodedJobsResult.Issues) > 0 {
				fmt.Printf("\n  %sHardcoded Jobs Found:%s\n", colorYellow, colorReset)
				for _, issue := range result.HardcodedJobsResult.Issues {
					fmt.Printf("    %s [%s] Job '%s' is hardcoded (not from include/component)\n", severityTag(issue.Code), issue.Code, issue.JobName)
					fmt.Printf("      %s↳ docs: %s%s\n", colorDim, issue.DocURL, colorReset)
				}
			}
		}
		fmt.Println()
	}

	// Control 5: Includes must be up to date
	if result.OutdatedIncludesResult != nil {
		oiCodes := make([]control.ErrorCode, 0, len(result.OutdatedIncludesResult.Issues))
		for _, issue := range result.OutdatedIncludesResult.Issues {
			oiCodes = append(oiCodes, issue.Code)
		}
		ctrl := controlSummary{
			name:       "Includes must be up to date",
			compliance: result.OutdatedIncludesResult.Compliance,
			issues:     len(result.OutdatedIncludesResult.Issues),
			skipped:    result.OutdatedIncludesResult.Skipped,
			codes:      uniqueSortedIssueCodeStrings(oiCodes),
			bySeverity: control.SeverityCountsFromIssueCodes(oiCodes),
		}
		controls = append(controls, ctrl)

		printControlHeader("Includes must be up to date", result.OutdatedIncludesResult.Compliance, result.OutdatedIncludesResult.Skipped)

		if result.OutdatedIncludesResult.Skipped {
			fmt.Printf("  %sStatus: SKIPPED (disabled in configuration)%s\n", colorDim, colorReset)
		} else {
			fmt.Printf("  Total Includes: %d\n", result.OutdatedIncludesResult.Metrics.Total)
			fmt.Printf("  Outdated: %d\n", result.OutdatedIncludesResult.Metrics.OriginOutdated)

			if len(result.OutdatedIncludesResult.Issues) > 0 {
				fmt.Printf("\n  %sOutdated Includes Found:%s\n", colorYellow, colorReset)
				for _, issue := range result.OutdatedIncludesResult.Issues {
					fmt.Printf("    %s [%s] %s uses version '%s' (latest: %s)\n", severityTag(issue.Code), issue.Code, issue.GitlabIncludeLocation, issue.Version, issue.LatestVersion)
					fmt.Printf("      %s↳ docs: %s%s\n", colorDim, issue.DocURL, colorReset)
				}
			}
		}
		fmt.Println()
	}

	// Control 6: Includes must not use forbidden versions
	if result.ForbiddenVersionsIncludesResult != nil {
		fvCodes := make([]control.ErrorCode, 0, len(result.ForbiddenVersionsIncludesResult.Issues))
		for _, issue := range result.ForbiddenVersionsIncludesResult.Issues {
			fvCodes = append(fvCodes, issue.Code)
		}
		ctrl := controlSummary{
			name:       "Includes must not use forbidden versions",
			compliance: result.ForbiddenVersionsIncludesResult.Compliance,
			issues:     len(result.ForbiddenVersionsIncludesResult.Issues),
			skipped:    result.ForbiddenVersionsIncludesResult.Skipped,
			codes:      uniqueSortedIssueCodeStrings(fvCodes),
			bySeverity: control.SeverityCountsFromIssueCodes(fvCodes),
		}
		controls = append(controls, ctrl)

		printControlHeader("Includes must not use forbidden versions", result.ForbiddenVersionsIncludesResult.Compliance, result.ForbiddenVersionsIncludesResult.Skipped)

		if result.ForbiddenVersionsIncludesResult.Skipped {
			fmt.Printf("  %sStatus: SKIPPED (disabled in configuration)%s\n", colorDim, colorReset)
		} else {
			fmt.Printf("  Total Includes: %d\n", result.ForbiddenVersionsIncludesResult.Metrics.Total)
			fmt.Printf("  Using Authorized Versions: %d\n", result.ForbiddenVersionsIncludesResult.Metrics.UsingAuthorizedVersion)
			fmt.Printf("  Using Forbidden Versions: %d\n", result.ForbiddenVersionsIncludesResult.Metrics.UsingForbiddenVersion)

			if len(result.ForbiddenVersionsIncludesResult.Issues) > 0 {
				fmt.Printf("\n  %sForbidden Versions Found:%s\n", colorYellow, colorReset)
				for _, issue := range result.ForbiddenVersionsIncludesResult.Issues {
					fmt.Printf("    %s [%s] %s uses forbidden version '%s'\n", severityTag(issue.Code), issue.Code, issue.GitlabIncludeLocation, issue.Version)
					fmt.Printf("      %s↳ docs: %s%s\n", colorDim, issue.DocURL, colorReset)
				}
			}
		}
		fmt.Println()
	}

	// Control 7: Pipeline must include component
	if result.RequiredComponentsResult != nil {
		totalComponentIssues := len(result.RequiredComponentsResult.Issues) + len(result.RequiredComponentsResult.OverriddenIssues)
		rcCodes := make([]control.ErrorCode, 0, totalComponentIssues)
		for _, issue := range result.RequiredComponentsResult.Issues {
			rcCodes = append(rcCodes, issue.Code)
		}
		for _, issue := range result.RequiredComponentsResult.OverriddenIssues {
			rcCodes = append(rcCodes, issue.Code)
		}
		ctrl := controlSummary{
			name:       "Pipeline must include component",
			compliance: result.RequiredComponentsResult.Compliance,
			issues:     totalComponentIssues,
			skipped:    result.RequiredComponentsResult.Skipped,
			codes:      uniqueSortedIssueCodeStrings(rcCodes),
			bySeverity: control.SeverityCountsFromIssueCodes(rcCodes),
		}
		controls = append(controls, ctrl)

		printControlHeader("Pipeline must include component", result.RequiredComponentsResult.Compliance, result.RequiredComponentsResult.Skipped)

		if result.RequiredComponentsResult.Skipped {
			fmt.Printf("  %sStatus: SKIPPED (disabled in configuration)%s\n", colorDim, colorReset)
		} else {
			fmt.Printf("  Requirement Groups: %d\n", result.RequiredComponentsResult.Metrics.TotalGroups)
			fmt.Printf("  Satisfied Groups: %d\n", result.RequiredComponentsResult.Metrics.SatisfiedGroups)

			if len(result.RequiredComponentsResult.Issues) > 0 {
				fmt.Printf("\n  %sMissing Components:%s\n", colorYellow, colorReset)
				for _, issue := range result.RequiredComponentsResult.Issues {
					fmt.Printf("    %s [%s] %s (group %d)\n", severityTag(issue.Code), issue.Code, issue.ComponentPath, issue.GroupIndex+1)
					fmt.Printf("      %s↳ docs: %s%s\n", colorDim, issue.DocURL, colorReset)
				}
			}

			if len(result.RequiredComponentsResult.OverriddenIssues) > 0 {
				fmt.Printf("\n  %sOverridden Components:%s\n", colorYellow, colorReset)
				for _, issue := range result.RequiredComponentsResult.OverriddenIssues {
					fmt.Printf("    %s [%s] %s (group %d)\n", severityTag(issue.Code), issue.Code, issue.ComponentPath, issue.GroupIndex+1)
					for _, job := range issue.OverriddenJobs {
						fmt.Printf("      job %s%s%s overrides: %s\n", colorDim, job.JobName, colorReset, strings.Join(job.OverriddenKeys, ", "))
					}
					fmt.Printf("      %s↳ docs: %s%s\n", colorDim, issue.DocURL, colorReset)
				}
			}
		}
		fmt.Println()
	}

	// Control 8: Pipeline must include template
	if result.RequiredTemplatesResult != nil {
		totalTemplateIssues := len(result.RequiredTemplatesResult.Issues) + len(result.RequiredTemplatesResult.OverriddenIssues)
		rtCodes := make([]control.ErrorCode, 0, totalTemplateIssues)
		for _, issue := range result.RequiredTemplatesResult.Issues {
			rtCodes = append(rtCodes, issue.Code)
		}
		for _, issue := range result.RequiredTemplatesResult.OverriddenIssues {
			rtCodes = append(rtCodes, issue.Code)
		}
		ctrl := controlSummary{
			name:       "Pipeline must include template",
			compliance: result.RequiredTemplatesResult.Compliance,
			issues:     totalTemplateIssues,
			skipped:    result.RequiredTemplatesResult.Skipped,
			codes:      uniqueSortedIssueCodeStrings(rtCodes),
			bySeverity: control.SeverityCountsFromIssueCodes(rtCodes),
		}
		controls = append(controls, ctrl)

		printControlHeader("Pipeline must include template", result.RequiredTemplatesResult.Compliance, result.RequiredTemplatesResult.Skipped)

		if result.RequiredTemplatesResult.Skipped {
			fmt.Printf("  %sStatus: SKIPPED (disabled in configuration)%s\n", colorDim, colorReset)
		} else {
			fmt.Printf("  Requirement Groups: %d\n", result.RequiredTemplatesResult.Metrics.TotalGroups)
			fmt.Printf("  Satisfied Groups: %d\n", result.RequiredTemplatesResult.Metrics.SatisfiedGroups)

			if len(result.RequiredTemplatesResult.Issues) > 0 {
				fmt.Printf("\n  %sMissing Templates:%s\n", colorYellow, colorReset)
				for _, issue := range result.RequiredTemplatesResult.Issues {
					fmt.Printf("    %s [%s] %s (group %d)\n", severityTag(issue.Code), issue.Code, issue.TemplatePath, issue.GroupIndex+1)
					fmt.Printf("      %s↳ docs: %s%s\n", colorDim, issue.DocURL, colorReset)
				}
			}

			if len(result.RequiredTemplatesResult.OverriddenIssues) > 0 {
				fmt.Printf("\n  %sOverridden Templates:%s\n", colorYellow, colorReset)
				for _, issue := range result.RequiredTemplatesResult.OverriddenIssues {
					fmt.Printf("    %s [%s] %s (group %d)\n", severityTag(issue.Code), issue.Code, issue.TemplatePath, issue.GroupIndex+1)
					for _, job := range issue.OverriddenJobs {
						fmt.Printf("      job %s%s%s overrides: %s\n", colorDim, job.JobName, colorReset, strings.Join(job.OverriddenKeys, ", "))
					}
					fmt.Printf("      %s↳ docs: %s%s\n", colorDim, issue.DocURL, colorReset)
				}
			}
		}
		fmt.Println()
	}

	// Control 9: Pipeline must not enable debug trace
	if result.DebugTraceResult != nil {
		dtCodes := make([]control.ErrorCode, 0, len(result.DebugTraceResult.Issues))
		for _, issue := range result.DebugTraceResult.Issues {
			dtCodes = append(dtCodes, issue.Code)
		}
		ctrl := controlSummary{
			name:       "Pipeline must not enable debug trace",
			compliance: result.DebugTraceResult.Compliance,
			issues:     len(result.DebugTraceResult.Issues),
			skipped:    result.DebugTraceResult.Skipped,
			codes:      uniqueSortedIssueCodeStrings(dtCodes),
			bySeverity: control.SeverityCountsFromIssueCodes(dtCodes),
		}
		controls = append(controls, ctrl)

		printControlHeader("Pipeline must not enable debug trace", result.DebugTraceResult.Compliance, result.DebugTraceResult.Skipped)

		if result.DebugTraceResult.Skipped {
			fmt.Printf("  %sStatus: SKIPPED (disabled in configuration)%s\n", colorDim, colorReset)
		} else {
			fmt.Printf("  Variables Checked: %d\n", result.DebugTraceResult.Metrics.TotalVariablesChecked)
			fmt.Printf("  Forbidden Found: %d\n", result.DebugTraceResult.Metrics.ForbiddenFound)

			if len(result.DebugTraceResult.Issues) > 0 {
				fmt.Printf("\n  %sForbidden Debug Variables Found:%s\n", colorYellow, colorReset)
				for _, issue := range result.DebugTraceResult.Issues {
					location := issue.Location
					if location == "global" {
						fmt.Printf("    %s [%s] %s = \"%s\" (global variables)\n", severityTag(issue.Code), issue.Code, issue.VariableName, issue.Value)
					} else {
						fmt.Printf("    %s [%s] %s = \"%s\" (job '%s')\n", severityTag(issue.Code), issue.Code, issue.VariableName, issue.Value, location)
					}
					fmt.Printf("      %s↳ docs: %s%s\n", colorDim, issue.DocURL, colorReset)
				}
			}
		}
		fmt.Println()
	}

	// Control 10: Pipeline must not use unsafe variable expansion
	if result.VariableInjectionResult != nil {
		viCodes := make([]control.ErrorCode, 0, len(result.VariableInjectionResult.Issues))
		for _, issue := range result.VariableInjectionResult.Issues {
			viCodes = append(viCodes, issue.Code)
		}
		ctrl := controlSummary{
			name:       "Pipeline must not use unsafe variable expansion",
			compliance: result.VariableInjectionResult.Compliance,
			issues:     len(result.VariableInjectionResult.Issues),
			skipped:    result.VariableInjectionResult.Skipped,
			codes:      uniqueSortedIssueCodeStrings(viCodes),
			bySeverity: control.SeverityCountsFromIssueCodes(viCodes),
		}
		controls = append(controls, ctrl)

		printControlHeader("Pipeline must not use unsafe variable expansion", result.VariableInjectionResult.Compliance, result.VariableInjectionResult.Skipped)

		if result.VariableInjectionResult.Skipped {
			fmt.Printf("  %sStatus: SKIPPED (disabled in configuration)%s\n", colorDim, colorReset)
		} else {
			fmt.Printf("  Jobs Checked: %d\n", result.VariableInjectionResult.Metrics.JobsChecked)
			fmt.Printf("  Script Lines Checked: %d\n", result.VariableInjectionResult.Metrics.TotalScriptLinesChecked)
			fmt.Printf("  Unsafe Expansions: %d\n", result.VariableInjectionResult.Metrics.UnsafeExpansionsFound)

			if len(result.VariableInjectionResult.Issues) > 0 {
				fmt.Printf("\n  %sUnsafe Variable Expansions Found:%s\n", colorYellow, colorReset)
				for _, issue := range result.VariableInjectionResult.Issues {
					if issue.JobName == "(global)" {
						fmt.Printf("    %s [%s] $%s in global %s: %s\n", severityTag(issue.Code), issue.Code, issue.VariableName, issue.ScriptBlock, issue.ScriptLine)
					} else {
						fmt.Printf("    %s [%s] $%s in job '%s' %s: %s\n", severityTag(issue.Code), issue.Code, issue.VariableName, issue.JobName, issue.ScriptBlock, issue.ScriptLine)
					}
					fmt.Printf("      %s↳ docs: %s%s\n", colorDim, issue.DocURL, colorReset)
				}
			}
		}
		fmt.Println()
	}

	// Control 11: Security jobs must not be weakened
	if result.SecurityJobsWeakenedResult != nil {
		sjCodes := make([]control.ErrorCode, 0, len(result.SecurityJobsWeakenedResult.Issues))
		for _, issue := range result.SecurityJobsWeakenedResult.Issues {
			sjCodes = append(sjCodes, issue.Code)
		}
		ctrl := controlSummary{
			name:       "Security jobs must not be weakened",
			compliance: result.SecurityJobsWeakenedResult.Compliance,
			issues:     len(result.SecurityJobsWeakenedResult.Issues),
			skipped:    result.SecurityJobsWeakenedResult.Skipped,
			codes:      uniqueSortedIssueCodeStrings(sjCodes),
			bySeverity: control.SeverityCountsFromIssueCodes(sjCodes),
		}
		controls = append(controls, ctrl)

		printControlHeader("Security jobs must not be weakened", result.SecurityJobsWeakenedResult.Compliance, result.SecurityJobsWeakenedResult.Skipped)

		if result.SecurityJobsWeakenedResult.Skipped {
			fmt.Printf("  %sStatus: SKIPPED (disabled in configuration)%s\n", colorDim, colorReset)
		} else {
			fmt.Printf("  Security Jobs Found: %d\n", result.SecurityJobsWeakenedResult.Metrics.SecurityJobsFound)
			fmt.Printf("  Weakened Jobs: %d\n", result.SecurityJobsWeakenedResult.Metrics.WeakenedJobs)

			if len(result.SecurityJobsWeakenedResult.Issues) > 0 {
				fmt.Printf("\n  %sWeakened Security Jobs Found:%s\n", colorYellow, colorReset)
				for _, issue := range result.SecurityJobsWeakenedResult.Issues {
					fmt.Printf("    %s [%s] Job '%s': %s\n", severityTag(issue.Code), issue.Code, issue.JobName, issue.Detail)
					fmt.Printf("      %s↳ docs: %s%s\n", colorDim, issue.DocURL, colorReset)
				}
			}
		}
		fmt.Println()
	}

	// Control 12: Pipeline must not execute unverified scripts
	if result.UnverifiedScriptsResult != nil {
		usCodes := make([]control.ErrorCode, 0, len(result.UnverifiedScriptsResult.Issues))
		for _, issue := range result.UnverifiedScriptsResult.Issues {
			usCodes = append(usCodes, issue.Code)
		}
		ctrl := controlSummary{
			name:       "Pipeline must not execute unverified scripts",
			compliance: result.UnverifiedScriptsResult.Compliance,
			issues:     len(result.UnverifiedScriptsResult.Issues),
			skipped:    result.UnverifiedScriptsResult.Skipped,
			codes:      uniqueSortedIssueCodeStrings(usCodes),
			bySeverity: control.SeverityCountsFromIssueCodes(usCodes),
		}
		controls = append(controls, ctrl)

		printControlHeader("Pipeline must not execute unverified scripts", result.UnverifiedScriptsResult.Compliance, result.UnverifiedScriptsResult.Skipped)

		if result.UnverifiedScriptsResult.Skipped {
			fmt.Printf("  %sStatus: SKIPPED (disabled in configuration)%s\n", colorDim, colorReset)
		} else {
			fmt.Printf("  Jobs Checked: %d\n", result.UnverifiedScriptsResult.Metrics.JobsChecked)
			fmt.Printf("  Script Lines Checked: %d\n", result.UnverifiedScriptsResult.Metrics.TotalScriptLinesChecked)
			fmt.Printf("  Unverified Scripts: %d\n", result.UnverifiedScriptsResult.Metrics.UnverifiedScriptsFound)

			if len(result.UnverifiedScriptsResult.Issues) > 0 {
				fmt.Printf("\n  %sUnverified Script Executions Found:%s\n", colorYellow, colorReset)
				for _, issue := range result.UnverifiedScriptsResult.Issues {
					if issue.JobName == "(global)" {
						fmt.Printf("    %s [%s] Global %s: %s\n", severityTag(issue.Code), issue.Code, issue.ScriptBlock, issue.ScriptLine)
					} else {
						fmt.Printf("    %s [%s] Job '%s' %s: %s\n", severityTag(issue.Code), issue.Code, issue.JobName, issue.ScriptBlock, issue.ScriptLine)
					}
					fmt.Printf("      %s↳ docs: %s%s\n", colorDim, issue.DocURL, colorReset)
				}
			}
		}
		fmt.Println()
	}

	// Control 13: Pipeline must not override job variables
	if result.JobVariablesOverrideResult != nil {
		jvCodes := make([]control.ErrorCode, 0, len(result.JobVariablesOverrideResult.Issues))
		for _, issue := range result.JobVariablesOverrideResult.Issues {
			jvCodes = append(jvCodes, issue.Code)
		}
		ctrl := controlSummary{
			name:       "Pipeline must not override job variables",
			compliance: result.JobVariablesOverrideResult.Compliance,
			issues:     len(result.JobVariablesOverrideResult.Issues),
			skipped:    result.JobVariablesOverrideResult.Skipped,
			codes:      uniqueSortedIssueCodeStrings(jvCodes),
			bySeverity: control.SeverityCountsFromIssueCodes(jvCodes),
		}
		controls = append(controls, ctrl)

		printControlHeader("Pipeline must not override job variables", result.JobVariablesOverrideResult.Compliance, result.JobVariablesOverrideResult.Skipped)

		if result.JobVariablesOverrideResult.Skipped {
			fmt.Printf("  %sStatus: SKIPPED (disabled in configuration)%s\n", colorDim, colorReset)
		} else {
			fmt.Printf("  Variables Checked: %d\n", result.JobVariablesOverrideResult.Metrics.TotalVariablesChecked)
			fmt.Printf("  Overridden Found: %d\n", result.JobVariablesOverrideResult.Metrics.OverriddenFound)

			if len(result.JobVariablesOverrideResult.Issues) > 0 {
				fmt.Printf("\n  %sOverridden Variables Found:%s\n", colorYellow, colorReset)
				for _, issue := range result.JobVariablesOverrideResult.Issues {
					location := issue.Location
					if location == "global" {
						fmt.Printf("    %s [%s] %s = \"%s\" (global variables)\n", severityTag(issue.Code), issue.Code, issue.VariableName, issue.Value)
					} else {
						fmt.Printf("    %s [%s] %s = \"%s\" (job '%s')\n", severityTag(issue.Code), issue.Code, issue.VariableName, issue.Value, location)
					}
					fmt.Printf("      %s↳ docs: %s%s\n", colorDim, issue.DocURL, colorReset)
				}
			}
		}
		fmt.Println()
	}

	// Control 14: Pipeline must not use Docker-in-Docker
	if result.DockerInDockerResult != nil {
		ddCodes := make([]control.ErrorCode, 0, len(result.DockerInDockerResult.Issues))
		for _, issue := range result.DockerInDockerResult.Issues {
			ddCodes = append(ddCodes, issue.Code)
		}
		ctrl := controlSummary{
			name:       "Pipeline must not use Docker-in-Docker",
			compliance: result.DockerInDockerResult.Compliance,
			issues:     len(result.DockerInDockerResult.Issues),
			skipped:    result.DockerInDockerResult.Skipped,
			codes:      uniqueSortedIssueCodeStrings(ddCodes),
			bySeverity: control.SeverityCountsFromIssueCodes(ddCodes),
		}
		controls = append(controls, ctrl)

		printControlHeader("Pipeline must not use Docker-in-Docker", result.DockerInDockerResult.Compliance, result.DockerInDockerResult.Skipped)

		if result.DockerInDockerResult.Skipped {
			fmt.Printf("  %sStatus: SKIPPED (disabled in configuration)%s\n", colorDim, colorReset)
		} else {
			fmt.Printf("  Jobs Checked: %d\n", result.DockerInDockerResult.Metrics.TotalJobsChecked)
			fmt.Printf("  DinD Services Found: %d\n", result.DockerInDockerResult.Metrics.DindServicesFound)
			fmt.Printf("  Insecure Daemon Config: %d\n", result.DockerInDockerResult.Metrics.InsecureDaemonFound)

			if len(result.DockerInDockerResult.Issues) > 0 {
				fmt.Printf("\n  %sDocker-in-Docker Issues Found:%s\n", colorYellow, colorReset)
				for _, issue := range result.DockerInDockerResult.Issues {
					if issue.Code == control.CodeDockerInDockerUsage {
						fmt.Printf("    %s [%s] Job '%s' uses DinD service: %s\n", severityTag(issue.Code), issue.Code, issue.JobName, issue.ServiceImage)
						fmt.Printf("      %sConsider using Kaniko or Buildah instead%s\n", colorDim, colorReset)
					} else {
						fmt.Printf("    %s [%s] Job '%s': %s\n", severityTag(issue.Code), issue.Code, issue.JobName, issue.Detail)
					}
					fmt.Printf("      %s↳ docs: %s%s\n", colorDim, issue.DocURL, colorReset)
				}
			}
		}
		fmt.Println()
	}

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
	parts := []int{sbWSev, sbWCnt, sbWWgt, sbWCap, sbWLoss}
	var segs []string
	for _, w := range parts {
		segs = append(segs, strings.Repeat("─", w+2))
	}
	return "┌" + strings.Join(segs, "┬") + "┐"
}

func scoreBreakdownBorderMid() string {
	parts := []int{sbWSev, sbWCnt, sbWWgt, sbWCap, sbWLoss}
	var segs []string
	for _, w := range parts {
		segs = append(segs, strings.Repeat("─", w+2))
	}
	return "├" + strings.Join(segs, "┼") + "┤"
}

func scoreBreakdownBorderMidFooter() string {
	parts := []int{sbWSev, sbWCnt, sbWWgt, sbWCap, sbWLoss}
	var segs []string
	for _, w := range parts {
		segs = append(segs, strings.Repeat("─", w+2))
	}
	return "├" + strings.Join(segs[:4], "┴") + "┼" + segs[4] + "┤"
}

func scoreBreakdownBorderBottom() string {
	parts := []int{sbWSev, sbWCnt, sbWWgt, sbWCap, sbWLoss}
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
	if len(score.Losses) > 0 {
		fmt.Printf("  %s%s%s\n", colorDim, scoreBreakdownBorderTop(), colorReset)
		fmt.Printf("  %s│ %s │ %s │ %s │ %s │ %s │%s\n", colorDim,
			padRunesRight("Severity", sbWSev),
			padRunesLeft("Count", sbWCnt),
			padRunesLeft("Weight", sbWWgt),
			padRunesLeft("Cap", sbWCap),
			padRunesLeft("Loss", sbWLoss),
			colorReset)
		fmt.Printf("  %s%s%s\n", colorDim, scoreBreakdownBorderMid(), colorReset)

		for _, l := range score.Losses {
			capPlain := "inf"
			if l.Severity != control.SeverityCritical {
				capPlain = fmt.Sprintf("%.0f", l.Cap)
			}
			sc := scoreBreakdownSevColor(l.Severity)
			lossStr := fmt.Sprintf("-%.1f", l.CappedLoss)
			fmt.Printf("  %s│ %s%s%s │ %s%s%s │ %s%s%s │ %s%s%s │ %s%s%s │%s\n", colorDim,
				sc, padRunesRight(string(l.Severity), sbWSev), colorReset,
				colorDim, padRunesLeft(fmt.Sprintf("%d", l.Count), sbWCnt), colorReset,
				colorDim, padRunesLeft(fmt.Sprintf("%.0f", l.Weight), sbWWgt), colorReset,
				colorDim, padRunesLeft(capPlain, sbWCap), colorReset,
				colorRed, padRunesLeft(lossStr, sbWLoss), colorReset,
				colorReset)
			totalLoss += l.CappedLoss
		}
		fmt.Printf("  %s%s%s\n", colorDim, scoreBreakdownBorderMidFooter(), colorReset)

		mergedW := sbWSev + 3 + sbWCnt + 3 + sbWWgt + 3 + sbWCap // " │ " between four columns
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
func scoreLetterBadgeLines(letter string) []string {
	gc := scoreLetterColor(letter) + colorBold
	// 7 interior columns keep the letter nicely framed (3 spaces on each side).
	top := fmt.Sprintf("%s╔═══════╗%s", gc, colorReset)
	mid := fmt.Sprintf("%s║       ║%s", gc, colorReset)
	let := fmt.Sprintf("%s║   %s   ║%s", gc, letter, colorReset)
	bot := fmt.Sprintf("%s╚═══════╝%s", gc, colorReset)
	return []string{top, mid, let, mid, bot}
}

func printSummaryScoreBanner(score *control.PlumberScoreResult, scoreMode bool) {
	if score == nil || !scoreMode {
		return
	}

	const indent = "     "
	const gap = "     "
	badge := scoreLetterBadgeLines(score.Score)

	fmt.Printf("  %s─── Plumber Score ─────────────────────────────────────%s\n\n", colorCyan, colorReset)

	gc := scoreLetterColor(score.Score)
	scoreLine := fmt.Sprintf("%s%s%.1f / 100 pts%s", colorBold, gc, score.FinalPoints, colorReset)
	bar := scoreBar(score.FinalPoints, 30)
	counts := fmt.Sprintf("%s%s Critical %s %-3d  %s%s High %s %-3d  %s Medium %s %-3d  %s Low %s %-3d",
		colorBgRed, colorWhite, colorReset, score.Counts.Critical,
		colorBgYellow, colorBlack, colorReset, score.Counts.High,
		colorCyan, colorReset, score.Counts.Medium,
		colorBlue, colorReset, score.Counts.Low)

	// Side panel rows align with the 3 middle lines of the badge so the
	// badge reads as the primary visual and the metrics sit beside it.
	side := []string{"", scoreLine, bar, counts, ""}
	for i, b := range badge {
		if side[i] == "" {
			fmt.Printf("%s%s\n", indent, b)
		} else {
			fmt.Printf("%s%s%s%s\n", indent, b, gap, side[i])
		}
	}

	if score.CriticalMalusApplied {
		fmt.Printf("\n%s%s⚠ Critical malus: final points capped at %.0f%s\n", indent, colorRed, score.CriticalMalusMax, colorReset)
	}

	fmt.Printf("\n  %s───────────────────────────────────────────────────────%s\n\n", colorDim, colorReset)
}

func printIssuesTable(controls []controlSummary) {
	var rows []controlSummary
	for _, c := range controls {
		if c.issues > 0 {
			rows = append(rows, c)
		}
	}

	fmt.Printf("  %sControls%s\n", colorBold, colorReset)
	if len(rows) == 0 {
		fmt.Printf("  %s(none with open issues)%s\n", colorDim, colorReset)
		return
	}

	sortControlSummariesForIssuesTable(rows)

	controlWidth := 44
	for _, ctrl := range rows {
		needed := len(ctrl.name) + 2
		if needed > controlWidth {
			controlWidth = needed
		}
	}
	codesWidth := 22
	for _, ctrl := range rows {
		codesStr := strings.Join(ctrl.codes, ", ")
		needed := len(codesStr) + 2
		if needed > codesWidth {
			codesWidth = needed
		}
	}
	sevWidth := 12
	issuesWidth := 6

	// Top border
	fmt.Printf("  %s╔%s╤%s╤%s╤%s╗%s\n",
		colorCyan,
		strings.Repeat("═", controlWidth),
		strings.Repeat("═", codesWidth),
		strings.Repeat("═", sevWidth),
		strings.Repeat("═", issuesWidth),
		colorReset)

	// Header row
	fmt.Printf("  %s║%s %-*s %s│%s %-*s %s│%s %-*s %s│%s %*s %s║%s\n",
		colorCyan, colorReset,
		controlWidth-2, "Control",
		colorCyan, colorReset,
		codesWidth-2, "Codes",
		colorCyan, colorReset,
		sevWidth-2, "Severity",
		colorCyan, colorReset,
		issuesWidth-2, "#",
		colorCyan, colorReset)

	// Header separator
	fmt.Printf("  %s╟%s┼%s┼%s┼%s╢%s\n",
		colorCyan,
		strings.Repeat("─", controlWidth),
		strings.Repeat("─", codesWidth),
		strings.Repeat("─", sevWidth),
		strings.Repeat("─", issuesWidth),
		colorReset)

	for _, ctrl := range rows {
		issueStr := "-"
		if !ctrl.skipped {
			issueStr = fmt.Sprintf("%d", ctrl.issues)
		}
		issueColor := colorReset
		if ctrl.issues > 0 {
			issueColor = colorRed
		}

		codesStr := strings.Join(ctrl.codes, ", ")
		if ctrl.skipped {
			codesStr = "-"
		}

		sevLabel := highestSeverityLabel(ctrl.bySeverity, sevWidth-2)
		if ctrl.skipped || ctrl.bySeverity.Critical+ctrl.bySeverity.High+ctrl.bySeverity.Medium+ctrl.bySeverity.Low == 0 {
			sevLabel = highestSeverityLabel(control.SeverityCounts{}, sevWidth-2)
		}

		fmt.Printf("  %s║%s %-*s %s│%s %-*s %s│%s %s %s│%s %s%*s%s %s║%s\n",
			colorCyan, colorReset,
			controlWidth-2, ctrl.name,
			colorCyan, colorReset,
			codesWidth-2, codesStr,
			colorCyan, colorReset,
			sevLabel,
			colorCyan, colorReset,
			issueColor, issuesWidth-2, issueStr, colorReset,
			colorCyan, colorReset)
	}

	// Bottom border
	fmt.Printf("  %s╚%s╧%s╧%s╧%s╝%s\n",
		colorCyan,
		strings.Repeat("═", controlWidth),
		strings.Repeat("═", codesWidth),
		strings.Repeat("═", sevWidth),
		strings.Repeat("═", issuesWidth),
		colorReset)

	fmt.Printf("  %s↳ docs: https://getplumber.io/docs/use-plumber/issues/<code>%s\n", colorDim, colorReset)
}

func printComplianceTable(controls []controlSummary, overallCompliance, threshold float64) {
	fmt.Printf("  %sCompliance%s\n", colorBold, colorReset)

	sorted := append([]controlSummary(nil), controls...)
	sortControlSummariesForComplianceTable(sorted)

	// Calculate column widths dynamically based on longest control name
	controlWidth := 52 // minimum width
	for _, ctrl := range sorted {
		needed := len(ctrl.name) + 2 // +2 for padding
		if needed > controlWidth {
			controlWidth = needed
		}
	}
	complianceWidth := 12
	statusWidth := 10

	// Top border
	fmt.Printf("  %s╔%s╤%s╤%s╗%s\n",
		colorCyan,
		strings.Repeat("═", controlWidth),
		strings.Repeat("═", complianceWidth),
		strings.Repeat("═", statusWidth),
		colorReset)

	// Header row
	fmt.Printf("  %s║%s %-*s %s│%s %*s %s│%s %*s %s║%s\n",
		colorCyan, colorReset,
		controlWidth-2, "Control",
		colorCyan, colorReset,
		complianceWidth-2, "Compliance",
		colorCyan, colorReset,
		statusWidth-2, "Status",
		colorCyan, colorReset)

	// Header separator
	fmt.Printf("  %s╟%s┼%s┼%s╢%s\n",
		colorCyan,
		strings.Repeat("─", controlWidth),
		strings.Repeat("─", complianceWidth),
		strings.Repeat("─", statusWidth),
		colorReset)

	// Data rows
	for _, ctrl := range sorted {
		compStr := "-"
		statusStr := "-"
		compColor := colorReset
		statusColor := colorDim

		if !ctrl.skipped {
			compStr = fmt.Sprintf("%.1f%%", ctrl.compliance)
			if ctrl.compliance >= 100 {
				compColor = colorGreen
				statusColor = colorGreen
				statusStr = "✓"
			} else {
				compColor = colorRed
				statusColor = colorRed
				statusStr = "✗"
			}
		}

		fmt.Printf("  %s║%s %-*s %s│%s %s%*s%s %s│%s %s%*s%s %s║%s\n",
			colorCyan, colorReset,
			controlWidth-2, ctrl.name,
			colorCyan, colorReset,
			compColor, complianceWidth-2, compStr, colorReset,
			colorCyan, colorReset,
			statusColor, statusWidth-2, statusStr, colorReset,
			colorCyan, colorReset)
	}

	// Separator before total
	fmt.Printf("  %s╟%s┼%s┼%s╢%s\n",
		colorCyan,
		strings.Repeat("─", controlWidth),
		strings.Repeat("─", complianceWidth),
		strings.Repeat("─", statusWidth),
		colorReset)

	// Total row
	totalCompStr := fmt.Sprintf("%.1f%%", overallCompliance)
	totalStatus := "✓"
	totalCompColor := colorGreen
	totalStatusColor := colorGreen
	if overallCompliance < threshold {
		totalStatus = "✗"
		totalCompColor = colorRed
		totalStatusColor = colorRed
	}

	fmt.Printf("  %s║%s %s%-*s%s %s│%s %s%*s%s %s│%s %s%*s%s %s║%s\n",
		colorCyan, colorReset,
		colorBold, controlWidth-2, fmt.Sprintf("Total (required: %.0f%%)", threshold), colorReset,
		colorCyan, colorReset,
		totalCompColor, complianceWidth-2, totalCompStr, colorReset,
		colorCyan, colorReset,
		totalStatusColor, statusWidth-2, totalStatus, colorReset,
		colorCyan, colorReset)

	// Bottom border
	fmt.Printf("  %s╚%s╧%s╧%s╝%s\n",
		colorCyan,
		strings.Repeat("═", controlWidth),
		strings.Repeat("═", complianceWidth),
		strings.Repeat("═", statusWidth),
		colorReset)
}
