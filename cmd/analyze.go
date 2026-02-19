package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

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
	controlsFilter    string
	skipControls      string
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
  --controls         Run only listed controls (comma-separated)
  --skip-controls    Skip listed controls (comma-separated)

Exit codes:
  0  Analysis passed (compliance >= threshold)
  1  Analysis failed (compliance < threshold or error occurred)

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
	analyzeCmd.Flags().StringVar(&controlsFilter, "controls", "", "Run only listed controls (comma-separated)")
	analyzeCmd.Flags().StringVar(&skipControls, "skip-controls", "", "Skip listed controls (comma-separated)")
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
	plumberConfig, configPath, err := configuration.LoadPlumberConfig(configFile)
	if err != nil {
		// if err contains "config file not found", tell them they can generate a default config with `plumber config generate`
		if strings.Contains(err.Error(), "config file not found") {
			return fmt.Errorf("configuration file not found: %w. You can generate a default config with `plumber config generate`", err)
		}
		return fmt.Errorf("configuration error: %w", err)
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

	result, err := control.RunAnalysis(conf)
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

	// Calculate average compliance
	// If no controls ran (e.g., data collection failed), compliance is 0% - we can't verify anything
	var compliance float64 = 0
	if controlCount > 0 {
		compliance = complianceSum / float64(controlCount)
	}

	// Print text output to stdout if enabled
	if printOutput {
		if err := outputText(result, threshold, compliance, controlCount); err != nil {
			return err
		}
	}

	// Write JSON to file if specified
	if outputFile != "" {
		if err := writeJSONToFile(result, threshold, compliance, outputFile); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Results written to: %s\n", outputFile)
	}

	// Write PBOM to file if specified
	if pbomFile != "" {
		if err := writePBOMToFile(result, cleanGitlabURL, defaultBranch, pbomFile); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "PBOM written to: %s\n", pbomFile)
	}

	// Write CycloneDX PBOM to file if specified
	if pbomCycloneDXFile != "" {
		if err := writePBOMCycloneDXToFile(result, cleanGitlabURL, defaultBranch, pbomCycloneDXFile); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "PBOM (CycloneDX) written to: %s\n", pbomCycloneDXFile)
	}

	// Post merge request comment if explicitly enabled and in a CI merge request pipeline
	if mrComment {
		if mrIID := glabCI.DetectMergeRequestIID(); mrIID != 0 {
			fmt.Fprintf(os.Stderr, "Merge request pipeline detected (MR !%d), posting compliance comment...\n", mrIID)
			if err := control.ManageMergeRequestComment(result.ProjectID, mrIID, result, compliance, threshold, conf); err != nil {
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
			if err := control.ManageProjectBadge(result.ProjectID, compliance, threshold, conf); err != nil {
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
		return fmt.Errorf("compliance %.1f%% is below threshold %.1f%%", compliance, threshold)
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

func writeJSONToFile(result *control.AnalysisResult, threshold, compliance float64, filePath string) error {
	// Create output with threshold info
	output := struct {
		*control.AnalysisResult
		Threshold  float64 `json:"threshold"`
		Compliance float64 `json:"compliance"`
		Passed     bool    `json:"passed"`
	}{
		AnalysisResult: result,
		Threshold:      threshold,
		Compliance:     compliance,
		Passed:         compliance >= threshold,
	}

	// Create/overwrite the file
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

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

func writePBOMToFile(result *control.AnalysisResult, gitlabURL, branch, filePath string) error {
	// Generate PBOM from collected data
	complianceData := buildImageComplianceData(result)
	generator := pbom.NewGenerator(result.ProjectPath, result.ProjectID, gitlabURL, branch).
		WithComplianceData(complianceData)
	pipelineBOM := generator.Generate(result.PipelineImageData, result.PipelineOriginData)

	// Create/overwrite the file
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create PBOM file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(pipelineBOM)
}

func writePBOMCycloneDXToFile(result *control.AnalysisResult, gitlabURL, branch, filePath string) error {
	// Generate PBOM from collected data
	complianceData := buildImageComplianceData(result)
	generator := pbom.NewGenerator(result.ProjectPath, result.ProjectID, gitlabURL, branch).
		WithComplianceData(complianceData)
	pipelineBOM := generator.Generate(result.PipelineImageData, result.PipelineOriginData)

	// Convert to CycloneDX format
	cycloneDX := pipelineBOM.ToCycloneDX(Version)

	// Create/overwrite the file
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create CycloneDX PBOM file: %w", err)
	}
	defer file.Close()

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
	colorCyan        = "\033[36m"
	colorGreenBright = "\033[92m"
	colorBold        = "\033[1m"
	colorDim         = "\033[2m"
)

// controlSummary holds summary data for a control
type controlSummary struct {
	name       string
	compliance float64
	issues     int
	skipped    bool
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

func outputText(result *control.AnalysisResult, threshold, compliance float64, controlCount int) error {
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

		ctrl := controlSummary{
			name:       controlName,
			compliance: result.ImageForbiddenTagsResult.Compliance,
			issues:     len(result.ImageForbiddenTagsResult.Issues),
			skipped:    result.ImageForbiddenTagsResult.Skipped,
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
					fmt.Printf("    %s•%s Job '%s' uses image without digest pinning: %s\n", colorYellow, colorReset, issue.Job, issue.Link)
				}
			}
		} else {
			// Standard forbidden tags mode
			fmt.Printf("  Total Images: %d\n", result.ImageForbiddenTagsResult.Metrics.Total)
			fmt.Printf("  Using Forbidden Tags: %d\n", result.ImageForbiddenTagsResult.Metrics.UsingForbiddenTags)

			if len(result.ImageForbiddenTagsResult.Issues) > 0 {
				fmt.Printf("\n  %sForbidden Tags Found:%s\n", colorYellow, colorReset)
				for _, issue := range result.ImageForbiddenTagsResult.Issues {
					fmt.Printf("    %s•%s Job '%s' uses forbidden tag '%s' (image: %s)\n", colorYellow, colorReset, issue.Job, issue.Tag, issue.Link)
				}
			}
		}
		fmt.Println()
	}

	// Control 2: Container images must come from authorized sources
	if result.ImageAuthorizedSourcesResult != nil {
		ctrl := controlSummary{
			name:       "Container images must come from authorized sources",
			compliance: result.ImageAuthorizedSourcesResult.Compliance,
			issues:     len(result.ImageAuthorizedSourcesResult.Issues),
			skipped:    result.ImageAuthorizedSourcesResult.Skipped,
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
					fmt.Printf("    %s•%s Job '%s' uses unauthorized image: %s\n", colorYellow, colorReset, issue.Job, issue.Link)
				}
			}
		}
		fmt.Println()
	}

	// Control 3: Branch must be protected
	if result.BranchProtectionResult != nil {
		ctrl := controlSummary{
			name:       "Branch must be protected",
			compliance: result.BranchProtectionResult.Compliance,
			issues:     len(result.BranchProtectionResult.Issues),
			skipped:    result.BranchProtectionResult.Skipped,
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
						fmt.Printf("    %s•%s Branch '%s' is not protected\n", colorYellow, colorReset, issue.BranchName)
					} else {
						fmt.Printf("    %s•%s Branch '%s' has non-compliant protection settings\n", colorYellow, colorReset, issue.BranchName)
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
					}
				}
			}
		}
		fmt.Println()
	}

	// Control 4: Pipeline must not include hardcoded jobs
	if result.HardcodedJobsResult != nil {
		ctrl := controlSummary{
			name:       "Pipeline must not include hardcoded jobs",
			compliance: result.HardcodedJobsResult.Compliance,
			issues:     len(result.HardcodedJobsResult.Issues),
			skipped:    result.HardcodedJobsResult.Skipped,
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
					fmt.Printf("    %s•%s Job '%s' is hardcoded (not from include/component)\n", colorYellow, colorReset, issue.JobName)
				}
			}
		}
		fmt.Println()
	}

	// Control 5: Includes must be up to date
	if result.OutdatedIncludesResult != nil {
		ctrl := controlSummary{
			name:       "Includes must be up to date",
			compliance: result.OutdatedIncludesResult.Compliance,
			issues:     len(result.OutdatedIncludesResult.Issues),
			skipped:    result.OutdatedIncludesResult.Skipped,
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
					fmt.Printf("    %s•%s %s uses version '%s' (latest: %s)\n", colorYellow, colorReset, issue.GitlabIncludeLocation, issue.Version, issue.LatestVersion)
				}
			}
		}
		fmt.Println()
	}

	// Control 6: Includes must not use forbidden versions
	if result.ForbiddenVersionsIncludesResult != nil {
		ctrl := controlSummary{
			name:       "Includes must not use forbidden versions",
			compliance: result.ForbiddenVersionsIncludesResult.Compliance,
			issues:     len(result.ForbiddenVersionsIncludesResult.Issues),
			skipped:    result.ForbiddenVersionsIncludesResult.Skipped,
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
					fmt.Printf("    %s•%s %s uses forbidden version '%s'\n", colorYellow, colorReset, issue.GitlabIncludeLocation, issue.Version)
				}
			}
		}
		fmt.Println()
	}

	// Control 7: Pipeline must include component
	if result.RequiredComponentsResult != nil {
		ctrl := controlSummary{
			name:       "Pipeline must include component",
			compliance: result.RequiredComponentsResult.Compliance,
			issues:     len(result.RequiredComponentsResult.Issues),
			skipped:    result.RequiredComponentsResult.Skipped,
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
					fmt.Printf("    %s•%s %s (group %d)\n", colorYellow, colorReset, issue.ComponentPath, issue.GroupIndex+1)
				}
			}
		}
		fmt.Println()
	}

	// Control 8: Pipeline must include template
	if result.RequiredTemplatesResult != nil {
		ctrl := controlSummary{
			name:       "Pipeline must include template",
			compliance: result.RequiredTemplatesResult.Compliance,
			issues:     len(result.RequiredTemplatesResult.Issues),
			skipped:    result.RequiredTemplatesResult.Skipped,
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
					fmt.Printf("    %s•%s %s (group %d)\n", colorYellow, colorReset, issue.TemplatePath, issue.GroupIndex+1)
				}
			}
		}
		fmt.Println()
	}

	// Summary Section
	printSectionHeader("Summary")
	fmt.Println()

	// Status
	if compliance >= threshold {
		fmt.Printf("  Status: %s%sPASSED ✓%s\n\n", colorBold, colorGreen, colorReset)
	} else {
		fmt.Printf("  Status: %s%sFAILED ✗%s\n\n", colorBold, colorRed, colorReset)
	}

	// Issues Table
	printIssuesTable(controls)
	fmt.Println()

	// Compliance Table
	printComplianceTable(controls, compliance, threshold)
	fmt.Println()

	return nil
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

func printIssuesTable(controls []controlSummary) {
	fmt.Printf("  %sIssues%s\n", colorBold, colorReset)

	// Calculate column widths dynamically based on longest control name
	controlWidth := 52 // minimum width
	for _, ctrl := range controls {
		needed := len(ctrl.name) + 2 // +2 for padding
		if needed > controlWidth {
			controlWidth = needed
		}
	}
	issuesWidth := 10

	// Top border
	fmt.Printf("  %s╔%s╤%s╗%s\n",
		colorCyan,
		strings.Repeat("═", controlWidth),
		strings.Repeat("═", issuesWidth),
		colorReset)

	// Header row
	fmt.Printf("  %s║%s %-*s %s│%s %*s %s║%s\n",
		colorCyan, colorReset,
		controlWidth-2, "Control",
		colorCyan, colorReset,
		issuesWidth-2, "Issues",
		colorCyan, colorReset)

	// Header separator
	fmt.Printf("  %s╟%s┼%s╢%s\n",
		colorCyan,
		strings.Repeat("─", controlWidth),
		strings.Repeat("─", issuesWidth),
		colorReset)

	// Data rows
	totalIssues := 0
	for _, ctrl := range controls {
		issueStr := "-"
		if !ctrl.skipped {
			issueStr = fmt.Sprintf("%d", ctrl.issues)
			totalIssues += ctrl.issues
		}

		issueColor := colorReset
		if ctrl.issues > 0 {
			issueColor = colorRed
		}

		fmt.Printf("  %s║%s %-*s %s│%s %s%*s%s %s║%s\n",
			colorCyan, colorReset,
			controlWidth-2, ctrl.name,
			colorCyan, colorReset,
			issueColor, issuesWidth-2, issueStr, colorReset,
			colorCyan, colorReset)
	}

	// Bottom border
	fmt.Printf("  %s╚%s╧%s╝%s\n",
		colorCyan,
		strings.Repeat("═", controlWidth),
		strings.Repeat("═", issuesWidth),
		colorReset)
}

func printComplianceTable(controls []controlSummary, overallCompliance, threshold float64) {
	fmt.Printf("  %sCompliance%s\n", colorBold, colorReset)

	// Calculate column widths dynamically based on longest control name
	controlWidth := 52 // minimum width
	for _, ctrl := range controls {
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
	for _, ctrl := range controls {
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
