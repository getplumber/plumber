package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	// Flags for analyze command
	gitlabURL     string
	projectPath   string
	defaultBranch string
	outputFile    string
	printOutput   bool
	configFile    string
	threshold     float64
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

Required environment variables:
  GITLAB_TOKEN    GitLab API token (required)

Required flags:
  --gitlab-url    GitLab instance URL
  --project       Full path of the project
  --config        Path to .plumber.yaml config file
  --threshold     Minimum compliance percentage to pass (0-100)

Optional flags:
  --branch        Branch to analyze (defaults to project's default branch)
  --print         Print text output to stdout (default: true)
  --output        Write JSON results to file (optional)

Exit codes:
  0  Analysis passed (compliance >= threshold)
  1  Analysis failed (compliance < threshold or error occurred)

Examples:
  # Set token via environment variable
  export GITLAB_TOKEN=glpat-xxxx

  # Analyze a project (prints text to stdout)
  plumber analyze --gitlab-url https://gitlab.com --project mygroup/myproject --config .plumber.yaml --threshold 100

  # Analyze and save JSON to file (no stdout)
  plumber analyze --gitlab-url https://gitlab.com --project mygroup/myproject --config .plumber.yaml --threshold 100 --print=false --output results.json

  # Analyze with both text output and JSON file
  plumber analyze --gitlab-url https://gitlab.com --project mygroup/myproject --config .plumber.yaml --threshold 100 --output results.json
`,
	RunE: runAnalyze,
}

func init() {
	rootCmd.AddCommand(analyzeCmd)

	// Required flags
	analyzeCmd.Flags().StringVar(&gitlabURL, "gitlab-url", "", "GitLab instance URL (required)")
	analyzeCmd.Flags().StringVar(&projectPath, "project", "", "Full path of the project (required)")
	analyzeCmd.Flags().StringVar(&configFile, "config", "", "Path to .plumber.yaml config file (required)")
	analyzeCmd.Flags().Float64Var(&threshold, "threshold", 0, "Minimum compliance percentage to pass, 0-100 (required)")

	// Optional flags
	analyzeCmd.Flags().StringVar(&defaultBranch, "branch", "", "Branch to analyze (defaults to project's default branch)")
	analyzeCmd.Flags().BoolVar(&printOutput, "print", true, "Print text output to stdout")
	analyzeCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write JSON results to file")

	// Mark required flags
	_ = analyzeCmd.MarkFlagRequired("gitlab-url")
	_ = analyzeCmd.MarkFlagRequired("project")
	_ = analyzeCmd.MarkFlagRequired("config")
	_ = analyzeCmd.MarkFlagRequired("threshold")
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

	// Get token from environment variable (required)
	gitlabToken := os.Getenv("GITLAB_TOKEN")
	if gitlabToken == "" {
		return fmt.Errorf("GITLAB_TOKEN environment variable is required")
	}

	// Validate threshold
	if threshold < 0 || threshold > 100 {
		return fmt.Errorf("threshold must be between 0 and 100")
	}

	// Clean up URL
	cleanGitlabURL := strings.TrimSuffix(gitlabURL, "/")

	// Load Plumber configuration (required)
	plumberConfig, configPath, err := configuration.LoadPlumberConfig(configFile)
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Using configuration: %s\n", configPath)

	// Create configuration
	conf := configuration.NewDefaultConfiguration()
	conf.GitlabURL = cleanGitlabURL
	conf.GitlabToken = gitlabToken
	conf.ProjectPath = projectPath
	conf.Branch = defaultBranch
	conf.PlumberConfig = plumberConfig

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

	// Calculate average compliance, default to 100 if no controls ran
	var compliance float64 = 100
	if controlCount > 0 {
		compliance = complianceSum / float64(controlCount)
	}

	// Print text output to stdout if enabled
	if printOutput {
		if err := outputText(result, threshold, compliance); err != nil {
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

	// Check compliance against threshold
	if compliance < threshold {
		return fmt.Errorf("compliance %.1f%% is below threshold %.1f%%", compliance, threshold)
	}

	return nil
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

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// controlSummary holds summary data for a control
type controlSummary struct {
	name       string
	compliance float64
	issues     int
	skipped    bool
}

func outputText(result *control.AnalysisResult, threshold, compliance float64) error {
	// Collect control summaries for tables
	var controls []controlSummary

	// Header
	fmt.Printf("\n%sProject: %s%s\n\n", colorBold, result.ProjectPath, colorReset)

	// Control 1: Container images must not use forbidden tags
	if result.ImageForbiddenTagsResult != nil {
		ctrl := controlSummary{
			name:       "Container images must not use forbidden tags",
			compliance: result.ImageForbiddenTagsResult.Compliance,
			issues:     len(result.ImageForbiddenTagsResult.Issues),
			skipped:    result.ImageForbiddenTagsResult.Skipped,
		}
		controls = append(controls, ctrl)

		printControlHeader("Container images must not use forbidden tags", result.ImageForbiddenTagsResult.Compliance, result.ImageForbiddenTagsResult.Skipped)

		if result.ImageForbiddenTagsResult.Skipped {
			fmt.Printf("  %sStatus: SKIPPED (disabled in configuration)%s\n", colorDim, colorReset)
		} else {
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

	// Calculate column widths
	controlWidth := 52
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

	// Calculate column widths
	controlWidth := 52
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
