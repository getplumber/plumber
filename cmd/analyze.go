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
  --config        Path to conf.pb.yaml config file
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
  plumber analyze --gitlab-url https://gitlab.com --project mygroup/myproject --config conf.pb.yaml --threshold 100

  # Analyze and save JSON to file (no stdout)
  plumber analyze --gitlab-url https://gitlab.com --project mygroup/myproject --config conf.pb.yaml --threshold 100 --print=false --output results.json

  # Analyze with both text output and JSON file
  plumber analyze --gitlab-url https://gitlab.com --project mygroup/myproject --config conf.pb.yaml --threshold 100 --output results.json
`,
	RunE: runAnalyze,
}

func init() {
	rootCmd.AddCommand(analyzeCmd)

	// Required flags
	analyzeCmd.Flags().StringVar(&gitlabURL, "gitlab-url", "", "GitLab instance URL (required)")
	analyzeCmd.Flags().StringVar(&projectPath, "project", "", "Full path of the project (required)")
	analyzeCmd.Flags().StringVar(&configFile, "config", "", "Path to conf.pb.yaml config file (required)")
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
	if verbose {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
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

	// Load PB configuration (required)
	pbConfig, configPath, err := configuration.LoadPBConfig(configFile)
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Using configuration: %s\n", configPath)

	// Create configuration
	conf := configuration.NewDefaultConfiguration()
	conf.GitlabURL = cleanGitlabURL
	conf.GitlabToken = gitlabToken
	conf.ProjectPath = projectPath
	conf.DefaultBranch = defaultBranch
	conf.PBConfig = pbConfig

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

	if result.ImageMutableResult != nil && !result.ImageMutableResult.Skipped {
		complianceSum += result.ImageMutableResult.Compliance
		controlCount++
	}

	if result.ImageUntrustedResult != nil && !result.ImageUntrustedResult.Skipped {
		complianceSum += result.ImageUntrustedResult.Compliance
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

func outputText(result *control.AnalysisResult, threshold, compliance float64) error {
	fmt.Printf("\n=== Pipeline Analysis Results ===\n\n")
	fmt.Printf("Project: %s\n", result.ProjectPath)
	fmt.Printf("CI Valid: %v\n", result.CiValid)
	fmt.Printf("CI Missing: %v\n\n", result.CiMissing)

	if result.PipelineOriginMetrics != nil {
		fmt.Printf("--- Pipeline Origin Metrics ---\n")
		fmt.Printf("  Total Jobs: %d\n", result.PipelineOriginMetrics.JobTotal)
		fmt.Printf("  Hardcoded Jobs: %d\n", result.PipelineOriginMetrics.JobHardcoded)
		fmt.Printf("  Total Origins: %d\n", result.PipelineOriginMetrics.OriginTotal)
		fmt.Printf("    - Components: %d\n", result.PipelineOriginMetrics.OriginComponent)
		fmt.Printf("    - Local: %d\n", result.PipelineOriginMetrics.OriginLocal)
		fmt.Printf("    - Project: %d\n", result.PipelineOriginMetrics.OriginProject)
		fmt.Printf("    - Remote: %d\n", result.PipelineOriginMetrics.OriginRemote)
		fmt.Printf("    - Template: %d\n", result.PipelineOriginMetrics.OriginTemplate)
		fmt.Printf("  GitLab Catalog Resources: %d\n", result.PipelineOriginMetrics.OriginGitLabCatalog)
		fmt.Printf("  Outdated: %d\n\n", result.PipelineOriginMetrics.OriginOutdated)
	}

	if result.PipelineImageMetrics != nil {
		fmt.Printf("--- Pipeline Image Metrics ---\n")
		fmt.Printf("  Total Images: %d\n\n", result.PipelineImageMetrics.Total)
	}

	if result.ImageMutableResult != nil {
		fmt.Printf("--- Mutable Image Tag Control ---\n")
		if result.ImageMutableResult.Skipped {
			fmt.Printf("  Status: SKIPPED (disabled in configuration)\n\n")
		} else {
			fmt.Printf("  Version: %s\n", result.ImageMutableResult.Version)
			fmt.Printf("  Compliance: %.1f%%\n", result.ImageMutableResult.Compliance)
			fmt.Printf("  Total Images: %d\n", result.ImageMutableResult.Metrics.Total)
			fmt.Printf("  Using Mutable Tags: %d\n", result.ImageMutableResult.Metrics.UsingMutableTag)

			if len(result.ImageMutableResult.Issues) > 0 {
				fmt.Printf("\n  Issues Found:\n")
				for _, issue := range result.ImageMutableResult.Issues {
					fmt.Printf("    - Job '%s' uses mutable tag '%s' (image: %s)\n", issue.Job, issue.Tag, issue.Link)
				}
			}
			fmt.Println()
		}
	}

	if result.ImageUntrustedResult != nil {
		fmt.Printf("--- Untrusted Image Control ---\n")
		if result.ImageUntrustedResult.Skipped {
			fmt.Printf("  Status: SKIPPED (disabled in configuration)\n\n")
		} else {
			fmt.Printf("  Version: %s\n", result.ImageUntrustedResult.Version)
			fmt.Printf("  Compliance: %.1f%%\n", result.ImageUntrustedResult.Compliance)
			fmt.Printf("  Total Images: %d\n", result.ImageUntrustedResult.Metrics.Total)
			fmt.Printf("  Trusted: %d\n", result.ImageUntrustedResult.Metrics.Trusted)
			fmt.Printf("  Untrusted: %d\n", result.ImageUntrustedResult.Metrics.Untrusted)

			if len(result.ImageUntrustedResult.Issues) > 0 {
				fmt.Printf("\n  Untrusted Images Found:\n")
				for _, issue := range result.ImageUntrustedResult.Issues {
					fmt.Printf("    - Job '%s' uses untrusted image: %s\n", issue.Job, issue.Link)
				}
			}
			fmt.Println()
		}
	}

	if result.BranchProtectionResult != nil {
		fmt.Printf("--- Branch Protection Control ---\n")
		if result.BranchProtectionResult.Skipped {
			fmt.Printf("  Status: SKIPPED (disabled in configuration)\n\n")
		} else {
			fmt.Printf("  Version: %s\n", result.BranchProtectionResult.Version)
			fmt.Printf("  Compliance: %.1f%%\n", result.BranchProtectionResult.Compliance)
			if result.BranchProtectionResult.Metrics != nil {
				fmt.Printf("  Total Branches: %d\n", result.BranchProtectionResult.Metrics.Branches)
				fmt.Printf("  Branches to Protect: %d\n", result.BranchProtectionResult.Metrics.BranchesToProtect)
				fmt.Printf("  Protected Branches: %d\n", result.BranchProtectionResult.Metrics.TotalProtectedBranches)
				fmt.Printf("  Unprotected: %d\n", result.BranchProtectionResult.Metrics.UnprotectedBranches)
				fmt.Printf("  Non-Compliant: %d\n", result.BranchProtectionResult.Metrics.NonCompliantBranches)
			}

			if len(result.BranchProtectionResult.Issues) > 0 {
				fmt.Printf("\n  Issues Found:\n")
				for _, issue := range result.BranchProtectionResult.Issues {
					if issue.Type == "unprotected" {
						fmt.Printf("    - Branch '%s' is not protected\n", issue.BranchName)
					} else {
						fmt.Printf("    - Branch '%s' has non-compliant protection settings\n", issue.BranchName)
						if issue.AllowForcePushDisplay {
							fmt.Printf("      * Force push is allowed (should be disabled)\n")
						}
						if issue.CodeOwnerApprovalRequiredDisplay {
							fmt.Printf("      * Code owner approval is not required\n")
						}
						if issue.MinMergeAccessLevelDisplay {
							fmt.Printf("      * Merge access level is too low (%d, minimum: %d)\n", issue.MinMergeAccessLevel, issue.AuthorizedMinMergeAccessLevel)
						}
						if issue.MinPushAccessLevelDisplay {
							fmt.Printf("      * Push access level is too low (%d, minimum: %d)\n", issue.MinPushAccessLevel, issue.AuthorizedMinPushAccessLevel)
						}
					}
				}
			}
			fmt.Println()
		}
	}

	// Summary with threshold check
	fmt.Printf("=== Summary ===\n")
	fmt.Printf("  Overall Compliance: %.1f%%\n", compliance)
	fmt.Printf("  Threshold: %.1f%%\n", threshold)
	if compliance >= threshold {
		fmt.Printf("  Status: PASSED ✓\n\n")
	} else {
		fmt.Printf("  Status: FAILED ✗\n\n")
	}

	return nil
}
