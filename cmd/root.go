package cmd

import (
	"fmt"
	"os"

	"github.com/getplumber/plumber/utils"
	"github.com/spf13/cobra"
)

var (
	// Global flags
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "plumber",
	Short: "Plumber - Trust Policy Manager for GitLab CI/CD",
	Long: `Plumber is a command-line tool that analyzes GitLab CI/CD pipelines
and enforces trust policies on third-party components, images, and branch protections.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Check for updates (non-blocking, fail-fast)
		checkForUpdates()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}

// checkForUpdates checks if a newer version is available
// This runs in the background and doesn't block execution
func checkForUpdates() {
	// Run in a goroutine to not block CLI startup
	go func() {
		checker := utils.NewVersionChecker(Version)
		latestVersion, hasUpdate, err := checker.CheckForUpdate()
		if err != nil {
			// Silently fail - version check is not critical
			return
		}
		if hasUpdate {
			utils.PrintUpdateMessage(Version, latestVersion)
		}
	}()
}
