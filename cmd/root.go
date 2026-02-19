package cmd

import (
	"os"

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
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		// Duplicated output
		// Cobra give same output;
		// from github.com/spf13/cobra v1.8.1
		// just commenting this duplication for now.
		// to validate, just uncomment that fmt line and run this command:
		// make build && ./plumber analyze --gitlab-url https://gitlab.com --project a/b --controls nope
		//
		// fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}
