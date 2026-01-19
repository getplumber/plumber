package cmd

import (
	"fmt"
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
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}
