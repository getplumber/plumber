package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	// Global flags
	verbose   bool
	updateMsg chan string
)

var rootCmd = &cobra.Command{
	Use:   "plumber",
	Short: "Plumber - Trust Policy Manager for GitLab CI/CD",
	Long: `Plumber is a command-line tool that analyzes GitLab CI/CD pipelines
and enforces trust policies on third-party components, images, and branch protections.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if os.Getenv("PLUMBER_NO_UPDATE_CHECK") == "" {
			updateMsg = make(chan string, 1)
			go checkForNewerVersion(updateMsg)
		}
		return nil
	},
}

func Execute() {
	err := rootCmd.Execute()

	if updateMsg != nil {
		select {
		case msg := <-updateMsg:
			if msg != "" {
				fmt.Fprint(os.Stderr, msg)
			}

		case <-time.After(500 * time.Millisecond):
			// Fast commands (e.g. "plumber version") finish before the GitHub
			// API responds. Give the check up to 500ms after the command ends
			// to avoid hanging on firewalled networks where packets are silently
			// dropped and the HTTP client waits for the full 3s timeout.
		}
	}

	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}
