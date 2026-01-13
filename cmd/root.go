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
	Use:   "tpm",
	Short: "TPM CLI - GitLab repository compliance checker",
	Long: `TPM CLI is a command-line tool that checks the compliance of GitLab
repositories against a defined set of controls.`,
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
