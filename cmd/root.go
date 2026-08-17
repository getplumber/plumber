package cmd

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	// Global flags
	verbose      bool
	updateMsg    chan string
	failWarnings bool
)

var rootCmd = &cobra.Command{
	Use:   "plumber",
	Short: "Plumber - Trust Policy Manager for GitLab CI/CD",
	Long: `Plumber is a command-line tool that analyzes GitLab CI/CD pipelines
and enforces trust policies on third-party components, images, and branch protections.`,
	// Errors are printed by Execute below, where each class gets its own
	// prefix — cobra's blanket "Error:" would mislabel a gate verdict
	// (a failed run, not a broken one) as a program error.
	SilenceErrors: true,
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
		prefix, code, emit := classifyExecError(err, printOutput)
		if emit {
			fmt.Fprintf(os.Stderr, "%s: %v\n", prefix, err)
		}
		os.Exit(code)
	}
}

// classifyExecError maps a command error to its stderr prefix, process exit
// code, and whether the reason should be printed at all. It is the pure
// decision behind Execute's error handling, split out so the class→exit-code
// mapping and the --print gate can be unit-tested without os.Exit.
//
//   - ScoreGateError / ComplianceError → "Blocked", exit 1. A gate block is a
//     verdict on the project, not a program error. When the full text report
//     was shown its "Status: FAILED" line already states the same score and
//     threshold, so the reason is emitted only when the report was suppressed
//     (--print=false, JSON/PBOM-only, CI capturing stderr), where it is the
//     sole human-readable failure reason.
//   - PlatformGateError → "Blocked", exit 1, same class as the local score
//     gate - also a verdict on the project. Always emitted, unlike the local
//     gate: the terminal report reflects only the local score, so on a run
//     that passes locally but is blocked by the platform, the report would
//     say "PASSED" while the process exits 1 unless this reason is printed
//     regardless of --print.
//   - DegradedError / IncompleteDataError → "Incomplete", exit 3. The run could
//     not fully verify the project — also not a program error.
//   - anything else → "Error", exit 2.
func classifyExecError(err error, printOutput bool) (prefix string, code int, emit bool) {
	var gateErr *ScoreGateError
	var complianceErr *ComplianceError
	var platformGateErr *PlatformGateError
	var degradedErr *DegradedError
	var incompleteErr *IncompleteDataError
	switch {
	case errors.As(err, &gateErr), errors.As(err, &complianceErr):
		return "Blocked", 1, !printOutput
	case errors.As(err, &platformGateErr):
		return "Blocked", 1, true
	case errors.As(err, &degradedErr), errors.As(err, &incompleteErr):
		return "Incomplete", 3, true
	default:
		return "Error", 2, true
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable debug logging on stderr (level=debug); replaces the progress bar")
}
