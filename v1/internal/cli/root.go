// Package cli holds the plumber command line: the root command and its
// global flags. Each command group has its own package below it, and only
// these packages import cobra.
package cli

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/getplumber/plumber/v1/internal/cli/version"
	"github.com/getplumber/plumber/v1/internal/log"
)

// Execute builds the root command, runs it with the arguments of the process
// and returns the error that ended it, already logged.
func Execute(info version.BuildInfo) error {
	setupEnv()
	return newRootCommand(info).Execute()
}

// setupEnv configures the global viper to read the environment variables of
// the CLI: a key k reads PLUMBER_<K> (log_level reads PLUMBER_LOG_LEVEL).
// Viper isn't safe for concurrent writes, so the process calls it once,
// before any command runs, and the rest of the CLI only reads.
func setupEnv() {
	viper.SetEnvPrefix("plumber")
	viper.AutomaticEnv()
}

type rootCommand struct {
	cmd *cobra.Command
	log zerolog.Logger
}

// newRootCommand returns the root command with its subcommands. Command output
// goes to cobra's writers (os.Stdout and os.Stderr unless a test sets others),
// logs to c.log on os.Stderr, at the level PLUMBER_LOG_LEVEL sets. It keeps no
// state outside what it returns, so a test can build it as often as it needs.
func newRootCommand(info version.BuildInfo) *rootCommand {
	c := &rootCommand{log: log.New(os.Stderr)}

	rootCmd := &cobra.Command{
		Use:   "plumber",
		Short: "CI/CD security scanner for GitHub Actions and GitLab CI",
		Long: `Plumber scans the CI/CD configuration of a GitHub or GitLab repository for risky
patterns and security gaps: GitHub Actions workflows, GitLab CI pipelines with their
includes, and the repository settings. It reports the findings and a score.`,
		Args: cobra.NoArgs,
		// Execute logs the error that ends a command, and an error prints no
		// usage, as in golangci-lint.
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	// A command that logs takes c.log in its constructor.
	rootCmd.AddCommand(version.NewCmd(info))

	c.cmd = rootCmd
	return c
}

// Execute runs the root command and logs the error that ends it.
func (c *rootCommand) Execute() error {
	err := c.cmd.Execute()
	if err != nil {
		c.log.Error().Msg(err.Error())
	}
	return err
}
