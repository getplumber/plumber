// Package version holds the version command, modeled on golangci-lint's
// pkg/commands/version.go without its --debug flag.
package version

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// BuildInfo identifies the build of the binary. main fills it.
type BuildInfo struct {
	GoVersion string `json:"goVersion"` // Go version the binary was built with, or "unknown"
	Version   string `json:"version"`   // release version without the leading v, or "dev"
	Commit    string `json:"commit"`    // commit the binary was built from, or "none"
	Date      string `json:"date"`      // build date, or "unknown"
}

func (b BuildInfo) String() string {
	return fmt.Sprintf("plumber has version %s built with %s from %s on %s",
		b.Version, b.GoVersion, b.Commit, b.Date)
}

type versionOptions struct {
	JSON  bool
	Short bool
}

type versionCommand struct {
	cmd  *cobra.Command
	opts versionOptions

	info BuildInfo
}

// NewCmd returns the version command, which writes info to the output of
// the command: one line, JSON with --json, or the version alone with --short.
func NewCmd(info BuildInfo) *cobra.Command {
	c := &versionCommand{info: info}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Display the plumber version",
		Args:  cobra.NoArgs,
		RunE:  c.execute,
	}

	fs := versionCmd.Flags()
	fs.SortFlags = false // sort them as they are defined here

	fs.BoolVar(&c.opts.JSON, "json", false, "Display as JSON")
	fs.BoolVar(&c.opts.Short, "short", false, "Display only the version number")

	c.cmd = versionCmd

	return c.cmd
}

func (c *versionCommand) execute(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()

	switch {
	case c.opts.JSON:
		return json.NewEncoder(out).Encode(c.info)
	case c.opts.Short:
		_, err := fmt.Fprintln(out, c.info.Version)
		return err
	default:
		return printVersion(out, c.info)
	}
}

func printVersion(w io.Writer, info BuildInfo) error {
	_, err := fmt.Fprintln(w, info.String())
	return err
}
