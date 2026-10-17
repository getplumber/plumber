package cmd

import (
	"io"
	"os"

	"github.com/getplumber/plumber/capability"
	"github.com/spf13/cobra"
)

// writeCapabilityDefaults writes the CLI's built-in capability list, the embedded
// builtin.yaml verbatim. Split from the cobra handler so the test reads the exact bytes the
// command emits.
func writeCapabilityDefaults(w io.Writer) error {
	_, err := w.Write(capability.BuiltinYAML())
	return err
}

var capabilitiesCmd = &cobra.Command{
	Use:   "capabilities",
	Short: "Inspect the pipeline capabilities the CLI recognizes",
	Long: `Commands for the pipeline capabilities the CLI recognizes in a pipeline's jobs
(for example secret_detection), listed in the bill of materials.`,
}

// capabilitiesDefaultsCmd prints the built-in capability list in the declaration schema of
// .plumber.yaml and of the platform's capabilities setting, so a user can copy it and edit
// it (spec 4.2). A declaration with a built-in's name replaces that built-in whole.
var capabilitiesDefaultsCmd = &cobra.Command{
	Use:   "defaults",
	Short: "Print the built-in capability list as YAML",
	Long: `Print the CLI's built-in capability list, in the schema of the capabilities key
of .plumber.yaml (and of the platform's capabilities setting).

Copy it into .plumber.yaml to edit it: a capability you declare with a built-in's
name replaces that built-in whole, the others stay in force.

Examples:
  plumber capabilities defaults
  plumber capabilities defaults > capabilities.yaml
`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return writeCapabilityDefaults(os.Stdout)
	},
}

func init() {
	rootCmd.AddCommand(capabilitiesCmd)
	capabilitiesCmd.AddCommand(capabilitiesDefaultsCmd)
}
