package cmd

import (
	"encoding/json"
	"io"
	"os"

	"github.com/getplumber/plumber/control"
	"github.com/spf13/cobra"
)

// writeCatalogJSON serializes the full catalog document. Split from the
// cobra handler so the golden test exercises the exact bytes the command
// emits, with a caller-controlled version for determinism.
func writeCatalogJSON(w io.Writer, cliVersion string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(control.Catalog(cliVersion))
}

// catalogCmd dumps the CLI's control/issue catalog as JSON: ids, names,
// descriptions, categories, providers, config schemas and issue types
// (#458). The platform imports control.Catalog() directly; this command is
// the same document for non-Go consumers (the docs site build).
var catalogCmd = &cobra.Command{
	Use:   "catalog",
	Short: "Print the control and issue catalog as JSON",
	RunE: func(cmd *cobra.Command, args []string) error {
		return writeCatalogJSON(os.Stdout, Version)
	},
}

func init() {
	rootCmd.AddCommand(catalogCmd)
}
