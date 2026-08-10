package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/getplumber/plumber/configuration"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
)

var (
	configResolveFile   string
	configResolveOutput string
)

var configResolveCmd = &cobra.Command{
	Use:   "resolve",
	Short: "Print the fully resolved effective configuration",
	Long: `Resolve extends and includePlumberDefaults and print the complete
effective .plumber.yaml. Use this to materialize a sparse overlay into a
full, self-contained config you can commit (nothing left implicit), or to
audit exactly what a scan will use.

Examples:
  plumber config resolve
  plumber config resolve -c overlay.yaml -o full.plumber.yaml`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return resolveConfigToFile(configResolveFile, configResolveOutput, cmd.Flags().Changed("config"))
	},
}

// resolveConfigToFile loads and resolves the config at src and writes the
// materialized YAML to dst. An empty dst writes to stdout.
//
// configExplicit reports whether the caller named src explicitly (for
// example via --config on the command line), mirroring the configExplicit
// parameter on loadConfigOrOffer and the Changed("config") check in
// runConfigView. When src is missing and configExplicit is true, the missing
// file is a hard error: we do not silently swap in the embedded default for a
// file the user asked for by name. Only the zero-config case (no --config,
// no local file) falls back to the built-in default.
func resolveConfigToFile(src, dst string, configExplicit bool) error {
	cfg, _, _, err := configuration.LoadPlumberConfig(src)
	if err != nil {
		if !configExplicit && errors.Is(err, configuration.ErrConfigNotFound) {
			cfg, _, _, err = configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), builtinDefaultConfigSource)
		}
		if err != nil {
			return err
		}
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to serialize resolved configuration: %w", err)
	}
	if dst == "" {
		fmt.Print(string(out))
		return nil
	}
	if err := os.WriteFile(dst, out, 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", dst, err)
	}
	fmt.Fprintf(os.Stderr, "Wrote resolved configuration to %s\n", dst)
	return nil
}
