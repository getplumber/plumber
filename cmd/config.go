package cmd

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/defaultconfig"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

var (
	// config view flags
	configViewFile    string
	configViewNoColor bool

	// config generate flags
	configGenerateOutput string
	configGenerateForce  bool
	// config validate flags
	configValidateFile string
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage Plumber configuration",
	Long:  `Commands for viewing and managing Plumber configuration files.`,
}

var configViewCmd = &cobra.Command{
	Use:   "view",
	Short: "Display the effective configuration",
	Long: `Display a clean, human-readable view of the effective configuration.

This command loads and parses the configuration file, then displays it
without comments, making it easy to see exactly what settings are active.

Booleans are colorized for quick scanning:
  - true  → green
  - false → red

Examples:
  # View the default .plumber.yaml
  plumber config view

  # View a specific config file
  plumber config view --config custom-plumber.yaml

  # View without colors (for piping or scripts)
  plumber config view --no-color
`,
	RunE: runConfigView,
}

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate a configuration file",
	Long: `Validate a Plumber configuration file for correctness.

This command checks the configuration file for:
  - Valid YAML syntax
  - Unknown configuration keys (warns with suggestions)
  - Required fields

Examples:
  # Validate the default .plumber.yaml
  plumber config validate

  # Validate a specific config file
  plumber config validate --config custom-plumber.yaml
`,
	RunE: runConfigValidate,
}

var configGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a default .plumber.yaml configuration file",
	Long: `Generate a default .plumber.yaml configuration file.

This creates a configuration file with sensible defaults that you can
customize for your organization's compliance requirements.

The generated config includes:
- Container image tag policies (forbid 'latest', 'dev', etc.)
- Container image digest pinning policy
- Trusted registry whitelist
- Branch protection requirements

Examples:
  # Generate default config in current directory
  plumber config generate

  # Generate config with custom filename
  plumber config generate --output my-plumber-config.yaml

  # Overwrite existing file
  plumber config generate --force
`,
	RunE: runConfigGenerate,
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configViewCmd)
	configCmd.AddCommand(configGenerateCmd)
	configCmd.AddCommand(configValidateCmd)

	// config validate flags
	configValidateCmd.Flags().StringVarP(&configValidateFile, "config", "c", ".plumber.yaml", "Path to configuration file")

	// config view flags
	configViewCmd.Flags().StringVarP(&configViewFile, "config", "c", ".plumber.yaml", "Path to configuration file")
	configViewCmd.Flags().BoolVar(&configViewNoColor, "no-color", false, "Disable colorized output")

	// config generate flags
	configGenerateCmd.Flags().StringVarP(&configGenerateOutput, "output", "o", ".plumber.yaml", "Output file path")
	configGenerateCmd.Flags().BoolVarP(&configGenerateForce, "force", "f", false, "Overwrite existing file")
}

func runConfigView(cmd *cobra.Command, args []string) error {
	// Suppress debug logs for clean output (unless verbose)
	if !verbose {
		logrus.SetLevel(logrus.WarnLevel)
	}

	// Determine if we should colorize output
	useColor := !configViewNoColor
	// Auto-detect: disable color if not a terminal (unless explicitly set)
	if !cmd.Flags().Changed("no-color") {
		if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode() & os.ModeCharDevice) == 0 {
			useColor = false
		}
	}

	// Load the configuration
	config, _, err := configuration.LoadPlumberConfig(configViewFile)
	if err != nil {
		return err
	}

	// Marshal to clean YAML (this strips comments)
	cleanYAML, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to serialize configuration: %w", err)
	}

	// Convert to string for processing
	output := string(cleanYAML)

	// Format nested arrays (like requiredGroups) for better readability
	output = formatNestedArrays(output)

	// Colorize if enabled
	if useColor {
		output = colorizeBooleans(output)
	}

	fmt.Print(output)
	return nil
}

// colorizeBooleans replaces true/false with colorized versions
func colorizeBooleans(input string) string {
	// Match 'true' and 'false' as YAML boolean values (after : or as list items)
	// This regex ensures we only match actual boolean values, not substrings
	trueRegex := regexp.MustCompile(`(:\s*)true(\s*$)`)
	falseRegex := regexp.MustCompile(`(:\s*)false(\s*$)`)

	lines := strings.Split(input, "\n")
	for i, line := range lines {
		lines[i] = trueRegex.ReplaceAllString(line, fmt.Sprintf("${1}%strue%s${2}", colorGreen, colorReset))
		lines[i] = falseRegex.ReplaceAllString(lines[i], fmt.Sprintf("${1}%sfalse%s${2}", colorRed, colorReset))
	}

	return strings.Join(lines, "\n")
}

// formatNestedArrays converts block-style nested arrays to flow-style for better readability
// Changes:
//
//	requiredGroups:
//	- - item1
//	  - item2
//	- - item3
//
// To:
//
//	requiredGroups:
//	  - [item1, item2]
//	  - [item3]
func formatNestedArrays(input string) string {
	lines := strings.Split(input, "\n")
	var result []string
	i := 0

	for i < len(lines) {
		line := lines[i]

		// Check if this line is a key ending with "Groups:" (like requiredGroups:)
		if strings.HasSuffix(strings.TrimSpace(line), "Groups:") || strings.HasSuffix(strings.TrimSpace(line), "groups:") {
			result = append(result, line)
			i++

			// Get the base indentation for the array items
			baseIndent := ""
			if i < len(lines) {
				// Find indentation of first "- -" pattern
				trimmed := strings.TrimLeft(lines[i], " ")
				baseIndent = strings.Repeat(" ", len(lines[i])-len(trimmed))
			}

			// Process nested arrays
			for i < len(lines) {
				currentLine := lines[i]
				trimmedCurrent := strings.TrimSpace(currentLine)

				// Check if this is the start of a nested array (- - pattern or just -)
				if strings.HasPrefix(trimmedCurrent, "- -") || strings.HasPrefix(trimmedCurrent, "- ") {
					// Collect all items in this group
					var groupItems []string

					// Get current line's indentation
					lineIndent := len(currentLine) - len(strings.TrimLeft(currentLine, " "))

					// Check if it's a "- -" pattern (nested array start)
					if strings.HasPrefix(trimmedCurrent, "- -") {
						// First item is after "- -"
						firstItem := strings.TrimPrefix(trimmedCurrent, "- -")
						firstItem = strings.TrimSpace(firstItem)
						if firstItem != "" {
							groupItems = append(groupItems, firstItem)
						}
						i++

						// Continue collecting items that are indented (continuation of same group)
						for i < len(lines) {
							nextLine := lines[i]
							nextTrimmed := strings.TrimSpace(nextLine)
							nextIndent := len(nextLine) - len(strings.TrimLeft(nextLine, " "))

							// If it's a "- " at greater indent, it's part of this group
							if strings.HasPrefix(nextTrimmed, "- ") && nextIndent > lineIndent {
								item := strings.TrimPrefix(nextTrimmed, "- ")
								item = strings.TrimSpace(item)
								if item != "" {
									groupItems = append(groupItems, item)
								}
								i++
							} else {
								break
							}
						}

						// Format as flow-style array
						if len(groupItems) > 0 {
							flowArray := "[" + strings.Join(groupItems, ", ") + "]"
							result = append(result, baseIndent+"  - "+flowArray)
						}
					} else if strings.HasPrefix(trimmedCurrent, "- ") && !strings.HasPrefix(trimmedCurrent, "- -") {
						// Single item array or regular list item - check if we're still in requiredGroups context
						// This might be a different key, so break out
						break
					}
				} else if trimmedCurrent == "" {
					// Empty line, keep it
					result = append(result, currentLine)
					i++
				} else if !strings.HasPrefix(trimmedCurrent, "-") && strings.Contains(trimmedCurrent, ":") {
					// This is a new key, break out of the nested array processing
					break
				} else {
					// Something else, move on
					i++
				}
			}
		} else {
			result = append(result, line)
			i++
		}
	}

	return strings.Join(result, "\n")
}

func runConfigGenerate(cmd *cobra.Command, args []string) error {
	// Check if file already exists
	if _, err := os.Stat(configGenerateOutput); err == nil {
		if !configGenerateForce {
			return fmt.Errorf("file %s already exists. Use --force to overwrite", configGenerateOutput)
		}
		fmt.Fprintf(os.Stderr, "Overwriting existing file: %s\n", configGenerateOutput)
	}

	// Get embedded default config
	configContent := defaultconfig.Get()

	// Write to file
	if err := os.WriteFile(configGenerateOutput, configContent, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Printf("Generated %s\n", configGenerateOutput)
	fmt.Println("\nNext steps:")
	fmt.Println("  1. Review and customize the configuration for your needs")
	fmt.Println("  2. Export the GITLAB_TOKEN environment variable if you haven't already")
	fmt.Println("  3. Run: plumber analyze --gitlab-url <url> --project <path>")

	return nil
}

func runConfigValidate(cmd *cobra.Command, args []string) error {
	// Suppress debug logs for clean output (unless verbose)
	if !verbose {
		logrus.SetLevel(logrus.WarnLevel)
	}

	// Read raw config file for unknown key validation
	rawData, err := os.ReadFile(configValidateFile)
	if err != nil {
		return fmt.Errorf("failed to read configuration file: %w", err)
	}

	// Check for unknown keys in raw YAML (before struct parsing loses them)
	warnings := configuration.ValidateKnownKeys(rawData)

	// Also validate the config parses correctly and passes structural validation
	_, _, err = configuration.LoadPlumberConfig(configValidateFile)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	if len(warnings) > 0 {
		fmt.Fprintf(os.Stderr, "Configuration validation warnings:\n")
		for _, warning := range warnings {
			fmt.Fprintf(os.Stderr, "  - %s\n", warning)
		}
		fmt.Fprintf(os.Stderr, "\nConfiguration loaded from: %s\n", configValidateFile)
		fmt.Fprintf(os.Stderr, "Please fix the warnings above for best results.\n")
	} else {
		fmt.Printf("Configuration %s is valid.\n", configValidateFile)
	}

	return nil
}
