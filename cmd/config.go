package cmd

import (
	"fmt"
	"os"
	"reflect"
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
	// config diff flags
	configDiffFile    string
	configDiffNoColor bool
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
	Use:          "validate",
	Short:        "Validate a configuration file",
	SilenceUsage: true,
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

var configDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Display the difference between current config and defaults",
	Long: `Display a clean, human-readable view of the differences between the current config and defaults.

This command loads and parses the configuration file and the default config, and then compares them.

Differences are colorized for quick scanning:
  - Added/modified  → green
  - Removed → red

Examples:
  # compare the .plumber.yaml in root of repo with default config
  plumber config diff

  # compare the default config with a custom config
  plumber config diff --config custom-plumber.yaml

  # View diff without colors (for piping or scripts)
  plumber config diff --config custom-plumber.yaml --no-color`,
	RunE: runConfigDiff,
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configViewCmd)
	configCmd.AddCommand(configGenerateCmd)
	configCmd.AddCommand(configValidateCmd)
	configCmd.AddCommand(configDiffCmd)

	// config validate flags
	configValidateCmd.Flags().StringVarP(&configValidateFile, "config", "c", ".plumber.yaml", "Path to configuration file")
	configValidateCmd.Flags().BoolVar(&failWarnings, "fail-warnings", false, "Treat configuration warnings as errors (exit 1)")

	// config view flags
	configViewCmd.Flags().StringVarP(&configViewFile, "config", "c", ".plumber.yaml", "Path to configuration file")
	configViewCmd.Flags().BoolVar(&configViewNoColor, "no-color", false, "Disable colorized output")

	// config generate flags
	configGenerateCmd.Flags().StringVarP(&configGenerateOutput, "output", "o", ".plumber.yaml", "Output file path")
	configGenerateCmd.Flags().BoolVarP(&configGenerateForce, "force", "f", false, "Overwrite existing file")

	// config diff flags
	configDiffCmd.Flags().StringVarP(&configDiffFile, "config", "c", ".plumber.yaml", "Path to configuration file")
	configDiffCmd.Flags().BoolVar(&configDiffNoColor, "no-color", false, "Disable colorized output")

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

	config, _, _, err := configuration.LoadPlumberConfig(configViewFile)
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
	if !verbose {
		logrus.SetLevel(logrus.WarnLevel)
	}

	_, _, warnings, err := configuration.LoadPlumberConfig(configValidateFile)
	if err != nil {
		return fmt.Errorf("failed to validate configuration: %w", err)
	}

	if len(warnings) > 0 {
		fmt.Fprintf(os.Stderr, "Configuration validation warnings:\n")
		for _, warning := range warnings {
			fmt.Fprintf(os.Stderr, "  - %s\n", warning)
		}
		fmt.Fprintf(os.Stderr, "\nConfiguration loaded from: %s\n", configValidateFile)
		if failWarnings {
			return fmt.Errorf("configuration has %d warning(s) and --fail-warnings is set", len(warnings))
		}
		fmt.Fprintf(os.Stderr, "Please fix the warnings above for best results.\n")
	} else {
		fmt.Printf("Configuration %s is valid.\n", configValidateFile)
	}

	return nil
}

func runConfigDiff(cmd *cobra.Command, args []string) error {

	// Determine if we should colorize output
	useColor := !configDiffNoColor
	// Auto-detect: disable color if not a terminal (unless explicitly set)
	if !cmd.Flags().Changed("no-color") {
		if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode() & os.ModeCharDevice) == 0 {
			useColor = false
		}
	}

	// Using a basic os.ReadFile call here instead of
	// configuration.LoadPlumberConfig(), since the load
	// plumber config method unmarshals the yaml content into
	// a PlumberConfig object, which ignores any new keys (non-standard)
	// introduced in the user yaml config.
	userBytes, err := os.ReadFile(configDiffFile)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("config file not found: %s", configDiffFile)
		}
		return err
	}

	defaultBytes := defaultconfig.Get()

	defaultMap, err := flattenYamlContentsIntoMap(defaultBytes)
	if err != nil {
		return fmt.Errorf("failed to convert default config into map: %w", err)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal user config: %w", err)
	}

	userMap, err := flattenYamlContentsIntoMap(userBytes)

	if err != nil {
		return fmt.Errorf("failed to convert user config into map: %w", err)
	}

	missingDefaults := make(map[string]struct{})
	matchingUserKeys := make(map[string]struct{})

	// Prints changed values
	fmt.Println("\nControls changed from defaults:")
	for key, val1 := range defaultMap {
		if val2, exists := userMap[key]; exists {
			if !reflect.DeepEqual(val1, val2) {
				if useColor {
					fmt.Printf("%s: ", key)
					colorizeChanges(val1, val2)
					fmt.Println()
				} else {
					fmt.Printf("%s: %v → %v\n", key, val1, val2)
				}
			}
			matchingUserKeys[key] = struct{}{}
		} else {
			missingDefaults[key] = struct{}{}
		}
	}

	// Prints keys present in default, but absent in user provided config
	fmt.Println("\nNew keys in default (missing from your config):")
	for key := range missingDefaults {
		fmt.Println(key)
	}

	// Prints keys that are present in user provided config, but absent in default
	fmt.Println("\nUnknown keys in your config (not in defaults):")
	for key := range userMap {
		if _, ok := matchingUserKeys[key]; !ok {
			fmt.Println(key)
		}
	}

	return nil
}

// Converts YAML contents into a map and then flattens that map
func flattenYamlContentsIntoMap(contents []byte) (map[string]any, error) {

	var convertedMap map[string]any
	if err := yaml.Unmarshal(contents, &convertedMap); err != nil {
		return nil, err
	}
	return flattenMap(convertedMap), nil
}

func flattenMap(mapToFlatten map[string]any) map[string]any {
	result := make(map[string]any)
	flattenRecursive("", mapToFlatten, result)
	return result
}

// Recursively flattens the map and returns a flattened map
// Keys are concatenated with . to indicate various levels of
// indentation.
func flattenRecursive(prefix string, currentMap map[string]any, result map[string]any) {
	for key, value := range currentMap {
		newKey := key
		if prefix != "" {
			newKey = prefix + "." + key
		}
		if childMap, ok := value.(map[string]any); ok {
			flattenRecursive(newKey, childMap, result)
		} else if interfaceMap, ok := value.(map[interface{}]interface{}); ok {
			converted := make(map[string]any)
			for k, v := range interfaceMap {
				converted[fmt.Sprintf("%v", k)] = v
			}
			flattenRecursive(newKey, converted, result)
		} else {
			result[newKey] = value
		}
	}
}

// colorizeChanges Colorises the changed for easy scanning
func colorizeChanges(val1, val2 any) {
	typeA := reflect.TypeOf(val1)
	typeB := reflect.TypeOf(val2)

	// If both are slices, scan through both of them
	// Prints removed items in red
	// Prints added/modified items in green
	if val1 != nil && val2 != nil && typeA.Kind() == reflect.Slice && typeB.Kind() == reflect.Slice {
		slice1 := convertToInterfaceSlice(val1)
		slice2 := convertToInterfaceSlice(val2)

		set1 := make(map[any]struct{})
		set2 := make(map[any]struct{})
		for _, item := range slice1 {
			set1[item] = struct{}{}
		}
		for _, item := range slice2 {
			set2[item] = struct{}{}
		}

		fmt.Printf("[")
		for value := range set1 {
			if _, ok := set2[value]; !ok {
				fmt.Printf(" %s%v%s ", colorRed, value, colorReset)
			} else {
				fmt.Printf(" %v ", value)
			}
		}
		fmt.Printf("] → [")
		for value := range set2 {
			if _, ok := set1[value]; !ok {
				fmt.Printf(" %s%v%s ", colorGreen, value, colorReset)
			} else {
				fmt.Printf(" %v ", value)
			}
		}
		fmt.Printf("]")

	} else {
		// For primitives (bool, string, int), show the transformation
		// Old value in red, new value in green
		fmt.Printf("%s%v%s → %s%v%s", colorRed, val1, colorReset, colorGreen, val2, colorReset)
	}

}

// Helper function to convert to interface slice.
func convertToInterfaceSlice(s any) []any {
	v := reflect.ValueOf(s)
	res := make([]any, v.Len())
	for i := 0; i < v.Len(); i++ {
		res[i] = v.Index(i).Interface()
	}
	return res
}
