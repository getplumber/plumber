package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/getplumber/plumber/control"
	"github.com/spf13/cobra"
)

var (
	explainJSON bool
	explainList bool
	explainAll  bool
)

var explainCmd = &cobra.Command{
	Use:   "explain [ISSUE-CODE]",
	Short: "Show detailed information about a Plumber issue code",
	Long: `Display detailed information about a Plumber issue code, including
its description, remediation guidance, and documentation link.

Use --list to see all available issue codes, or --all for a full reference dump.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if explainList {
			return runExplainList()
		}
		if explainAll {
			return runExplainAll()
		}

		if len(args) == 0 {
			return fmt.Errorf("please provide an issue code (e.g., plumber explain ISSUE-412 or plumber explain 412)\n\nRun 'plumber explain --list' to see all available issue codes")
		}

		code := normalizeIssueCode(args[0])
		info := control.LookupCode(code)
		if info == nil {
			return fmt.Errorf("unknown issue code: %s\n\nRun 'plumber explain --list' to see all available issue codes", args[0])
		}

		if explainJSON {
			return printJSON(info)
		}

		printIssueDetail(info)
		return nil
	},
}

// normalizeIssueCode accepts both full issue format (ISSUE-412)
// and shorthand numeric format (412).
func normalizeIssueCode(raw string) control.ErrorCode {
	input := strings.ToUpper(strings.TrimSpace(raw))
	input = strings.TrimPrefix(input, "ISSUE-")
	return control.ErrorCode("ISSUE-" + input)
}

func runExplainList() error {
	codes := control.AllCodes()
	if explainJSON {
		return printJSON(codes)
	}
	for _, info := range codes {
		fmt.Printf("%-10s  %s\n", info.Code, info.Title)
	}
	return nil
}

func runExplainAll() error {
	codes := control.AllCodes()
	if explainJSON {
		return printJSON(codes)
	}
	for i, info := range codes {
		if i > 0 {
			fmt.Println(strings.Repeat("─", 60))
		}
		printIssueDetail(&info)
		fmt.Println()
	}
	return nil
}

func printIssueDetail(info *control.ErrorCodeInfo) {
	fmt.Printf("%s: %s\n", info.Code, info.Title)
	fmt.Printf("Control:     %s\n", info.ControlName)
	fmt.Println()
	fmt.Printf("Description:\n  %s\n", wrapText(info.Description, 74, "  "))
	fmt.Println()
	fmt.Printf("Remediation:\n  %s\n", wrapText(info.Remediation, 74, "  "))
	fmt.Println()
	fmt.Printf("Documentation: %s\n", info.DocURL)
}

// wrapText wraps text to the given width with the specified indent for continuation lines.
func wrapText(text string, width int, indent string) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}

	var lines []string
	currentLine := words[0]

	for _, word := range words[1:] {
		if len(currentLine)+1+len(word) > width {
			lines = append(lines, currentLine)
			currentLine = word
		} else {
			currentLine += " " + word
		}
	}
	lines = append(lines, currentLine)

	return strings.Join(lines, "\n"+indent)
}

func printJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func init() {
	explainCmd.Flags().BoolVar(&explainJSON, "json", false, "Output in JSON format")
	explainCmd.Flags().BoolVar(&explainList, "list", false, "List all issue codes with short descriptions")
	explainCmd.Flags().BoolVar(&explainAll, "all", false, "Show detailed information for all issue codes")
	rootCmd.AddCommand(explainCmd)
}
