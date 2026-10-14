package cmd

import (
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
)

var (
	// Version is set by -X ldflags on release builds (release.yml). A
	// `go install github.com/getplumber/plumber@latest` build gets no
	// ldflags; init falls back to the module version Go stamps into the
	// binary so that build reports its real version and gets update notices.
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		Version = resolveVersion(Version, info.Main.Version)
	}
}

// resolveVersion keeps the ldflags version when there is one and otherwise
// takes the module version from the build info, in the ldflags format
// (no leading v). "(devel)" is what a local `go build` stamps and carries
// no information, so it leaves the "dev" value alone.
func resolveVersion(ldflagsVersion, mainVersion string) string {
	if ldflagsVersion != "dev" && ldflagsVersion != "" {
		return ldflagsVersion
	}
	if mainVersion == "" || mainVersion == "(devel)" {
		return ldflagsVersion
	}
	return strings.TrimPrefix(mainVersion, "v")
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("plumber version %s\n", Version)
		fmt.Printf("  commit: %s\n", Commit)
		fmt.Printf("  built:  %s\n", BuildDate)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
