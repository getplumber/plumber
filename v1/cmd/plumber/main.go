// Command plumber is the rewritten Plumber CLI
// (https://github.com/orgs/getplumber/projects/1/views/18).
package main

import (
	"os"
	"runtime/debug"
	"strings"

	"github.com/getplumber/plumber/v1/internal/cli"
	"github.com/getplumber/plumber/v1/internal/cli/version"
)

// Set by -X ldflags on release builds.
var (
	buildVersion = "dev"
	buildCommit  = "none"
	buildDate    = "unknown"
)

func main() {
	if cli.Execute(buildInfo()) != nil {
		os.Exit(1) // Execute already logged the error.
	}
}

// buildInfo returns the build info of the binary: the ldflags values, with
// the version completed from the module version Go stamps into the binary,
// so a `go install …@latest` build reports its real version.
func buildInfo() version.BuildInfo {
	info := version.BuildInfo{GoVersion: "unknown", Version: buildVersion, Commit: buildCommit, Date: buildDate}
	if bi, ok := debug.ReadBuildInfo(); ok {
		info.GoVersion = bi.GoVersion
		info.Version = resolveVersion(info.Version, bi.Main.Version)
	}
	return info
}

// resolveVersion keeps the ldflags version when there is one and otherwise
// takes the module version, without its leading v. "(devel)" is what a local
// `go build` stamps; it carries no information and leaves "dev" alone.
func resolveVersion(ldflagsVersion, moduleVersion string) string {
	if ldflagsVersion != "dev" && ldflagsVersion != "" {
		return ldflagsVersion
	}
	if moduleVersion == "" || moduleVersion == "(devel)" {
		return ldflagsVersion
	}
	return strings.TrimPrefix(moduleVersion, "v")
}
