package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/getplumber/plumber/configuration"
)

// platformModeNotices prints, once, what platform mode makes inert (spec s1):
// a local configuration file that was read, and every local threshold that
// was supplied. Returns the lines for tests. Silent outside platform mode and
// on a default component run (no file, no threshold set).
func platformModeNotices(conf *configuration.Configuration) []string {
	on, endpoint := effectivePlatformPush()
	if !on {
		return nil
	}
	var lines []string
	if conf != nil && localConfigFileWasRead(conf) {
		lines = append(lines, fmt.Sprintf("  linked to %s: local %s ignored, policies come from the platform", endpoint, conf.ConfigFilePath))
	}
	for _, f := range []struct {
		name string
		set  bool
	}{
		{"--min-points", minPointsSet},
		{"--min-score", minScore != ""},
		{"--threshold", thresholdSet},
	} {
		if f.set {
			lines = append(lines, fmt.Sprintf("  %s ignored: enforcement comes from the platform's policies", f.name))
		}
	}
	for _, l := range lines {
		fmt.Fprintln(os.Stderr, l)
	}
	return lines
}

// localConfigFileWasRead reports whether conf's PlumberConfig came from a file
// on disk rather than the embedded default. ConfigFilePath is the field
// configuration.Configuration carries for this (see its doc comment);
// builtinDefaultConfigSource is the existing sentinel a zero-config run
// stamps there instead of a real path (cmd/platform_push.go's
// platformPolicyNameFor treats it the same way).
func localConfigFileWasRead(conf *configuration.Configuration) bool {
	path := strings.TrimSpace(conf.ConfigFilePath)
	return path != "" && path != builtinDefaultConfigSource
}
