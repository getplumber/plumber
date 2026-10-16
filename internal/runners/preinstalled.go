// This file names the command-line tools GitHub's own hosted runner
// images ship by default, per OS family: a download a workflow only
// reaches when that tool is absent (a `command -v X ||` guard and the
// like) never runs at all on a runner where X is already on PATH.
package runners

import "strings"

// PreinstalledAsOf is the date this table was last checked against
// GitHub's own hosted runner image documentation (actions/runner-images).
// A tool the images gain or drop after this date is not reflected here
// until the table is updated.
const PreinstalledAsOf = "2026-10-15"

// preinstalledTools is the dated set of tools each hosted OS family
// ships, lower case. Updating this table is the only maintenance
// Preinstalled ever needs.
var preinstalledTools = map[string]map[string]bool{
	"ubuntu": {
		"rustup": true, "cargo": true, "go": true, "node": true, "npm": true,
		"pnpm": true, "yarn": true, "python3": true, "pip": true, "pipx": true,
		"uv": true, "docker": true, "gh": true, "aws": true, "az": true,
		"gcloud": true, "kubectl": true, "helm": true, "terraform": true,
	},
	"macos": {
		"rustup": true, "cargo": true, "go": true, "node": true, "npm": true,
		"pnpm": true, "yarn": true, "python3": true, "pip": true, "pipx": true,
		"gh": true, "aws": true, "az": true, "gcloud": true, "kubectl": true,
		"helm": true, "terraform": true,
		// macOS hosted images carry no docker daemon.
	},
	"windows": {
		"go": true, "node": true, "npm": true, "pnpm": true, "yarn": true,
		"python": true, "pip": true, "gh": true, "aws": true, "az": true,
		"gcloud": true, "kubectl": true, "helm": true, "terraform": true,
		"docker": true,
		// Windows hosted images carry no rustup/cargo by default.
	},
}

// Preinstalled reports whether tool is preinstalled on the hosted
// runner image of labelFamily ("ubuntu", "macos", "windows", case
// insensitive), and whether labelFamily itself is one of those hosted
// families at all. known is false for a self-hosted label, a label
// LabelFamily could not read with certainty (a matrix or an
// expression), or any other family this table does not cover: a
// download-guard check against an unknown family answers nothing, it
// does not answer "not preinstalled".
func Preinstalled(labelFamily, tool string) (preinstalled, known bool) {
	tools, ok := preinstalledTools[strings.ToLower(labelFamily)]
	if !ok {
		return false, false
	}
	return tools[strings.ToLower(tool)], true
}

// LabelFamily derives the hosted OS family ("ubuntu", "macos",
// "windows") from a job's runs-on labels, the same plain-label logic
// Known (retired.go) reads them with: a "<family>-*" label, case
// insensitive. isExpression (ir.Job.RunsOnExpression) and a label set
// that disagrees across its entries (a matrix) both answer unknown: a
// `${{ matrix.os }}` or similar names no single family with certainty.
func LabelFamily(labels []string, isExpression bool) (family string, known bool) {
	if isExpression || len(labels) == 0 {
		return "", false
	}
	var found string
	for _, label := range labels {
		f, ok := hostedFamilyOf(label)
		if !ok {
			return "", false
		}
		if found == "" {
			found = f
		} else if found != f {
			return "", false
		}
	}
	return found, found != ""
}

// hostedFamilyOf is the hosted OS family a single runs-on label names
// ("ubuntu-latest" -> "ubuntu"), "" when the label is not one of the
// three hosted families at all (self-hosted, or anything else).
func hostedFamilyOf(label string) (string, bool) {
	l := normalizeLabel(label)
	switch {
	case strings.HasPrefix(l, "ubuntu-"):
		return "ubuntu", true
	case strings.HasPrefix(l, "macos-"):
		return "macos", true
	case strings.HasPrefix(l, "windows-"):
		return "windows", true
	}
	return "", false
}
