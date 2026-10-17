// This file names the command-line tools GitHub's own hosted runner
// images ship by default, per image: a download a workflow only reaches
// when that tool is absent (a `command -v X ||` guard and the like)
// never runs at all on a runner where X is already on PATH.
package runners

import (
	"regexp"
	"strings"
)

// PreinstalledAsOf is the date this table was last checked against
// GitHub's own hosted runner image documentation (actions/runner-images:
// the Ubuntu 22.04 image 20261004.315.1 and the Ubuntu 24.04 image
// 20261012.334.1 software lists). A tool the images gain or drop after
// this date is not reflected here until the table is updated.
const PreinstalledAsOf = "2026-10-16"

// ubuntuTools is what both Ubuntu images ship on PATH. Go is only in the
// tool cache (not on PATH until a setup step adds it), and neither image
// ships pnpm or uv: none of the three is listed.
var ubuntuTools = []string{
	"rustup", "cargo", "node", "npm", "yarn", "python3", "pip", "pipx",
	"docker", "gh", "aws", "az", "gcloud", "kubectl", "helm",
}

// preinstalledTools is the dated set of tools each hosted image ships,
// lower case. Updating this table is the only maintenance Preinstalled
// ever needs.
var preinstalledTools = map[string]map[string]bool{
	// Ubuntu 22.04 also ships terraform.
	"ubuntu-22.04": toolSet(ubuntuTools, "terraform"),
	// Ubuntu 24.04 dropped terraform.
	"ubuntu-24.04": toolSet(ubuntuTools),
	"macos": toolSet([]string{
		"rustup", "cargo", "go", "node", "npm",
		"pnpm", "yarn", "python3", "pip", "pipx",
		"gh", "aws", "az", "gcloud", "kubectl",
		"helm", "terraform",
		// macOS hosted images carry no docker daemon.
	}),
	"windows": toolSet([]string{
		"go", "node", "npm", "pnpm", "yarn",
		"python", "pip", "gh", "aws", "az",
		"gcloud", "kubectl", "helm", "terraform",
		"docker",
		// Windows hosted images carry no rustup/cargo by default.
	}),
}

// latestImage is the image each family's "-latest" label runs today:
// ubuntu-latest moves to a newer image when GitHub says so, and this
// table with it.
var latestImage = map[string]string{
	"ubuntu":  "ubuntu-24.04",
	"macos":   "macos",
	"windows": "windows",
}

func toolSet(tools []string, extra ...string) map[string]bool {
	out := make(map[string]bool, len(tools)+len(extra))
	for _, t := range append(append([]string(nil), tools...), extra...) {
		out[t] = true
	}
	return out
}

// Preinstalled reports whether tool is preinstalled on the hosted
// runner image ("ubuntu-22.04", "ubuntu-24.04", "macos", "windows", case
// insensitive: LabelImages), and whether the image itself is one this
// table covers at all. known is false for any other image: a
// download-guard check against an unknown image answers nothing, it does
// not answer "not preinstalled".
func Preinstalled(image, tool string) (preinstalled, known bool) {
	tools, ok := preinstalledTools[strings.ToLower(image)]
	if !ok {
		return false, false
	}
	return tools[strings.ToLower(tool)], true
}

// plainHostedLabels match only the plain hosted runner labels GitHub
// documents for each family ("ubuntu-24.04", "ubuntu-latest",
// "macos-14", "macos-latest", "windows-2025", "windows-latest"): any
// other shape ("-large", "-xlarge", "-arm", "-intel", a self-hosted
// label, anything with an extra suffix) is not one this program reads a
// hosted image or an architecture off at all.
var plainHostedLabels = []struct {
	family string
	re     *regexp.Regexp
}{
	{"ubuntu", regexp.MustCompile(`^ubuntu-(latest|\d+\.\d+)$`)},
	{"macos", regexp.MustCompile(`^macos-(latest|\d+)$`)},
	{"windows", regexp.MustCompile(`^windows-(latest|\d+)$`)},
}

// PlainHostedLabel is the hosted family ("ubuntu", "macos", "windows")
// a plain hosted runner label names (plainHostedLabels), case
// insensitive; ok is false for every other label.
func PlainHostedLabel(label string) (family string, ok bool) {
	l := normalizeLabel(label)
	for _, p := range plainHostedLabels {
		if p.re.MatchString(l) {
			return p.family, true
		}
	}
	return "", false
}

// imageOf is the hosted image a plain hosted label runs: "<family>-latest"
// the family's latestImage, an Ubuntu version its own image, any macOS
// or Windows version the family's one table.
func imageOf(label string) (string, bool) {
	family, ok := PlainHostedLabel(label)
	if !ok {
		return "", false
	}
	l := normalizeLabel(label)
	if family == "ubuntu" && !strings.HasSuffix(l, "-latest") {
		return l, true
	}
	return latestImage[family], true
}

// LabelImages resolves a job's runs-on labels to the hosted images they
// run, one per label, in order. isExpression (ir.Job.RunsOnExpression),
// no label at all, or any label PlainHostedLabel does not read answers
// unknown: a `${{ matrix.os }}`, a larger runner or a self-hosted label
// names no hosted image with certainty.
func LabelImages(labels []string, isExpression bool) (images []string, known bool) {
	if isExpression || len(labels) == 0 {
		return nil, false
	}
	for _, label := range labels {
		image, ok := imageOf(label)
		if !ok {
			return nil, false
		}
		images = append(images, image)
	}
	return images, true
}
