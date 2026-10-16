// Package runners names the GitHub-hosted runner labels that stopped
// scheduling jobs: a job pinned to one of them (alone, or whose every
// `runs-on:` label is one of them) can never run, whatever its other
// gates say.
package runners

import "strings"

// RetiredAsOf is the date this list was last checked against GitHub's own
// retirement notices. A label GitHub retires after this date is not
// caught here until the list is updated.
const RetiredAsOf = "2026-10-15"

// retiredLabels is the dated set of hosted runner labels GitHub stopped
// scheduling jobs on, normalized (lower case). Updating this list is the
// only maintenance Retired ever needs.
var retiredLabels = map[string]bool{
	"ubuntu-18.04": true,
	"ubuntu-20.04": true,
	"macos-11":     true,
	"macos-12":     true,
	"macos-13":     true,
	"windows-2019": true,
}

// hostedFamilies are the `runs-on:` label prefixes GitHub's own hosted
// runners use, read by Known alongside the "-latest" alias.
var hostedFamilies = []string{"ubuntu-", "macos-", "windows-"}

// normalizeLabel trims surrounding whitespace and lower-cases label, so a
// workflow author's casing or stray indentation never hides a match.
func normalizeLabel(label string) string {
	return strings.ToLower(strings.TrimSpace(label))
}

// Retired reports whether label names one of the dated retired runner
// labels (RetiredAsOf), matching case-insensitively and ignoring
// surrounding whitespace.
func Retired(label string) bool {
	return retiredLabels[normalizeLabel(label)]
}

// Known reports whether label names a GitHub-hosted runner: one of the
// three OS families (ubuntu-*, macos-*, windows-*) at any version, or any
// "*-latest" alias. A retired label is always Known too, since every
// retired label in RetiredAsOf's list is one of these families. A
// self-hosted or otherwise custom label is not Known.
func Known(label string) bool {
	l := normalizeLabel(label)
	if l == "" {
		return false
	}
	if strings.HasSuffix(l, "-latest") {
		return true
	}
	for _, prefix := range hostedFamilies {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}
