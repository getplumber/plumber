package cmd

import (
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
)

// Spec s1: a present local config and any local threshold are ignored in
// platform mode, each with one line; nothing is printed when none is set.
func TestPlatformModeNotices(t *testing.T) {
	newGateFlagsCmd(t)
	origURL := platformURL
	platformURL = "https://platform.example.com"
	defer func() { platformURL = origURL }()

	conf := configuration.NewDefaultConfiguration()
	conf.ConfigFilePath = ""
	if lines := platformModeNotices(conf); len(lines) != 0 {
		t.Fatalf("nothing set: want no notice, got %v", lines)
	}

	conf.ConfigFilePath = ".plumber.yaml"
	minPointsSet, minScore, thresholdSet = true, "B", false
	lines := platformModeNotices(conf)
	want := []string{
		"  linked to https://platform.example.com: local .plumber.yaml ignored, policies come from the platform",
		"  --min-points ignored: enforcement comes from the platform's policies",
		"  --min-score ignored: enforcement comes from the platform's policies",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}

	platformURL = platformSentinelURL
	if lines := platformModeNotices(conf); len(lines) != 0 {
		t.Fatalf("sentinel URL is not platform mode: got %v", lines)
	}
}

// Row 64: --controls and --skip-controls are ignored on a linked run, and
// platformModeNotices names each one the same way it names an inert
// threshold.
func TestPlatformModeNotices_Row64_NamesTheIgnoredControlFilters(t *testing.T) {
	newGateFlagsCmd(t)
	origURL := platformURL
	origInclude, origSkip := controlsFilter, skipControls
	defer func() {
		platformURL = origURL
		controlsFilter, skipControls = origInclude, origSkip
	}()

	conf := configuration.NewDefaultConfiguration()
	conf.ConfigFilePath = ""

	platformURL = "https://platform.example.com"
	controlsFilter, skipControls = "a", ""
	lines := platformModeNotices(conf)
	if !contains(lines, "  --controls ignored: the platform's policies decide which controls run") {
		t.Fatalf("expected a --controls notice, got %v", lines)
	}

	controlsFilter, skipControls = "", "b"
	lines = platformModeNotices(conf)
	if !contains(lines, "  --skip-controls ignored: the platform's policies decide which controls run") {
		t.Fatalf("expected a --skip-controls notice, got %v", lines)
	}

	controlsFilter, skipControls = "", ""
	lines = platformModeNotices(conf)
	if contains(lines, "  --controls ignored: the platform's policies decide which controls run") ||
		contains(lines, "  --skip-controls ignored: the platform's policies decide which controls run") {
		t.Fatalf("neither flag set: expected no control-filter notice, got %v", lines)
	}

	controlsFilter, skipControls = "a", "b"
	platformURL = platformSentinelURL
	lines = platformModeNotices(conf)
	if len(lines) != 0 {
		t.Fatalf("sentinel URL is not platform mode: got %v", lines)
	}
}
