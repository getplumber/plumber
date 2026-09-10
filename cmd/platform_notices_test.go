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
