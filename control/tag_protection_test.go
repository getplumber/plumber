package control

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// tagMustBeProtected (ISSUE-510) reads the provider's API, never the CI
// file: it passes only on rules and tags read authoritatively, errors on
// its own fetch failure or an unreadable answer, and its degraded reason
// never taints the CI-file controls.
func TestStatusFor_TagMustBeProtected(t *testing.T) {
	tag := ControlEntry{ControlName: controlTagMustBeProtected}
	content := ControlEntry{ControlName: "actionsMustBePinnedByCommitSha"}
	known := &ir.NormalizedPipeline{TagProtection: &ir.TagProtection{Known: true}}
	unknown := &ir.NormalizedPipeline{TagProtection: &ir.TagProtection{Known: false}}
	tagDegraded := []string{degradedReasonTagProtectionPrefix + " (network or timeout)"}

	cases := []struct {
		name     string
		entry    ControlEntry
		result   *AnalysisResult
		findings int
		want     string
	}{
		{"known data, no findings: passed", tag, &AnalysisResult{CiValid: true, GitHubPipeline: known}, 0, StatusPassed},
		{"known data passes with no CI config at all", tag, &AnalysisResult{CiMissing: true, Pipeline: known}, 0, StatusPassed},
		{"findings mean failed", tag, &AnalysisResult{CiValid: true, GitHubPipeline: known}, 1, StatusFailed},
		{"unreadable rules or tags: error", tag, &AnalysisResult{CiValid: true, GitHubPipeline: unknown}, 0, StatusError},
		{"collection never ran (platform mode on GitLab): error", tag, &AnalysisResult{CiValid: true, Pipeline: &ir.NormalizedPipeline{}}, 0, StatusError},
		{"own fetch failure: error", tag, &AnalysisResult{CiValid: true, GitHubPipeline: unknown, DegradedReasons: tagDegraded}, 0, StatusError},
		{"tag degradation does not taint content controls", content, &AnalysisResult{CiValid: true, DegradedReasons: tagDegraded}, 0, StatusPassed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := StatusFor(tc.entry, tc.result, tc.findings); got != tc.want {
				t.Errorf("StatusFor = %q, want %q", got, tc.want)
			}
		})
	}
}

// A collection that ran but could not read the rules or the tags marks the
// control not evaluated (what a standalone summary reads) and drops its
// findings; known data, no collection, or a skipped control are left alone.
func TestMarkTagProtectionGap(t *testing.T) {
	finding := opaengine.Finding{Code: "ISSUE-510"}
	cases := []struct {
		name     string
		pipeline *ir.NormalizedPipeline
		skipped  bool
		want     bool
	}{
		{"unknown data is marked", &ir.NormalizedPipeline{TagProtection: &ir.TagProtection{Known: false}}, false, true},
		{"known data is not marked", &ir.NormalizedPipeline{TagProtection: &ir.TagProtection{Known: true}}, false, false},
		{"no collection is left to the lane markers", &ir.NormalizedPipeline{}, false, false},
		{"a skipped control is not marked", &ir.NormalizedPipeline{TagProtection: &ir.TagProtection{Known: false}}, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &AnalysisResult{GitHubPipeline: tc.pipeline, Findings: []opaengine.Finding{finding}}
			markTagProtectionGap(r, []ControlEntry{{ControlName: controlTagMustBeProtected, Skipped: tc.skipped}})
			reason, marked := r.NotEvaluable[controlTagMustBeProtected]
			if marked != tc.want {
				t.Fatalf("marked = %v (%q), want %v", marked, reason, tc.want)
			}
			if marked && (reason != ReasonCollectionFailed || len(r.Findings) != 0) {
				t.Errorf("want reason %q and the findings dropped, got %q and %d findings", ReasonCollectionFailed, reason, len(r.Findings))
			}
		})
	}
}

// The GitHub tag lane runs when some collecting configuration enables the
// control and the project path names a repository, and never otherwise.
func TestTagLaneCollected(t *testing.T) {
	on, off := true, false
	conf := func(enabled *bool) *configuration.Configuration {
		pc := &configuration.PlumberConfig{Version: "2.0", GitHub: &configuration.ProviderConfig{}}
		if enabled != nil {
			pc.GitHub.Controls.TagMustBeProtected = &configuration.TagProtectionControlConfig{Enabled: enabled}
		}
		return &configuration.Configuration{PlumberConfig: pc}
	}
	if !tagLaneCollected(conf(&on), "acme/app") {
		t.Error("enabled control on an addressable repo must collect")
	}
	if tagLaneCollected(conf(&off), "acme/app") {
		t.Error("disabled control must not collect")
	}
	if tagLaneCollected(conf(nil), "acme/app") {
		t.Error("absent control must not collect")
	}
	if tagLaneCollected(conf(&on), "not-a-repo") {
		t.Error("an unaddressable project path must not collect")
	}
	if tagLaneCollected(nil, "acme/app") {
		t.Error("nil configuration must not collect")
	}
}

// The control's engine config carries the effective patterns (the v*
// default when unset) and the creation requirement.
func TestBuildEngineConfig_TagMustBeProtected(t *testing.T) {
	off := false
	cfg := buildEngineConfig(&configuration.ControlsConfig{
		TagMustBeProtected: &configuration.TagProtectionControlConfig{RequireCreationRestricted: &off},
	}, "")
	entry, ok := cfg["tagMustBeProtected"].(map[string]any)
	if !ok {
		t.Fatalf("tagMustBeProtected missing from engine config: %v", cfg)
	}
	if p, _ := entry["namePatterns"].([]string); len(p) != 1 || p[0] != "v*" {
		t.Errorf("namePatterns = %v, want [v*]", entry["namePatterns"])
	}
	if entry["requireCreationRestricted"] != false {
		t.Errorf("requireCreationRestricted = %v, want false", entry["requireCreationRestricted"])
	}
}
