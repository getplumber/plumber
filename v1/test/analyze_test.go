//go:build cli

package test

import (
	"testing"
)

// TestAnalyze covers the analyze inputs rejected before any request. An
// analysis that reaches a provider is the e2e suite's job (monorepo#651).
func TestAnalyze(t *testing.T) {
	t.Parallel()
	tests := []cliCase{
		{name: "analyze-no-provider", args: []string{"analyze"}},
		{name: "analyze-bad-provider", args: []string{"analyze", "--provider", "bogus", "--project", "a/b"}},
		{name: "analyze-bad-target", args: []string{"analyze", "notaurl::x"}},
		{name: "analyze-github-no-token", args: []string{"analyze", "--provider", "github", "--project", "a/b"}},
		{
			name: "analyze-gitlab-no-token",
			args: []string{"analyze", "--provider", "gitlab", "--project", "a/b", "--gitlab-url", "https://gitlab.com"},
		},
		{
			name: "analyze-bad-min-score",
			args: []string{"analyze", "--provider", "github", "--project", "a/b", "--min-score", "Z"},
		},
		{
			name: "analyze-bad-min-points",
			args: []string{"analyze", "--provider", "github", "--project", "a/b", "--min-points", "150"},
		},
		{
			name: "analyze-bad-threshold",
			args: []string{"analyze", "--provider", "github", "--project", "a/b", "--threshold", "150"},
		},
		{
			name: "analyze-bad-score-profile",
			args: []string{"analyze", "--provider", "github", "--project", "a/b", "--score-profile", "v9"},
		},
		{
			name: "analyze-unknown-control",
			args: []string{"analyze", "--provider", "github", "--project", "a/b", "--controls", "bogusControl"},
		},
		{
			name: "analyze-unknown-skip-control",
			args: []string{"analyze", "--provider", "github", "--project", "a/b", "--skip-controls", "bogusControl"},
		},
		{
			name: "analyze-no-controls-with-controls",
			args: []string{"analyze", "--provider", "github", "--project", "a/b", "--no-controls", "--controls", "x"},
		},
		{
			name: "analyze-missing-config",
			args: []string{"analyze", "--provider", "github", "--project", "a/b", "--config", "missing.yaml"},
		},
		{
			name: "analyze-platform-plain-http",
			args: []string{"analyze", "--provider", "github", "--project", "a/b", "--platform", "http://example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			runCase(t, tt)
		})
	}
}
