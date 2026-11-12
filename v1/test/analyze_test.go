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
		{name: "analyze-no-provider", args: []string{"analyze"}, exit: 2},
		{name: "analyze-bad-provider", args: []string{"analyze", "--provider", "bogus", "--project", "a/b"}, exit: 2},
		{name: "analyze-bad-target", args: []string{"analyze", "notaurl::x"}, exit: 2},
		{name: "analyze-github-no-token", args: []string{"analyze", "--provider", "github", "--project", "a/b"}, exit: 2},
		{
			name: "analyze-gitlab-no-token",
			args: []string{"analyze", "--provider", "gitlab", "--project", "a/b", "--gitlab-url", "https://gitlab.com"},
			exit: 2,
		},
		{
			name: "analyze-bad-min-score",
			args: []string{"analyze", "--provider", "github", "--project", "a/b", "--min-score", "Z"},
			exit: 2,
		},
		{
			name: "analyze-bad-min-points",
			args: []string{"analyze", "--provider", "github", "--project", "a/b", "--min-points", "150"},
			exit: 2,
		},
		{
			name: "analyze-bad-threshold",
			args: []string{"analyze", "--provider", "github", "--project", "a/b", "--threshold", "150"},
			exit: 2,
		},
		{
			name: "analyze-bad-score-profile",
			args: []string{"analyze", "--provider", "github", "--project", "a/b", "--score-profile", "v9"},
			exit: 2,
		},
		{
			name: "analyze-unknown-control",
			args: []string{"analyze", "--provider", "github", "--project", "a/b", "--controls", "bogusControl"},
			exit: 2,
		},
		{
			name: "analyze-unknown-skip-control",
			args: []string{"analyze", "--provider", "github", "--project", "a/b", "--skip-controls", "bogusControl"},
			exit: 2,
		},
		{
			name: "analyze-no-controls-with-controls",
			args: []string{"analyze", "--provider", "github", "--project", "a/b", "--no-controls", "--controls", "x"},
			exit: 2,
		},
		{
			name: "analyze-missing-config",
			args: []string{"analyze", "--provider", "github", "--project", "a/b", "--config", "missing.yaml"},
			exit: 2,
		},
		{
			name: "analyze-platform-plain-http",
			args: []string{"analyze", "--provider", "github", "--project", "a/b", "--platform", "http://example.com"},
			exit: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			runCase(t, tt)
		})
	}
}
