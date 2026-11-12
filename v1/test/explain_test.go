//go:build cli

package test

import "testing"

// TestExplain covers explain on a saved analyze report, and the attack lookup
// that fails without a cache.
func TestExplain(t *testing.T) {
	t.Parallel()
	const report = "score-compare/plumber-example-critical.v4.json"
	tests := []cliCase{
		{name: "explain-code", args: []string{"explain", "ISSUE-101"}},
		{name: "explain-code-json", args: []string{"explain", "ISSUE-101", "--json"}},
		{name: "explain-unknown-code", args: []string{"explain", "BOGUS"}},
		{name: "explain-list", args: []string{"explain", "--list"}},
		{name: "explain-list-json", args: []string{"explain", "--list", "--json"}},
		{name: "explain-all", args: []string{"explain", "--all"}},
		{name: "explain-all-json", args: []string{"explain", "--all", "--json"}},
		{
			name:   "explain-attack-from-run",
			args:   []string{"explain", "-a", "1", "--run", report},
			inputs: []string{"score-compare"},
		},
		{
			name:   "explain-attack-all-from-run",
			args:   []string{"explain", "--attack", "all", "--run", report},
			inputs: []string{"score-compare"},
		},
		{name: "explain-attack-no-cache", args: []string{"explain", "-a", "1"}},
		{
			name: "explain-attack-project-no-cache",
			args: []string{"explain", "-a", "1", "--project", "a/b", "--provider", "github"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			runCase(t, tt)
		})
	}
}
