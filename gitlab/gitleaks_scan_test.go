package gitlab

import (
	"strings"
	"testing"
)

// TestRedactPreview is the load-bearing safety test for ISSUE-301:
// the raw secret value must never leave the collector. Every other
// guard depends on this function producing a redacted form.
func TestRedactPreview(t *testing.T) {
	cases := []struct {
		name   string
		secret string
		want   string
	}{
		{"slack-bot-token-like", "xoxb-EXAMPLE-EXAMPLE-redactedfortestingonly", "xoxb***only"},
		{"github-pat-like", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "ghp_***6789"},
		{"aws-access-key-like", "AKIAIOSFODNN7EXAMPLE", "AKIA***MPLE"},
		{"exactly-eight-chars", "12345678", "1234***5678"},
		{"under-eight-chars", "abc1234", "***"},
		{"empty", "", "***"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactPreview(tc.secret)
			if got != tc.want {
				t.Fatalf("redactPreview(%q) = %q, want %q", tc.secret, got, tc.want)
			}
			// Belts and braces: for non-trivial inputs, the middle of the
			// secret must not appear verbatim in the redacted form.
			if len(tc.secret) >= 12 {
				mid := tc.secret[4 : len(tc.secret)-4]
				if mid != "" && strings.Contains(got, mid) {
					t.Fatalf("redacted preview %q leaks the middle of the secret %q", got, tc.secret)
				}
			}
		})
	}
}

// TestParseGitleaksReport covers the JSON-decoding side of the
// collector independent of the gitleaks subprocess. The empty / null
// / array cases exercise gitleaks's actual on-the-wire shapes.
func TestParseGitleaksReport(t *testing.T) {
	t.Run("empty report -> no entries", func(t *testing.T) {
		entries, err := parseGitleaksReport(strings.NewReader(""))
		if err != nil || len(entries) != 0 {
			t.Fatalf("empty: entries=%d err=%v", len(entries), err)
		}
	})
	t.Run("null report -> no entries", func(t *testing.T) {
		entries, err := parseGitleaksReport(strings.NewReader("null"))
		if err != nil || len(entries) != 0 {
			t.Fatalf("null: entries=%d err=%v", len(entries), err)
		}
	})
	t.Run("single-entry report decodes", func(t *testing.T) {
		body := `[{"RuleID":"slack-bot-token","Description":"Slack","Secret":"xoxb-aaa-bbb","StartLine":13,"File":"x.yml"}]`
		entries, err := parseGitleaksReport(strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Fatalf("entries=%d, want 1", len(entries))
		}
		if entries[0].RuleID != "slack-bot-token" || entries[0].StartLine != 13 || entries[0].File != "x.yml" {
			t.Fatalf("decoded entry wrong: %+v", entries[0])
		}
	})
	t.Run("malformed JSON surfaces an error", func(t *testing.T) {
		if _, err := parseGitleaksReport(strings.NewReader("not json")); err == nil {
			t.Fatal("expected decode error, got nil")
		}
	})
}
