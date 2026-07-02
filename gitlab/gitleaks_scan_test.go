package gitlab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
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

// TestResolveGitleaksBinaryRejectsWorkspacePath is the RCE regression guard.
// gitleaksPath is read from the analyzed repo's .plumber.yaml; when plumber
// scans an untrusted branch (fork MR/PR pipeline) that file — and any binary
// committed to the checkout — is attacker-controlled. resolveGitleaksBinary
// must refuse to execute a binary that resolves inside the workspace, while
// still accepting a binary located outside it.
func TestResolveGitleaksBinaryRejectsWorkspacePath(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()
	t.Chdir(workspace)

	writeExecutable(t, filepath.Join(workspace, "pwn"))       // attacker-planted, in-repo
	writeExecutable(t, filepath.Join(outside, "gitleaks-ok")) // legitimate, outside repo

	t.Run("relative in-workspace path is refused", func(t *testing.T) {
		cfg := &configuration.SecretDetectionControlConfig{GitleaksPath: "./pwn"}
		if _, err := resolveGitleaksBinary(cfg); err == nil {
			t.Fatal("expected refusal for ./pwn inside workspace, got nil")
		} else if !strings.Contains(err.Error(), "workspace") {
			t.Fatalf("error should explain the workspace-containment refusal, got: %v", err)
		}
	})

	t.Run("absolute in-workspace path is refused", func(t *testing.T) {
		cfg := &configuration.SecretDetectionControlConfig{GitleaksPath: filepath.Join(workspace, "pwn")}
		if _, err := resolveGitleaksBinary(cfg); err == nil {
			t.Fatal("expected refusal for absolute in-workspace path, got nil")
		}
	})

	t.Run("absolute path outside the workspace is allowed", func(t *testing.T) {
		want := filepath.Join(outside, "gitleaks-ok")
		cfg := &configuration.SecretDetectionControlConfig{GitleaksPath: want}
		got, err := resolveGitleaksBinary(cfg)
		if err != nil {
			t.Fatalf("outside-workspace binary should be allowed, got error: %v", err)
		}
		if resolved, _ := filepath.EvalSymlinks(want); got != want && got != resolved {
			t.Fatalf("resolved path = %q, want %q", got, want)
		}
	})
}

func TestPathWithin(t *testing.T) {
	root := filepath.FromSlash("/home/ci/repo")
	cases := []struct {
		target string
		want   bool
	}{
		{filepath.FromSlash("/home/ci/repo"), true},
		{filepath.FromSlash("/home/ci/repo/pwn"), true},
		{filepath.FromSlash("/home/ci/repo/sub/dir/pwn"), true},
		{filepath.FromSlash("/home/ci/other/gitleaks"), false},
		{filepath.FromSlash("/usr/bin/gitleaks"), false},
		{filepath.FromSlash("/home/ci/repo-sibling/gitleaks"), false}, // prefix-string trap
	}
	for _, tc := range cases {
		if got := pathWithin(root, tc.target); got != tc.want {
			t.Errorf("pathWithin(%q, %q) = %v, want %v", root, tc.target, got, tc.want)
		}
	}
}

func writeExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\ntrue\n"), 0o755); err != nil {
		t.Fatalf("write executable %q: %v", path, err)
	}
}
