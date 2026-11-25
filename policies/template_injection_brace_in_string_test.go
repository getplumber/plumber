package policies_test

import (
	"context"
	"strings"
	"testing"
)

func TestTemplateInjectionBraceInsideStringLiteral(t *testing.T) {
	const workflow = `name: format-injection
on: issue_comment
jobs:
  direct:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ format('{0}', github.event.comment.body) }}"
  escaped-quote:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ format('it''s {0}', github.event.issue.title) }}"
  env-redirect:
    runs-on: ubuntu-latest
    steps:
      - run: echo "BODY=${{ format('{0}', github.event.comment.body) }}" >> "$GITHUB_ENV"
  safe-quoted-expression:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ format('github.event.issue.title') }}"
`
	findings, err := evaluateStrict(loadPolicies(t), context.Background(), scanWorkflow(t, workflow), nil)
	if err != nil {
		t.Fatalf("evaluate policies: %v", err)
	}

	for _, tc := range []struct {
		job     string
		code    string
		subject string
	}{
		{"direct", "ISSUE-207", "format('{0}', github.event.comment.body)"},
		{"escaped-quote", "ISSUE-207", "format('it''s {0}', github.event.issue.title)"},
		{"env-redirect", "ISSUE-209", "format('{0}', github.event.comment.body)"},
		{"safe-quoted-expression", "ISSUE-207", ""},
	} {
		matches := 0
		for _, f := range findings {
			if f.Code != tc.code || (f.Job != tc.job && !strings.HasSuffix(f.Job, "/"+tc.job)) {
				continue
			}
			matches++
			if tc.subject != "" && f.Subject != tc.subject {
				t.Errorf("%s %s: Subject = %q, want %q", tc.job, tc.code, f.Subject, tc.subject)
			}
		}
		want := 1
		if tc.subject == "" {
			want = 0
		}
		if matches != want {
			t.Errorf("%s: got %d %s findings, want %d", tc.job, matches, tc.code, want)
		}
	}
}
