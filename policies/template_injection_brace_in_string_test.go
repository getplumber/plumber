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
  env-tojson-later-argument:
    runs-on: ubuntu-latest
    steps:
      - run: echo "X=${{ format('{0} {1}', github.event.comment.body, toJSON(github.sha)) }}" >> "$GITHUB_ENV"
  env-tojson-other-expression:
    runs-on: ubuntu-latest
    steps:
      - run: echo "A=${{ toJSON(github.sha) }} B=${{ github.event.issue.title }}" >> "$GITHUB_ENV"
  env-tojson-wrapped:
    runs-on: ubuntu-latest
    steps:
      - run: echo "B=${{ toJSON(github.event.comment.body) }}" >> "$GITHUB_ENV"
  heredoc-tojson-later-argument:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cat <<'EOF'
          ${{ format('{0} {1}', github.event.comment.body, toJSON(github.sha)) }}
          EOF
  heredoc-tojson-other-expression:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cat <<'EOF'
          ${{ toJSON(github.sha) }} ${{ github.event.issue.title }}
          EOF
  heredoc-tojson-wrapped:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cat <<'EOF'
          ${{ toJSON(github.event.issue.title) }}
          EOF
`
	findings, err := evaluateStrict(loadPolicies(t), context.Background(), scanWorkflow(t, workflow), nil)
	if err != nil {
		t.Fatalf("evaluate policies: %v", err)
	}

	for _, tc := range []struct {
		job     string
		code    string
		want    int
		subject string
	}{
		{"direct", "ISSUE-207", 1, "format('{0}', github.event.comment.body)"},
		{"escaped-quote", "ISSUE-207", 1, "format('it''s {0}', github.event.issue.title)"},
		{"env-redirect", "ISSUE-209", 1, "format('{0}', github.event.comment.body)"},
		{"safe-quoted-expression", "ISSUE-207", 0, ""},
		// toJSON must wrap the untrusted field itself: a toJSON elsewhere in
		// the expression, or in another expression on the line, leaves the
		// field raw.
		{"env-tojson-later-argument", "ISSUE-209", 1, "format('{0} {1}', github.event.comment.body, toJSON(github.sha))"},
		{"env-tojson-other-expression", "ISSUE-209", 1, "github.event.issue.title"},
		{"env-tojson-wrapped", "ISSUE-209", 0, ""},
		{"heredoc-tojson-later-argument", "ISSUE-207", 1, "format('{0} {1}', github.event.comment.body, toJSON(github.sha))"},
		{"heredoc-tojson-other-expression", "ISSUE-207", 1, "github.event.issue.title"},
		{"heredoc-tojson-wrapped", "ISSUE-207", 0, ""},
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
		if matches != tc.want {
			t.Errorf("%s: got %d %s findings, want %d", tc.job, matches, tc.code, tc.want)
		}
	}
}
