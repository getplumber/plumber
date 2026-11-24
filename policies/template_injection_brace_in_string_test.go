package policies_test

import (
	"context"
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
  safe-quoted-shell:
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ github.ref }}' && echo 'harmless'
`
	findings, err := evaluateStrict(loadPolicies(t), context.Background(), scanWorkflow(t, workflow), nil)
	if err != nil {
		t.Fatalf("evaluate policies: %v", err)
	}

	hasFinding := func(jobSuffix, code string) bool {
		for _, f := range findings {
			if f.Code == code && (f.Job == jobSuffix || len(f.Job) > len(jobSuffix) && f.Job[len(f.Job)-len(jobSuffix)-1:] == "/"+jobSuffix) {
				return true
			}
		}
		return false
	}

	if !hasFinding("direct", "ISSUE-207") {
		t.Errorf("direct job with format('{0}', github.event.comment.body) evaded ISSUE-207")
	}
	if !hasFinding("escaped-quote", "ISSUE-207") {
		t.Errorf("escaped-quote job with format('it''s {0}', github.event.issue.title) evaded ISSUE-207")
	}
	if !hasFinding("env-redirect", "ISSUE-209") {
		t.Errorf("env-redirect job with format('{0}', github.event.comment.body) evaded ISSUE-209")
	}
	if hasFinding("safe-quoted-shell", "ISSUE-207") {
		t.Errorf("safe-quoted-shell job should not trigger ISSUE-207")
	}
}
