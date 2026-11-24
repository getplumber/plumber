package policies_test

import (
	"context"
	"strings"
	"testing"
)

func TestCaseInsensitiveActionMatching(t *testing.T) {
	const workflow = `name: case-detect
on: pull_request_target
permissions:
  contents: read
jobs:
  lower:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make test
  upper:
    runs-on: ubuntu-latest
    steps:
      - uses: Actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make test
  app-token:
    runs-on: ubuntu-latest
    steps:
      - uses: Actions/Create-GitHub-App-Token@v1
        with:
          skip-token-revoke: true
`
	findings, err := evaluateStrict(loadPolicies(t), context.Background(), scanWorkflow(t, workflow), nil)
	if err != nil {
		t.Fatalf("evaluate policies: %v", err)
	}

	hasFinding := func(jobSuffix, code string) bool {
		for _, f := range findings {
			if f.Code == code && (f.Job == jobSuffix || strings.HasSuffix(f.Job, "/"+jobSuffix)) {
				return true
			}
		}
		return false
	}

	for _, code := range []string{"ISSUE-307", "ISSUE-804"} {
		if !hasFinding("lower", code) {
			t.Errorf("lower job missing expected finding %s", code)
		}
		if !hasFinding("upper", code) {
			t.Errorf("upper job (Actions/checkout@v4) evaded %s", code)
		}
	}

	if !hasFinding("app-token", "ISSUE-306") {
		t.Errorf("app-token job (Actions/Create-GitHub-App-Token@v1) evaded ISSUE-306")
	}
}
