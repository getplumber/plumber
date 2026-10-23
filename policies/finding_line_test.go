package policies_test

import (
	"context"
	"testing"
)

// lineWorkflow's line numbers are what TestFindingLine_GitHub expects:
// keep every edit to it in step with the table.
const lineWorkflow = `name: loc
on: [pull_request_target, issue_comment]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: node:latest
    env:
      ACTIONS_STEP_DEBUG: true
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: safe
        run: echo safe
      - name: inject
        run: |
          echo start
          echo "${{ github.event.pull_request.title }}"
          echo "T=${{ github.event.pull_request.body }}" >> "$GITHUB_ENV"
          curl -sSL https://example.com/install.sh | bash
          echo '${{ toJSON(secrets) }}'
  codeql-scan:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - run: echo scan
  call:
    uses: evilcorp/shared/.github/workflows/x.yml@main
    secrets: inherit
`

// TestFindingLine_GitHub is #572: a finding about a step, an image, a
// variable or a job key points at that construct's line, not at the job
// header. Codes left on the header (801, a missing key) are not listed.
func TestFindingLine_GitHub(t *testing.T) {
	cfg := map[string]any{
		"imageMutableTag":                           map[string]any{"forbiddenTags": []any{"latest"}},
		"containerImageMustNotUseForbiddenTags":     map[string]any{"mustBePinnedByDigest": true},
		"debugTrace":                                map[string]any{"forbiddenVariables": []any{"ACTIONS_STEP_DEBUG"}},
		"securityJobsWeakened":                      map[string]any{"securityJobPatterns": []any{"*codeql*"}, "allowFailureMustBeFalse": true},
		"actionsMustBePinnedByCommitSha":            map[string]any{"trustedOwners": []any{"actions", "github"}},
		"githubActionMustComeFromAuthorizedSources": map[string]any{"trustGithubOfficialActions": true},
	}
	findings, err := evaluateStrict(loadPolicies(t), context.Background(), scanWorkflow(t, lineWorkflow), cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	type key struct{ code, job string }
	got := map[key][]int{}
	for _, f := range findings {
		got[key{f.Code, f.Job}] = append(got[key{f.Code, f.Job}], f.Line)
	}
	want := []struct {
		code, job string
		line      int
	}{
		{"ISSUE-102", "repro/build", 8},
		{"ISSUE-103", "repro/build", 8},
		{"ISSUE-203", "repro/build", 10},
		{"ISSUE-207", "repro/build", 20},
		{"ISSUE-209", "repro/build", 21},
		{"ISSUE-411", "repro/build", 22},
		{"ISSUE-309", "repro/build", 23},
		{"ISSUE-802", "repro/build", 12},
		{"ISSUE-803", "repro/build", 3},
		{"ISSUE-410", "repro/codeql-scan", 26},
		{"ISSUE-302", "repro/call", 31},
		{"ISSUE-701", "repro/call", 30},
		{"ISSUE-713", "repro/call", 30},
	}
	for _, w := range want {
		lines := got[key{w.code, w.job}]
		if len(lines) != 1 || lines[0] != w.line {
			t.Errorf("%s on %s: lines %v, want [%d]", w.code, w.job, lines, w.line)
		}
	}
}
