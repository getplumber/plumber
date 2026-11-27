package policies_test

import (
	"context"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

func TestCaseInsensitiveActionMatching(t *testing.T) {
	const workflow = `name: case-detect
on: [pull_request_target, workflow_run]
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
  artifact:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Actions/Upload-Artifact@v4
        with:
          path: .
          include-hidden-files: true
  upstream:
    runs-on: ubuntu-latest
    steps:
      - uses: Actions/Checkout@v4
        with:
          ref: ${{ github.event.workflow_run.head_sha }}
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: js-devtools/npm-publish@v3
        with:
          token: ${{ secrets.NPM_TOKEN }}
      - uses: Actions/attest-build-provenance@v1
      - uses: Nick-Fields/Retry@v3
  unsigned-publish:
    runs-on: ubuntu-latest
    steps:
      - uses: js-devtools/npm-publish@v3
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/Init@v3
  app-token:
    runs-on: ubuntu-latest
    steps:
      - uses: Actions/Create-GitHub-App-Token@v1
        with:
          skip-token-revoke: true
`
	engine := loadPolicies(t)
	findings, err := evaluateStrict(engine, context.Background(), scanWorkflow(t, workflow), nil)
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

	for _, tc := range []struct {
		job  string
		code string
		want bool
	}{
		{"artifact", "ISSUE-310", true},
		{"artifact", "ISSUE-419", true},
		{"upstream", "ISSUE-802", true},
		{"publish", "ISSUE-305", true},
		{"publish", "ISSUE-421", true},
		{"publish", "ISSUE-711", true},
		{"publish", "ISSUE-712", false},
		{"unsigned-publish", "ISSUE-712", true},
	} {
		if got := hasFinding(tc.job, tc.code); got != tc.want {
			t.Errorf("job %s: %s present = %t, want %t", tc.job, tc.code, got, tc.want)
		}
	}

	if got := countCode(findings, "ISSUE-904"); got != 1 {
		t.Errorf("CodeQL subpath Init: got %d ISSUE-904 findings, want 1", got)
	}

	recognizedSAST := strings.Replace(workflow, "github/codeql-action/Init@v3", "GitHub/CodeQL-Action/init@v3", 1)
	findings, err = evaluateStrict(engine, context.Background(), scanWorkflow(t, recognizedSAST), nil)
	if err != nil {
		t.Fatalf("evaluate policies with recognized SAST: %v", err)
	}
	if got := countCode(findings, "ISSUE-904"); got != 0 {
		t.Errorf("CodeQL subpath init: got %d ISSUE-904 findings, want 0", got)
	}
}

// TestRequiredActionIgnoresOwnerCase pins that a required action is found
// whatever the case of its owner and repository in the workflow or in the
// config (ISSUE-417), while the path after them keeps its case.
func TestRequiredActionIgnoresOwnerCase(t *testing.T) {
	engine := loadPolicies(t)
	cfg := map[string]any{"workflowMustIncludeRequiredActions": map[string]any{
		"requiredGroups": []any{[]any{"MyOrg/Security-Scan"}},
	}}
	for _, tc := range []struct {
		uses string
		want int
	}{
		{"myorg/security-scan@v1", 0},
		{"MYORG/security-scan/sub@v1", 0},
		{"myorg/security-scan-fork@v1", 1},
	} {
		p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{{Name: "ci/scan", Uses: []ir.Action{{Uses: tc.uses}}}}}
		findings, err := evaluateStrict(engine, context.Background(), p, cfg)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if got := countCode(findings, "ISSUE-417"); got != tc.want {
			t.Errorf("%s: %d ISSUE-417 findings, want %d", tc.uses, got, tc.want)
		}
	}
}
