package policies_test

import (
	"context"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
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
		"imageAuthorizedSources":                    map[string]any{"trustedUrls": []any{}},
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
		{"ISSUE-101", "repro/build", 8},
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

// sharedIdentityWorkflow's line numbers are what
// TestFindingLine_OneLinePerIdentity expects.
const sharedIdentityWorkflow = `on: pull_request
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      ACTIONS_STEP_DEBUG: true
    steps:
      - run: echo "ACTIONS_STEP_DEBUG=true" >> $GITHUB_ENV
  h:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cat >> $GITHUB_ENV <<EOF
          ACTIONS_STEP_DEBUG=true
          EOF
  k:
    runs-on: ubuntu-latest
    env:
      BODY: ${{ github.event.pull_request.body }}
    steps:
      - run: |
          echo "B=$BODY" >> "$GITHUB_ENV"
          cat <<EOF >> "$GITHUB_ENV"
          $BODY
          EOF
`

// TestFindingLine_OneLinePerIdentity pins that the branches of one rule
// sharing an identity report one line: ISSUE-203 set in env: and written
// to $GITHUB_ENV, ISSUE-209 written inline and through a heredoc. Two
// lines for one fingerprint would make two results of one issue. A
// $GITHUB_ENV write whose name sits on a later heredoc line points at
// the script's first line.
func TestFindingLine_OneLinePerIdentity(t *testing.T) {
	cfg := map[string]any{"debugTrace": map[string]any{"forbiddenVariables": []any{"ACTIONS_STEP_DEBUG"}}}
	findings, err := evaluateStrict(loadPolicies(t), context.Background(), scanWorkflow(t, sharedIdentityWorkflow), cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	type key struct{ code, job string }
	got := map[key]map[int]int{}
	for _, f := range findings {
		k := key{f.Code, f.Job}
		if got[k] == nil {
			got[k] = map[int]int{}
		}
		got[k][f.Line]++
	}
	want := []struct {
		code, job string
		line, n   int
	}{
		{"ISSUE-203", "repro/j", 6, 2},
		{"ISSUE-203", "repro/h", 13, 1},
		{"ISSUE-209", "repro/k", 22, 2},
	}
	for _, w := range want {
		lines := got[key{w.code, w.job}]
		if len(lines) != 1 || lines[w.line] != w.n {
			t.Errorf("%s on %s: %v (line: count), want %d findings at line %d", w.code, w.job, lines, w.n, w.line)
		}
	}
}

// TestFindingLine_GitLabKeepsTheJobHeader pins that a collector recording
// no construct line (GitLab, until #573) keeps the job-header fallback on
// the shared rules.
func TestFindingLine_GitLabKeepsTheJobHeader(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{{
			Name: "build", OriginFile: ".gitlab-ci.yml", OriginLine: 6,
			Image: &ir.Image{Name: "alpine", Tag: "latest"},
		}},
	}
	cfg := map[string]any{"imageMutableTag": map[string]any{"forbiddenTags": []any{"latest"}}}
	findings, err := evaluateStrict(loadPolicies(t), context.Background(), p, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	for _, f := range findings {
		if f.Code == "ISSUE-102" {
			if f.Line != 6 {
				t.Fatalf("ISSUE-102 line = %d, want the job header 6", f.Line)
			}
			return
		}
	}
	t.Fatalf("no ISSUE-102 in %+v", findings)
}

// branchLineWorkflow gives every line source of ISSUE-209's env-bound
// rules and of ISSUE-309 a job of its own, so each source alone decides
// its finding's line. Its line numbers are what
// TestFindingLine_EachSource expects.
const branchLineWorkflow = `on: pull_request
jobs:
  envbound:
    runs-on: ubuntu-latest
    env:
      BODY: ${{ github.event.pull_request.body }}
    steps:
      - run: echo "B=$BODY" >> "$GITHUB_ENV"
  pathbound:
    runs-on: ubuntu-latest
    env:
      REF: ${{ github.event.pull_request.head.ref }}
    steps:
      - run: echo "$REF" >> "$GITHUB_PATH"
  envheredoc:
    runs-on: ubuntu-latest
    env:
      BODY: ${{ github.event.pull_request.body }}
    steps:
      - run: |
          echo start
          cat <<EOF >> "$GITHUB_ENV"
          B=$BODY
          EOF
  pathheredoc:
    runs-on: ubuntu-latest
    env:
      REF: ${{ github.event.pull_request.head.ref }}
    steps:
      - run: |
          echo start
          cat <<EOF >> "$GITHUB_PATH"
          $REF
          EOF
  dumpenv:
    runs-on: ubuntu-latest
    env:
      ALL: ${{ toJSON(secrets) }}
    steps:
      - run: echo hi
  dumpwith:
    runs-on: ubuntu-latest
    steps:
      - uses: some/action@v1
        with:
          data: ${{ toJSON(secrets) }}
`

// TestFindingLine_EachSource pins every line source the table test does
// not reach: ISSUE-209's env-bound write to $GITHUB_ENV and $GITHUB_PATH,
// inline (the redirect line) and through a heredoc (its header line), and
// ISSUE-309's secrets dump in env: (the entry) and in a step input (the
// step's uses: line).
func TestFindingLine_EachSource(t *testing.T) {
	findings, err := evaluateStrict(loadPolicies(t), context.Background(), scanWorkflow(t, branchLineWorkflow), nil)
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
		{"ISSUE-209", "repro/envbound", 8},
		{"ISSUE-209", "repro/pathbound", 14},
		{"ISSUE-209", "repro/envheredoc", 22},
		{"ISSUE-209", "repro/pathheredoc", 32},
		{"ISSUE-309", "repro/dumpenv", 38},
		{"ISSUE-309", "repro/dumpwith", 44},
	}
	for _, w := range want {
		lines := got[key{w.code, w.job}]
		if len(lines) != 1 || lines[0] != w.line {
			t.Errorf("%s on %s: lines %v, want [%d]", w.code, w.job, lines, w.line)
		}
	}
}
