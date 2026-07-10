package cmd

import (
	"testing"

	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// TestPullRequestTargetHeadCheckoutJSONBlock locks the ISSUE-804 fix: the
// JSON export must carry a pullRequestTargetHeadCheckoutResult block whose
// issues[] surface the file/job/line, not just a plumberScore.codeLosses
// line. Before the fix the dispatch returned ("", nil) for this control,
// so dashboards saw the criticals with no location.
func TestPullRequestTargetHeadCheckoutJSONBlock(t *testing.T) {
	entry := control.ControlEntry{
		DisplayName: "pull_request_target workflows must not check out the PR head",
		ControlName: "pullRequestTargetMustNotCheckoutHead",
	}
	findings := []opaengine.Finding{{
		Code: "ISSUE-804",
		Job:  "ci/build",
		File: ".github/workflows/ci.yml",
		Line: 12,
		URL:  ".github/workflows/ci.yml:12",
	}}
	result := &control.AnalysisResult{
		CiValid:     true,
		GitHubStats: &control.GitHubAnalysisStats{WorkflowsTotal: 3},
	}

	name, block := buildLegacyResultGitHub(entry, result, nil, findings)
	if name != "pullRequestTargetHeadCheckoutResult" {
		t.Fatalf("block name = %q, want pullRequestTargetHeadCheckoutResult", name)
	}
	m, ok := block.(map[string]any)
	if !ok {
		t.Fatalf("block is %T, want map[string]any", block)
	}
	issues, ok := m["issues"].([]map[string]any)
	if !ok || len(issues) != 1 {
		t.Fatalf("issues = %v, want exactly 1 entry", m["issues"])
	}
	if issues[0]["code"] != "ISSUE-804" {
		t.Errorf("issue code = %v, want ISSUE-804", issues[0]["code"])
	}
	if issues[0]["job"] != "ci/build" {
		t.Errorf("issue job = %v, want ci/build", issues[0]["job"])
	}
	if alias, present := issues[0]["jobName"]; present {
		t.Errorf("the jobName alias was retired in favour of job; block still carries %v", alias)
	}
	if issues[0]["url"] == nil {
		t.Errorf("issue must carry a url (file:line link), got %v", issues[0])
	}
	if _, present := m["compliance"]; present {
		t.Errorf("per-control compliance was removed (#320); block still carries %v", m["compliance"])
	}

	// Clean run: no findings → empty issues, still no compliance key.
	cleanName, cleanBlock := buildLegacyResultGitHub(entry, result, nil, nil)
	if cleanName != "pullRequestTargetHeadCheckoutResult" {
		t.Fatalf("clean block name = %q", cleanName)
	}
	if cm := cleanBlock.(map[string]any); cm["compliance"] != nil {
		t.Errorf("clean block must not carry compliance (#320), got %v", cm["compliance"])
	}
}

// TestAuthorizedActionSourcesJSONBlock locks the ISSUE-713 JSON export:
// the authorizedActionSourcesResult block must surface each unauthorized
// `uses:` (with its file/job/line) rather than leaving only a
// plumberScore.codeLosses line — the same dropped-findings bug the
// pull_request_target block above was fixed for.
func TestAuthorizedActionSourcesJSONBlock(t *testing.T) {
	entry := control.ControlEntry{
		DisplayName: "Actions must come from authorized sources",
		ControlName: "githubActionMustComeFromAuthorizedSources",
	}
	findings := []opaengine.Finding{{
		Code: "ISSUE-713",
		Job:  "ci/build",
		File: ".github/workflows/ci.yml",
		Line: 35,
		URL:  ".github/workflows/ci.yml:35",
		Data: map[string]any{"uses": "tj-actions/changed-files@v45.0.0"},
	}}
	result := &control.AnalysisResult{
		CiValid:     true,
		GitHubStats: &control.GitHubAnalysisStats{ActionRefsTotal: 4, ActionRefsExempt: 2},
	}

	name, block := buildLegacyResultGitHub(entry, result, nil, findings)
	if name != "authorizedActionSourcesResult" {
		t.Fatalf("block name = %q, want authorizedActionSourcesResult", name)
	}
	m, ok := block.(map[string]any)
	if !ok {
		t.Fatalf("block is %T, want map[string]any", block)
	}
	issues, ok := m["issues"].([]map[string]any)
	if !ok || len(issues) != 1 {
		t.Fatalf("issues = %v, want exactly 1 entry", m["issues"])
	}
	if issues[0]["code"] != "ISSUE-713" {
		t.Errorf("issue code = %v, want ISSUE-713", issues[0]["code"])
	}
	if issues[0]["uses"] != "tj-actions/changed-files@v45.0.0" {
		t.Errorf("issue must carry the offending uses, got %v", issues[0]["uses"])
	}
	if issues[0]["url"] == nil {
		t.Errorf("issue must carry a url (file:line link), got %v", issues[0])
	}
	metrics := m["metrics"].(map[string]any)
	if metrics["actionRefsUnauthorized"] != 1 {
		t.Errorf("actionRefsUnauthorized = %v, want 1", metrics["actionRefsUnauthorized"])
	}
	// Denominator must include pin-exempt refs (actions/*, github/*),
	// which ISSUE-713 still evaluates — matching the terminal stats.
	if metrics["actionRefsTotal"] != 6 {
		t.Errorf("actionRefsTotal = %v, want 6 (ActionRefsTotal 4 + ActionRefsExempt 2)", metrics["actionRefsTotal"])
	}
	if _, present := m["compliance"]; present {
		t.Errorf("per-control compliance was removed (#320); block still carries %v", m["compliance"])
	}

	// Clean run: no findings → still no compliance key.
	cleanName, cleanBlock := buildLegacyResultGitHub(entry, result, nil, nil)
	if cleanName != "authorizedActionSourcesResult" {
		t.Fatalf("clean block name = %q", cleanName)
	}
	if cm := cleanBlock.(map[string]any); cm["compliance"] != nil {
		t.Errorf("clean block must not carry compliance (#320), got %v", cm["compliance"])
	}
}

// TestImpostorCommitJSONBlock locks the ISSUE-707 JSON export: the
// dispatch must return an impostorCommitResult block whose issues[]
// carry the finding's code/job/url and whose metrics expose
// actionRefsAbsentUpstream alongside the shared actionRefsTotal
// denominator. Same dropped-findings regression the two blocks above
// guard against: a removed case or mis-wired key would silently drop
// every critical ISSUE-707 from the JSON export while the suite stays
// green.
func TestImpostorCommitJSONBlock(t *testing.T) {
	entry := control.ControlEntry{
		DisplayName: "Actions must pin commits that exist upstream",
		ControlName: "actionRefsMustExistUpstream",
	}
	findings := []opaengine.Finding{{
		Code: "ISSUE-707",
		Job:  "ci/build",
		File: ".github/workflows/ci.yml",
		Line: 21,
		URL:  ".github/workflows/ci.yml:21",
	}}
	result := &control.AnalysisResult{
		CiValid:     true,
		GitHubStats: &control.GitHubAnalysisStats{ActionRefsTotal: 8},
	}

	name, block := buildLegacyResultGitHub(entry, result, nil, findings)
	if name != "impostorCommitResult" {
		t.Fatalf("block name = %q, want impostorCommitResult", name)
	}
	m, ok := block.(map[string]any)
	if !ok {
		t.Fatalf("block is %T, want map[string]any", block)
	}
	issues, ok := m["issues"].([]map[string]any)
	if !ok || len(issues) != 1 {
		t.Fatalf("issues = %v, want exactly 1 entry", m["issues"])
	}
	if issues[0]["code"] != "ISSUE-707" {
		t.Errorf("issue code = %v, want ISSUE-707", issues[0]["code"])
	}
	if issues[0]["job"] != "ci/build" {
		t.Errorf("issue job = %v, want ci/build", issues[0]["job"])
	}
	if issues[0]["url"] == nil {
		t.Errorf("issue must carry a url (file:line link), got %v", issues[0])
	}
	metrics := m["metrics"].(map[string]any)
	if metrics["actionRefsAbsentUpstream"] != 1 {
		t.Errorf("actionRefsAbsentUpstream = %v, want 1", metrics["actionRefsAbsentUpstream"])
	}
	if metrics["actionRefsTotal"] != 8 {
		t.Errorf("actionRefsTotal = %v, want 8", metrics["actionRefsTotal"])
	}
	if _, present := m["compliance"]; present {
		t.Errorf("per-control compliance was removed (#320); block still carries %v", m["compliance"])
	}

	// Clean run: no findings → empty issues, zero numerator, no compliance.
	cleanName, cleanBlock := buildLegacyResultGitHub(entry, result, nil, nil)
	if cleanName != "impostorCommitResult" {
		t.Fatalf("clean block name = %q", cleanName)
	}
	cm := cleanBlock.(map[string]any)
	if ci, _ := cm["issues"].([]map[string]any); len(ci) != 0 {
		t.Errorf("clean issues = %v, want empty", cm["issues"])
	}
	if cmm := cm["metrics"].(map[string]any); cmm["actionRefsAbsentUpstream"] != 0 {
		t.Errorf("clean actionRefsAbsentUpstream = %v, want 0", cmm["actionRefsAbsentUpstream"])
	}
	if cm["compliance"] != nil {
		t.Errorf("clean block must not carry compliance (#320), got %v", cm["compliance"])
	}
}

// TestMutableRemoteExecJSONBlock locks the ISSUE-714/715/716 JSON export
// for actionsMustNotExecuteMutableRemoteCode: the dispatch must return a
// mutableRemoteExecResult block whose issues[] carry each finding's
// code/job/uses/url, not just a plumberScore.codeLosses line. This is the
// same dropped-findings regression the sibling blocks guard against — the
// PR shipped the control's rego + collector but no JSON wiring, so every
// mutable-exec finding was silently absent from --output.
func TestMutableRemoteExecJSONBlock(t *testing.T) {
	entry := control.ControlEntry{
		DisplayName: "Actions must not execute mutable remote code",
		ControlName: "actionsMustNotExecuteMutableRemoteCode",
	}
	findings := []opaengine.Finding{{
		Code: "ISSUE-714",
		Job:  "ci/scan",
		File: ".github/workflows/ci.yml",
		Line: 9,
		URL:  ".github/workflows/ci.yml:9",
		Data: map[string]any{"uses": "anchore/scan-action@229edc86a0f0a8c34ea883607b5fa8310b1c35d8"},
	}}
	result := &control.AnalysisResult{
		CiValid:     true,
		GitHubStats: &control.GitHubAnalysisStats{ActionRefsTotal: 5},
	}

	name, block := buildLegacyResultGitHub(entry, result, nil, findings)
	if name != "mutableRemoteExecResult" {
		t.Fatalf("block name = %q, want mutableRemoteExecResult", name)
	}
	m, ok := block.(map[string]any)
	if !ok {
		t.Fatalf("block is %T, want map[string]any", block)
	}
	issues, ok := m["issues"].([]map[string]any)
	if !ok || len(issues) != 1 {
		t.Fatalf("issues = %v, want exactly 1 entry", m["issues"])
	}
	if issues[0]["code"] != "ISSUE-714" {
		t.Errorf("issue code = %v, want ISSUE-714", issues[0]["code"])
	}
	if issues[0]["job"] != "ci/scan" {
		t.Errorf("issue job = %v, want ci/scan", issues[0]["job"])
	}
	if issues[0]["uses"] != "anchore/scan-action@229edc86a0f0a8c34ea883607b5fa8310b1c35d8" {
		t.Errorf("issue must carry the offending uses, got %v", issues[0]["uses"])
	}
	if issues[0]["url"] == nil {
		t.Errorf("issue must carry a url (file:line link), got %v", issues[0])
	}
	metrics := m["metrics"].(map[string]any)
	if metrics["actionsWithMutableRemoteExec"] != 1 {
		t.Errorf("actionsWithMutableRemoteExec = %v, want 1", metrics["actionsWithMutableRemoteExec"])
	}
	if metrics["actionRefsTotal"] != 5 {
		t.Errorf("actionRefsTotal = %v, want 5", metrics["actionRefsTotal"])
	}
	if _, present := m["compliance"]; present {
		t.Errorf("per-control compliance was removed (#320); block still carries %v", m["compliance"])
	}

	// Clean run: no findings → empty issues, zero numerator.
	cleanName, cleanBlock := buildLegacyResultGitHub(entry, result, nil, nil)
	if cleanName != "mutableRemoteExecResult" {
		t.Fatalf("clean block name = %q", cleanName)
	}
	cm := cleanBlock.(map[string]any)
	if ci, _ := cm["issues"].([]map[string]any); len(ci) != 0 {
		t.Errorf("clean issues = %v, want empty", cm["issues"])
	}
	if cmm := cm["metrics"].(map[string]any); cmm["actionsWithMutableRemoteExec"] != 0 {
		t.Errorf("clean actionsWithMutableRemoteExec = %v, want 0", cmm["actionsWithMutableRemoteExec"])
	}
}
