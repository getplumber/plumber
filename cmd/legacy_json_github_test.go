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
	if issues[0]["jobName"] != "ci/build" {
		t.Errorf("issue jobName = %v, want ci/build", issues[0]["jobName"])
	}
	if issues[0]["url"] == nil {
		t.Errorf("issue must carry a url (file:line link), got %v", issues[0])
	}
	if m["compliance"] != 0.0 {
		t.Errorf("compliance with a finding = %v, want 0", m["compliance"])
	}

	// Clean run: no findings → 100% compliant, empty issues.
	cleanName, cleanBlock := buildLegacyResultGitHub(entry, result, nil, nil)
	if cleanName != "pullRequestTargetHeadCheckoutResult" {
		t.Fatalf("clean block name = %q", cleanName)
	}
	if cm := cleanBlock.(map[string]any); cm["compliance"] != 100.0 {
		t.Errorf("clean compliance = %v, want 100", cm["compliance"])
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
		GitHubStats: &control.GitHubAnalysisStats{ActionRefsTotal: 4},
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
	if m["compliance"] != 0.0 {
		t.Errorf("compliance with a finding = %v, want 0", m["compliance"])
	}

	// Clean run: no findings → 100% compliant.
	cleanName, cleanBlock := buildLegacyResultGitHub(entry, result, nil, nil)
	if cleanName != "authorizedActionSourcesResult" {
		t.Fatalf("clean block name = %q", cleanName)
	}
	if cm := cleanBlock.(map[string]any); cm["compliance"] != 100.0 {
		t.Errorf("clean compliance = %v, want 100", cm["compliance"])
	}
}
