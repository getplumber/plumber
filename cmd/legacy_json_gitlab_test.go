package cmd

import (
	"testing"

	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// TestMRApprovalRulesJSONBlocks locks the results.json detail blocks for the
// two GitLab merge-request approval-rule controls (ISSUE-502/504). Before the
// per-control wiring, buildLegacyResult would return ("", nil) and the blocks
// would be dropped entirely — a dashboard would see the score deficit in
// plumberScore.codeLosses with no per-control detail. Mirrors the GitHub
// TestPullRequestTargetHeadCheckoutJSONBlock, the guard for the same bug class.
func TestMRApprovalRulesJSONBlocks(t *testing.T) {
	result := &control.AnalysisResult{CiValid: true}

	// ISSUE-502: minimum-approvals — one failing rule, keyed on the stable ID.
	minEntry := control.ControlEntry{
		DisplayName: "MR approval rules must require a minimum number of approvals",
		ControlName: "mergeRequestApprovalRulesMustRequireMinimumApprovals",
	}
	minFindings := []opaengine.Finding{{
		Code: "ISSUE-502",
		Data: map[string]any{
			"approvalRuleId":       "42",
			"ruleName":             "Security",
			"approvalsRequired":    1,
			"minApprovalsRequired": 2,
		},
	}}

	name, block := buildLegacyResult(minEntry, result, nil, minFindings)
	if name != "mrApprovalRulesMinApprovalsResult" {
		t.Fatalf("502 block name = %q, want mrApprovalRulesMinApprovalsResult (dispatch dropped the block)", name)
	}
	m, ok := block.(map[string]any)
	if !ok {
		t.Fatalf("502 block is %T, want map[string]any", block)
	}
	issues, ok := m["issues"].([]map[string]any)
	if !ok || len(issues) != 1 {
		t.Fatalf("502 issues = %v, want exactly 1 entry", m["issues"])
	}
	if issues[0]["code"] != "ISSUE-502" {
		t.Errorf("502 issue code = %v, want ISSUE-502", issues[0]["code"])
	}
	// The rule identity (approvalRuleId) must survive into the issue block, so a
	// platform can group the finding across runs; the renameable name is data.
	if issues[0]["approvalRuleId"] != "42" {
		t.Errorf("502 issue must carry approvalRuleId=42, got %v", issues[0]["approvalRuleId"])
	}
	if metrics, ok := m["metrics"].(map[string]any); !ok || metrics["rulesBelowMinimum"] != 1 {
		t.Errorf("502 metrics.rulesBelowMinimum = %v, want 1", m["metrics"])
	}

	// ISSUE-504: cover-all — singleton finding.
	coverEntry := control.ControlEntry{
		DisplayName: "MR approval rules must cover all protected branches",
		ControlName: "mergeRequestApprovalRulesMustCoverAllProtectedBranches",
	}
	coverFindings := []opaengine.Finding{{
		Code: "ISSUE-504",
		Data: map[string]any{"totalRules": 2},
	}}

	name, block = buildLegacyResult(coverEntry, result, nil, coverFindings)
	if name != "mrApprovalRulesCoverAllBranchesResult" {
		t.Fatalf("504 block name = %q, want mrApprovalRulesCoverAllBranchesResult (dispatch dropped the block)", name)
	}
	m, ok = block.(map[string]any)
	if !ok {
		t.Fatalf("504 block is %T, want map[string]any", block)
	}
	if issues, ok := m["issues"].([]map[string]any); !ok || len(issues) != 1 || issues[0]["code"] != "ISSUE-504" {
		t.Fatalf("504 issues = %v, want exactly 1 ISSUE-504 entry", m["issues"])
	}
	if metrics, ok := m["metrics"].(map[string]any); !ok || metrics["allProtectedBranchesRuleMissing"] != 1 {
		t.Errorf("504 metrics.allProtectedBranchesRuleMissing = %v, want 1", m["metrics"])
	}

	// A clean run (no findings) still returns a block, with an empty issues list
	// — the control is present and evaluated, not absent.
	if _, clean := buildLegacyResult(minEntry, result, nil, nil); clean == nil {
		t.Errorf("502 clean run returned a nil block; the control must still appear")
	}
}

// TestMRApprovalRulesTierCaveatJSON pins the structured Premium/Ultimate caveat
// stamped onto the approval-rule blocks when the run flagged the ambiguous
// zero-rules case (GitLab Free returns an empty list). It must attach only to
// the two approval-rule controls, and only when the run set the flag.
func TestMRApprovalRulesTierCaveatJSON(t *testing.T) {
	flagged := &control.AnalysisResult{CiValid: true, ApprovalRulesTierCaveat: true}
	approval := control.ControlEntry{ControlName: "mergeRequestApprovalRulesMustCoverAllProtectedBranches"}

	block := _withControlMeta(map[string]any{"issues": []map[string]any{}}, approval, flagged, 0)
	m := block.(map[string]any)
	tc, ok := m["tierCaveat"].(map[string]any)
	if !ok {
		t.Fatalf("expected a tierCaveat on the approval-rule block, got %v", m)
	}
	if tc["reason"] != "no-approval-rules-returned" || tc["requiresTier"] != "premium_or_ultimate" {
		t.Errorf("tierCaveat shape mismatch: %v", tc)
	}

	// A non-approval control must NOT get the caveat, even when the flag is set.
	other := _withControlMeta(map[string]any{}, control.ControlEntry{ControlName: "branchMustBeProtected"}, flagged, 0)
	if _, present := other.(map[string]any)["tierCaveat"]; present {
		t.Errorf("tierCaveat leaked onto a non-approval control")
	}

	// Flag not set (rules were present, or a premium project): no caveat.
	clean := &control.AnalysisResult{CiValid: true}
	if _, present := _withControlMeta(map[string]any{}, approval, clean, 0).(map[string]any)["tierCaveat"]; present {
		t.Errorf("tierCaveat present when the run did not flag it")
	}
}
