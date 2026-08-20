package control

import (
	"testing"

	"github.com/getplumber/plumber/gitlab"
	glab "gitlab.com/gitlab-org/api/client-go"
)

func TestStatusFor(t *testing.T) {
	content := ControlEntry{ControlName: "actionsMustBePinnedByCommitSha"}
	branch := ControlEntry{ControlName: "branchMustBeProtected"}
	approval := ControlEntry{ControlName: "mergeRequestApprovalRulesMustRequireMinimumApprovals"}
	variables := ControlEntry{ControlName: "cicdVariablesMustBeProtected"}
	approvalSettings := ControlEntry{ControlName: "mergeRequestApprovalSettingsMustBeCompliant"}
	healthy := &AnalysisResult{CiValid: true}

	cases := []struct {
		name     string
		entry    ControlEntry
		result   *AnalysisResult
		findings int
		want     string
	}{
		{"skipped wins over everything", ControlEntry{ControlName: "x", Skipped: true}, &AnalysisResult{CiMissing: true}, 3, StatusSkipped},
		{"findings mean failed even on a degraded run", content, &AnalysisResult{CiValid: true, DataCollectionDegraded: true, DegradedReasons: []string{"3 workflow file(s) could not be fetched and were skipped"}}, 2, StatusFailed},
		{"clean run, no findings: passed", content, healthy, 0, StatusPassed},
		{"missing CI config: empty findings are not a pass", content, &AnalysisResult{CiMissing: true}, 0, StatusError},
		{"invalid CI config: empty findings are not a pass", content, &AnalysisResult{CiValid: false}, 0, StatusError},
		{"degraded content collection: error", content, &AnalysisResult{CiValid: true, DataCollectionDegraded: true, DegradedReasons: []string{"pipeline configuration could not be fetched (network or timeout)"}}, 0, StatusError},
		{"branch-only degradation does not taint content controls", content, &AnalysisResult{CiValid: true, DataCollectionDegraded: true, DegradedReasons: []string{"branch protection could not be fetched (network or timeout)"}}, 0, StatusPassed},
		{"branch control on github ignores missing CI config (protection enrichment ran)", branch, &AnalysisResult{CiMissing: true, GitHubStats: &GitHubAnalysisStats{}}, 0, StatusPassed},
		{"branch control on gitlab ignores missing CI config only when the protection collection ran", branch, &AnalysisResult{CiMissing: true, ProtectionData: &gitlab.GitlabProtectionAnalysisData{}}, 0, StatusPassed},
		{"branch control on gitlab errors when the protection collection never ran (limited analysis, early return, or any fetch error incl. 401/403)", branch, &AnalysisResult{CiMissing: true}, 0, StatusError},
		{"branch control errors on its own fetch failure (gitlab phrasing)", branch, &AnalysisResult{CiValid: true, DegradedReasons: []string{degradedReasonBranchProtectionPrefix + " (network or timeout)"}}, 0, StatusError},
		{"branch control errors on its own fetch failure (github phrasing)", branch, &AnalysisResult{CiValid: true, GitHubStats: &GitHubAnalysisStats{}, DegradedReasons: []string{degradedReasonBranchProtectionPrefix + "; branch controls were not evaluated"}}, 0, StatusError},
		{"branch control errors on partial protection details", branch, &AnalysisResult{CiValid: true, GitHubStats: &GitHubAnalysisStats{BranchesProtectionDetailsUnknown: 2}}, 0, StatusError},
		{"branch control on github ignores content-only degradation", branch, &AnalysisResult{CiValid: true, GitHubStats: &GitHubAnalysisStats{}, DegradedReasons: []string{"2 workflow file(s) could not be fetched and were skipped"}}, 0, StatusPassed},
		{"branch control on gitlab ignores content-only degradation when its own collection ran", branch, &AnalysisResult{CiValid: true, ProtectionData: &gitlab.GitlabProtectionAnalysisData{}, DegradedReasons: []string{"2 include(s) could not be resolved; their jobs were not analysed"}}, 0, StatusPassed},
		{"approval-rule control passes when the approvals listing was read and clean", approval, &AnalysisResult{CiValid: true, ProtectionData: &gitlab.GitlabProtectionAnalysisData{MRApprovalRulesKnown: true}}, 0, StatusPassed},
		{"approval-rule control ignores missing CI config (settings-independent) when the listing was read", approval, &AnalysisResult{CiMissing: true, ProtectionData: &gitlab.GitlabProtectionAnalysisData{MRApprovalRulesKnown: true}}, 0, StatusPassed},
		{"approval-rule control errors when the protection collection never ran", approval, &AnalysisResult{CiValid: true}, 0, StatusError},
		{"approval-rule control errors on an unreadable approvals listing (401/403, Known=false): empty findings are not a pass", approval, &AnalysisResult{CiValid: true, ProtectionData: &gitlab.GitlabProtectionAnalysisData{MRApprovalRulesKnown: false}}, 0, StatusError},
		{"approval-rule control with findings is failed regardless of CI/collection state", approval, &AnalysisResult{CiValid: true, ProtectionData: &gitlab.GitlabProtectionAnalysisData{MRApprovalRulesKnown: true}}, 3, StatusFailed},
		{"approval-settings control passes when the settings were read and clean", approvalSettings, &AnalysisResult{CiValid: true, ProtectionData: &gitlab.GitlabProtectionAnalysisData{MRApprovalSettings: &glab.ProjectApprovals{}}}, 0, StatusPassed},
		{"approval-settings control ignores missing CI config when the settings were read", approvalSettings, &AnalysisResult{CiMissing: true, ProtectionData: &gitlab.GitlabProtectionAnalysisData{MRApprovalSettings: &glab.ProjectApprovals{}}}, 0, StatusPassed},
		{"approval-settings control errors when the protection collection never ran", approvalSettings, &AnalysisResult{CiValid: true}, 0, StatusError},
		{"approval-settings control errors on unreadable settings (401/403, nil): empty findings are not a pass", approvalSettings, &AnalysisResult{CiValid: true, ProtectionData: &gitlab.GitlabProtectionAnalysisData{}}, 0, StatusError},
		{"approval-settings control with findings is failed", approvalSettings, &AnalysisResult{CiValid: true, ProtectionData: &gitlab.GitlabProtectionAnalysisData{MRApprovalSettings: &glab.ProjectApprovals{}}}, 1, StatusFailed},
		{"nil result defaults to passed (hand-built test fixtures)", content, nil, 0, StatusPassed},
		{"variable control passes when the listing was read and clean", variables, &AnalysisResult{CiValid: true, VariablesData: &gitlab.GitlabVariablesAnalysisData{Known: true}}, 0, StatusPassed},
		{"variable control ignores missing CI config (settings-independent) when the listing was read", variables, &AnalysisResult{CiMissing: true, VariablesData: &gitlab.GitlabVariablesAnalysisData{Known: true}}, 0, StatusPassed},
		{"variable control errors when its collection never ran", variables, &AnalysisResult{CiValid: true}, 0, StatusError},
		{"variable control errors on an unreadable listing (401/403, Known=false): empty findings are not a pass", variables, &AnalysisResult{CiValid: true, VariablesData: &gitlab.GitlabVariablesAnalysisData{Known: false}}, 0, StatusError},
		{"variable control with findings is failed regardless of CI state", variables, &AnalysisResult{CiValid: true, VariablesData: &gitlab.GitlabVariablesAnalysisData{Known: true}}, 3, StatusFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := StatusFor(tc.entry, tc.result, tc.findings); got != tc.want {
				t.Errorf("StatusFor() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCodesForControl(t *testing.T) {
	// containerImageMustNotUseForbiddenTags spans two codes (ISSUE-102 +
	// ISSUE-103) -- the multi-code case block-level status has to handle.
	got := CodesForControl("containerImageMustNotUseForbiddenTags")
	want := map[ErrorCode]bool{CodeImageForbiddenTag: false, CodeImageNotPinnedByDigest: false}
	for _, c := range got {
		if _, ok := want[c]; ok {
			want[c] = true
		}
	}
	for c, seen := range want {
		if !seen {
			t.Errorf("CodesForControl missing %s", c)
		}
	}
	// Sorted for determinism.
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Errorf("codes not sorted: %v", got)
		}
	}
	if len(CodesForControl("noSuchControl")) != 0 {
		t.Errorf("unknown control should return no codes")
	}
}
