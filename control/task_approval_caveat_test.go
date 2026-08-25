package control

import (
	"testing"

	"github.com/getplumber/plumber/gitlab"
	glab "gitlab.com/gitlab-org/api/client-go"
)

// TestApprovalRulesReturnedNone covers the tier-caveat trigger's data
// condition. The caveat fires only when the approvals API was read
// authoritatively (Known=true) and returned zero rules — the ambiguous
// GitLab-Free-vs-Premium-with-no-rules case. nil data or an unreadable listing
// (Known=false) is a collection failure, not "zero rules", and must not fire;
// a listing that returned rules is a clearly-Premium project, also no caveat.
func TestApprovalRulesReturnedNone(t *testing.T) {
	cases := []struct {
		name string
		data *gitlab.GitlabProtectionAnalysisData
		want bool
	}{
		{"nil protection (collection never ran)", nil, false},
		{"unreadable listing (401/403, Known=false)", &gitlab.GitlabProtectionAnalysisData{MRApprovalRulesKnown: false}, false},
		{"known and zero rules (the caveat case)", &gitlab.GitlabProtectionAnalysisData{MRApprovalRulesKnown: true}, true},
		{"known with rules present", &gitlab.GitlabProtectionAnalysisData{MRApprovalRulesKnown: true, MRApprovalRules: []*glab.ProjectApprovalRule{{ID: 1}}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := approvalRulesReturnedNone(tc.data); got != tc.want {
				t.Errorf("approvalRulesReturnedNone = %v, want %v", got, tc.want)
			}
		})
	}
}
