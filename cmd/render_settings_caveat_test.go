package cmd

import (
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/gitlab"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	glab "gitlab.com/gitlab-org/api/client-go"
)

// The two settings-level MR controls report `error` in JSON via
// control.StatusFor when the payload they read was never fetched. The terminal
// has no access to that verdict: it builds its stat lines separately, so
// without a caveat it prints a bare green check and counts the control toward
// the score while the JSON for the same run says error.
//
// These tests pin the two surfaces together. Each case asserts the caveat and
// StatusFor agree, so a future change to one guard that forgets the other
// fails here rather than silently reintroducing the false green.
func TestSettingsCaveatsAgreeWithStatusFor(t *testing.T) {
	cases := []struct {
		name        string
		result      *control.AnalysisResult
		wantCaveat  bool
		controlName string
		caveat      func(*control.AnalysisResult) []statLine
	}{
		{
			name:        "approval settings: collection never ran",
			result:      &control.AnalysisResult{CiValid: true},
			wantCaveat:  true,
			controlName: "mergeRequestApprovalSettingsMustBeCompliant",
			caveat:      approvalSettingsUnreadableCaveat,
		},
		{
			name:        "approval settings: unreadable (401/403 leaves them nil)",
			result:      &control.AnalysisResult{CiValid: true, ProtectionData: &gitlab.GitlabProtectionAnalysisData{}},
			wantCaveat:  true,
			controlName: "mergeRequestApprovalSettingsMustBeCompliant",
			caveat:      approvalSettingsUnreadableCaveat,
		},
		{
			name:        "approval settings: read authoritatively",
			result:      &control.AnalysisResult{CiValid: true, ProtectionData: &gitlab.GitlabProtectionAnalysisData{MRApprovalSettings: &glab.ProjectApprovals{}}},
			wantCaveat:  false,
			controlName: "mergeRequestApprovalSettingsMustBeCompliant",
			caveat:      approvalSettingsUnreadableCaveat,
		},
		{
			name:        "mr settings: collection never ran",
			result:      &control.AnalysisResult{CiValid: true},
			wantCaveat:  true,
			controlName: "mergeRequestSettingsMustBeCompliant",
			caveat:      mrSettingsUnreadableCaveat,
		},
		{
			name:        "mr settings: project payload unread",
			result:      &control.AnalysisResult{CiValid: true, ProtectionData: &gitlab.GitlabProtectionAnalysisData{}},
			wantCaveat:  true,
			controlName: "mergeRequestSettingsMustBeCompliant",
			caveat:      mrSettingsUnreadableCaveat,
		},
		{
			name:        "mr settings: read authoritatively",
			result:      &control.AnalysisResult{CiValid: true, ProtectionData: &gitlab.GitlabProtectionAnalysisData{MRSettings: &glab.Project{}}},
			wantCaveat:  false,
			controlName: "mergeRequestSettingsMustBeCompliant",
			caveat:      mrSettingsUnreadableCaveat,
		},
		{
			name:        "members: collection never ran",
			result:      &control.AnalysisResult{CiValid: true},
			wantCaveat:  true,
			controlName: "numberOfProjectMembersMustRespectQuota",
			caveat:      membersUnreadableCaveat,
		},
		{
			name:        "members: listing unreadable (Known false)",
			result:      &control.AnalysisResult{CiValid: true, MembersData: &gitlab.GitlabMembersAnalysisData{}},
			wantCaveat:  true,
			controlName: "numberOfProjectMembersMustRespectQuota",
			caveat:      membersUnreadableCaveat,
		},
		{
			name:        "members: read authoritatively",
			result:      &control.AnalysisResult{CiValid: true, MembersData: &gitlab.GitlabMembersAnalysisData{Known: true}},
			wantCaveat:  false,
			controlName: "numberOfProjectMembersMustRespectQuota",
			caveat:      membersUnreadableCaveat,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := tc.caveat(tc.result)
			gotCaveat := len(lines) > 0
			if gotCaveat != tc.wantCaveat {
				t.Fatalf("caveat: got %v, want %v", gotCaveat, tc.wantCaveat)
			}
			if gotCaveat && !strings.HasPrefix(lines[0].Label, statCaveatPrefix) {
				t.Fatalf("caveat line must carry the caveat prefix, got %q", lines[0].Label)
			}

			// The invariant: a caveat in the terminal means, and only means,
			// StatusFor reports error for the same run with zero findings.
			status := control.StatusFor(control.ControlEntry{ControlName: tc.controlName}, tc.result, 0)
			wantStatus := control.StatusPassed
			if tc.wantCaveat {
				wantStatus = control.StatusError
			}
			if status != wantStatus {
				t.Fatalf("terminal caveat=%v but StatusFor=%q (want %q): the two surfaces disagree",
					gotCaveat, status, wantStatus)
			}
		})
	}
}

// The member quota block: an unread listing prints the single caveat line
// (and nothing that looks like a count); a read listing prints the four
// counts and the number of roles out of quota, which is the findings count.
func TestMemberQuotaStatLines(t *testing.T) {
	const name = "numberOfProjectMembersMustRespectQuota"
	for _, result := range []*control.AnalysisResult{
		{CiValid: true},
		{CiValid: true, MembersData: &gitlab.GitlabMembersAnalysisData{Counts: gitlab.MemberCounts{Owners: 9}}},
	} {
		lines := buildGitLabControlStats(name, result, nil, nil)
		if len(lines) != 1 || !strings.HasPrefix(lines[0].Label, statCaveatPrefix) {
			t.Fatalf("an unread listing must print only the caveat line, got %+v", lines)
		}
	}

	result := &control.AnalysisResult{CiValid: true, MembersData: &gitlab.GitlabMembersAnalysisData{
		Known:  true,
		Counts: gitlab.MemberCounts{Owners: 3, Maintainers: 1, Developers: 5, Total: 12},
	}}
	findings := []opaengine.Finding{{Code: "ISSUE-507"}, {Code: "ISSUE-507"}}
	got := buildGitLabControlStats(name, result, nil, findings)
	want := []statLine{
		{Label: "Owners", Value: "3"},
		{Label: "Maintainers", Value: "1"},
		{Label: "Developers", Value: "5"},
		{Label: "Total Members", Value: "12"},
		{Label: "Roles Out Of Quota", Value: "2"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d stat lines, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Label != want[i].Label || got[i].Value != want[i].Value {
			t.Errorf("line %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
