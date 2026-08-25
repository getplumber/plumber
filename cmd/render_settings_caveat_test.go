package cmd

import (
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/gitlab"
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
