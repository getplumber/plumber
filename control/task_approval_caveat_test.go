package control

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	"github.com/getplumber/plumber/internal/platform"
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

// TestMRSettingsPremiumCaveatOverSnapshotSettings covers the ISSUE-506
// caveat now that its input can come from the platform's snapshot rather
// than a project payload the CLI fetched.
//
// The caveat says "this expectation needs a paid tier", which is only
// honest about a setting somebody actually read as OFF. A snapshot-sourced
// MRSettings is either fully populated or nil (gitlab.ProtectionFromSnapshot
// refuses to invent the missing half), so the two cases below are the only
// two that reach here - and the nil one must produce no caveat at all
// rather than reading an unserved lane as a Free-tier project.
func TestMRSettingsPremiumCaveatOverSnapshotSettings(t *testing.T) {
	on := true
	conf := &configuration.Configuration{
		PlumberConfig: &configuration.PlumberConfig{
			Version: "2.0",
			GitLab: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
				MergeRequestSettingsMustBeCompliant: &configuration.MRSettingsControlConfig{
					Enabled:               &on,
					MergePipelinesEnabled: &on,
					MergeTrainsEnabled:    &on,
				},
			}},
		},
	}

	t.Run("settings served as off raise the caveat", func(t *testing.T) {
		// What the platform serves for a Free project: both premium
		// features present in the lane and genuinely false.
		data, served := gitlab.ProtectionFromSnapshot(snapshotRunWithMergeSettings(false))
		if !served || data.MRSettings == nil {
			t.Fatalf("the fixture must serve the merge settings, got served=%v data=%+v", served, data)
		}
		got := mrSettingsPremiumFieldsNeedingUpgrade(conf, data)
		if len(got) != 2 {
			t.Errorf("both premium expectations read as off and must be flagged, got %v", got)
		}
	})

	t.Run("settings served as on raise nothing", func(t *testing.T) {
		data, _ := gitlab.ProtectionFromSnapshot(snapshotRunWithMergeSettings(true))
		if got := mrSettingsPremiumFieldsNeedingUpgrade(conf, data); len(got) != 0 {
			t.Errorf("the features are on; no upgrade is needed, got %v", got)
		}
	})

	t.Run("an unserved lane raises nothing", func(t *testing.T) {
		run := &platform.RunContext{Context: &platform.ProjectContext{Snapshot: platform.Snapshot{
			Data: &platform.SnapshotData{SchemaVersion: platform.SnapshotSchemaV2},
		}}}
		data, _ := gitlab.ProtectionFromSnapshot(run)
		if data.MRSettings != nil {
			t.Fatalf("no project_details lane means no settings, got %+v", data.MRSettings)
		}
		if got := mrSettingsPremiumFieldsNeedingUpgrade(conf, data); len(got) != 0 {
			t.Errorf("nobody read these settings, so no tier can be advised, got %v", got)
		}
	})
}

// snapshotRunWithMergeSettings builds a served project_details lane whose
// two premium settings carry the given value and whose six other settings
// are present, since the projection is all-or-nothing.
func snapshotRunWithMergeSettings(premiumOn bool) *platform.RunContext {
	str := func(v string) *string { return &v }
	b := func(v bool) *bool { return &v }
	return &platform.RunContext{
		Context: &platform.ProjectContext{Snapshot: platform.Snapshot{Data: &platform.SnapshotData{
			SchemaVersion: platform.SnapshotSchemaV2,
			ProjectDetails: &platform.ProjectDetails{
				DefaultBranch:                   "main",
				PathWithNamespace:               "group/project",
				MergeMethod:                     str("ff"),
				SquashOption:                    str("always"),
				MergePipelinesEnabled:           b(premiumOn),
				MergeTrainsEnabled:              b(premiumOn),
				AllowMergeOnSkippedPipeline:     b(false),
				ResolveOutdatedDiffDiscussions:  b(false),
				PrintingMergeRequestLinkEnabled: b(true),
				RemoveSourceBranchAfterMerge:    b(true),
			},
		}}},
	}
}
