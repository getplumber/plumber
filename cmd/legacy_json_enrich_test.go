package cmd

import (
	"testing"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/gitlab"
)

func TestEnrichBranchProtection505IssueMaps_LegacyDisplays(t *testing.T) {
	t.Parallel()
	f := false
	min40 := 40
	pc := &configuration.PlumberConfig{
		Version: "1.0",
		GitLab: &configuration.ProviderConfig{
			Controls: configuration.ControlsConfig{
				BranchMustBeProtected: &configuration.BranchProtectionControlConfig{
					AllowForcePush:            &f,
					CodeOwnerApprovalRequired: boolPtr(true),
					MinMergeAccessLevel:       &min40,
					MinPushAccessLevel:        &min40,
				},
			},
		},
	}
	result := &control.AnalysisResult{
		ProtectionData: &collector.GitlabProtectionAnalysisData{
			BranchProtections: []gitlab.BranchProtection{
				{
					ProtectionPattern:         "main",
					AllowForcePush:            true,
					CodeOwnerApprovalRequired: false,
					PushAccessLevels:          []gitlab.BranchProtectionAccessLevel{{AccessLevel: 30}},
					MergeAccessLevels:         []gitlab.BranchProtectionAccessLevel{{AccessLevel: 30}},
				},
			},
		},
	}
	issues := []map[string]any{{
		"code":   string(control.CodeBranchNonCompliant),
		"docUrl": "x",
		"branchName": "main",
		"job":    "main",
	}}
	enrichBranchProtection505IssueMaps(issues, result, pc)
	iss := issues[0]
	if iss["codeOwnerApprovalRequired"] != false {
		t.Fatalf("codeOwnerApprovalRequired: got %v", iss["codeOwnerApprovalRequired"])
	}
	if iss["allowForcePushDisplay"] != true {
		t.Fatalf("allowForcePushDisplay: got %v", iss["allowForcePushDisplay"])
	}
	if iss["codeOwnerApprovalRequiredDisplay"] != true {
		t.Fatalf("codeOwnerApprovalRequiredDisplay: got %v", iss["codeOwnerApprovalRequiredDisplay"])
	}
	if iss["minMergeAccessLevelDisplay"] != true {
		t.Fatalf("minMergeAccessLevelDisplay: got %v", iss["minMergeAccessLevelDisplay"])
	}
	if iss["minPushAccessLevelDisplay"] != true {
		t.Fatalf("minPushAccessLevelDisplay: got %v", iss["minPushAccessLevelDisplay"])
	}
}

func boolPtr(b bool) *bool { return &b }

func TestEnrichForbiddenVersion404IssueMaps_OriginFields(t *testing.T) {
	t.Parallel()
	result := &control.AnalysisResult{
		PipelineOriginData: &collector.GitlabPipelineOriginData{
			Origins: []collector.GitlabPipelineOriginDataFull{
				{
					GitlabPipelineOriginDataGeneric: collector.GitlabPipelineOriginDataGeneric{
						OriginType: "project",
						GitlabIncludeOrigin: gitlab.IncludeOriginWithoutRef{
							Location: "file@1.0.0",
							Type:     "file",
							Project:  "g/x",
						},
						OriginHash: 99,
					},
					GitlabPipelineOriginDataProjectSpecific: collector.GitlabPipelineOriginDataProjectSpecific{
						Version:  "1.0.0",
						Nested:   true,
					},
				},
			},
		},
	}
	issues := []map[string]any{{
		"code":   string(control.CodeIncludeForbiddenVersion),
		"docUrl": "x",
		"job":    "file@1.0.0",
	}}
	enrichForbiddenVersion404IssueMaps(issues, result)
	iss := issues[0]
	if iss["version"] != "1.0.0" {
		t.Fatalf("version: got %v", iss["version"])
	}
	if iss["gitlabIncludeLocation"] != "file@1.0.0" {
		t.Fatalf("gitlabIncludeLocation: got %v", iss["gitlabIncludeLocation"])
	}
	if iss["gitlabIncludeType"] != "file" {
		t.Fatalf("gitlabIncludeType: got %v", iss["gitlabIncludeType"])
	}
	if iss["nested"] != true {
		t.Fatalf("nested: got %v", iss["nested"])
	}
	if iss["originHash"] != uint64(99) {
		t.Fatalf("originHash: got %v", iss["originHash"])
	}
}
