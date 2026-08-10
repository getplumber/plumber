package cmd

import (
	"context"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/gitlab"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
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
		ProtectionData: &gitlab.GitlabProtectionAnalysisData{
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
		"code":       string(control.CodeBranchNonCompliant),
		"docUrl":     "x",
		"branchName": "main",
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
		PipelineOriginData: &gitlab.GitlabPipelineOriginData{
			Origins: []gitlab.GitlabPipelineOriginDataFull{
				{
					GitlabPipelineOriginDataGeneric: gitlab.GitlabPipelineOriginDataGeneric{
						OriginType: "project",
						GitlabIncludeOrigin: gitlab.IncludeOriginWithoutRef{
							Location: "file@1.0.0",
							Type:     "file",
							Project:  "g/x",
						},
						OriginHash: 99,
					},
					GitlabPipelineOriginDataProjectSpecific: gitlab.GitlabPipelineOriginDataProjectSpecific{
						Version: "1.0.0",
						Nested:  true,
					},
				},
			},
		},
	}
	issues := []map[string]any{{
		"code":        string(control.CodeIncludeForbiddenVersion),
		"docUrl":      "x",
		"includePath": "file@1.0.0",
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

// TestBuildForbiddenVersionsBlock_EnrichmentSurvivesRealFindings is the
// regression guard the job-field-semantics change was missing: it is the
// only test that runs the OPA engine over an ISSUE-404 fixture and pipes the
// resulting findings through buildForbiddenVersionsBlock, joining the two
// halves that a real regression once let drift apart (the rule started
// emitting includePath while the enrichment still read job, and nothing
// caught it because no test exercised both together). It asserts that the
// origin-collector enrichment (gitlabIncludeLocation, version) still lands
// on the issue once the rule's payload changes.
func TestBuildForbiddenVersionsBlock_EnrichmentSurvivesRealFindings(t *testing.T) {
	t.Parallel()
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"includesForbiddenVersions": map[string]any{
			"forbiddenVersions": []string{"main"},
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Includes: []ir.Include{
			{Kind: "project", Source: "group/project@main", Ref: "main"},
		},
	}
	findings, err := engine.Evaluate(context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	var forbidden []opaengine.Finding
	for _, f := range findings {
		if f.Code == "ISSUE-404" {
			forbidden = append(forbidden, f)
		}
	}
	if len(forbidden) != 1 {
		t.Fatalf("expected 1 ISSUE-404 finding, got %d (%v)", len(forbidden), findings)
	}
	if forbidden[0].Job != "" {
		t.Fatalf("ISSUE-404 finding carries job = %q, want empty", forbidden[0].Job)
	}

	result := &control.AnalysisResult{
		PipelineOriginData: &gitlab.GitlabPipelineOriginData{
			Origins: []gitlab.GitlabPipelineOriginDataFull{
				{
					GitlabPipelineOriginDataGeneric: gitlab.GitlabPipelineOriginDataGeneric{
						OriginType: "project",
						GitlabIncludeOrigin: gitlab.IncludeOriginWithoutRef{
							Location: "group/project@main",
							Type:     "project",
							Project:  "group/project",
						},
						OriginHash: 42,
					},
					GitlabPipelineOriginDataProjectSpecific: gitlab.GitlabPipelineOriginDataProjectSpecific{
						Version: "main",
					},
				},
			},
		},
	}

	block := buildForbiddenVersionsBlock(legacyCommon{}, result, forbidden)
	issues, ok := block["issues"].([]map[string]any)
	if !ok || len(issues) != 1 {
		t.Fatalf("issues = %#v, want exactly one issue map", block["issues"])
	}
	iss := issues[0]
	if _, has := iss["job"]; has {
		t.Errorf("issue carries a job key = %v, want it absent for a finding that is not about a job", iss["job"])
	}
	if iss["includePath"] != "group/project@main" {
		t.Fatalf("includePath: got %v", iss["includePath"])
	}
	if iss["gitlabIncludeLocation"] != "group/project@main" {
		t.Fatalf("gitlabIncludeLocation enrichment did not survive: got %v", iss["gitlabIncludeLocation"])
	}
	if iss["version"] != "main" {
		t.Fatalf("version enrichment did not survive: got %v", iss["version"])
	}
}
