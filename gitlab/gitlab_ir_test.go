package gitlab

import (
	"testing"

	"github.com/getplumber/plumber/internal/ir"
	glab "gitlab.com/gitlab-org/api/client-go"
)

// TestBuildApprovalRules covers the approval-rules projection: an unreadable
// listing stays known=false (so ISSUE-502/504 report not-evaluable), and a
// known listing projects the stable ID (stringified), the renameable name,
// the approvals count, and protected-branch coverage.
func TestBuildApprovalRules(t *testing.T) {
	// nil protection -> not known, no rules.
	if got, known := buildApprovalRules(nil); got != nil || known {
		t.Fatalf("nil protection: got %v known %v, want nil/false", got, known)
	}

	// An unreadable listing (a 403 the collector recorded) stays known=false
	// even if rules are somehow present.
	if _, known := buildApprovalRules(&GitlabProtectionAnalysisData{MRApprovalRulesKnown: false}); known {
		t.Fatal("unreadable approval-rules listing must report known=false")
	}

	data := &GitlabProtectionAnalysisData{
		MRApprovalRulesKnown: true,
		MRApprovalRules: []*glab.ProjectApprovalRule{
			{ID: 42, Name: "Security", ApprovalsRequired: 1, AppliesToAllProtectedBranches: true},
			{ID: 7, Name: "Scoped", ApprovalsRequired: 2, ProtectedBranches: []*glab.ProtectedBranch{{Name: "main"}}},
			nil,
		},
	}
	got, known := buildApprovalRules(data)
	if !known {
		t.Fatal("known listing must report known=true")
	}
	if len(got) != 2 {
		t.Fatalf("want 2 projected rules (nil entry skipped), got %d", len(got))
	}
	if r := got[0]; r.ID != "42" || r.Name != "Security" || r.ApprovalsRequired != 1 || !r.AppliesToAllProtectedBranches || r.ProtectedBranchCount != 0 {
		t.Fatalf("rule 0 projection mismatch: %+v", r)
	}
	if r := got[1]; r.ID != "7" || r.ApprovalsRequired != 2 || r.AppliesToAllProtectedBranches || r.ProtectedBranchCount != 1 {
		t.Fatalf("rule 1 projection mismatch: %+v", r)
	}
}

func TestBuildSettingsVariables(t *testing.T) {
	// nil collector data -> not known, no variables, so a control keyed on
	// these reports not-evaluable rather than a false pass.
	if got, known := buildSettingsVariables(nil); got != nil || known {
		t.Fatalf("nil data: got %v known %v, want nil/false", got, known)
	}

	// An unreadable listing (a 401/403 the collector recorded) stays
	// known=false even if variables are somehow present.
	if _, known := buildSettingsVariables(&GitlabVariablesAnalysisData{Known: false}); known {
		t.Fatal("unreadable listing must report known=false")
	}

	// A known listing projects identity + flags. The value is fetched but
	// never projected: ir.SettingsVariable has no Value field, so the secret
	// cannot leak through the IR.
	data := &GitlabVariablesAnalysisData{
		Known: true,
		Variables: []CICDVariable{
			{Name: "AWS_KEY", Type: "env_var", Environment: "*", Protected: false, Masked: true, Value: "supersecretvalue"},
		},
	}
	got, known := buildSettingsVariables(data)
	if !known {
		t.Fatal("known listing must report known=true")
	}
	if len(got) != 1 {
		t.Fatalf("want 1 projected variable, got %d", len(got))
	}
	if v := got[0]; v.Name != "AWS_KEY" || v.Type != "env_var" || v.Environment != "*" || v.Protected || !v.Masked {
		t.Fatalf("projection mismatch: %+v", v)
	}
}

// TestBuildApprovalSettings covers the approval-settings projection: unread
// settings project to nil (so ISSUE-503 reports not-evaluable), booleans are
// normalized to positive-security form (author-approval polarity inverted),
// and the two GitLab reset flags collapse onto the behaviorWhenCommitIsAdded
// ladder the way the legacy platform derived it.
func TestBuildApprovalSettings(t *testing.T) {
	// nil protection, or settings the collector could not read -> nil.
	if got := buildApprovalSettings(nil); got != nil {
		t.Fatalf("nil protection: got %+v, want nil", got)
	}
	if got := buildApprovalSettings(&GitlabProtectionAnalysisData{}); got != nil {
		t.Fatalf("unread settings (403/404): got %+v, want nil", got)
	}

	// Polarity: author approval ALLOWED and committers/editing/re-auth all
	// off must project to all-false prevent* fields.
	weak := buildApprovalSettings(&GitlabProtectionAnalysisData{
		MRApprovalSettings: &glab.ProjectApprovals{
			MergeRequestsAuthorApproval: true,
		},
	})
	if weak == nil || weak.PreventApprovalByAuthor || weak.PreventApprovalsByCommitters ||
		weak.PreventEditingApprovalRulesInMR || weak.RequireReAuthToApprove {
		t.Fatalf("weak settings projection mismatch: %+v", weak)
	}
	if weak.BehaviorWhenCommitIsAdded != ir.MRApprovalBehaviorKeepApprovals {
		t.Fatalf("neither reset flag set must project keep_approvals, got %q", weak.BehaviorWhenCommitIsAdded)
	}

	// Polarity: everything locked down projects to all-true prevent* fields.
	strict := buildApprovalSettings(&GitlabProtectionAnalysisData{
		MRApprovalSettings: &glab.ProjectApprovals{
			MergeRequestsAuthorApproval:               false,
			MergeRequestsDisableCommittersApproval:    true,
			DisableOverridingApproversPerMergeRequest: true,
			RequirePasswordToApprove:                  true,
			ResetApprovalsOnPush:                      true,
		},
	})
	if strict == nil || !strict.PreventApprovalByAuthor || !strict.PreventApprovalsByCommitters ||
		!strict.PreventEditingApprovalRulesInMR || !strict.RequireReAuthToApprove {
		t.Fatalf("strict settings projection mismatch: %+v", strict)
	}
	if strict.BehaviorWhenCommitIsAdded != ir.MRApprovalBehaviorRemoveAllApprovals {
		t.Fatalf("reset_approvals_on_push alone must project remove_all_approvals, got %q", strict.BehaviorWhenCommitIsAdded)
	}

	// selective_code_owner_removals wins the ladder's middle rung whenever it
	// is set, even alongside reset_approvals_on_push (legacy derivation).
	for _, reset := range []bool{false, true} {
		selective := buildApprovalSettings(&GitlabProtectionAnalysisData{
			MRApprovalSettings: &glab.ProjectApprovals{
				ResetApprovalsOnPush:       reset,
				SelectiveCodeOwnerRemovals: true,
			},
		})
		if selective.BehaviorWhenCommitIsAdded != ir.MRApprovalBehaviorRemoveCodeOwnerApprovals {
			t.Fatalf("selective_code_owner_removals (reset=%v) must project remove_approvals_by_code_owners, got %q", reset, selective.BehaviorWhenCommitIsAdded)
		}
	}
}

func TestToNormalizedPipeline_Empty(t *testing.T) {
	pipeline := ToNormalizedPipeline("group/project", "main", "", nil, nil, nil, nil)
	if pipeline.Provider != ir.ProviderGitLab {
		t.Fatalf("expected provider gitlab, got %q", pipeline.Provider)
	}
	if pipeline.ProjectPath != "group/project" {
		t.Fatalf("expected project path propagated, got %q", pipeline.ProjectPath)
	}
	if pipeline.DefaultBranch != "main" {
		t.Fatalf("expected default branch propagated, got %q", pipeline.DefaultBranch)
	}
	if len(pipeline.Jobs) != 0 {
		t.Fatalf("expected no jobs, got %d", len(pipeline.Jobs))
	}
}

func TestToNormalizedPipeline_JobsAndImages(t *testing.T) {
	origin := &GitlabPipelineOriginData{
		JobMap: map[string]*GitlabPipelineJobData{
			"build":  {Name: "build"},
			"deploy": {Name: "deploy"},
			"lint":   {Name: "lint"},
		},
	}
	images := &GitlabPipelineImageData{
		Images: []GitlabPipelineImageInfo{
			{Job: "build", Link: "docker.io/alpine:3.20", Name: "alpine", Tag: "3.20"},
			{Job: "deploy", Link: "registry.example.com/deployer@sha256:abcdef", Name: "deployer"},
		},
	}

	pipeline := ToNormalizedPipeline("grp/proj", "main", "", origin, images, nil, nil)

	if got := len(pipeline.Jobs); got != 3 {
		t.Fatalf("expected 3 jobs, got %d", got)
	}

	// Sorted alphabetically: build, deploy, lint
	names := []string{pipeline.Jobs[0].Name, pipeline.Jobs[1].Name, pipeline.Jobs[2].Name}
	expected := []string{"build", "deploy", "lint"}
	for i := range names {
		if names[i] != expected[i] {
			t.Fatalf("jobs[%d]: expected %q, got %q", i, expected[i], names[i])
		}
	}

	if pipeline.Jobs[0].Image == nil || pipeline.Jobs[0].Image.Tag != "3.20" {
		t.Fatalf("build job image: expected tag 3.20, got %+v", pipeline.Jobs[0].Image)
	}
	if pipeline.Jobs[1].Image == nil || pipeline.Jobs[1].Image.Digest != "sha256:abcdef" {
		t.Fatalf("deploy job image: expected digest sha256:abcdef, got %+v", pipeline.Jobs[1].Image)
	}
	if pipeline.Jobs[2].Image != nil {
		t.Fatalf("lint job: expected no image, got %+v", pipeline.Jobs[2].Image)
	}
}

func TestToNormalizedPipeline_NilJobInMap(t *testing.T) {
	origin := &GitlabPipelineOriginData{
		JobMap: map[string]*GitlabPipelineJobData{
			"valid":     {Name: "valid"},
			"corrupted": nil,
		},
	}

	pipeline := ToNormalizedPipeline("grp/proj", "main", "", origin, nil, nil, nil)
	if got := len(pipeline.Jobs); got != 1 {
		t.Fatalf("expected 1 job (nil entry skipped), got %d", got)
	}
	if pipeline.Jobs[0].Name != "valid" {
		t.Fatalf("expected valid job kept, got %q", pipeline.Jobs[0].Name)
	}
}

// TestBuildMRSettings covers the MR-settings projection. buildMRSettings copies
// eight fields straight across from GitLab's project payload, and nothing else
// exercises it: every ISSUE-506 test hand-builds an ir.MRSettings and bypasses
// the projection, so a swapped or mis-pointed field mapping would produce wrong
// compliance results with the whole suite green. Each field is given a value
// distinct from its neighbours so a transposition cannot pass by coincidence.
func TestBuildMRSettings(t *testing.T) {
	// Unread settings project to nil, so ISSUE-506 abstains and reports
	// not-evaluable rather than a false pass.
	if got := buildMRSettings(nil); got != nil {
		t.Fatalf("nil protection: got %+v, want nil", got)
	}
	if got := buildMRSettings(&GitlabProtectionAnalysisData{}); got != nil {
		t.Fatalf("unread project payload: got %+v, want nil", got)
	}

	// The four booleans are deliberately NOT all true: an alternating pattern
	// catches a mapping that points at the wrong source field.
	got := buildMRSettings(&GitlabProtectionAnalysisData{
		MRSettings: &glab.Project{
			MergeMethod:                     glab.FastForwardMerge,
			SquashOption:                    glab.SquashOptionDefaultOn,
			MergePipelinesEnabled:           true,
			MergeTrainsEnabled:              false,
			AllowMergeOnSkippedPipeline:     true,
			ResolveOutdatedDiffDiscussions:  false,
			PrintingMergeRequestLinkEnabled: true,
			RemoveSourceBranchAfterMerge:    false,
		},
	})
	if got == nil {
		t.Fatal("populated project payload projected to nil")
	}
	if got.MergeMethod != string(glab.FastForwardMerge) {
		t.Errorf("MergeMethod = %q, want %q", got.MergeMethod, glab.FastForwardMerge)
	}
	if got.SquashOption != string(glab.SquashOptionDefaultOn) {
		t.Errorf("SquashOption = %q, want %q", got.SquashOption, glab.SquashOptionDefaultOn)
	}
	if !got.MergePipelinesEnabled {
		t.Error("MergePipelinesEnabled = false, want true")
	}
	if got.MergeTrainsEnabled {
		t.Error("MergeTrainsEnabled = true, want false (mapped from the wrong field?)")
	}
	if !got.AllowMergeOnSkippedPipeline {
		t.Error("AllowMergeOnSkippedPipeline = false, want true")
	}
	if got.ResolveOutdatedDiffDiscussions {
		t.Error("ResolveOutdatedDiffDiscussions = true, want false (mapped from the wrong field?)")
	}
	if !got.PrintingMergeRequestLinkEnabled {
		t.Error("PrintingMergeRequestLinkEnabled = false, want true")
	}
	if got.RemoveSourceBranchAfterMerge {
		t.Error("RemoveSourceBranchAfterMerge = true, want false (mapped from the wrong field?)")
	}
}
