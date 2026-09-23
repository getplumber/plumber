package gitlab

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v2"

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

// TestBuildSecurityPolicyProject pins the collector-data -> IR projection that
// decides abstain vs fire for ISSUE-601. The subtle case is a successful read
// with nothing linked (Known=true, no project): the projection must return a
// non-nil state with LinkedProjectID 0 so the rule's require-any mode fires,
// rather than nil (which would abstain and silently miss an unlinked project).
func TestBuildSecurityPolicyProject(t *testing.T) {
	cases := []struct {
		name string
		in   *SecurityPolicyData
		want *ir.SecurityPolicyProjectState
	}{
		{
			name: "nil data -> nil (control disabled, never collected)",
			in:   nil,
			want: nil,
		},
		{
			name: "unreadable (Known=false, no project) -> nil (abstain)",
			in:   &SecurityPolicyData{Known: false, Project: nil},
			want: nil,
		},
		{
			name: "read OK, none linked -> non-nil Known with id 0 (must fire)",
			in:   &SecurityPolicyData{Known: true, Project: nil},
			want: &ir.SecurityPolicyProjectState{Known: true, LinkedProjectID: 0, LinkedProjectPath: ""},
		},
		{
			name: "read OK, one linked -> non-nil Known with id/path",
			in:   &SecurityPolicyData{Known: true, Project: &SecurityPolicyProjectLink{ID: 42, FullPath: "grp/pol"}},
			want: &ir.SecurityPolicyProjectState{Known: true, LinkedProjectID: 42, LinkedProjectPath: "grp/pol"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildSecurityPolicyProject(tc.in)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("expected nil projection, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected non-nil projection %+v, got nil", tc.want)
			}
			if got.Known != tc.want.Known || got.LinkedProjectID != tc.want.LinkedProjectID || got.LinkedProjectPath != tc.want.LinkedProjectPath {
				t.Fatalf("projection mismatch: got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestToNormalizedPipeline_Empty(t *testing.T) {
	pipeline := ToNormalizedPipeline("group/project", "main", "", nil, nil, nil, nil, nil)
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

	pipeline := ToNormalizedPipeline("grp/proj", "main", "", origin, images, nil, nil, nil)

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

	pipeline := ToNormalizedPipeline("grp/proj", "main", "", origin, nil, nil, nil, nil)
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

// TestBuildIncludesCarriesTemplateIdentityWithoutALatestVersion covers a
// versioned project include whose source project's tag listing could not be
// read (private repository, insufficient rights): the collector still sets
// FromPlumber and PlumberOrigin.Path from the ref alone, and buildIncludes
// must carry that identity into Path or AltPath so template-matching rules
// (pipelineMustIncludeTemplate) still recognise the include - even though no
// Current (latest) version is known.
func TestBuildIncludesCarriesTemplateIdentityWithoutALatestVersion(t *testing.T) {
	origin := &GitlabPipelineOriginData{
		Origins: []GitlabPipelineOriginDataFull{
			{
				GitlabPipelineOriginDataGeneric: GitlabPipelineOriginDataGeneric{
					OriginType:  originProject,
					FromPlumber: true,
					PlumberOrigin: GitlabPipelineJobPlumberOrigin{
						Path:          "templates/trivy/trivy",
						LatestVersion: "", // the tag listing failed
					},
					GitlabIncludeOrigin: IncludeOriginWithoutRef{
						Location: "templates/trivy/trivy.yml",
						Type:     glOriginProject,
						Project:  "my-org/templates",
					},
				},
				GitlabPipelineOriginDataProjectSpecific: GitlabPipelineOriginDataProjectSpecific{
					Version: "0.1.0",
				},
			},
		},
	}

	got := buildIncludes(origin, ".gitlab-ci.yml")
	if len(got) != 1 {
		t.Fatalf("expected exactly one include, got %d", len(got))
	}
	inc := got[0]

	if inc.Current != "" {
		t.Errorf("Current = %q, want empty (the latest version could not be determined)", inc.Current)
	}
	if inc.Path != "templates/trivy/trivy" && inc.AltPath != "templates/trivy/trivy" {
		t.Errorf("expected the template identity (templates/trivy/trivy) in Path or AltPath, got Path=%q AltPath=%q", inc.Path, inc.AltPath)
	}
}

// TestBuildIncludesExposesTemplateIdentityWhenFilePathDiffersFromTheTagName
// covers the repository layout that TestBuildIncludesCarriesTemplateIdentityWithoutALatestVersion
// does not: a template whose file path in its source project has nothing to
// do with the name its tags are pinned under. Here the include is
// `project: bigtech-150/templates/hub, ref: gitleaks@1.2.2, file: /jobs/gitleaks/gitleaks.yml`,
// which GitLab serves back with the location `jobs/gitleaks/gitleaks.yml`.
// Neither Path (`jobs/gitleaks/gitleaks.yml`) nor its extension-less AltPath
// (`jobs/gitleaks/gitleaks`) equals the template's own identity (`gitleaks`),
// so a policy requiring the template `gitleaks` has nothing to match against
// unless the identity is exposed on its own field.
func TestBuildIncludesExposesTemplateIdentityWhenFilePathDiffersFromTheTagName(t *testing.T) {
	origin := &GitlabPipelineOriginData{
		Origins: []GitlabPipelineOriginDataFull{
			{
				GitlabPipelineOriginDataGeneric: GitlabPipelineOriginDataGeneric{
					OriginType:  originProject,
					FromPlumber: true,
					PlumberOrigin: GitlabPipelineJobPlumberOrigin{
						Path: "gitleaks",
					},
					GitlabIncludeOrigin: IncludeOriginWithoutRef{
						Location: "jobs/gitleaks/gitleaks.yml",
						Type:     glOriginProject,
						Project:  "bigtech-150/templates/hub",
					},
				},
				GitlabPipelineOriginDataProjectSpecific: GitlabPipelineOriginDataProjectSpecific{
					Version: "1.2.2",
				},
			},
		},
	}

	got := buildIncludes(origin, ".gitlab-ci.yml")
	if len(got) != 1 {
		t.Fatalf("expected exactly one include, got %d", len(got))
	}
	inc := got[0]

	// The file-location forms are unaffected by this fix: they still read
	// the include's actual path in its source project.
	if inc.Path != "jobs/gitleaks/gitleaks.yml" {
		t.Errorf("Path = %q, want %q (unaffected by the identity fix)", inc.Path, "jobs/gitleaks/gitleaks.yml")
	}
	if inc.AltPath != "jobs/gitleaks/gitleaks" {
		t.Errorf("AltPath = %q, want %q (unaffected by the identity fix)", inc.AltPath, "jobs/gitleaks/gitleaks")
	}
	if inc.TemplatePath != "gitleaks" {
		t.Errorf("TemplatePath = %q, want %q (the template's own identity, from the ref)", inc.TemplatePath, "gitleaks")
	}
}

// TestBuildJobs_RunnerTags covers the dependencies-graph requirement that the
// pipeline model carries each job's runner tags (design spec
// 2026-09-23-dependencies-graph-design section 5: the push's `bom` names a
// job's runner_tags, and the CLI is the only parser of CI configuration).
//
// The merged YAML is what is read, so a `tags:` inherited from `default:` is
// already applied by GitLab and counts like a job-level one. The list is
// de-duplicated and sorted so the wire order never depends on authoring
// order, and a job with no `tags:` keeps a nil slice rather than an empty
// one, which is what keeps the key out of the JSON.
func TestBuildJobs_RunnerTags(t *testing.T) {
	const merged = `
build:
  image: node:20
  tags: [docker, linux, docker]
lint:
  image: node:20
`
	var conf GitlabCIConf
	if err := yaml.Unmarshal([]byte(merged), &conf); err != nil {
		t.Fatalf("merged fixture does not parse: %v", err)
	}
	origin := &GitlabPipelineOriginData{
		JobMap: map[string]*GitlabPipelineJobData{
			"build": {Name: "build"},
			"lint":  {Name: "lint"},
		},
		MergedConf: &conf,
	}

	byName := map[string]ir.Job{}
	for _, j := range buildJobs(origin, nil, ".gitlab-ci.yml", nil) {
		byName[j.Name] = j
	}

	if got, want := byName["build"].Tags, []string{"docker", "linux"}; !reflect.DeepEqual(got, want) {
		t.Errorf("build.Tags = %#v, want %#v (de-duplicated and sorted)", got, want)
	}
	if got := byName["lint"].Tags; got != nil {
		t.Errorf("lint.Tags = %#v, want nil: a job with no tags: keyword claims no runner tag", got)
	}
}

// TestExtractGitLabTags covers the polymorphic `tags:` keyword: GitLab accepts
// a list of strings, and authors reach the parser with a bare string or a list
// holding a non-string entry. Nothing is invented and nothing panics: entries
// are trimmed, empties dropped, non-strings skipped.
func TestExtractGitLabTags(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   any
		want []string
	}{
		{"nil", nil, nil},
		{"bare string", "docker", []string{"docker"}},
		{"blank string", "   ", nil},
		{"list", []any{" linux ", "docker", "docker"}, []string{"docker", "linux"}},
		{"list with a non-string", []any{"docker", 42, nil, ""}, []string{"docker"}},
		{"not a tags value", map[any]any{"a": "b"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractGitLabTags(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("extractGitLabTags(%#v) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}
