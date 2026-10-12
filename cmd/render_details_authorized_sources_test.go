package cmd

import (
	"reflect"
	"testing"

	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// TestBuildGitLabControlStats_ComponentAuthorizedSources pins the stat block
// of componentMustComeFromAuthorizedSources: only component includes count
// toward the total, and the findings are the unauthorized ones.
func TestBuildGitLabControlStats_ComponentAuthorizedSources(t *testing.T) {
	result := &control.AnalysisResult{Pipeline: &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Includes: []ir.Include{
			{Kind: "component", Source: "gitlab.com/my-group/c/build"},
			{Kind: "component", Source: "gitlab.com/components/sast/sast"},
			{Kind: "component", Source: "gitlab.com/attacker/c/backdoor"},
			{Kind: "local", Source: "ci/common.yml"},
		},
	}}
	findings := []opaengine.Finding{{Code: "ISSUE-414"}}

	got := buildGitLabControlStats("componentMustComeFromAuthorizedSources", result, nil, findings)
	want := []statLine{
		{Label: "Total Components", Value: "3"},
		{Label: "Authorized", Value: "2"},
		{Label: "Unauthorized", Value: "1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}

// TestBuildGitLabControlStats_FunctionAuthorizedSources pins the stat block
// of functionMustComeFromAuthorizedSources. Deprecated is the only
// user-visible surface of the step:-alias / git-form deprecation tracking
// (the policy deliberately ignores it), so it is pinned too.
func TestBuildGitLabControlStats_FunctionAuthorizedSources(t *testing.T) {
	result := &control.AnalysisResult{Pipeline: &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{
			{Name: "build", Functions: []ir.Function{
				{Name: "echo", Ref: "registry.gitlab.com/my-group/p/echo:1", Kind: "oci"},
				{Name: "legacy", Ref: "gitlab.com/my-group/p@v1", Kind: "git", Deprecated: true},
			}},
			{Name: "deploy", Functions: []ir.Function{
				{Name: "pwn", Ref: "registry.gitlab.com/attacker/x/backdoor:1", Kind: "oci", Deprecated: true},
			}},
			{Name: "test"},
		},
	}}
	findings := []opaengine.Finding{{Code: "ISSUE-415", Job: "deploy"}}

	got := buildGitLabControlStats("functionMustComeFromAuthorizedSources", result, nil, findings)
	want := []statLine{
		{Label: "Total Functions", Value: "3"},
		{Label: "Authorized", Value: "2"},
		{Label: "Unauthorized", Value: "1"},
		{Label: "Deprecated", Value: "2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}

// TestBuildGitLabControlStats_AuthorizedSourcesWithoutPipeline locks in what
// both blocks print when result.Pipeline is nil: totals fall to zero while
// Unauthorized still reports the findings. This is the output a broken
// Pipeline plumbing produces (see
// TestRunAnalysis_ExposesPipelineForAuthorizedSourcesStats in control), so a
// change here must be deliberate.
func TestBuildGitLabControlStats_AuthorizedSourcesWithoutPipeline(t *testing.T) {
	result := &control.AnalysisResult{}
	findings := []opaengine.Finding{{Code: "ISSUE-414"}}

	got := buildGitLabControlStats("componentMustComeFromAuthorizedSources", result, nil, findings)
	want := []statLine{
		{Label: "Total Components", Value: "0"},
		{Label: "Authorized", Value: "0"},
		{Label: "Unauthorized", Value: "1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("component stats = %+v, want %+v", got, want)
	}

	got = buildGitLabControlStats("functionMustComeFromAuthorizedSources", result, nil, nil)
	want = []statLine{
		{Label: "Total Functions", Value: "0"},
		{Label: "Authorized", Value: "0"},
		{Label: "Unauthorized", Value: "0"},
		{Label: "Deprecated", Value: "0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("function stats = %+v, want %+v", got, want)
	}
}
