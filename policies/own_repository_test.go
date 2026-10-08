package policies_test

import (
	"context"
	"sort"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// TestOwnRepositoryReferences_NotThirdParty pins that a reference to the
// scanned repository itself is never a third-party dependency, for the
// unauthorized-source control (ISSUE-713) and the pin-by-SHA control
// (ISSUE-701), on step actions and reusable workflow calls alike. The
// repository's own references are the local `./` form, the `$/` form
// some workflows write the same path in, and `owner/repo/...` naming the
// repository by its canonical full name (pipeline projectPath), compared
// case-insensitively. A sibling repository of the same owner is not the
// repository's own: it stays judged like any other.
func TestOwnRepositoryReferences_NotThirdParty(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	// Same-owner trust is off, so only the own-repository rule can keep
	// the repository's references quiet.
	cfg := map[string]any{
		"githubActionMustComeFromAuthorizedSources": map[string]any{
			"trustGithubOfficialActions": true,
			"trustSameOrgActions":        false,
			"minimumStars":               0,
		},
		"actionsMustBePinnedByCommitSha": map[string]any{},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider:    ir.ProviderGitHub,
		ProjectPath: "react/react",
		Jobs: []ir.Job{
			{Name: "ci/build", Uses: []ir.Action{
				{Uses: "react/react/.github/actions/setup@main", Line: 10},
				{Uses: "React/React/.github/actions/other@main", Line: 11},
				{Uses: "$/.github/actions/local", Line: 12},
				{Uses: "react/sibling@main", Line: 13},
				{Uses: "other/thing@v1", Line: 14},
			}},
			{Name: "ci/shared", ReusableWorkflowUses: "react/react/.github/workflows/shared.yml@main"},
			{Name: "ci/release", ReusableWorkflowUses: "$/.github/workflows/release.yml"},
			{Name: "ci/local", ReusableWorkflowUses: "./.github/workflows/build.yml"},
			{Name: "ci/foreign", ReusableWorkflowUses: "other/repo/.github/workflows/x.yml@v1"},
		},
	}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	hits := map[string][]string{}
	for _, f := range findings {
		if f.Code != "ISSUE-713" && f.Code != "ISSUE-701" {
			continue
		}
		uses, _ := f.Data["uses"].(string)
		hits[f.Code] = append(hits[f.Code], uses)
	}
	want := []string{"other/repo/.github/workflows/x.yml@v1", "other/thing@v1", "react/sibling@main"}
	for _, code := range []string{"ISSUE-713", "ISSUE-701"} {
		got := hits[code]
		sort.Strings(got)
		if !stringSlicesEqual(got, want) {
			t.Errorf("%s: got %v, want %v", code, got, want)
		}
	}
}

// TestOwnRepositoryReferences_UnknownProjectPath pins that, with no
// projectPath, only the path forms (`./`, `$/`) are the repository's
// own: an owner/repo reference is never trusted on missing data.
func TestOwnRepositoryReferences_UnknownProjectPath(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"githubActionMustComeFromAuthorizedSources": map[string]any{
			"trustGithubOfficialActions": true,
			"minimumStars":               0,
		},
		"actionsMustBePinnedByCommitSha": map[string]any{},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{
			{Name: "ci/release", ReusableWorkflowUses: "$/.github/workflows/release.yml"},
			{Name: "ci/shared", ReusableWorkflowUses: "react/react/.github/workflows/shared.yml@main"},
		},
	}
	findings, err := evaluateStrict(engine, context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	for _, code := range []string{"ISSUE-713", "ISSUE-701"} {
		var got []string
		for _, f := range findings {
			if f.Code == code {
				uses, _ := f.Data["uses"].(string)
				got = append(got, uses)
			}
		}
		want := []string{"react/react/.github/workflows/shared.yml@main"}
		if !stringSlicesEqual(got, want) {
			t.Errorf("%s: got %v, want %v", code, got, want)
		}
	}
}
