package policies_test

import (
	"context"
	"sort"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// TestTrustedOwnerLists_IgnoreCase pins that the trusted lists of the
// pin-by-SHA control (trustedOwners, ISSUE-701) and the authorized-source
// control (trustedGithubActions and the official owners, ISSUE-713) match
// the owner and repository of a reference without regard to case, as
// GitHub resolves them (#623). A path below the repository stays
// case-sensitive: `myorg/tools/sub` does not cover `myorg/tools/Sub/...`.
func TestTrustedOwnerLists_IgnoreCase(t *testing.T) {
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	cfg := map[string]any{
		"githubActionMustComeFromAuthorizedSources": map[string]any{
			"trustGithubOfficialActions": true,
			"trustSameOrgActions":        false,
			"minimumStars":               0,
			"trustedGithubActions":       []any{"someowner/*", "acme/deploy", "myorg/*"},
		},
		"actionsMustBePinnedByCommitSha": map[string]any{
			"trustedOwners": []any{"actions", "github", "someowner", "myorg/tools/sub"},
		},
	}
	pipeline := &ir.NormalizedPipeline{
		Provider:    ir.ProviderGitHub,
		ProjectPath: "scanned/repo",
		Jobs: []ir.Job{
			{Name: "ci/build", Uses: []ir.Action{
				{Uses: "SomeOwner/some-action@v1", Line: 10},
				{Uses: "someowner/other-action@v1", Line: 11},
				{Uses: "Actions/checkout@v4", Line: 12},
				{Uses: "GITHUB/codeql-action/init@v3", Line: 13},
				{Uses: "ACME/Deploy@v1", Line: 14},
				{Uses: "MYORG/Tools/sub/x@v1", Line: 15},
				{Uses: "myorg/tools/Sub/x@v1", Line: 16},
				{Uses: "other/thing@v1", Line: 17},
			}},
			{Name: "ci/shared", ReusableWorkflowUses: "SomeOwner/repo/.github/workflows/x.yml@v1"},
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
	want := map[string][]string{
		"ISSUE-701": {"ACME/Deploy@v1", "myorg/tools/Sub/x@v1", "other/repo/.github/workflows/x.yml@v1", "other/thing@v1"},
		"ISSUE-713": {"other/repo/.github/workflows/x.yml@v1", "other/thing@v1"},
	}
	for code, w := range want {
		got := hits[code]
		sort.Strings(got)
		if !stringSlicesEqual(got, w) {
			t.Errorf("%s: got %v, want %v", code, got, w)
		}
	}
}
