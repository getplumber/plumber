package github

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// nestedGoldenRoot holds the recorded reproduction of spec 2026-10-16
// section 1 (testdata/nested/README.md names the commits).
var nestedGoldenRoot = filepath.Join("testdata", "nested")

// recordedFetch serves the recorded action.yml of
// thomasboni/nested-actions-<x> at main. override maps a repository letter
// to another file (the synthetic fixtures beside the recorded ones).
func recordedFetch(override map[string]string) rawFetcher {
	return func(owner, repo, ref, p string) (string, fetchStatus) {
		letter, ok := strings.CutPrefix(repo, "nested-actions-")
		if owner != "thomasboni" || ref != "main" || p != "action.yml" || !ok || len(letter) != 1 {
			return "", fetchMissing
		}
		file := filepath.Join(nestedGoldenRoot, letter, "action.yml")
		if o, has := override[letter]; has {
			file = o
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fetchMissing
		}
		return string(b), fetchOK
	}
}

// resolveRecorded collects the recorded workflow of nested-actions-a and
// resolves its closure over the recorded containers.
func resolveRecorded(t *testing.T, defs *definitionFetcher) *ir.NormalizedPipeline {
	t.Helper()
	repo := filepath.Join(nestedGoldenRoot, "a")
	jobs, _, _, partial, err := collectWorkflowJobs(repo)
	if err != nil || len(partial) != 0 || len(jobs) != 1 {
		t.Fatalf("collect: %v %v %d jobs", err, partial, len(jobs))
	}
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "thomasboni/nested-actions-a", Jobs: jobs}
	resolveNestedActions(p, defs, nestedScope{projectPath: p.ProjectPath, readLocal: diskReader(repo), localOnDisk: true})
	return p
}

// TestNestedGolden_Reproduction pins spec 2026-10-16 section 10 on the
// recorded reproduction: one job, four entries B, C, D, E in runner order
// with their via and definedIn (R1), every entry on the line of the
// outermost workflow step (R9), nothing left unexpanded.
func TestNestedGolden_Reproduction(t *testing.T) {
	t.Setenv(EnvDisableGitHubAPI, "0")
	t.Setenv(EnvMetadataToken, "test-token")
	p := resolveRecorded(t, newDefinitionFetcher(recordedFetch(nil), nil))
	got, err := json.MarshalIndent(p.Jobs[0].Uses, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(nestedGoldenRoot, "resolved_uses.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want []ir.Action
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	wantJSON, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(wantJSON) {
		t.Fatalf("resolved uses:\n%s\nwant:\n%s", got, wantJSON)
	}
	if p.Jobs[0].Name != "ci/nested" || len(p.UnexpandedActions) != 0 || p.NestedBudgetExceeded || p.NestedUnresolvedCause != "" {
		t.Fatalf("job %q, unexpanded %v, overflow %v, cause %q", p.Jobs[0].Name, p.UnexpandedActions, p.NestedBudgetExceeded, p.NestedUnresolvedCause)
	}
}

// TestNestedGolden_NestedEntryGetsTheMutableExecScan pins spec 2026-10-16
// section 4.1 (every nested entry gets its mutable-exec scan like a direct
// one, Task 1 review L3): with the synthetic E whose step pipes a script
// fetched from a moving ref into bash, the nested E entry (two levels
// down, via B then D) carries the exec tier, and the recorded B, C and D,
// which only echo, carry no signal.
func TestNestedGolden_NestedEntryGetsTheMutableExecScan(t *testing.T) {
	t.Setenv(EnvDisableGitHubAPI, "0")
	t.Setenv(EnvMetadataToken, "test-token")
	client := stubbedMetadataClient(t, func(*http.Request) (string, int) { return `{}`, http.StatusNotFound })
	defs := newDefinitionFetcher(recordedFetch(map[string]string{"e": filepath.Join(nestedGoldenRoot, "synthetic", "e", "action.yml")}), client)
	p := resolveRecorded(t, defs)
	enrichActions(p, client, defs, true, nil)
	uses := p.Jobs[0].Uses
	if len(uses) != 4 {
		t.Fatalf("entries = %d, want 4", len(uses))
	}
	for _, u := range uses {
		var mre *ir.MutableRemoteExec
		if u.Metadata != nil {
			mre = u.Metadata.MutableRemoteExec
		}
		if u.Uses == "thomasboni/nested-actions-e@main" {
			if mre == nil || mre.Tier != "exec" || !u.Nested {
				t.Fatalf("nested E: mutable exec %+v, nested %v, want tier exec", mre, u.Nested)
			}
			continue
		}
		if mre != nil {
			t.Errorf("%s: mutable exec %+v, want none", u.Uses, mre)
		}
	}
}
