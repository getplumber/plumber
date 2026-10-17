package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/finding/identity"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/pbom"
	"github.com/getplumber/plumber/policies"
)

// TestNestedGolden_FindingsLinksIdentitiesAndBill pins spec 2026-10-16
// section 10 end to end on the recorded reproduction: four ISSUE-701
// findings (B direct, C and D via B, E via B then D) at the same severity
// (R5) on the workflow step (R9), with the provenance clause and the
// container URLs, their recipe 8 identities (B keeps its recipe 7 value),
// the origin metrics counting three nested entries, and four PBOM
// includes, three of them nested with their chain. The nested messages
// close on the nested fix, the direct one on the direct remediation (spec
// section 6, maintainer review of PR 549).
func TestNestedGolden_FindingsLinksIdentitiesAndBill(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "github", "testdata", "nested", "resolved_uses.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var uses []ir.Action
	if err := json.Unmarshal(raw, &uses); err != nil {
		t.Fatal(err)
	}
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "thomasboni/nested-actions-a", Jobs: []ir.Job{{
		Name: "ci/nested", OriginFile: ".github/workflows/ci.yml", OriginLine: 9, Triggers: []string{"push", "workflow_dispatch"}, Uses: uses,
	}}}
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{"actionsMustBePinnedByCommitSha": map[string]any{"trustedOwners": []any{"actions", "github"}}}
	all, failed, err := engine.EvaluateModules(context.Background(), p, cfg)
	if err != nil || len(failed) != 0 {
		t.Fatalf("evaluate: %v %v", err, failed)
	}
	var fs []opaengine.Finding
	for _, f := range all {
		if f.Code == "ISSUE-701" {
			fs = append(fs, f)
		}
	}
	l := &locationLinker{provider: "github", serverURL: "https://github.com", repo: "thomasboni/nested-actions-a", ref: "main", useRemote: true}
	l.Annotate(fs)
	control.NestedFixMessages(fs)
	b, c, d, e := "thomasboni/nested-actions-b@main", "thomasboni/nested-actions-c@main", "thomasboni/nested-actions-d@main", "thomasboni/nested-actions-e@main"
	// The half after the consequence dash: the direct remediation on B,
	// the nested fix on C, D and E (maintainer review of PR 549).
	direct := " \u2014 pin by commit SHA instead"
	nestedFix := " \u2014 pin the outermost action to a commit SHA whose definition pins this reference, or vendor the chain into `./.github/actions/` and pin it there"
	want := map[string]struct{ clause, half, url, fingerprint string }{
		b: {"", direct, "https://github.com/thomasboni/nested-actions-a/blob/main/.github/workflows/ci.yml#L13", "3d9f11bfd8c3bf94"},
		c: {", pulled in via " + b, nestedFix, "https://github.com/thomasboni/nested-actions-b/blob/main/action.yml#L8", "4fe90b2a1fdc935d"},
		d: {", pulled in via " + b, nestedFix, "https://github.com/thomasboni/nested-actions-b/blob/main/action.yml#L9", "10abe70c4cd930e4"},
		e: {", pulled in via " + b + " > " + d, nestedFix, "https://github.com/thomasboni/nested-actions-d/blob/main/action.yml#L8", "a3d46c9354db3be5"},
	}
	if len(fs) != 4 {
		t.Fatalf("ISSUE-701 findings = %d, want 4: %+v", len(fs), fs)
	}
	seen := map[string]bool{}
	for _, f := range fs {
		ref, _ := f.Data["uses"].(string)
		w, ok := want[ref]
		if !ok || seen[ref] {
			t.Fatalf("unexpected ISSUE-701 on %q", ref)
		}
		seen[ref] = true
		if f.Severity != "high" || f.File != ".github/workflows/ci.yml" || f.Line != 13 || f.URL != w.url {
			t.Errorf("%s: severity %q at %s:%d url %q, want high at .github/workflows/ci.yml:13 url %q", ref, f.Severity, f.File, f.Line, f.URL, w.url)
		}
		if (w.clause != "" && !strings.Contains(f.Message, w.clause)) || (w.clause == "" && strings.Contains(f.Message, "pulled in via")) {
			t.Errorf("%s: message %q, want clause %q", ref, f.Message, w.clause)
		}
		if !strings.HasSuffix(f.Message, w.clause+w.half) {
			t.Errorf("%s: message %q, want it to close on %q", ref, f.Message, w.clause+w.half)
		}
		if got := identity.Fingerprint(f.IdentityInput()); got != w.fingerprint {
			t.Errorf("%s: fingerprint %q, want %q", ref, got, w.fingerprint)
		}
	}
	if s := control.AggregateGitHubStats(p, nil); s.ActionRefsNested != 3 {
		t.Errorf("originActionNested = %d, want 3", s.ActionRefsNested)
	}
	doc := pbom.NewGenerator(p.ProjectPath, 0, "", "main").GenerateFromGitHubIR(p)
	nested := map[string][]string{}
	for _, inc := range doc.Includes {
		if inc.Type == "action" && inc.Nested {
			nested[inc.Location] = inc.Via
		}
	}
	wantNested := map[string][]string{
		"thomasboni/nested-actions-c": {b},
		"thomasboni/nested-actions-d": {b},
		"thomasboni/nested-actions-e": {b, d},
	}
	if len(doc.Includes) != 4 || len(nested) != len(wantNested) {
		t.Fatalf("includes = %+v", doc.Includes)
	}
	for loc, via := range wantNested {
		if !slices.Equal(nested[loc], via) {
			t.Errorf("include %s: via %v, want %v", loc, nested[loc], via)
		}
	}
}
