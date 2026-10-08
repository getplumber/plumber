package control

import (
	"reflect"
	"slices"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// The Note on an unconfirmed impact names what could not be checked: a
// push is not a deploy.
func TestTheUnverifiedNoteNamesWhatIsUnresolved(t *testing.T) {
	cases := []struct {
		kinds []string
		want  string
	}{
		{[]string{"writes_repo"}, "Plumber could not check that this job pushes to the repository"},
		{[]string{"deploys"}, "Plumber could not check that this job deploys"},
		{[]string{"publishes", "deploys"}, "Plumber could not check that this job publishes or deploys"},
	}
	for _, c := range cases {
		var impacts []ImpactFact
		for _, k := range c.kinds {
			impacts = append(impacts, ImpactFact{Kind: k, State: "unresolvable", Evidence: "step"})
		}
		p := AttackPath{BaseTier: TierCritical, Tier: TierHigh, State: PathUnverified, Modifiers: []string{"unresolvable"}, Jobs: []string{"w/j"},
			EntryKind: EntryMutableDependency, AnchorCode: CodeActionUnpinned, Entry: EntryFact{Subject: "o/a@v1"},
			Reach: Reach{Secrets: []string{"S"}, Impacts: impacts, Executes: true}}
		if notes := NewPathBlock(p, nil).Notes(); !slices.Contains(notes, c.want) {
			t.Errorf("%v: notes %q, want %q", c.kinds, notes, c.want)
		}
	}
}

// A reference computed at run time is fixed by writing a literal in place
// of the expression the line names.
func TestARunTimeReferenceFixNamesTheExpression(t *testing.T) {
	p := AttackPath{Tier: TierMedium, State: PathUnverified, Jobs: []string{"ci/build"}, EntryKind: EntryMutableDependency,
		AnchorCode: CodeImageNotPinnedByDigest, AnchorCodes: []ErrorCode{CodeImageNotPinnedByDigest},
		Entry: EntryFact{State: "unresolvable", Subject: "ghcr.io/o/${{ inputs.image }}:latest", File: ".github/workflows/ci.yml"}}
	if fix := NewPathBlock(p, nil).Fix; fix != "pin the reference to a literal in place of `${{ inputs.image }}`" {
		t.Errorf("fix %q", fix)
	}
}

// A job fed by a job of another workflow reads through that workflow.
func TestACrossWorkflowEdgeSaysThroughWorkflow(t *testing.T) {
	build := JobSituation{RefTriggers: []string{"push"}, CacheScopes: defaultScope, Feeds: []string{"release-publish/publish", "build/test"},
		FeedsVia: map[string][]string{"release-publish/publish": {FeedArtifact}, "build/test": {FeedArtifact}}}
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{
		"build/ubuntu": build, "release-publish/publish": {}, "build/test": {},
	}}
	findings := []opaengine.Finding{
		{Code: "ISSUE-701", Job: "build/ubuntu", File: ".github/workflows/build.yml", Line: 4, Data: map[string]any{"uses": "o/a@v1"}},
		{Code: "ISSUE-701", Job: "release-publish/publish", File: ".github/workflows/release-publish.yml", Line: 4, Data: map[string]any{"uses": "o/b@v1"}},
	}
	paths := assemblePaths(findings, sit)
	i := slices.IndexFunc(paths, func(p AttackPath) bool { return p.Entry.Subject == "o/a@v1" })
	b := NewPathBlock(paths[i], findings)
	want := []string{"job `publish` through workflow `release-publish.yml`", "job `test` from workflow `build.yml`"}
	if !reflect.DeepEqual(b.Branches[0].Fed, want) {
		t.Errorf("fed %q, want %q", b.Branches[0].Fed, want)
	}
}

// An entry whose findings share one identity across matrix values names
// every value it stands for.
func TestAMatrixEntryListsItsValues(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"test/test": {}}}
	f := func(image string) opaengine.Finding {
		return opaengine.Finding{Code: string(CodeImageNotPinnedByDigest), Job: "test/test", File: ".github/workflows/test.yml", Line: 58, Data: map[string]any{"link": image}}
	}
	findings := []opaengine.Finding{f("python:3.6"), f("python:2.7")}
	h1, _ := findingAnchorHash(findings[0])
	h2, _ := findingAnchorHash(findings[1])
	if h1 != h2 {
		t.Skip("the two findings do not share an identity: nothing to fold")
	}
	paths := assemblePaths(findings, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	if b := NewPathBlock(paths[0], findings); b.Entry != "one of: python:2.7, python:3.6 (mutable image tag, source not checked on GitHub)" {
		t.Errorf("entry %q", b.Entry)
	}
}
