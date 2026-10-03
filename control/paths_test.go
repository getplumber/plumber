package control

import (
	"encoding/json"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

func finding(code, job string, data map[string]any) opaengine.Finding {
	return opaengine.Finding{Code: code, Job: job, File: ".github/workflows/ci.yml", Line: 10, Data: data}
}

// The JSON report is a public contract: a path's reach marshals with
// camelCase keys, and modifiers and gateHashes are arrays, never null.
func TestAttackPathJSONShape(t *testing.T) {
	raw, err := json.Marshal(AttackPath{ID: "p", Reach: Reach{Secrets: []string{"S"}, TokenWrite: []string{"contents"}, Executes: true}})
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, want := range []string{`"reach":{"secrets":["S"],"tokenWrite":["contents"],"impacts":`, `"executes":true`, `"modifiers":[]`, `"gateHashes":[]`} {
		if !strings.Contains(got, want) {
			t.Errorf("JSON lacks %s: %s", want, got)
		}
	}
	for _, unwanted := range []string{`"Secrets"`, `"TokenWrite"`, `"Impacts"`, `"Executes"`, `"modifiers":null`, `"gateHashes":null`} {
		if strings.Contains(got, unwanted) {
			t.Errorf("JSON carries %s: %s", unwanted, got)
		}
	}
}

func releaseSituation(exposure string) *Situation {
	s := &Situation{Exposure: exposure, Jobs: map[string]JobSituation{}}
	j := JobSituation{
		Entries: []EntryFact{{Kind: EntryMutableDependency, State: "proven", Evidence: "some/action@v1", Subject: "some/action@v1"}},
		Impact:  []ImpactFact{{Kind: "publishes", State: "proven", Evidence: "npm publish"}},
	}
	j.Privilege.Secrets = []string{"NPM_TOKEN"}
	j.Privilege.SecretsState = "proven"
	j.Privilege.TokenWrite = []string{"contents"}
	s.Jobs["release"] = j
	return s
}

func TestReleaseMutableActionIsACriticalPath(t *testing.T) {
	paths := AssemblePaths([]opaengine.Finding{finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"})}, releaseSituation(ir.VisibilityPublic))
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	p := paths[0]
	if p.Tier != TierCritical || p.State != PathProven || p.ReachKind != "impact:publishes" || p.EntryKind != EntryMutableDependency {
		t.Errorf("path = %+v", p)
	}
	if p.Jobs[0] != "release" || p.AnchorCode != "ISSUE-713" {
		t.Errorf("anchor/jobs = %+v", p)
	}
}

func TestPrivateExposureDoesNotWeakenThirdPartyEntries(t *testing.T) {
	paths := AssemblePaths([]opaengine.Finding{finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"})}, releaseSituation(ir.VisibilityPrivate))
	if paths[0].Tier != TierCritical || len(paths[0].Modifiers) != 0 {
		t.Errorf("a tag hijack does not care about visibility: %+v", paths[0])
	}
}

func injectionSituation(exposure string, secrets []string) *Situation {
	s := &Situation{Exposure: exposure, Jobs: map[string]JobSituation{}}
	j := JobSituation{Entries: []EntryFact{
		{Kind: EntryForkPR, State: "proven", Evidence: "on: pull_request", Subject: "pull_request"},
		{Kind: EntryUntrustedExpression, State: "proven", Evidence: `echo "${{ github.event.pull_request.title }}"`, Subject: "github.event.pull_request.title"},
	}}
	j.Privilege.Secrets = secrets
	j.Privilege.SecretsState = "proven"
	s.Jobs["build"] = j
	return s
}

func TestInjectionInAnEmptyHandedJobIsMedium(t *testing.T) {
	paths := AssemblePaths([]opaengine.Finding{finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"})}, injectionSituation(ir.VisibilityPublic, nil))
	if len(paths) != 1 || paths[0].Tier != TierMedium || paths[0].ReachKind != "execution" {
		t.Fatalf("paths = %+v", paths)
	}
}

func TestPrivateExposureWeakensContributorEntries(t *testing.T) {
	paths := AssemblePaths([]opaengine.Finding{finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"})}, injectionSituation(ir.VisibilityPrivate, nil))
	if paths[0].Tier != TierLow || paths[0].Modifiers[0] != "private_exposure" {
		t.Errorf("want Low with private_exposure, got %+v", paths[0])
	}
}

func TestUnknownExposureCountsAsPublic(t *testing.T) {
	paths := AssemblePaths([]opaengine.Finding{finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"})}, injectionSituation(ir.VisibilityUnknown, nil))
	if paths[0].Tier != TierMedium || len(paths[0].Modifiers) != 0 {
		t.Errorf("unknown is public: %+v", paths[0])
	}
}

func TestGateAmplifiesAPath(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	j := sit.Jobs["release"]
	j.Impact = nil // secrets, no impact: High
	sit.Jobs["release"] = j
	findings := []opaengine.Finding{
		finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-305", "release", nil), // publish without an environment: a gate on this job
	}
	paths := AssemblePaths(findings, sit)
	if len(paths) != 1 || paths[0].Tier != TierCritical || paths[0].Modifiers[0] != "gate:ISSUE-305" || len(paths[0].GateHashes) != 1 {
		t.Errorf("want High amplified to Critical by the gate, got %+v", paths)
	}
}

func TestUnresolvableFactMarksThePathUnverifiedAndLowersIt(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	j := sit.Jobs["release"]
	j.Entries[0].State = "unresolvable"
	sit.Jobs["release"] = j
	paths := AssemblePaths([]opaengine.Finding{finding("ISSUE-716", "release", map[string]any{"uses": "some/action@v1"})}, sit)
	if paths[0].Tier != TierHigh || paths[0].State != PathUnverified || paths[0].Modifiers[0] != "unresolvable" {
		t.Errorf("path = %+v", paths[0])
	}
}

func TestOneHopWalkReachesTheFedJob(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{}}
	sit.Jobs["build"] = JobSituation{
		Entries: []EntryFact{{Kind: EntryForkPR, State: "proven", Subject: "pull_request"}, {Kind: EntryUntrustedExpression, State: "proven", Subject: "github.event.pull_request.title"}},
		Feeds:   []string{"publish"},
	}
	pub := JobSituation{Impact: []ImpactFact{{Kind: "publishes", State: "proven", Evidence: "npm publish"}}}
	pub.Privilege.Secrets = []string{"NPM_TOKEN"}
	pub.Privilege.SecretsState = "proven"
	sit.Jobs["publish"] = pub
	paths := AssemblePaths([]opaengine.Finding{finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"})}, sit)
	if len(paths) != 1 || paths[0].Tier != TierCritical || len(paths[0].Jobs) != 2 || paths[0].Jobs[1] != "publish" {
		t.Fatalf("paths = %+v", paths)
	}
}

func TestDismissedAndRoleLessFindingsAnchorNothing(t *testing.T) {
	dismissed := finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"})
	dismissed.Dismissed = true
	hygiene := finding("ISSUE-999", "release", nil)
	if paths := AssemblePaths([]opaengine.Finding{dismissed, hygiene}, releaseSituation(ir.VisibilityPublic)); len(paths) != 0 {
		t.Errorf("want no path, got %+v", paths)
	}
}

func TestTwoImpactsGiveTwoPathsOnOneAnchor(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	j := sit.Jobs["release"]
	j.Impact = append(j.Impact, ImpactFact{Kind: "deploys", State: "proven", Evidence: "environment: production"})
	sit.Jobs["release"] = j
	paths := AssemblePaths([]opaengine.Finding{finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"})}, sit)
	if len(paths) != 2 || paths[0].AnchorHash != paths[1].AnchorHash || paths[0].ID == paths[1].ID {
		t.Errorf("paths = %+v", paths)
	}
}

// Two findings sharing one identity hash (ISSUE-207 is {"file", "job"})
// but anchoring different entry facts in the same job must always resolve
// to the same winner regardless of input order: the first one in (code,
// job, file, line, message) order.
func TestSharedIdentityFindingsResolveDeterministicallyToTheFirstInSortOrder(t *testing.T) {
	sit := injectionSituation(ir.VisibilityPublic, nil)
	b := sit.Jobs["build"]
	b.Entries = append(b.Entries, EntryFact{Kind: EntryUntrustedExpression, State: "proven", Evidence: "echo other", Subject: "github.event.comment.body"})
	sit.Jobs["build"] = b

	earlier := finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"})
	earlier.Line = 10
	later := finding("ISSUE-207", "build", map[string]any{"expression": "github.event.comment.body"})
	later.Line = 20

	forward := AssemblePaths([]opaengine.Finding{earlier, later}, sit)
	backward := AssemblePaths([]opaengine.Finding{later, earlier}, sit)
	if len(forward) != 1 || !reflect.DeepEqual(forward, backward) {
		t.Fatalf("shared-identity findings must collapse to one deterministic path: forward=%+v backward=%+v", forward, backward)
	}
	if forward[0].Entry.Subject != "github.event.pull_request.title" {
		t.Errorf("want the earlier finding (by sort order) to win, got entry = %+v", forward[0].Entry)
	}
}

// gateFindings sorts by Code+Job only, which is not total when two
// gates share both but differ in identity (ISSUE-305's identity includes
// file). GateHashes/Modifiers order must not depend on the caller's input
// order even then: tie-break on the finding hash.
func TestGateFindingsOrderIsStableAcrossInputOrder(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	j := sit.Jobs["release"]
	j.Impact = nil
	sit.Jobs["release"] = j
	m := finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"})
	a := finding("ISSUE-305", "release", nil)
	a.File = ".github/workflows/a.yml"
	b := finding("ISSUE-305", "release", nil)
	b.File = ".github/workflows/b.yml"
	forward := AssemblePaths([]opaengine.Finding{m, a, b}, sit)
	backward := AssemblePaths([]opaengine.Finding{m, b, a}, sit)
	if !reflect.DeepEqual(forward, backward) {
		t.Fatalf("GateHashes/Modifiers order must not depend on input order: forward=%+v backward=%+v", forward, backward)
	}
}

// TestOutputOrderIsDeterministicUnderShuffledInput's fixture combines
// every shape that must stay order-independent: a job-bearing anchor plus
// a job-matched gate (release/ISSUE-305), an include anchor spanning two
// jobs (includeA/includeB, map-iteration order in sit.Jobs), a branch gate
// that matches the pipeline default branch regardless of which jobs a path
// walks (amplifying every path here, including the release path a second
// time: two gates on one path), and two ISSUE-207 findings in one job
// sharing an identity hash but anchoring different entry facts.
func TestOutputOrderIsDeterministicUnderShuffledInput(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	rel := sit.Jobs["release"]
	rel.Impact = nil // secrets, no impact: High base, so both gates below are observable
	sit.Jobs["release"] = rel
	sit.DefaultBranch = "main"
	for name, j := range injectionSituation(ir.VisibilityPublic, nil).Jobs {
		sit.Jobs[name] = j
	}
	build := sit.Jobs["build"]
	build.Entries = append(build.Entries, EntryFact{Kind: EntryUntrustedExpression, State: "proven", Evidence: "echo other", Subject: "github.event.comment.body"})
	sit.Jobs["build"] = build
	for name, j := range includeSituation(ir.VisibilityPublic, "includeA", "includeB").Jobs {
		sit.Jobs[name] = j
	}

	earlier207 := finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"})
	earlier207.Line = 10
	later207 := finding("ISSUE-207", "build", map[string]any{"expression": "github.event.comment.body"})
	later207.Line = 20

	findings := []opaengine.Finding{
		finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-305", "release", nil),
		finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"}),
		finding("ISSUE-404", "", map[string]any{"includePath": "org/repo/template.yml"}),
		earlier207, later207,
	}
	want := AssemblePaths(findings, sit)
	if len(want) == 0 {
		t.Fatal("fixture produced no paths at all, the shuffle below would be vacuous")
	}
	for seed := int64(1); seed <= 20; seed++ {
		shuffled := append([]opaengine.Finding(nil), findings...)
		r := rand.New(rand.NewSource(seed))
		r.Shuffle(len(shuffled), func(i, k int) { shuffled[i], shuffled[k] = shuffled[k], shuffled[i] })
		got := AssemblePaths(shuffled, sit)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("seed %d: order-dependent result\n got  %+v\n want %+v", seed, got, want)
		}
	}
}

// --- Reach.Executes is true for every path, including an unprotected_push
// entry anchored by its own gate finding, which has no script of its own
// on the walked job. ---

func unprotectedPushSituation(exposure string) *Situation {
	s := &Situation{Exposure: exposure, Jobs: map[string]JobSituation{}}
	s.Jobs["build"] = JobSituation{
		Entries: []EntryFact{{Kind: EntryUnprotectedPush, State: "proven", Evidence: "push: branches: [main]", Subject: "main"}},
	}
	return s
}

func TestUnprotectedPushGateFindingAnchorsItsOwnEntryFactAndAlwaysExecutes(t *testing.T) {
	f := finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"})
	paths := AssemblePaths([]opaengine.Finding{f}, unprotectedPushSituation(ir.VisibilityPublic))
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	p := paths[0]
	if p.EntryKind != EntryUnprotectedPush || p.Jobs[0] != "build" || p.AnchorCode != CodeBranchUnprotected {
		t.Errorf("unprotected push path = %+v", p)
	}
	if !p.Reach.Executes {
		t.Errorf("Executes must be true for every path (Reach.Executes is documented as always true): %+v", p)
	}
	// The finding that anchors this path is also a RoleGate finding (it is
	// the 501 itself), but it never amplifies the path it anchors.
	if p.Tier != p.BaseTier {
		t.Errorf("an anchor must never amplify its own path: tier %s, base %s", p.Tier, p.BaseTier)
	}
	if len(p.GateHashes) != 0 {
		t.Errorf("an anchor must not list itself in GateHashes: %+v", p.GateHashes)
	}
}

func TestBranchNonCompliantAlsoAnchorsUnprotectedPush(t *testing.T) {
	f := finding(string(CodeBranchNonCompliant), "", map[string]any{"branchName": "main"})
	paths := AssemblePaths([]opaengine.Finding{f}, unprotectedPushSituation(ir.VisibilityPublic))
	if len(paths) != 1 || paths[0].EntryKind != EntryUnprotectedPush {
		t.Errorf("want ISSUE-505 to anchor the same way as ISSUE-501, got %+v", paths)
	}
}

// One gate finding amplifies a path at most once, even when it matches
// through more than one walked job. The fed job's declared "contents"
// write token is what lets a branch gate amplify the path at all.
func TestGateMatchingTwoWalkedJobsAmplifiesOnlyOnce(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{}}
	sit.Jobs["build"] = JobSituation{
		Entries: []EntryFact{
			{Kind: EntryMutableDependency, State: "proven", Evidence: "some/action@v1", Subject: "some/action@v1"},
			{Kind: EntryUnprotectedPush, State: "proven", Evidence: "push: branches: [main]", Subject: "main"},
		},
		Feeds: []string{"deploy"},
	}
	deploy := JobSituation{
		Entries: []EntryFact{{Kind: EntryUnprotectedPush, State: "proven", Evidence: "push: branches: [main]", Subject: "main"}},
	}
	deploy.Privilege.TokenWrite = []string{"contents"}
	deploy.Privilege.TokenWriteSource = "declared"
	sit.Jobs["deploy"] = deploy
	findings := []opaengine.Finding{
		finding("ISSUE-713", "build", map[string]any{"uses": "some/action@v1"}),
		finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"}),
	}
	paths := AssemblePaths(findings, sit)
	var p *AttackPath
	for i := range paths {
		if paths[i].AnchorCode == "ISSUE-713" {
			p = &paths[i]
		}
	}
	if p == nil {
		t.Fatalf("want a path anchored by ISSUE-713, got %+v", paths)
	}
	if p.Tier != tierShift(p.BaseTier, 1) {
		t.Errorf("want the gate to raise the tier by exactly one step, got base %s tier %s", p.BaseTier, p.Tier)
	}
	gateCount := 0
	for _, m := range p.Modifiers {
		if m == "gate:ISSUE-501" {
			gateCount++
		}
	}
	if gateCount != 1 {
		t.Errorf("want gate:ISSUE-501 listed once despite matching two walked jobs, got %+v", p.Modifiers)
	}
	if len(p.GateHashes) != 1 {
		t.Errorf("want one gate hash, got %v", p.GateHashes)
	}
}

// A default-branch gate amplifies a path only when the path's reach
// writes the repository (a writes_repo impact, or a surviving "contents"
// write token), not merely because it runs on the default branch's data.
// A fork_pr path whose fed job keeps a declared "contents" write token
// (the entry job's own privilege is pruned, but the fed job's is not) is
// amplified once, not only through a push-triggered job.
func TestDefaultBranchGateAmplifiesAForkPRPathThatReachesAContentsWriteToken(t *testing.T) {
	sit := injectionSituation(ir.VisibilityPublic, nil)
	build := sit.Jobs["build"]
	build.Feeds = []string{"deploy"}
	sit.Jobs["build"] = build
	deploy := JobSituation{}
	deploy.Privilege.TokenWrite = []string{"contents"}
	deploy.Privilege.TokenWriteSource = "declared"
	sit.Jobs["deploy"] = deploy
	sit.DefaultBranch = "main"
	findings := []opaengine.Finding{
		finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"}),
		finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"}),
	}
	paths := AssemblePaths(findings, sit)
	var p *AttackPath
	for i := range paths {
		if paths[i].AnchorCode == "ISSUE-207" {
			p = &paths[i]
		}
	}
	if p == nil {
		t.Fatalf("want a path anchored by ISSUE-207, got %+v", paths)
	}
	if p.BaseTier != TierHigh || p.Tier != TierCritical || p.Modifiers[0] != "gate:ISSUE-501" {
		t.Errorf("want a 501 on the default branch to raise the contents-write fork_pr path from High to Critical, got %+v", p)
	}
}

// A branch gate's sentence names the branch it is about, the slot the
// spec's modifier clause carries ("and `main` accepts unreviewed pushes"):
// the gate's title alone does not say which branch is unprotected.
func TestBranchGateSentenceNamesTheBranch(t *testing.T) {
	sit := injectionSituation(ir.VisibilityPublic, nil)
	build := sit.Jobs["build"]
	build.Feeds = []string{"deploy"}
	sit.Jobs["build"] = build
	deploy := JobSituation{}
	deploy.Privilege.TokenWrite = []string{"contents"}
	deploy.Privilege.TokenWriteSource = "declared"
	sit.Jobs["deploy"] = deploy
	sit.DefaultBranch = "main"
	findings := []opaengine.Finding{
		finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"}),
		finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"}),
	}
	for _, p := range AssemblePaths(findings, sit) {
		if p.AnchorCode != "ISSUE-207" {
			continue
		}
		if got := PathSentence(p); !strings.Contains(got, "Nothing stands between this and the default branch: Branch protection missing on `main`.") {
			t.Errorf("want the gate sentence to name `main`, got %q", got)
		}
		return
	}
	t.Fatal("want a path anchored by ISSUE-207")
}

// An unprotected default branch protects nothing on a path that never
// writes to it. The demo's shape (a fork_pr entry on ci/build, execution
// only, no secret, no write token) is not amplified by a 501 on `main`.
func TestDefaultBranchGateDoesNotAmplifyAnExecutionOnlyPath(t *testing.T) {
	sit := injectionSituation(ir.VisibilityPublic, nil)
	sit.DefaultBranch = "main"
	findings := []opaengine.Finding{
		finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"}),
		finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"}),
	}
	paths := AssemblePaths(findings, sit)
	var p *AttackPath
	for i := range paths {
		if paths[i].AnchorCode == "ISSUE-207" {
			p = &paths[i]
		}
	}
	if p == nil {
		t.Fatalf("want a path anchored by ISSUE-207, got %+v", paths)
	}
	if p.Tier != p.BaseTier || len(p.Modifiers) != 0 || len(p.GateHashes) != 0 {
		t.Errorf("want an execution-only path untouched by the default-branch gate, got %+v", p)
	}
}

// A branch gate matched through a walked push-triggered job obeys the same
// rule as the default-branch clause: it amplifies only a path whose reach
// writes the repository. The most common CI shape (on: [push,
// pull_request] with an injection, holding nothing) stays Medium with no
// gate modifier, since the 501 already prices the branch on its own
// unprotected_push path.
func TestPushTriggeredBranchGateDoesNotAmplifyAnExecutionOnlyPath(t *testing.T) {
	sit := injectionSituation(ir.VisibilityPublic, nil)
	build := sit.Jobs["build"]
	build.Entries = append(build.Entries, EntryFact{Kind: EntryUnprotectedPush, State: "proven", Evidence: "on: [push, pull_request]", Subject: "main"})
	sit.Jobs["build"] = build
	sit.DefaultBranch = "main"
	findings := []opaengine.Finding{
		finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"}),
		finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"}),
	}
	var p *AttackPath
	paths := AssemblePaths(findings, sit)
	for i := range paths {
		if paths[i].AnchorCode == "ISSUE-207" {
			p = &paths[i]
		}
	}
	if p == nil {
		t.Fatalf("want a path anchored by ISSUE-207, got %+v", paths)
	}
	if p.Tier != TierMedium || len(p.Modifiers) != 0 || len(p.GateHashes) != 0 {
		t.Errorf("want the execution-only path Medium with no gate modifier, got %+v", p)
	}
}

// reachWritesRepo backs the default-branch gate rule directly: a
// writes_repo impact or a "contents" write token says yes, anything else
// (secrets, a read-only token, execution alone) says no.
func TestReachWritesRepoChecksImpactAndTokenWrite(t *testing.T) {
	cases := []struct {
		name string
		r    Reach
		want bool
	}{
		{"writes_repo impact", Reach{Impacts: []ImpactFact{{Kind: "writes_repo", State: "proven", Evidence: "git push"}}}, true},
		{"contents write token", Reach{TokenWrite: []string{"contents"}}, true},
		{"other write token", Reach{TokenWrite: []string{"issues"}}, false},
		{"secrets only", Reach{Secrets: []string{"NPM_TOKEN"}}, false},
		{"publishes impact", Reach{Impacts: []ImpactFact{{Kind: "publishes", State: "proven", Evidence: "npm publish"}}}, false},
		{"execution only", Reach{Executes: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := reachWritesRepo(tc.r); got != tc.want {
				t.Errorf("reachWritesRepo(%+v) = %v, want %v", tc.r, got, tc.want)
			}
		})
	}
}

// --- A job-less finding (ISSUE-404/ISSUE-402 on an
// include, no "job" field) anchors through every JobSituation carrying a
// matching mutable_dependency fact, one path per reached job, sharing the
// anchor hash. ---

func includeSituation(exposure string, jobNames ...string) *Situation {
	s := &Situation{Exposure: exposure, Jobs: map[string]JobSituation{}}
	for _, name := range jobNames {
		s.Jobs[name] = JobSituation{
			Entries: []EntryFact{{Kind: EntryMutableDependency, State: "proven", Evidence: "include org/repo/template.yml@main", Subject: "org/repo/template.yml@main"}},
			Impact:  []ImpactFact{{Kind: "deploys", State: "proven", Evidence: "environment: production"}},
		}
	}
	return s
}

func TestJobLessIncludeFindingAnchorsEveryJobCarryingTheFact(t *testing.T) {
	sit := includeSituation(ir.VisibilityPublic, "build", "deploy")
	f := finding("ISSUE-404", "", map[string]any{"includePath": "org/repo/template.yml"})
	paths := AssemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 2 {
		t.Fatalf("want one path per job carrying the include fact, got %+v", paths)
	}
	if paths[0].AnchorHash != paths[1].AnchorHash {
		t.Errorf("paths from one include share the anchor: %+v", paths)
	}
	if paths[0].ID == paths[1].ID {
		t.Errorf("want distinct ids per entry job, got %+v", paths)
	}
	entryJobs := map[string]bool{paths[0].Jobs[0]: true, paths[1].Jobs[0]: true}
	if !entryJobs["build"] || !entryJobs["deploy"] {
		t.Errorf("want each job carrying the fact as its own entry job, got %+v", paths)
	}
}

func TestJobLessFindingWithNoMatchingFactAnchorsNothing(t *testing.T) {
	sit := includeSituation(ir.VisibilityPublic, "build")
	f := finding("ISSUE-404", "", map[string]any{"includePath": "org/other/unrelated.yml"})
	if paths := AssemblePaths([]opaengine.Finding{f}, sit); len(paths) != 0 {
		t.Errorf("want no path for an unmatched include, got %+v", paths)
	}
}

// A job-less include finding anchors a fact iff subject == includePath
// or strings.HasPrefix(subject, includePath+"@"), never a substring match in
// either direction, and never by splitting the subject on "@".
func TestJobLessIncludeMatchingIsExactNotSubstring(t *testing.T) {
	sit := includeSituation(ir.VisibilityPublic, "build")
	// subject is "org/repo/template.yml@main".
	fragment := finding("ISSUE-404", "", map[string]any{"includePath": "template.yml"})
	if paths := AssemblePaths([]opaengine.Finding{fragment}, sit); len(paths) != 0 {
		t.Errorf("a bare filename fragment must not anchor the include, got %+v", paths)
	}
	repo := finding("ISSUE-404", "", map[string]any{"includePath": "repo"})
	if paths := AssemblePaths([]opaengine.Finding{repo}, sit); len(paths) != 0 {
		t.Errorf("a substring of the path must not anchor the include, got %+v", paths)
	}
	exact := finding("ISSUE-404", "", map[string]any{"includePath": "org/repo/template.yml"})
	if paths := AssemblePaths([]opaengine.Finding{exact}, sit); len(paths) != 1 {
		t.Errorf("the exact source before @ref must anchor the include, got %+v", paths)
	}
}

func TestJobLessIncludeMatchingRejectsASiblingPath(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{
		"build": {
			Entries: []EntryFact{{Kind: EntryMutableDependency, State: "proven", Evidence: "include b/a/ci.yml@main", Subject: "b/a/ci.yml@main"}},
			Impact:  []ImpactFact{{Kind: "deploys", State: "proven", Evidence: "environment: production"}},
		},
	}}
	f := finding("ISSUE-404", "", map[string]any{"includePath": "a/ci.yml"})
	if paths := AssemblePaths([]opaengine.Finding{f}, sit); len(paths) != 0 {
		t.Errorf("a sibling path sharing a suffix must not anchor the include, got %+v", paths)
	}
}

func TestJobLessIncludeMatchingAllowsAComponentSubjectCarryingItsOwnVersion(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{
		"build": {
			Entries: []EntryFact{{Kind: EntryMutableDependency, State: "proven", Evidence: "include x/comp@1.0@1.0", Subject: "x/comp@1.0@1.0"}},
			Impact:  []ImpactFact{{Kind: "deploys", State: "proven", Evidence: "environment: production"}},
		},
	}}
	f := finding("ISSUE-404", "", map[string]any{"includePath": "x/comp@1.0"})
	if paths := AssemblePaths([]opaengine.Finding{f}, sit); len(paths) != 1 {
		t.Errorf("a component location that already carries @version must still anchor, got %+v", paths)
	}
}

// --- A walked job's default (assumed) token write, with no secret and no
// declared token anywhere on the path, is unresolvable: the path is marked
// unverified and lowered a tier, same as any other unresolvable fact. ---

func defaultTokenSituation(exposure string) *Situation {
	s := &Situation{Exposure: exposure, Jobs: map[string]JobSituation{}}
	j := JobSituation{
		Entries: []EntryFact{{Kind: EntryMutableDependency, State: "proven", Evidence: "some/action@v1", Subject: "some/action@v1"}},
	}
	j.Privilege.TokenWrite = []string{"contents"}
	j.Privilege.TokenWriteSource = "default"
	s.Jobs["release"] = j
	return s
}

func TestDefaultTokenAsOnlyPrivilegeIsUnresolvable(t *testing.T) {
	f := finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"})
	paths := AssemblePaths([]opaengine.Finding{f}, defaultTokenSituation(ir.VisibilityPublic))
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	p := paths[0]
	if p.Tier != TierMedium || p.State != PathUnverified || p.Modifiers[0] != "unresolvable" {
		t.Errorf("a default token alone is an assumption, want Medium/unverified: %+v", p)
	}
}

func TestDeclaredTokenIsNotUnresolvable(t *testing.T) {
	sit := defaultTokenSituation(ir.VisibilityPublic)
	j := sit.Jobs["release"]
	j.Privilege.TokenWriteSource = "declared"
	sit.Jobs["release"] = j
	f := finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"})
	paths := AssemblePaths([]opaengine.Finding{f}, sit)
	if paths[0].Tier != TierHigh || paths[0].State != PathProven || len(paths[0].Modifiers) != 0 {
		t.Errorf("a declared token write stays proven: %+v", paths[0])
	}
}

func TestSecretAlongsideDefaultTokenIsNotUnresolvable(t *testing.T) {
	sit := defaultTokenSituation(ir.VisibilityPublic)
	j := sit.Jobs["release"]
	j.Privilege.Secrets = []string{"NPM_TOKEN"}
	j.Privilege.SecretsState = "proven"
	sit.Jobs["release"] = j
	f := finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"})
	paths := AssemblePaths([]opaengine.Finding{f}, sit)
	if paths[0].State != PathProven || len(paths[0].Modifiers) != 0 {
		t.Errorf("a secret on the path keeps it proven even with a default token: %+v", paths[0])
	}
}

// Feeds naming a job absent from the situation must not break the walk,
// and a finding whose own Job is absent from the situation anchors
// nothing.
func TestFeedsNamingAMissingJobIsSkipped(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	j := sit.Jobs["release"]
	j.Feeds = []string{"ghost"}
	sit.Jobs["release"] = j
	paths := AssemblePaths([]opaengine.Finding{finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"})}, sit)
	if len(paths) != 1 || paths[0].Tier != TierCritical {
		t.Errorf("a Feeds entry naming a missing job must not break the walk, got %+v", paths)
	}
}

func TestFindingWithJobAbsentFromSituationAnchorsNothing(t *testing.T) {
	f := finding("ISSUE-713", "ghost", map[string]any{"uses": "some/action@v1"})
	if paths := AssemblePaths([]opaengine.Finding{f}, releaseSituation(ir.VisibilityPublic)); len(paths) != 0 {
		t.Errorf("want no path for a finding whose job is missing from the situation, got %+v", paths)
	}
}

// Jobs lists each job once and Reach.Impacts never doubles, even when a
// job feeds itself and feeds a job absent from the situation.
func TestJobsListDedupesAndSkipsAFeedToItselfAndAMissingJob(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	j := sit.Jobs["release"]
	j.Feeds = []string{"release", "ghost"}
	sit.Jobs["release"] = j
	paths := AssemblePaths([]opaengine.Finding{finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"})}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	p := paths[0]
	if !reflect.DeepEqual(p.Jobs, []string{"release"}) {
		t.Errorf("want Jobs deduped to [release], got %v", p.Jobs)
	}
	if len(p.Reach.Impacts) != 1 {
		t.Errorf("want impacts counted once despite the self-feed, got %+v", p.Reach.Impacts)
	}
}

// Rule 1's fallback to the first fact of the kind, when the finding's
// structured data names no subject that matches any fact.
func TestNoMatchingSubjectFallsBackToTheFirstFactOfTheKind(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	j := sit.Jobs["release"]
	j.Entries = append(j.Entries, EntryFact{Kind: EntryMutableDependency, State: "proven", Evidence: "other/action@v1", Subject: "other/action@v1"})
	sit.Jobs["release"] = j
	// No "uses" key at all: nothing in the finding's data can match any
	// fact's subject, so matchEntryFact must fall back to the first fact of
	// EntryMutableDependency, "some/action@v1".
	f := finding("ISSUE-713", "release", nil)
	paths := AssemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 1 || paths[0].Entry.Subject != "some/action@v1" {
		t.Errorf("want the fallback to the first fact of the kind, got %+v", paths)
	}
}

// When several modifiers apply to one path, they are recorded in a fixed
// order: private_exposure, then unresolvable, then one gate per matching
// code.
func TestModifiersAppearInFixedOrderPrivateThenUnresolvableThenGate(t *testing.T) {
	sit := injectionSituation(ir.VisibilityPrivate, nil)
	j := sit.Jobs["build"]
	j.Entries[1].State = "unresolvable" // the untrusted_expression entry fact
	sit.Jobs["build"] = j
	findings := []opaengine.Finding{
		finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"}),
		finding("ISSUE-305", "build", nil), // a gate on the same job
	}
	paths := AssemblePaths(findings, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	want := []string{"private_exposure", "unresolvable", "gate:ISSUE-305"}
	if !reflect.DeepEqual(paths[0].Modifiers, want) {
		t.Errorf("modifiers = %v, want %v", paths[0].Modifiers, want)
	}
}

// Tier clamping at both ends. Low never drops below Low even with two
// down-modifiers; Critical never rises above Critical even with a gate.
func TestLowTierClampsAtTheFloorWithTwoDownModifiers(t *testing.T) {
	sit := injectionSituation(ir.VisibilityPrivate, nil)
	j := sit.Jobs["build"]
	j.Entries[1].State = "unresolvable"
	sit.Jobs["build"] = j
	f := finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"})
	paths := AssemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 1 || paths[0].Tier != TierLow || len(paths[0].Modifiers) != 2 {
		t.Errorf("want Low clamped at the floor with both down-modifiers recorded, got %+v", paths[0])
	}
}

func TestCriticalTierClampsAtTheCeilingWithAGate(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic) // secrets + token + impact: Critical already
	findings := []opaengine.Finding{
		finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-305", "release", nil),
	}
	paths := AssemblePaths(findings, sit)
	if len(paths) != 1 || paths[0].Tier != TierCritical || paths[0].BaseTier != TierCritical || paths[0].Modifiers[0] != "gate:ISSUE-305" {
		t.Errorf("want Critical to stay Critical when a gate amplifies it further, got %+v", paths[0])
	}
}

// --- Platform reach rules. A GitHub fork pull_request run has no secrets
// and a read-only token; a GitLab fork MR pipeline sees no protected
// variable; pull_request_target keeps everything (the secrets are the
// base repository's own). ---

func TestForkPRJobOnGitHubGetsNoSecrets(t *testing.T) {
	sit := injectionSituation(ir.VisibilityPublic, []string{"NPM_TOKEN"})
	j := sit.Jobs["build"]
	j.Privilege.TokenWrite = []string{"contents", "packages"} // the permissive default
	sit.Jobs["build"] = j
	paths := AssemblePaths([]opaengine.Finding{finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"})}, sit)
	if paths[0].Tier != TierMedium || len(paths[0].Reach.Secrets) != 0 || len(paths[0].Reach.TokenWrite) != 0 {
		t.Errorf("a fork pull_request run never sees secrets or a write token: %+v", paths[0])
	}
}

func TestPRTargetJobKeepsItsSecrets(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{}}
	j := JobSituation{Entries: []EntryFact{{Kind: EntryPRTarget, State: "proven", Evidence: "on: pull_request_target + checkout ref github.event.pull_request.head.sha", Subject: "github.event.pull_request.head.sha"}}}
	j.Privilege.Secrets = []string{"NPM_TOKEN"}
	j.Privilege.SecretsState = "proven"
	sit.Jobs["build"] = j
	paths := AssemblePaths([]opaengine.Finding{finding("ISSUE-802", "build", nil)}, sit)
	if paths[0].Tier != TierHigh || len(paths[0].Reach.Secrets) != 1 {
		t.Errorf("pull_request_target runs with the base repository's secrets: %+v", paths[0])
	}
}

func TestGitLabForkMRDropsProtectedVariablesOnly(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{}}
	j := JobSituation{Entries: []EntryFact{
		{Kind: EntryForkPR, State: "proven", Evidence: "rules: merge_request_event", Subject: "merge_request_event"},
		{Kind: EntryUntrustedExpression, State: "proven", Evidence: `echo "$CI_MERGE_REQUEST_TITLE"`, Subject: "$CI_MERGE_REQUEST_TITLE"},
	}}
	j.Privilege.Secrets = []string{"NPM_TOKEN", "STAGING_URL"}
	j.Privilege.ProtectedSecrets = []string{"NPM_TOKEN"}
	j.Privilege.SecretsState = "proven"
	sit.Jobs["test"] = j
	paths := AssemblePaths([]opaengine.Finding{finding("ISSUE-207", "test", map[string]any{"variableName": "CI_MERGE_REQUEST_TITLE"})}, sit)
	if paths[0].Tier != TierHigh || !reflect.DeepEqual(paths[0].Reach.Secrets, []string{"STAGING_URL"}) {
		t.Errorf("only the unprotected variable is reachable from a fork MR: %+v", paths[0])
	}
}

// --- The default-token unresolvable check must read the reach AFTER
// the platform rules pruned it. A fork pull_request run drops the default
// token entirely (GitHub never hands it a write token at all), so the
// dropped token must not make the path unresolvable: there is nothing left
// on the path to be unsure about. ---

func TestForkPRWithOnlyADefaultTokenIsNotUnresolvable(t *testing.T) {
	sit := injectionSituation(ir.VisibilityPublic, nil)
	j := sit.Jobs["build"]
	j.Privilege.TokenWrite = []string{"contents"}
	j.Privilege.TokenWriteSource = "default"
	sit.Jobs["build"] = j
	paths := AssemblePaths([]opaengine.Finding{finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"})}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	p := paths[0]
	if p.Tier != TierMedium || p.State != PathProven || len(p.Modifiers) != 0 {
		t.Errorf("a fork run's default token is dropped, not left as an unresolvable guess: %+v", p)
	}
}

// Two fed non-fork jobs sharing a secret name must list it once.
// Reach.Secrets and Reach.TokenWrite are documented as the sorted SET of
// what is reachable, never a multiset.
func TestForkPRFedJobsSharingASecretListItOnce(t *testing.T) {
	sit := injectionSituation(ir.VisibilityPublic, nil)
	build := sit.Jobs["build"]
	build.Feeds = []string{"deployA", "deployB"}
	sit.Jobs["build"] = build
	mk := func() JobSituation {
		j := JobSituation{}
		j.Privilege.Secrets = []string{"NPM_TOKEN"}
		j.Privilege.SecretsState = "proven"
		j.Privilege.TokenWrite = []string{"contents"}
		j.Privilege.TokenWriteSource = "declared"
		return j
	}
	sit.Jobs["deployA"] = mk()
	sit.Jobs["deployB"] = mk()
	paths := AssemblePaths([]opaengine.Finding{finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"})}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	if !reflect.DeepEqual(paths[0].Reach.Secrets, []string{"NPM_TOKEN"}) {
		t.Errorf("want the shared secret deduped to one entry, got %+v", paths[0].Reach.Secrets)
	}
	if !reflect.DeepEqual(paths[0].Reach.TokenWrite, []string{"contents"}) {
		t.Errorf("want the shared scope deduped to one entry, got %+v", paths[0].Reach.TokenWrite)
	}
}

// Spec section 2, "findings on no path": an entry-role finding whose job
// carries no fact of its own kind still anchors a path, synthesized from
// the finding itself, rather than dropping silently to hygiene.
func TestEntryFindingWithNoMatchingFactSynthesizesAPath(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{
		"build": {}, // no entry facts, no privilege, no impact: nothing reachable
	}}
	f := finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"})
	paths := AssemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one synthesized path, got %+v", paths)
	}
	p := paths[0]
	if p.Tier != TierLow || p.State != PathUnverified || p.EntryKind != EntryUntrustedExpression {
		t.Errorf("want a Low unverified synthesized path, got %+v", p)
	}
	if p.Entry.Subject != "github.event.pull_request.title" || p.Entry.State != "unresolvable" {
		t.Errorf("want the synthesized fact to carry the finding's own subject, got %+v", p.Entry)
	}
	if p.Jobs[0] != "build" {
		t.Errorf("want the finding's own job as the entry job, got %+v", p.Jobs)
	}
}

// A synthesized path still reaches real privilege when the job holds
// any, through the normal reach computation, not forced to Low.
func TestEntryFindingWithNoMatchingFactStillReachesRealPrivilege(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic) // "release": secrets + token + impact
	f := finding("ISSUE-207", "release", map[string]any{"expression": "github.event.pull_request.title"})
	paths := AssemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	p := paths[0]
	// The reach (secrets, token, impact) is real and proven; only the
	// entry itself is a guess, so the modifier lowers the real base tier
	// by one, it does not clamp straight to Low.
	if p.BaseTier != TierCritical || p.Tier != TierHigh || p.State != PathUnverified {
		t.Errorf("want the real reach lowered by one tier, got %+v", p)
	}
}

// A branch-protection gate (ISSUE-501/ISSUE-505) never amplifies an
// unprotected_push path; two branch gates on the same branch must not
// raise each other's paths. A branch gate still amplifies every OTHER
// entry kind that writes the repository, including through the
// default-branch rule: the fork path's fed job keeps a declared
// "contents" write token.
func TestBranchGatesNeverAmplifyEachOthersUnprotectedPushPath(t *testing.T) {
	sit := unprotectedPushSituation(ir.VisibilityPublic)
	sit.DefaultBranch = "main"
	for name, j := range injectionSituation(ir.VisibilityPublic, nil).Jobs {
		sit.Jobs[name] = j
	}
	build := sit.Jobs["build"]
	build.Feeds = []string{"deploy"}
	sit.Jobs["build"] = build
	deploy := JobSituation{}
	deploy.Privilege.TokenWrite = []string{"contents"}
	deploy.Privilege.TokenWriteSource = "declared"
	sit.Jobs["deploy"] = deploy
	findings := []opaengine.Finding{
		finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"}),
		finding(string(CodeBranchNonCompliant), "", map[string]any{"branchName": "main"}),
		finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"}),
	}
	paths := AssemblePaths(findings, sit)
	var forkPath *AttackPath
	for i := range paths {
		switch paths[i].AnchorCode {
		case "ISSUE-501", "ISSUE-505":
			if paths[i].Tier != paths[i].BaseTier || len(paths[i].GateHashes) != 0 {
				t.Errorf("an unprotected_push path must never be amplified by the other branch gate: %+v", paths[i])
			}
		case "ISSUE-207":
			forkPath = &paths[i]
		}
	}
	if forkPath == nil || len(forkPath.GateHashes) != 2 {
		t.Fatalf("want the fork_pr path amplified once per gate, got %+v", forkPath)
	}
}

// --- The unresolvable check (SecretsState, declared vs default token)
// must read the jobs whose privilege survived pruning, not every walked
// job, or a dropped job's own token source/secrets state can make a
// pruned path wrongly (or wrongly not) unresolvable. ---

func TestForkEntryDeclaredTokenDoesNotMaskAFedJobsDefaultToken(t *testing.T) {
	sit := injectionSituation(ir.VisibilityPublic, nil)
	build := sit.Jobs["build"]
	build.Privilege.TokenWrite = []string{"issues"}
	build.Privilege.TokenWriteSource = "declared"
	build.Feeds = []string{"deploy"}
	sit.Jobs["build"] = build
	deploy := JobSituation{}
	deploy.Privilege.TokenWrite = []string{"contents"}
	deploy.Privilege.TokenWriteSource = "default"
	sit.Jobs["deploy"] = deploy

	paths := AssemblePaths([]opaengine.Finding{finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"})}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	p := paths[0]
	if p.State != PathUnverified || len(p.Modifiers) == 0 || p.Modifiers[len(p.Modifiers)-1] != "unresolvable" {
		t.Errorf("a pruned fork entry's declared token must not mask a surviving fed job's default token: %+v", p)
	}
}

func TestForkEntryUnresolvableSecretsStateDoesNotLeakAfterPruning(t *testing.T) {
	sit := injectionSituation(ir.VisibilityPublic, nil)
	build := sit.Jobs["build"]
	build.Privilege.SecretsState = "unresolvable" // the dropped entry job's own secrets state
	build.Feeds = []string{"deploy"}
	sit.Jobs["build"] = build
	deploy := JobSituation{}
	deploy.Privilege.Secrets = []string{"NPM_TOKEN"}
	deploy.Privilege.SecretsState = "proven"
	sit.Jobs["deploy"] = deploy

	paths := AssemblePaths([]opaengine.Finding{finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"})}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	p := paths[0]
	if p.State != PathProven || len(p.Modifiers) != 0 {
		t.Errorf("a dropped fork entry job's unresolvable secrets state must not leak after pruning: %+v", p)
	}
}

// sortedFindings is a total order even when two findings tie on every
// field above Data: the canonical encoding of Data breaks the tie, so the
// result never depends on input order.
func TestSortedFindingsIsTotalOnDataWhenEverythingElseTies(t *testing.T) {
	a := finding("ISSUE-207", "build", map[string]any{"expression": "a"})
	b := finding("ISSUE-207", "build", map[string]any{"expression": "b"})
	forward := sortedFindings([]opaengine.Finding{a, b})
	backward := sortedFindings([]opaengine.Finding{b, a})
	if !reflect.DeepEqual(forward, backward) {
		t.Fatalf("sortedFindings must not depend on input order: forward=%+v backward=%+v", forward, backward)
	}
	if forward[0].Data["expression"] != "a" {
		t.Errorf("want the canonical Data encoding to break the tie deterministically, got %+v", forward)
	}
}

// AssemblePaths records WHY a path is unresolvable, not just that it is,
// so explain.go's sentence can name the real cause.
func TestDefaultTokenPathRecordsTheDefaultTokenCause(t *testing.T) {
	f := finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"})
	paths := AssemblePaths([]opaengine.Finding{f}, defaultTokenSituation(ir.VisibilityPublic))
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	if paths[0].cause != unresolvableDefaultToken {
		t.Errorf("cause = %q, want default-token, paths=%+v", paths[0].cause, paths)
	}
}

func TestUnresolvableSecretsStateRecordsTheSecretsCause(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	j := sit.Jobs["release"]
	j.Privilege.SecretsState = "unresolvable"
	sit.Jobs["release"] = j
	f := finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"})
	paths := AssemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	if paths[0].cause != unresolvableSecrets {
		t.Errorf("cause = %q, want secrets, paths=%+v", paths[0].cause, paths)
	}
}

// Spec section 9: no path without an anchoring finding. Over a situation
// offering every kind of entry fact and a finding set that mixes entry,
// gate, privilege, role-less and dismissed findings, every assembled
// path's AnchorHash is the hash of a non-dismissed input finding, under
// any input order.
func TestNoPathWithoutAnAnchoringFinding(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	for name, j := range injectionSituation(ir.VisibilityPublic, []string{"DEPLOY_KEY"}).Jobs {
		sit.Jobs[name] = j
	}
	build := sit.Jobs["build"]
	build.Entries = append(build.Entries, EntryFact{Kind: EntryUnprotectedPush, State: "proven", Evidence: "push: branches: [main]", Subject: "main"})
	build.Feeds = []string{"release"}
	sit.Jobs["build"] = build
	sit.DefaultBranch = "main"

	dismissedEntry := finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"})
	dismissedEntry.Dismissed = true
	dismissedGate := finding(string(CodeBranchNonCompliant), "", map[string]any{"branchName": "main"})
	dismissedGate.Dismissed = true
	findings := []opaengine.Finding{
		dismissedEntry,
		dismissedGate,
		finding("ISSUE-207", "build", map[string]any{"expression": "github.event.pull_request.title"}),
		finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"}),
		finding("ISSUE-305", "release", nil),
		finding("ISSUE-307", "release", nil),
		finding("ISSUE-999", "release", nil),
		finding("ISSUE-713", "nowhere", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-102", "build", map[string]any{"link": "node:latest"}),
	}
	live := map[string]bool{}
	for _, f := range findings {
		if h, ok := findingAnchorHash(f); ok && !f.Dismissed {
			live[h] = true
		}
	}
	for seed := int64(0); seed < 50; seed++ {
		shuffled := append([]opaengine.Finding(nil), findings...)
		r := rand.New(rand.NewSource(seed))
		r.Shuffle(len(shuffled), func(i, k int) { shuffled[i], shuffled[k] = shuffled[k], shuffled[i] })
		paths := AssemblePaths(shuffled, sit)
		if len(paths) == 0 {
			t.Fatal("fixture drifted: want paths to check")
		}
		for _, p := range paths {
			if !live[p.AnchorHash] {
				t.Fatalf("seed %d: path %s (%s) is anchored by %s, not a non-dismissed input finding", seed, p.ID, p.AnchorCode, p.AnchorHash)
			}
		}
	}
}
