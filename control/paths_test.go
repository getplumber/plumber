package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
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
	for _, want := range []string{`"reach":{"secrets":["S"],"allSecrets":false,"tokenWrite":["contents"],"impacts":`, `"executes":true`, `"modifiers":[]`, `"gateHashes":[]`, `"reachKinds":[]`} {
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
		Impact: []ImpactFact{{Kind: "publishes", State: "proven", Evidence: "npm publish"}},
	}
	j.Privilege.Secrets = []string{"NPM_TOKEN"}
	j.Privilege.SecretsState = "proven"
	j.Privilege.TokenWrite = []string{"contents"}
	s.Jobs["release"] = j
	return s
}

// A mutable action in a release job reaches a Critical, and the dependency
// cap holds the path at Medium: the reference is only not pinned.
func TestReleaseMutableActionIsAMediumPath(t *testing.T) {
	paths := assemblePaths([]opaengine.Finding{finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"})}, releaseSituation(ir.VisibilityPublic))
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	p := paths[0]
	if p.Tier != TierMedium || p.BaseTier != TierCritical || p.State != PathProven || p.ReachKind != "impact:publishes" || p.EntryKind != EntryMutableDependency {
		t.Errorf("path = %+v", p)
	}
	if p.Jobs[0] != "release" || p.AnchorCode != "ISSUE-701" {
		t.Errorf("anchor/jobs = %+v", p)
	}
}

func TestPrivateExposureDoesNotWeakenThirdPartyEntries(t *testing.T) {
	paths := assemblePaths([]opaengine.Finding{finding("ISSUE-703", "release", map[string]any{"uses": "some/action@v1"})}, releaseSituation(ir.VisibilityPrivate))
	if paths[0].Tier != TierCritical || len(paths[0].Modifiers) != 0 {
		t.Errorf("a tag hijack does not care about visibility: %+v", paths[0])
	}
}

func injectionSituation(exposure string, secrets []string) *Situation {
	s := &Situation{Exposure: exposure, Provider: "github", Jobs: map[string]JobSituation{}}
	j := JobSituation{ForkPR: []EntryFact{{Kind: EntryForkPR, State: "proven", Evidence: "on: pull_request", Subject: "pull_request"}}}
	j.Privilege.Secrets = secrets
	j.Privilege.SecretsState = "proven"
	s.Jobs["build"] = j
	return s
}

func TestInjectionInAnEmptyHandedJobIsHigh(t *testing.T) {
	paths := assemblePaths([]opaengine.Finding{entryFinding("ISSUE-207", "build", "github.event.pull_request.title")}, injectionSituation(ir.VisibilityPublic, nil))
	if len(paths) != 1 || paths[0].Tier != TierHigh || paths[0].ReachKind != "execution" {
		t.Fatalf("paths = %+v", paths)
	}
}

func TestPrivateExposureWeakensContributorEntries(t *testing.T) {
	paths := assemblePaths([]opaengine.Finding{entryFinding("ISSUE-207", "build", "github.event.pull_request.title")}, injectionSituation(ir.VisibilityPrivate, nil))
	if paths[0].Tier != TierMedium || paths[0].Modifiers[0] != "private_exposure" {
		t.Errorf("want Medium with private_exposure, got %+v", paths[0])
	}
}

func TestUnknownExposureCountsAsPublic(t *testing.T) {
	paths := assemblePaths([]opaengine.Finding{entryFinding("ISSUE-207", "build", "github.event.pull_request.title")}, injectionSituation(ir.VisibilityUnknown, nil))
	if paths[0].Tier != TierHigh || len(paths[0].Modifiers) != 0 {
		t.Errorf("unknown is public: %+v", paths[0])
	}
}

func TestGateAmplifiesAPath(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	j := sit.Jobs["release"]
	j.Impact = nil // secrets, no impact: High
	sit.Jobs["release"] = j
	findings := []opaengine.Finding{
		finding("ISSUE-703", "release", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-305", "release", nil), // publish without an environment: a gate on this job
	}
	paths := assemblePaths(findings, sit)
	if len(paths) != 1 || paths[0].Tier != TierCritical || paths[0].Modifiers[0] != "gate:ISSUE-305" || len(paths[0].GateHashes) != 1 {
		t.Errorf("want High amplified to Critical by the gate, got %+v", paths)
	}
}

// ISSUE-704 and ISSUE-901 are gates whose risk does not depend on any
// pipeline path (a hard-coded registry password, Dependabot's insecure
// code execution): a 704 finding landing on the very job a High path
// walks must leave that path alone, never amplify it to Critical, and
// still price as an other finding at its own severity.
func TestNonAmplifyingGateCodesNeverAmplifyAPath(t *testing.T) {
	for _, code := range []string{"ISSUE-704", "ISSUE-901"} {
		sit := releaseSituation(ir.VisibilityPublic)
		j := sit.Jobs["release"]
		j.Impact = nil // secrets, no impact: High
		sit.Jobs["release"] = j
		findings := []opaengine.Finding{
			finding("ISSUE-714", "release", map[string]any{"uses": "some/action@v1"}),
			finding(code, "release", nil),
		}
		paths := assemblePaths(findings, sit)
		if len(paths) != 1 || paths[0].Tier != TierHigh || len(paths[0].Modifiers) != 0 || len(paths[0].GateHashes) != 0 {
			t.Errorf("%s: want High left alone with no gate modifier, got %+v", code, paths)
		}
		s := ComputePlumberScoreV4(ScoreInputV4{Findings: findings, Paths: paths})
		if s.OtherFindings == nil || s.OtherFindings.Count != 1 || len(s.CodeLosses) != 1 || s.CodeLosses[0].Code != ErrorCode(code) {
			t.Errorf("%s: want one other finding for the code itself, got %+v, code losses %+v", code, s.OtherFindings, s.CodeLosses)
		}
	}
}

func TestUnresolvableFactMarksThePathUnverifiedAndLowersIt(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	paths := assemblePaths([]opaengine.Finding{finding("ISSUE-716", "release", map[string]any{"uses": "some/action@v1"})}, sit)
	if paths[0].Tier != TierHigh || paths[0].State != PathUnverified || paths[0].Modifiers[0] != "unresolvable" {
		t.Errorf("path = %+v", paths[0])
	}
}

// TestAttackPathJSONShapeAnchorless pins MarshalJSON's nil-to-[] guards for
// AnchorHashes and AnchorCodes specifically: TestAttackPathJSONShape above
// never sets either field, and the two-anchor tests only marshal paths
// that already have them populated, so an anchor-less path (as produced
// when reading back an older report with no anchors recorded) never
// exercised these two guards.
func TestAttackPathJSONShapeAnchorless(t *testing.T) {
	raw, err := json.Marshal(AttackPath{ID: "p"})
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, want := range []string{`"anchorHashes":[]`, `"anchorCodes":[]`} {
		if !strings.Contains(got, want) {
			t.Errorf("JSON lacks %s, want never null: %s", want, got)
		}
	}
	for _, unwanted := range []string{`"anchorHashes":null`, `"anchorCodes":null`} {
		if strings.Contains(got, unwanted) {
			t.Errorf("JSON carries %s: %s", unwanted, got)
		}
	}
}

func TestOneHopWalkReachesTheFedJob(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{}}
	sit.Jobs["build"] = JobSituation{
		ForkPR: []EntryFact{{Kind: EntryForkPR, State: "proven", Subject: "pull_request"}},
		Feeds:  []string{"publish"},
	}
	pub := JobSituation{Impact: []ImpactFact{{Kind: "publishes", State: "proven", Evidence: "npm publish"}}}
	pub.Privilege.Secrets = []string{"NPM_TOKEN"}
	pub.Privilege.SecretsState = "proven"
	sit.Jobs["publish"] = pub
	paths := assemblePaths([]opaengine.Finding{entryFinding("ISSUE-207", "build", "github.event.pull_request.title")}, sit)
	if len(paths) != 1 || paths[0].Tier != TierCritical || len(paths[0].Jobs) != 2 || paths[0].Jobs[1] != "publish" {
		t.Fatalf("paths = %+v", paths)
	}
}

// TestTwoHopChainDoesNotReachBeyondTheDirectlyFedJob pins the one-hop walk
// as the intended design, not a gap to close: a job fed by the job the walk
// already reached is not itself reached, because the facts say an edge
// exists, not that the intermediate job forwards what it received. A
// secret held two edges from the entry prices as execution only; the same
// secret held by the job the entry directly feeds prices Critical.
func TestTwoHopChainDoesNotReachBeyondTheDirectlyFedJob(t *testing.T) {
	entryJob := func() JobSituation {
		return JobSituation{
			ForkPR: []EntryFact{{Kind: EntryForkPR, State: "proven", Subject: "pull_request"}},
		}
	}
	f := entryFinding("ISSUE-207", "build", "github.event.pull_request.title")

	t.Run("the job two hops from the entry is not reached", func(t *testing.T) {
		sit := &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{}}
		build := entryJob()
		build.Feeds = []string{"mid"}
		sit.Jobs["build"] = build
		sit.Jobs["mid"] = JobSituation{Feeds: []string{"publish"}}
		pub := JobSituation{Impact: []ImpactFact{{Kind: "publishes", State: "proven", Evidence: "npm publish"}}}
		pub.Privilege.Secrets = []string{"NPM_TOKEN"}
		pub.Privilege.SecretsState = "proven"
		sit.Jobs["publish"] = pub

		paths := assemblePaths([]opaengine.Finding{f}, sit)
		if len(paths) != 1 || paths[0].Tier == TierCritical || len(paths[0].Jobs) != 2 {
			t.Fatalf("paths = %+v, want the two-hop publish job (and its secret) unreached", paths)
		}
	})

	t.Run("the job the entry directly feeds is reached", func(t *testing.T) {
		sit := &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{}}
		build := entryJob()
		build.Feeds = []string{"publish"}
		sit.Jobs["build"] = build
		pub := JobSituation{Impact: []ImpactFact{{Kind: "publishes", State: "proven", Evidence: "npm publish"}}}
		pub.Privilege.Secrets = []string{"NPM_TOKEN"}
		pub.Privilege.SecretsState = "proven"
		sit.Jobs["publish"] = pub

		paths := assemblePaths([]opaengine.Finding{f}, sit)
		if len(paths) != 1 || paths[0].Tier != TierCritical || len(paths[0].Jobs) != 2 {
			t.Fatalf("paths = %+v, want the directly-fed publish job reached as Critical", paths)
		}
	})
}

func TestDismissedAndRoleLessFindingsAnchorNothing(t *testing.T) {
	dismissed := finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"})
	dismissed.Dismissed = true
	hygiene := finding("ISSUE-999", "release", nil)
	if paths := assemblePaths([]opaengine.Finding{dismissed, hygiene}, releaseSituation(ir.VisibilityPublic)); len(paths) != 0 {
		t.Errorf("want no path, got %+v", paths)
	}
}

// One entry into one job is one attack, whatever it reaches: one path whose
// reach is everything the walked jobs hold and change, priced once. Its
// reach kind is the strongest of its reach kinds, and reachKinds lists them
// all, strongest first.
func TestOneEntryIntoOneJobIsOnePath(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	j := sit.Jobs["release"]
	j.Impact = append(j.Impact, ImpactFact{Kind: "deploys", State: "proven", Evidence: "kubectl apply -f production.yaml"},
		ImpactFact{Kind: "writes_repo", State: "proven", Evidence: "git push"})
	sit.Jobs["release"] = j
	paths := assemblePaths([]opaengine.Finding{finding("ISSUE-703", "release", map[string]any{"uses": "some/action@v1"})}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path for one entry into one job, got %+v", paths)
	}
	p := paths[0]
	if p.Tier != TierCritical || p.ReachKind != "impact:publishes" || len(p.Reach.Impacts) != 3 {
		t.Errorf("path = %+v", p)
	}
	want := []string{"impact:publishes", "impact:deploys", "impact:writes_repo", "secrets", "token", "execution"}
	if !reflect.DeepEqual(p.ReachKinds, want) {
		t.Errorf("reachKinds = %v, want %v", p.ReachKinds, want)
	}
}

// A proven impact holds the path's tier, so an impact of the same path that
// could not be resolved does not lower it; a path whose every impact could
// not be resolved is unverified.
func TestAProvenImpactKeepsTheMergedPathProven(t *testing.T) {
	j := JobSituation{Impact: []ImpactFact{
		{Kind: "publishes", State: "proven", Evidence: "npm publish"},
		{Kind: "writes_repo", State: "unresolvable", Evidence: "git push"},
	}}
	j.Privilege.Secrets = []string{"NPM_TOKEN"}
	j.Privilege.SecretsState = "proven"
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"release": j}}
	f := finding("ISSUE-703", "release", map[string]any{"uses": "some/action@v1"})
	paths := assemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 1 || paths[0].Tier != TierCritical || paths[0].State != PathProven {
		t.Errorf("want one proven Critical path, got %+v", paths)
	}
	j.Impact = j.Impact[1:]
	sit.Jobs["release"] = j
	paths = assemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 1 || paths[0].BaseTier != TierCritical || paths[0].Tier != TierHigh || paths[0].State != PathUnverified {
		t.Errorf("want the unresolved push lowered and unverified, got %+v", paths)
	}
}

// Two findings sharing one identity hash (ISSUE-207 is {"file", "job"})
// but naming different entry subjects in the same job must always resolve
// to the same winner regardless of input order: the first one in (code,
// job, file, line, message) order.
func TestSharedIdentityFindingsResolveDeterministicallyToTheFirstInSortOrder(t *testing.T) {
	sit := injectionSituation(ir.VisibilityPublic, nil)

	earlier := entryFinding("ISSUE-207", "build", "github.event.pull_request.title")
	earlier.Line = 10
	later := entryFinding("ISSUE-207", "build", "github.event.comment.body")
	later.Line = 20

	forward := assemblePaths([]opaengine.Finding{earlier, later}, sit)
	backward := assemblePaths([]opaengine.Finding{later, earlier}, sit)
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
	m := finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"})
	a := finding("ISSUE-305", "release", nil)
	a.File = ".github/workflows/a.yml"
	b := finding("ISSUE-305", "release", nil)
	b.File = ".github/workflows/b.yml"
	forward := assemblePaths([]opaengine.Finding{m, a, b}, sit)
	backward := assemblePaths([]opaengine.Finding{m, b, a}, sit)
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
// sharing an identity hash but naming different entry subjects.
func TestOutputOrderIsDeterministicUnderShuffledInput(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	rel := sit.Jobs["release"]
	rel.Impact = nil // secrets, no impact: High base, so both gates below are observable
	sit.Jobs["release"] = rel
	sit.DefaultBranch = "main"
	for name, j := range injectionSituation(ir.VisibilityPublic, nil).Jobs {
		sit.Jobs[name] = j
	}
	inc := includeSituation(ir.VisibilityPublic, "includeA", "includeB")
	for name, j := range inc.Jobs {
		sit.Jobs[name] = j
	}
	sit.Includes = inc.Includes

	earlier207 := entryFinding("ISSUE-207", "build", "github.event.pull_request.title")
	earlier207.Line = 10
	later207 := entryFinding("ISSUE-207", "build", "github.event.comment.body")
	later207.Line = 20

	findings := []opaengine.Finding{
		finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-305", "release", nil),
		finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"}),
		includeFinding(),
		earlier207, later207,
	}
	want := assemblePaths(findings, sit)
	if len(want) == 0 {
		t.Fatal("fixture produced no paths at all, the shuffle below would be vacuous")
	}
	for seed := int64(1); seed <= 20; seed++ {
		shuffled := append([]opaengine.Finding(nil), findings...)
		r := rand.New(rand.NewSource(seed))
		r.Shuffle(len(shuffled), func(i, k int) { shuffled[i], shuffled[k] = shuffled[k], shuffled[i] })
		got := assemblePaths(shuffled, sit)
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
		Push: []EntryFact{{Kind: EntryUnprotectedPush, State: "proven", Evidence: "push: branches: [main]", Subject: "main"}},
	}
	return s
}

func TestUnprotectedPushGateFindingAnchorsItsOwnEntryFactAndAlwaysExecutes(t *testing.T) {
	f := finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"})
	paths := assemblePaths([]opaengine.Finding{f}, unprotectedPushSituation(ir.VisibilityPublic))
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
	paths := assemblePaths([]opaengine.Finding{f}, unprotectedPushSituation(ir.VisibilityPublic))
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
		Push:  []EntryFact{{Kind: EntryUnprotectedPush, State: "proven", Evidence: "push: branches: [main]", Subject: "main"}},
		Feeds: []string{"deploy"},
	}
	deploy := JobSituation{
		Push: []EntryFact{{Kind: EntryUnprotectedPush, State: "proven", Evidence: "push: branches: [main]", Subject: "main"}},
	}
	deploy.Privilege.TokenWrite = []string{"contents"}
	deploy.Privilege.TokenWriteSource = "declared"
	sit.Jobs["deploy"] = deploy
	findings := []opaengine.Finding{
		finding("ISSUE-703", "build", map[string]any{"uses": "some/action@v1"}),
		finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"}),
	}
	paths := assemblePaths(findings, sit)
	var p *AttackPath
	for i := range paths {
		if paths[i].AnchorCode == "ISSUE-703" {
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
// amplified once, not only through a push-triggered job. The path is
// Critical before the gate already: a contributor entry holding a write
// token is.
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
		entryFinding("ISSUE-207", "build", "github.event.pull_request.title"),
		finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"}),
	}
	paths := assemblePaths(findings, sit)
	var p *AttackPath
	for i := range paths {
		if paths[i].AnchorCode == "ISSUE-207" {
			p = &paths[i]
		}
	}
	if p == nil {
		t.Fatalf("want a path anchored by ISSUE-207, got %+v", paths)
	}
	if p.BaseTier != TierCritical || p.Tier != TierCritical || p.Modifiers[0] != "gate:ISSUE-501" {
		t.Errorf("want a 501 on the default branch on the Critical contents-write fork_pr path, got %+v", p)
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
		entryFinding("ISSUE-207", "build", "github.event.pull_request.title"),
		finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"}),
	}
	for _, p := range assemblePaths(findings, sit) {
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
		entryFinding("ISSUE-207", "build", "github.event.pull_request.title"),
		finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"}),
	}
	paths := assemblePaths(findings, sit)
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
	build.Push = append(build.Push, EntryFact{Kind: EntryUnprotectedPush, State: "proven", Evidence: "on: [push, pull_request]", Subject: "main"})
	sit.Jobs["build"] = build
	sit.DefaultBranch = "main"
	findings := []opaengine.Finding{
		entryFinding("ISSUE-207", "build", "github.event.pull_request.title"),
		finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"}),
	}
	var p *AttackPath
	paths := assemblePaths(findings, sit)
	for i := range paths {
		if paths[i].AnchorCode == "ISSUE-207" {
			p = &paths[i]
		}
	}
	if p == nil {
		t.Fatalf("want a path anchored by ISSUE-207, got %+v", paths)
	}
	if p.Tier != TierHigh || len(p.Modifiers) != 0 || len(p.GateHashes) != 0 {
		t.Errorf("want the execution-only path High with no gate modifier, got %+v", p)
	}
}

// reachWritesRepo backs the branch gate rule directly: a proven push,
// publish or deploy impact or a declared "contents" write token says yes,
// anything else (an assumed default token, an unconfirmed impact, secrets,
// a read-only token, execution alone) says no.
func TestReachWritesRepoChecksImpactAndTokenWrite(t *testing.T) {
	cases := []struct {
		name string
		r    Reach
		want bool
	}{
		{"writes_repo impact", Reach{Impacts: []ImpactFact{{Kind: "writes_repo", State: "proven", Evidence: "git push"}}}, true},
		{"unconfirmed writes_repo impact", Reach{Impacts: []ImpactFact{{Kind: "writes_repo", State: "unresolvable", Evidence: "git push"}}}, false},
		{"contents write token", Reach{TokenWrite: []string{"contents"}}, true},
		{"assumed contents write token", Reach{TokenWrite: []string{"contents"}, tokenAssumed: true}, false},
		{"other write token", Reach{TokenWrite: []string{"issues"}}, false},
		{"secrets only", Reach{Secrets: []string{"NPM_TOKEN"}}, false},
		{"publishes impact", Reach{Impacts: []ImpactFact{{Kind: "publishes", State: "proven", Evidence: "npm publish"}}}, true},
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
// include, no "job" field) enters every job the include it names shapes:
// one path, one branch per job. ---

func includeSituation(exposure string, jobNames ...string) *Situation {
	s := &Situation{Exposure: exposure, Jobs: map[string]JobSituation{},
		Includes: []IncludeFact{{Subject: "org/repo/template.yml@main", Jobs: jobNames}}}
	for _, name := range jobNames {
		s.Jobs[name] = JobSituation{
			Impact: []ImpactFact{{Kind: "deploys", State: "proven", Evidence: "kubectl apply -f production.yaml"}},
		}
	}
	return s
}

// includeFinding is the ISSUE-404 finding on includeSituation's include.
func includeFinding() opaengine.Finding {
	f := finding("ISSUE-404", "", map[string]any{"includePath": "org/repo/template.yml"})
	f.Subject = "org/repo/template.yml@main"
	return f
}

func TestJobLessIncludeFindingAnchorsEveryJobItsIncludeShapes(t *testing.T) {
	sit := includeSituation(ir.VisibilityPublic, "build", "deploy")
	paths := assemblePaths([]opaengine.Finding{includeFinding()}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path for one include, got %+v", paths)
	}
	p := paths[0]
	if len(p.AnchorHashes) != 1 || len(p.Branches) != 2 {
		t.Fatalf("want one anchor entering two jobs, got %+v", p)
	}
	entryJobs := map[string]bool{p.Branches[0].Job: true, p.Branches[1].Job: true}
	if !entryJobs["build"] || !entryJobs["deploy"] || !reflect.DeepEqual(p.Jobs, []string{"build", "deploy"}) {
		t.Errorf("want each job the include shapes as an entry job, got %+v", p)
	}
}

// --- A walked job's default (assumed) token write, with no secret and no
// declared token anywhere on the path, is unresolvable: the path is marked
// unverified and lowered a tier, same as any other unresolvable fact. ---

func defaultTokenSituation(exposure string) *Situation {
	s := &Situation{Exposure: exposure, Jobs: map[string]JobSituation{}}
	j := JobSituation{}
	j.Privilege.TokenWrite = []string{"contents"}
	j.Privilege.TokenWriteSource = "default"
	s.Jobs["release"] = j
	return s
}

// A default token whose write is assumed is the only privilege: the tier
// rests on the code execution, which gives High on its own, so the path
// stays proven and keeps the assumption as its cause.
func TestDefaultTokenAsOnlyPrivilegeKeepsTheCodeExecutionTier(t *testing.T) {
	f := finding("ISSUE-714", "release", map[string]any{"uses": "some/action@v1"})
	paths := assemblePaths([]opaengine.Finding{f}, defaultTokenSituation(ir.VisibilityPublic))
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	p := paths[0]
	if p.Tier != TierHigh || p.State != PathProven || len(p.Modifiers) != 0 || p.cause != unresolvableDefaultToken {
		t.Errorf("a default token alone is an assumption the tier does not rest on, want High/proven: %+v", p)
	}
	// The path still says the token's write is assumed.
	if s := PathSentence(p); !strings.HasSuffix(s, " Plumber could not verify that `GITHUB_TOKEN` is really writable (no `permissions` block).") {
		t.Errorf("sentence = %q", s)
	}
	if b := NewPathBlock(p, nil); b.Unverified || b.ReachUnverified != "Plumber could not check that the token can write (no permissions block)" {
		t.Errorf("block = %+v", b)
	}
}

func TestDeclaredTokenIsNotUnresolvable(t *testing.T) {
	sit := defaultTokenSituation(ir.VisibilityPublic)
	j := sit.Jobs["release"]
	j.Privilege.TokenWriteSource = "declared"
	sit.Jobs["release"] = j
	f := finding("ISSUE-714", "release", map[string]any{"uses": "some/action@v1"})
	paths := assemblePaths([]opaengine.Finding{f}, sit)
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
	f := finding("ISSUE-714", "release", map[string]any{"uses": "some/action@v1"})
	paths := assemblePaths([]opaengine.Finding{f}, sit)
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
	paths := assemblePaths([]opaengine.Finding{finding("ISSUE-703", "release", map[string]any{"uses": "some/action@v1"})}, sit)
	if len(paths) != 1 || paths[0].Tier != TierCritical {
		t.Errorf("a Feeds entry naming a missing job must not break the walk, got %+v", paths)
	}
}

func TestFindingWithJobAbsentFromSituationAnchorsNothing(t *testing.T) {
	f := finding("ISSUE-701", "ghost", map[string]any{"uses": "some/action@v1"})
	if paths := assemblePaths([]opaengine.Finding{f}, releaseSituation(ir.VisibilityPublic)); len(paths) != 0 {
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
	paths := assemblePaths([]opaengine.Finding{finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"})}, sit)
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

// unresolvableSecretsSituation is a build job holding nothing settled: no
// fork trigger prunes its privilege, and its secrets cannot be decided.
func unresolvableSecretsSituation(exposure string) *Situation {
	j := JobSituation{}
	j.Privilege.SecretsState = "unresolvable"
	return &Situation{Exposure: exposure, Provider: "github", Jobs: map[string]JobSituation{"build": j}}
}

// When several modifiers apply to one path, they are recorded in a fixed
// order: private_exposure, then unresolvable, then one gate per matching
// code.
func TestModifiersAppearInFixedOrderPrivateThenUnresolvableThenGate(t *testing.T) {
	sit := unresolvableSecretsSituation(ir.VisibilityPrivate)
	findings := []opaengine.Finding{
		entryFinding("ISSUE-207", "build", "github.event.issue.title"),
		finding("ISSUE-305", "build", nil), // a gate on the same job
	}
	paths := assemblePaths(findings, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	want := []string{"private_exposure", "unresolvable", "gate:ISSUE-305"}
	if !reflect.DeepEqual(paths[0].Modifiers, want) {
		t.Errorf("modifiers = %v, want %v", paths[0].Modifiers, want)
	}
}

// Both down-modifiers apply in turn: unlisted secrets and an impact that
// could not be confirmed give Critical, the private repository and the
// unverified facts take it down one step each, to Medium, and both are
// recorded. Critical never rises above Critical even with a gate.
func TestTwoDownModifiersTakeAPathDownTwoSteps(t *testing.T) {
	sit := unresolvableSecretsSituation(ir.VisibilityPrivate)
	j := sit.Jobs["build"]
	j.Impact = []ImpactFact{{Kind: "deploys", State: "unresolvable", Evidence: "kubectl apply -f ${{ inputs.env }}.yaml"}}
	sit.Jobs["build"] = j
	f := entryFinding("ISSUE-207", "build", "github.event.issue.title")
	paths := assemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 1 || paths[0].BaseTier != TierCritical || paths[0].Tier != TierMedium || len(paths[0].Modifiers) != 2 {
		t.Errorf("want Critical taken down to Medium with both down-modifiers recorded, got %+v", paths[0])
	}
	if got := tierShift(TierLow, -1); got != TierLow {
		t.Errorf("Low lowered again = %s, want Low clamped at the floor", got)
	}
}

func TestCriticalTierClampsAtTheCeilingWithAGate(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic) // secrets + token + impact: Critical already
	findings := []opaengine.Finding{
		finding("ISSUE-703", "release", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-305", "release", nil),
	}
	paths := assemblePaths(findings, sit)
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
	paths := assemblePaths([]opaengine.Finding{entryFinding("ISSUE-207", "build", "github.event.pull_request.title")}, sit)
	if paths[0].Tier != TierHigh || len(paths[0].Reach.Secrets) != 0 || len(paths[0].Reach.TokenWrite) != 0 {
		t.Errorf("a fork pull_request run never sees secrets or a write token: %+v", paths[0])
	}
}

func TestPRTargetJobKeepsItsSecrets(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{}}
	j := JobSituation{}
	j.Privilege.Secrets = []string{"NPM_TOKEN"}
	j.Privilege.SecretsState = "proven"
	sit.Jobs["build"] = j
	paths := assemblePaths([]opaengine.Finding{finding("ISSUE-802", "build", nil)}, sit)
	// A contributor entry holding a secret is Critical.
	if paths[0].Tier != TierCritical || len(paths[0].Reach.Secrets) != 1 {
		t.Errorf("pull_request_target runs with the base repository's secrets: %+v", paths[0])
	}
}

func TestGitLabForkMRDropsProtectedVariablesOnly(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "gitlab", Jobs: map[string]JobSituation{}}
	j := JobSituation{ForkPR: []EntryFact{{Kind: EntryForkPR, State: "proven", Evidence: "rules: merge_request_event", Subject: "merge_request_event"}}}
	j.Privilege.Secrets = []string{"NPM_TOKEN", "STAGING_URL"}
	j.Privilege.ProtectedSecrets = []string{"NPM_TOKEN"}
	j.Privilege.SecretsState = "proven"
	sit.Jobs["test"] = j
	paths := assemblePaths([]opaengine.Finding{finding("ISSUE-207", "test", map[string]any{"variableName": "CI_MERGE_REQUEST_TITLE"})}, sit)
	// A contributor entry holding a secret is Critical.
	if paths[0].Tier != TierCritical || !reflect.DeepEqual(paths[0].Reach.Secrets, []string{"STAGING_URL"}) {
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
	paths := assemblePaths([]opaengine.Finding{entryFinding("ISSUE-207", "build", "github.event.pull_request.title")}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	p := paths[0]
	if p.Tier != TierHigh || p.State != PathProven || len(p.Modifiers) != 0 || p.cause != "" {
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
	paths := assemblePaths([]opaengine.Finding{entryFinding("ISSUE-207", "build", "github.event.pull_request.title")}, sit)
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
		entryFinding("ISSUE-207", "build", "github.event.pull_request.title"),
	}
	paths := assemblePaths(findings, sit)
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

	paths := assemblePaths([]opaengine.Finding{entryFinding("ISSUE-207", "build", "github.event.pull_request.title")}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	p := paths[0]
	if p.cause != unresolvableDefaultToken {
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

	paths := assemblePaths([]opaengine.Finding{entryFinding("ISSUE-207", "build", "github.event.pull_request.title")}, sit)
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
	f := finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"})
	paths := assemblePaths([]opaengine.Finding{f}, defaultTokenSituation(ir.VisibilityPublic))
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
	f := finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"})
	paths := assemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	if paths[0].cause != unresolvableSecrets {
		t.Errorf("cause = %q, want secrets, paths=%+v", paths[0].cause, paths)
	}
}

// Spec section 9: no path without an anchoring finding. Over a situation
// offering every kind of trigger fact and a finding set that mixes entry,
// gate, privilege, role-less and dismissed findings, every assembled
// path's AnchorHash is the hash of a non-dismissed input finding, under
// any input order.
func TestNoPathWithoutAnAnchoringFinding(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	for name, j := range injectionSituation(ir.VisibilityPublic, []string{"DEPLOY_KEY"}).Jobs {
		sit.Jobs[name] = j
	}
	build := sit.Jobs["build"]
	build.Push = append(build.Push, EntryFact{Kind: EntryUnprotectedPush, State: "proven", Evidence: "push: branches: [main]", Subject: "main"})
	build.Feeds = []string{"release"}
	sit.Jobs["build"] = build
	sit.DefaultBranch = "main"

	dismissedEntry := finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"})
	dismissedEntry.Dismissed = true
	dismissedGate := finding(string(CodeBranchNonCompliant), "", map[string]any{"branchName": "main"})
	dismissedGate.Dismissed = true
	findings := []opaengine.Finding{
		dismissedEntry,
		dismissedGate,
		entryFinding("ISSUE-207", "build", "github.event.pull_request.title"),
		finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"}),
		finding("ISSUE-305", "release", nil),
		finding("ISSUE-307", "release", nil),
		finding("ISSUE-999", "release", nil),
		finding("ISSUE-701", "nowhere", map[string]any{"uses": "some/action@v1"}),
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
		paths := assemblePaths(shuffled, sit)
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

// --- One path per (entry kind, entry subject): two findings on one
// subject are one attack, told and priced once. ---

const pinnedAction = "tj-actions/changed-files@2d756ea4c53f7f6b397767d8723b3a10a9f35bf2"

func pinnedActionSituation() *Situation {
	s := &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{}}
	s.Jobs["build"] = JobSituation{}
	return s
}

func pinnedActionFindings() []opaengine.Finding {
	unauthorized := finding("ISSUE-713", "build", map[string]any{"uses": pinnedAction})
	unauthorized.Message = "job \"build\" references action \"" + pinnedAction + "\" from an unauthorized source"
	advisory := finding("ISSUE-703", "build", map[string]any{"uses": pinnedAction})
	advisory.Message = "job \"build\" references \"" + pinnedAction + "\": published advisories"
	return []opaengine.Finding{unauthorized, advisory}
}

func imageFindings() []opaengine.Finding {
	tag := finding("ISSUE-102", "build", map[string]any{"link": "node:latest"})
	tag.Message = "Job `build` uses the forbidden tag `latest` of image `node:latest`."
	digest := finding("ISSUE-103", "build", map[string]any{"link": "node:latest"})
	digest.Message = "Job `build` uses image `node:latest` without a digest."
	return []opaengine.Finding{tag, digest}
}

func hashesOf(t *testing.T, findings []opaengine.Finding) []string {
	t.Helper()
	var out []string
	for _, f := range findings {
		h, ok := findingAnchorHash(f)
		if !ok {
			t.Fatalf("finding %s has no identity", f.Code)
		}
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func TestTwoFindingsOnOneActionMakeOnePathWithTwoAnchors(t *testing.T) {
	findings := pinnedActionFindings()
	paths := assemblePaths(findings, pinnedActionSituation())
	if len(paths) != 1 {
		t.Fatalf("want one path for one action in one job, got %d: %+v", len(paths), paths)
	}
	p := paths[0]
	want := hashesOf(t, findings)
	if !reflect.DeepEqual(p.AnchorHashes, want) {
		t.Errorf("anchorHashes = %v, want every anchoring finding sorted %v", p.AnchorHashes, want)
	}
	if !reflect.DeepEqual(p.AnchorCodes, []ErrorCode{"ISSUE-703", "ISSUE-713"}) {
		t.Errorf("anchorCodes = %v, want [ISSUE-703 ISSUE-713]", p.AnchorCodes)
	}
	if p.AnchorHash != want[0] || p.AnchorCode != "ISSUE-703" {
		t.Errorf("anchorHash/anchorCode must be the first of each: %s %s", p.AnchorHash, p.AnchorCode)
	}
	sum := sha256.Sum256([]byte(string(EntryMutableDependency) + "|" + pinnedAction))
	if p.ID != hex.EncodeToString(sum[:])[:16] {
		t.Errorf("id = %s, want sha256(entryKind|subject)[:16]", p.ID)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"anchorHashes":[`, `"anchorCodes":["ISSUE-703","ISSUE-713"]`, `"anchorHash":"`, `"anchorCode":"ISSUE-703"`} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("JSON lacks %s: %s", key, raw)
		}
	}
}

func TestTwoFindingsOnOneImageMakeOnePath(t *testing.T) {
	findings := imageFindings()
	paths := assemblePaths(findings, pinnedActionSituation())
	if len(paths) != 1 || paths[0].Entry.Subject != "node:latest" {
		t.Fatalf("want one node:latest path, got %+v", paths)
	}
	if !reflect.DeepEqual(paths[0].AnchorCodes, []ErrorCode{"ISSUE-102", "ISSUE-103"}) || len(paths[0].AnchorHashes) != 2 {
		t.Errorf("anchors = %v %v, want both image findings", paths[0].AnchorCodes, paths[0].AnchorHashes)
	}
}

// An owner or a registry outside the authorized list is a trust policy
// finding, not a way in: on a reference pinned by a full commit SHA nothing
// can change without a commit in the repository, so the finding starts no
// path and is priced as an individual finding: Medium for an action pinned
// by a full commit SHA, the registry's High for the image.
func TestAnUnauthorizedSourceAloneStartsNoPath(t *testing.T) {
	const pinned = "some/action@0123456789abcdef0123456789abcdef01234567"
	findings := []opaengine.Finding{
		finding("ISSUE-713", "release", map[string]any{"uses": pinned}),
		finding("ISSUE-101", "release", map[string]any{"link": "registry.example.com/tool@sha256:" + strings.Repeat("a", 64)}),
	}
	paths := assemblePaths(findings, releaseSituation(ir.VisibilityPublic))
	if len(paths) != 0 {
		t.Fatalf("an unauthorized source alone is no entry, got %+v", paths)
	}
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: findings, Paths: paths})
	if s.OtherFindings == nil || s.OtherFindings.Counts.High != 1 || s.OtherFindings.Counts.Medium != 1 || s.FinalPoints != 85 {
		t.Errorf("want the action at Medium and the image at High: %+v %v", s.OtherFindings, s.FinalPoints)
	}
}

// On a reference that can change, the pinning code anchors the path and the
// unauthorized source finding on the same subject and job is listed with
// it, charged through the path; the entry still reads as the pinning code.
func TestAnUnauthorizedSourceJoinsThePathItsPinningCodeAnchors(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	action := []opaengine.Finding{
		finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"}),
	}
	image := []opaengine.Finding{
		finding("ISSUE-101", "release", map[string]any{"link": "registry.example.com/tool:latest"}),
		finding("ISSUE-103", "release", map[string]any{"link": "registry.example.com/tool:latest"}),
	}
	for _, tc := range []struct {
		findings []opaengine.Finding
		codes    []ErrorCode
		anchor   ErrorCode
	}{
		{action, []ErrorCode{"ISSUE-701", "ISSUE-713"}, "ISSUE-701"},
		{image, []ErrorCode{"ISSUE-101", "ISSUE-103"}, "ISSUE-103"},
	} {
		paths := assemblePaths(tc.findings, sit)
		if len(paths) != 1 {
			t.Fatalf("want one path, got %+v", paths)
		}
		p := paths[0]
		if !reflect.DeepEqual(p.AnchorCodes, tc.codes) || !reflect.DeepEqual(p.AnchorHashes, hashesOf(t, tc.findings)) {
			t.Errorf("anchors = %v %v, want both findings", p.AnchorCodes, p.AnchorHashes)
		}
		if p.AnchorCode != tc.anchor {
			t.Errorf("the entry reads as the pinning code: %s", p.AnchorCode)
		}
		s := ComputePlumberScoreV4(ScoreInputV4{Findings: tc.findings, Paths: paths})
		if s.OtherFindings != nil {
			t.Errorf("the joined finding is charged through the path: %+v", s.OtherFindings)
		}
	}
}

// The unauthorized source finding never sets the entry a path reads as,
// whatever code anchors it.
func TestAnUnauthorizedSourceNeverNamesTheEntry(t *testing.T) {
	findings := []opaengine.Finding{
		finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-716", "release", map[string]any{"uses": "some/action@v1"}),
	}
	paths := assemblePaths(findings, releaseSituation(ir.VisibilityPublic))
	if len(paths) != 1 || paths[0].AnchorCode != "ISSUE-716" || paths[0].State != PathUnverified {
		t.Fatalf("want one unverified ISSUE-716 path, got %+v", paths)
	}
}

// A third-party dependency takes a compromise of its own first. A
// dependency that is not a reference to pin (a script fetched at run time,
// an action fetching remote code, a source that could not be fetched) is
// at most High, after the amplification, and says so, unless a finding on
// it says it is already bad (a published advisory on the pinned version, a
// commit its repository does not have, an obfuscated remote fetch). The
// cache and contributor entries are not capped.
func TestADependencyPathIsCappedAtHighUnlessKnownBad(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	for _, codes := range [][]string{{"ISSUE-714"}, {"ISSUE-411"}} {
		var findings []opaengine.Finding
		for _, c := range codes {
			findings = append(findings, finding(c, "release", map[string]any{"uses": "some/action@v1", "scriptLine": "curl https://example.com/i.sh | sh"}))
		}
		paths := assemblePaths(findings, sit)
		if len(paths) != 1 {
			t.Fatalf("%v: want one path, got %+v", codes, paths)
		}
		p := paths[0]
		if p.Tier != TierHigh || p.BaseTier != TierCritical || !reflect.DeepEqual(p.Modifiers, []string{"dependency_cap"}) {
			t.Errorf("%v: want a High path capped from Critical, got %s from %s, %v", codes, p.Tier, p.BaseTier, p.Modifiers)
		}
		if s := PathSentence(p); !strings.Contains(s, "The dependency must be compromised first, so this path is capped at High.") {
			t.Errorf("%v: sentence = %q", codes, s)
		}
		b := NewPathBlock(p, nil)
		if b.Cap != "Capped at High: it needs a dependency compromise first" {
			t.Errorf("%v: block cap line = %q", codes, b.Cap)
		}
		if b.Branches[0].Marker != "" {
			t.Errorf("%v: branch marker = %q, want no cap marker", codes, b.Branches[0].Marker)
		}
		raw, _ := json.Marshal(p)
		if !strings.Contains(string(raw), `"modifiers":["dependency_cap"]`) {
			t.Errorf("%v: JSON lacks the modifier: %s", codes, raw)
		}
	}
	for _, code := range []string{"ISSUE-703", "ISSUE-715"} {
		paths := assemblePaths([]opaengine.Finding{
			finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"}),
			finding(code, "release", map[string]any{"uses": "some/action@v1"}),
		}, sit)
		if len(paths) != 1 || paths[0].Tier != TierCritical || len(paths[0].Modifiers) != 0 {
			t.Errorf("%s: a dependency known bad keeps its Critical path, got %+v", code, paths)
		}
		if b := NewPathBlock(paths[0], nil); b.Cap != "" {
			t.Errorf("%s: no cap line, got %q", code, b.Cap)
		}
	}
	// A commit its repository does not have is unresolvable, so it lowers
	// the path; merged with a code that proves the entry it stays Critical.
	known := assemblePaths([]opaengine.Finding{
		finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-707", "release", map[string]any{"uses": "some/action@v1"}),
	}, sit)
	if len(known) != 1 || known[0].Tier != TierCritical {
		t.Errorf("ISSUE-707: want a Critical path, got %+v", known)
	}

	// A gate raising a High dependency path to Critical is capped back,
	// down to the pinning ceiling.
	gated := releaseSituation(ir.VisibilityPublic)
	j := gated.Jobs["release"]
	j.Impact = nil
	gated.Jobs["release"] = j
	paths := assemblePaths([]opaengine.Finding{
		finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-305", "release", nil),
	}, gated)
	if len(paths) != 1 || paths[0].Tier != TierMedium || !reflect.DeepEqual(paths[0].Modifiers, []string{"gate:ISSUE-305", "dependency_cap"}) {
		t.Errorf("an amplified dependency path is capped after the gate, got %+v", paths)
	}

	// Contributor and cache entries are not capped.
	expr := assemblePaths([]opaengine.Finding{entryFinding("ISSUE-207", "release", "github.event.issue.title")}, sit)
	if len(expr) != 1 || expr[0].Tier != TierCritical {
		t.Errorf("an untrusted expression keeps its Critical path, got %+v", expr)
	}
}

// The dependency cap depends on what anchors the path. A reference that is
// only not pinned (an action off a commit SHA, an image on a mutable tag
// or off a digest, an include on a mutable ref) caps at Medium: changing
// what runs needs a compromise of a source the team chose. The same
// subject from a source outside the authorized list caps at High: the
// compromise is more likely. A finding saying the dependency is already
// bad keeps the path uncapped.
func TestTheDependencyCapDependsOnWhatAnchorsThePath(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	action := map[string]any{"uses": "some/action@v1"}
	image := map[string]any{"link": "registry.example.com/tool:latest"}
	const (
		mediumNote = "Capped at Medium: it needs a dependency compromise first"
		mediumSay  = "The dependency must be compromised first, so this path is capped at Medium."
		highNote   = "Capped at High: the source is not authorized, so a compromise is more likely"
		highSay    = "The dependency must be compromised first, but its source is not authorized, so this path is capped at High."
	)
	for _, tc := range []struct {
		name      string
		codes     []string
		data      map[string]any
		tier      PathTier
		modifiers []string
		note      string
		say       string
		fix       string
	}{
		{"action not pinned", []string{"ISSUE-701"}, action, TierMedium, []string{"dependency_cap"}, mediumNote, mediumSay, "pin the version on the commit SHA"},
		{"action not pinned, unauthorized owner", []string{"ISSUE-701", "ISSUE-713"}, action, TierHigh, []string{"dependency_cap", "source_cap"}, highNote, highSay, "use an action from a trusted source and pin the version on the commit SHA"},
		{"action ref confusion", []string{"ISSUE-402"}, action, TierMedium, []string{"dependency_cap"}, mediumNote, mediumSay, "pin the version on the commit SHA"},
		{"known bad wins over the source", []string{"ISSUE-703", "ISSUE-701", "ISSUE-713"}, action, TierCritical, []string{}, "", "", "move to a version without the advisory"},
		{"image on a forbidden tag", []string{"ISSUE-102"}, image, TierMedium, []string{"dependency_cap"}, mediumNote, mediumSay, "pin the image by digest"},
		{"image off a digest", []string{"ISSUE-103"}, image, TierMedium, []string{"dependency_cap"}, mediumNote, mediumSay, "pin the image by digest"},
		{"image off a digest, unauthorized registry", []string{"ISSUE-103", "ISSUE-101"}, image, TierHigh, []string{"dependency_cap", "source_cap"}, highNote, highSay, "use an image from a trusted registry and pin it by digest"},
		{"image on a forbidden tag, unauthorized registry", []string{"ISSUE-102", "ISSUE-101"}, image, TierHigh, []string{"dependency_cap", "source_cap"}, highNote, highSay, "use an image from a trusted registry and pin it by digest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var findings []opaengine.Finding
			for _, c := range tc.codes {
				findings = append(findings, finding(c, "release", tc.data))
			}
			paths := assemblePaths(findings, sit)
			if len(paths) != 1 {
				t.Fatalf("want one path, got %+v", paths)
			}
			p := paths[0]
			if p.Tier != tc.tier || p.BaseTier != TierCritical || !reflect.DeepEqual(append([]string{}, p.Modifiers...), tc.modifiers) {
				t.Errorf("tier %s from %s, modifiers %v; want %s, %v", p.Tier, p.BaseTier, p.Modifiers, tc.tier, tc.modifiers)
			}
			b := NewPathBlock(p, nil)
			if b.Branches[0].Marker != "" || b.Cap != tc.note || b.Fix != tc.fix {
				t.Errorf("marker %q, note %q, fix %q", b.Branches[0].Marker, b.Cap, b.Fix)
			}
			if s := PathSentence(p); tc.say != "" && !strings.Contains(s, tc.say) {
				t.Errorf("sentence = %q", s)
			}
		})
	}

	// A GitLab include on a mutable ref is a pinning finding too.
	paths := assemblePaths([]opaengine.Finding{includeFinding()}, includeSituation(ir.VisibilityPublic, "deploy"))
	if len(paths) != 1 || paths[0].Tier != TierMedium || !reflect.DeepEqual(paths[0].Modifiers, []string{"dependency_cap"}) {
		t.Fatalf("an include on a mutable ref caps at Medium, got %+v", paths)
	}
	if b := NewPathBlock(paths[0], nil); b.Branches[0].Marker != "" || b.Cap != mediumNote {
		t.Errorf("include: marker %q, note %q", b.Branches[0].Marker, b.Cap)
	}

	// A pinning code next to a dependency that is not a reference to pin
	// keeps the High ceiling of that dependency.
	mixed := assemblePaths([]opaengine.Finding{
		finding("ISSUE-701", "release", action),
		finding("ISSUE-714", "release", action),
	}, sit)
	if len(mixed) != 1 || mixed[0].Tier != TierHigh || !reflect.DeepEqual(mixed[0].Modifiers, []string{"dependency_cap"}) {
		t.Errorf("701 with 714 stays at High, got %+v", mixed)
	}

	// The JSON names both modifiers on a path the source raised.
	raised := assemblePaths([]opaengine.Finding{finding("ISSUE-701", "release", action), finding("ISSUE-713", "release", action)}, sit)
	raw, _ := json.Marshal(raised[0])
	if !strings.Contains(string(raw), `"modifiers":["dependency_cap","source_cap"]`) {
		t.Errorf("JSON modifiers: %s", raw)
	}
}

// A pinning entry joined by a finding on its source says so: the source
// finding is what holds the path's ceiling at High, so the entry names it
// and the fix offers to authorize the source as well as to pin, whether
// the ceiling lowered the path (a release job, Critical by its reach) or
// not (a job holding a secret, High by its reach). A dependency already
// known bad reads as that finding. The paths table and the best fix read
// the same words.
func TestAnUnauthorizedSourceJoinsThePinningEntry(t *testing.T) {
	release := releaseSituation(ir.VisibilityPublic)
	holder := &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{}}
	j := JobSituation{}
	j.Privilege.Secrets = []string{"TOKEN"}
	j.Privilege.SecretsState = "proven"
	holder.Jobs["release"] = j
	for _, tc := range []struct {
		name, entry, fix string
		codes            []string
		data             map[string]any
		sit              *Situation
	}{
		{"action", "dorny/paths-filter@v3 (untrusted and mutable external action)",
			"use an action from a trusted source and pin the version on the commit SHA",
			[]string{"ISSUE-701", "ISSUE-713"}, map[string]any{"uses": "dorny/paths-filter@v3"}, release},
		{"action, High by its reach", "dorny/paths-filter@v3 (untrusted and mutable external action)",
			"use an action from a trusted source and pin the version on the commit SHA",
			[]string{"ISSUE-701", "ISSUE-713"}, map[string]any{"uses": "dorny/paths-filter@v3"}, holder},
		{"known bad", "dorny/paths-filter@v3 (external action with a known vulnerability)", "move to a version without the advisory",
			[]string{"ISSUE-703", "ISSUE-701", "ISSUE-713"}, map[string]any{"uses": "dorny/paths-filter@v3"}, release},
		{"image on a mutable tag", "evil.registry.io/app:latest (untrusted and mutable image)",
			"use an image from a trusted registry and pin it by digest",
			[]string{"ISSUE-102", "ISSUE-101"}, map[string]any{"link": "evil.registry.io/app:latest"}, release},
		{"image off a digest", "evil.registry.io/app:latest (untrusted and mutable image)",
			"use an image from a trusted registry and pin it by digest",
			[]string{"ISSUE-103", "ISSUE-101"}, map[string]any{"link": "evil.registry.io/app:latest"}, release},
		{"action without a source finding", "dorny/paths-filter@v3 (mutable external action)", "pin the version on the commit SHA",
			[]string{"ISSUE-701"}, map[string]any{"uses": "dorny/paths-filter@v3"}, release},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var findings []opaengine.Finding
			for _, c := range tc.codes {
				findings = append(findings, finding(c, "release", tc.data))
			}
			paths := assemblePaths(findings, tc.sit)
			if len(paths) != 1 {
				t.Fatalf("want one path, got %+v", paths)
			}
			b := NewPathBlock(paths[0], nil)
			if b.Entry != tc.entry || b.Fix != tc.fix {
				t.Errorf("entry %q, fix %q; want %q, %q", b.Entry, b.Fix, tc.entry, tc.fix)
			}
			if line := PathRowOf(paths[0]); line.Entry != tc.entry {
				t.Errorf("paths table entry %q", line.Entry)
			}
			score := &PlumberScoreResult{Paths: paths, BestFix: &BestFix{PathID: paths[0].ID, PointsGained: 15, NewPoints: 100, NewLetter: "A"}}
			if got := BestFixSummary(score); !strings.HasPrefix(got, tc.fix+" (") {
				t.Errorf("best fix = %q", got)
			}
		})
	}
}

// A dependency path that stays Critical because a finding says the
// dependency is already bad reads as that finding: its entry says why, and
// its fix is that finding's.
func TestAKnownBadDependencyNamesTheEntry(t *testing.T) {
	paths := assemblePaths([]opaengine.Finding{
		finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-703", "release", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"}),
	}, releaseSituation(ir.VisibilityPublic))
	if len(paths) != 1 || paths[0].Tier != TierCritical {
		t.Fatalf("want one Critical path, got %+v", paths)
	}
	b := NewPathBlock(paths[0], nil)
	if paths[0].AnchorCode != "ISSUE-703" || b.Entry != "some/action@v1 (external action with a known vulnerability)" || b.Fix != "move to a version without the advisory" {
		t.Errorf("anchor %s, entry %q, fix %q", paths[0].AnchorCode, b.Entry, b.Fix)
	}
}

// A workflow or an action inside the repository is no third-party
// dependency: it changes only with a commit here, whichever form the
// workflow writes its path in, so a finding on it anchors no path.
func TestALocalReferenceAnchorsNoPath(t *testing.T) {
	for _, uses := range []string{"./.github/workflows/build.yml", "$/.github/workflows/release.yml", "./.github/actions/setup"} {
		findings := []opaengine.Finding{
			finding("ISSUE-701", "release", map[string]any{"uses": uses}),
			finding("ISSUE-713", "release", map[string]any{"uses": uses}),
		}
		if paths := assemblePaths(findings, releaseSituation(ir.VisibilityPublic)); len(paths) != 0 {
			t.Errorf("%s: a local reference is no entry, got %+v", uses, paths)
		}
	}
}

func TestDismissingOneOfTwoAnchorsKeepsThePath(t *testing.T) {
	findings := pinnedActionFindings()
	findings[0].Dismissed = true
	paths := assemblePaths(findings, pinnedActionSituation())
	if len(paths) != 1 {
		t.Fatalf("the path survives on its other anchor, got %+v", paths)
	}
	if !reflect.DeepEqual(paths[0].AnchorHashes, hashesOf(t, findings[1:])) || !reflect.DeepEqual(paths[0].AnchorCodes, []ErrorCode{"ISSUE-703"}) {
		t.Errorf("anchors = %v %v, want the live one only", paths[0].AnchorHashes, paths[0].AnchorCodes)
	}
}

// Two branch findings on one branch anchor one unprotected_push path, and
// neither amplifies it: no anchor of a merged path is ever one of its gates.
func TestNoAnchorOfAMergedPathAmplifiesIt(t *testing.T) {
	sit := unprotectedPushSituation(ir.VisibilityPublic)
	sit.DefaultBranch = "main"
	build := sit.Jobs["build"]
	build.Privilege.Secrets = []string{"NPM_TOKEN"} // something the job gate protects
	sit.Jobs["build"] = build
	unprotected := finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"})
	nonCompliant := finding(string(CodeBranchNonCompliant), "", map[string]any{"branchName": "main"})
	gate := finding("ISSUE-305", "build", nil)
	paths := assemblePaths([]opaengine.Finding{unprotected, nonCompliant, gate}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one push path for one branch and one job, got %+v", paths)
	}
	p := paths[0]
	if len(p.AnchorHashes) != 2 {
		t.Errorf("anchors = %v, want both branch findings", p.AnchorCodes)
	}
	if !reflect.DeepEqual(p.Modifiers, []string{"gate:ISSUE-305", "push_entry_cap"}) || len(p.GateHashes) != 1 {
		t.Errorf("only the job gate amplifies, once: modifiers %v, gates %v", p.Modifiers, p.GateHashes)
	}
}

func TestMergedPathIsDeterministicUnderShuffle(t *testing.T) {
	findings := append(pinnedActionFindings(), imageFindings()...)
	findings = append(findings, finding("ISSUE-305", "build", nil))
	sit := pinnedActionSituation()
	want := assemblePaths(findings, sit)
	if len(want) != 2 {
		t.Fatalf("fixture drifted: want two merged paths, got %+v", want)
	}
	for seed := int64(1); seed <= 30; seed++ {
		shuffled := append([]opaengine.Finding(nil), findings...)
		r := rand.New(rand.NewSource(seed))
		r.Shuffle(len(shuffled), func(i, k int) { shuffled[i], shuffled[k] = shuffled[k], shuffled[i] })
		if got := assemblePaths(shuffled, sit); !reflect.DeepEqual(got, want) {
			t.Fatalf("seed %d: order-dependent result\n got  %+v\n want %+v", seed, got, want)
		}
	}
}

// entryFinding is an entry-role finding naming its subject the way the
// rules do once the engine has lifted it.
func entryFinding(code, job, subject string) opaengine.Finding {
	return opaengine.Finding{Code: code, Job: job, File: ".github/workflows/ci.yml", Line: 10, Subject: subject}
}

// An entry-role finding is its own entry: a job with no fact of any kind
// still yields a proven path, priced by what the job reaches.
func TestEntryFindingIsItsOwnEntry(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{"build": {}}}
	f := entryFinding("ISSUE-207", "build", "github.event.pull_request.title")
	f.Message = `job "build" interpolates a user-controlled template expression into an inline script`
	paths := assemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	p := paths[0]
	if p.EntryKind != EntryUntrustedExpression || p.Tier != TierHigh || p.State != PathProven {
		t.Errorf("path = %+v", p)
	}
	if p.Entry.Subject != "github.event.pull_request.title" || p.Entry.State != "proven" || p.Entry.Evidence != f.Message {
		t.Errorf("entry = %+v", p.Entry)
	}
	if p.Entry.File != f.File || p.Entry.Line != f.Line {
		t.Errorf("entry location = %s:%d", p.Entry.File, p.Entry.Line)
	}
}

// The subject of each entry code, read off the finding's own data.
func TestEntrySubjectPerCode(t *testing.T) {
	cases := []struct {
		name string
		f    opaengine.Finding
		want string
	}{
		{"lifted subject wins", opaengine.Finding{Code: "ISSUE-207", Subject: "github.event.issue.title"}, "github.event.issue.title"},
		{"action", finding("ISSUE-713", "j", map[string]any{"uses": "some/action@v1"}), "some/action@v1"},
		{"image, collector placeholder registry dropped", finding("ISSUE-102", "j", map[string]any{"link": "unknown/alpine:latest"}), "alpine:latest"},
		{"image with a registry", finding("ISSUE-103", "j", map[string]any{"link": "docker.io/alpine:latest"}), "docker.io/alpine:latest"},
		{"script, first URL", finding("ISSUE-411", "j", map[string]any{"scriptLine": "set -e\ncurl -sL https://example.com/install.sh | bash"}), "https://example.com/install.sh"},
		{"script without a URL", finding("ISSUE-411", "j", map[string]any{"scriptLine": "  bash <(wget -qO- $URL)  "}), "bash <(wget -qO- $URL)"},
		{"variable", finding("ISSUE-204", "j", map[string]any{"variableName": "CI_MERGE_REQUEST_TITLE"}), "CI_MERGE_REQUEST_TITLE"},
		{"checkout ref", finding("ISSUE-804", "j", map[string]any{"ref": "${{ github.event.pull_request.head.sha }}"}), "github.event.pull_request.head.sha"},
		{"nothing named, the message", opaengine.Finding{Code: "ISSUE-213", Message: "job dumps the context"}, "job dumps the context"},
	}
	for _, tc := range cases {
		if got := entrySubject(tc.f); got != tc.want {
			t.Errorf("%s: entrySubject = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A reference that is an expression, or an image that still names a
// variable, is computed at run time: Plumber cannot know what runs, so the
// entry is unresolvable, the path unverified and one tier lower, and its
// entry says why. A fetched script is not a reference: an expression in
// its line leaves the path proven.
func TestAReferenceComputedAtRunTimeIsUnverified(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	for _, f := range []opaengine.Finding{
		finding("ISSUE-103", "release", map[string]any{"link": "${{ needs.build-image.outputs.image-tag }}"}),
		finding("ISSUE-103", "release", map[string]any{"link": "nvidia/cuda:${{ matrix.cuda }}-devel"}),
		finding("ISSUE-102", "release", map[string]any{"link": "$CI_REGISTRY_IMAGE/app:latest"}),
		finding("ISSUE-103", "release", map[string]any{"link": "registry.example.com/${IMAGE_NAME}:1"}),
	} {
		paths := assemblePaths([]opaengine.Finding{f}, sit)
		if len(paths) != 1 {
			t.Fatalf("%v: want one path, got %+v", f.Data, paths)
		}
		p := paths[0]
		if p.State != PathUnverified || p.Tier != TierMedium || p.Entry.State != "unresolvable" {
			t.Errorf("%v: want an unverified Medium path, got %s %s %s", f.Data, p.State, p.Tier, p.Entry.State)
		}
		if b := NewPathBlock(p, nil); b.EntryUnverified != "the reference is computed at run time, so Plumber cannot know what runs" {
			t.Errorf("%v: entry line = %q", f.Data, b.EntryUnverified)
		}
		if s := PathSentence(p); !strings.Contains(s, "The reference is computed at run time, so this path is unverified.") {
			t.Errorf("%v: sentence = %q", f.Data, s)
		}
	}
	for _, f := range []opaengine.Finding{
		finding("ISSUE-103", "release", map[string]any{"link": "registry.example.com/tool:1"}),
		finding("ISSUE-411", "release", map[string]any{"scriptLine": "curl -sL https://example.com/${{ inputs.version }}/install.sh | bash"}),
	} {
		paths := assemblePaths([]opaengine.Finding{f}, sit)
		if len(paths) != 1 || paths[0].State != PathProven {
			t.Errorf("%v: want one proven path, got %+v", f.Data, paths)
		}
	}
}

// A code saying the entry itself could not be checked marks the path
// unverified; merged with a code that proves it, the path is proven.
func TestUnverifiableEntryCodesMarkThePathUnverified(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	alone := assemblePaths([]opaengine.Finding{finding("ISSUE-716", "release", map[string]any{"uses": "some/action@v1"})}, sit)
	if len(alone) != 1 || alone[0].State != PathUnverified || alone[0].Tier != TierHigh {
		t.Errorf("ISSUE-716 alone: %+v", alone)
	}
	merged := assemblePaths([]opaengine.Finding{
		finding("ISSUE-707", "release", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"}),
	}, sit)
	if len(merged) != 1 || merged[0].State != PathProven || merged[0].Tier != TierCritical {
		t.Errorf("ISSUE-707 with ISSUE-713: %+v", merged)
	}
}

// A job-less include finding enters every job its include shapes, at the
// include's own location, matched on the exact subject.
func TestJobLessIncludeFindingStartsAPathOnEveryJobItsIncludeShapes(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{"build": {}, "test": {}, "lint": {}},
		Includes: []IncludeFact{
			{Subject: "group/ci@main", File: ".gitlab-ci.yml", Line: 3, Jobs: []string{"build", "test"}},
			{Subject: "group/ci-extra@main", Jobs: []string{"lint"}},
		}}
	f := opaengine.Finding{Code: "ISSUE-404", Subject: "group/ci@main", Data: map[string]any{"includePath": "group/ci"}}
	paths := assemblePaths([]opaengine.Finding{f}, sit)
	var jobs []string
	for _, p := range paths {
		for _, b := range p.Branches {
			jobs = append(jobs, b.Job)
		}
		if p.Entry.Subject != "group/ci@main" || p.Entry.File != ".gitlab-ci.yml" || p.Entry.Line != 3 {
			t.Errorf("entry = %+v", p.Entry)
		}
	}
	if len(paths) != 1 {
		t.Errorf("want one path, got %d", len(paths))
	}
	sort.Strings(jobs)
	if !reflect.DeepEqual(jobs, []string{"build", "test"}) {
		t.Errorf("entry jobs = %v", jobs)
	}
}

// A dismissed ISSUE-804 finding on the entry job still says a privileged
// trigger runs there: the fork run's secrets stay in play for an injection.
// The trigger, not a finding, is what keeps a fork run's secrets: a job
// that also runs on pull_request_target holds them on the path with no
// ISSUE-802 or ISSUE-804 finding anywhere, and a plain pull_request job
// from a fork holds none.
func TestPrivilegedTriggerKeepsAForkRunsSecrets(t *testing.T) {
	sit := injectionSituation(ir.VisibilityPublic, []string{"NPM_TOKEN"})
	f := entryFinding("ISSUE-207", "build", "github.event.pull_request.title")
	pruned := assemblePaths([]opaengine.Finding{f}, sit)
	if len(pruned) != 1 || len(pruned[0].Reach.Secrets) != 0 {
		t.Fatalf("a fork run holds no secret: %+v", pruned)
	}
	j := sit.Jobs["build"]
	j.PrivilegedTriggers, j.CacheScopes = []string{"pull_request_target"}, defaultScope
	sit.Jobs["build"] = j
	kept := assemblePaths([]opaengine.Finding{f}, sit)
	if len(kept) != 1 || !reflect.DeepEqual(kept[0].Reach.Secrets, []string{"NPM_TOKEN"}) || !reflect.DeepEqual(kept[0].survivingJobs, []string{"build"}) {
		t.Errorf("a privileged trigger on the job keeps the secrets: %+v", kept)
	}
}

// unlistedSecretsJob is a job whose secret names could not be listed,
// holding writeScopes of the token from source and the listed secrets.
func unlistedSecretsJob(source string, writeScopes, secrets []string) *Situation {
	j := JobSituation{}
	j.Privilege.SecretsState = "unresolvable"
	j.Privilege.Secrets = secrets
	j.Privilege.TokenWrite = writeScopes
	j.Privilege.TokenWriteSource = source
	return &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"build": j}}
}

// Secrets that could not be listed lower a path only when its tier rests
// on them: a declared write token, or a secret that was listed, already
// gives the path its tier, so the path stays proven at that tier, and its
// block still says the secrets could not be listed.
func TestUnlistedSecretsDoNotLowerAPathAProvenPrivilegeHolds(t *testing.T) {
	f := finding("ISSUE-714", "build", map[string]any{"uses": "some/action@v1"})
	for name, sit := range map[string]*Situation{
		"declared write token": unlistedSecretsJob("declared", []string{"contents"}, nil),
		"listed secret":        unlistedSecretsJob("", nil, []string{"NPM_TOKEN"}),
	} {
		paths := assemblePaths([]opaengine.Finding{f}, sit)
		if len(paths) != 1 {
			t.Fatalf("%s: want one path, got %+v", name, paths)
		}
		p := paths[0]
		if p.Tier != TierHigh || p.BaseTier != TierHigh || p.State != PathProven || len(p.Modifiers) != 0 {
			t.Errorf("%s: want a proven High path, got %+v", name, p)
		}
		if p.cause != unresolvableSecrets {
			t.Errorf("%s: cause = %q, want secrets", name, p.cause)
		}
		if b := NewPathBlock(p, nil); b.ReachUnverified != "Plumber could not list the secrets" || b.Unverified {
			t.Errorf("%s: block = %+v", name, b)
		}
	}
	// The one-line reach names the privilege the tier rests on.
	paths := assemblePaths([]opaengine.Finding{f}, unlistedSecretsJob("declared", []string{"contents"}, nil))
	if got := PathRowOf(paths[0]).Reaches; got != "unlisted secrets; token: write" {
		t.Errorf("row reach = %q, want the write token", got)
	}
}

// When the only privilege is the one that could not be read (secrets that
// could not be listed, a default token whose write is assumed), the path
// keeps the High its code execution proves: the tier does not rest on the
// privilege, so the path stays proven.
func TestAnUnreadPrivilegeBesideCodeExecutionKeepsItHigh(t *testing.T) {
	f := finding("ISSUE-714", "build", map[string]any{"uses": "some/action@v1"})
	for name, sit := range map[string]*Situation{
		"nothing else":  unlistedSecretsJob("", nil, nil),
		"default token": unlistedSecretsJob("default", []string{"contents"}, nil),
	} {
		paths := assemblePaths([]opaengine.Finding{f}, sit)
		if len(paths) != 1 || paths[0].Tier != TierHigh || paths[0].BaseTier != TierHigh || paths[0].State != PathProven || len(paths[0].Modifiers) != 0 {
			t.Errorf("%s: want a proven High path, got %+v", name, paths)
		}
	}
}

// Secrets that could not be listed never lower a path below the tier its
// proven reach gives: the path is priced one step below the tier it would
// have if the secrets were real, which is never under the proven one. A
// proven impact holds High on its own, so unlisted secrets beside it give
// Critical lowered to High, not High lowered to Medium; an impact that
// could not be confirmed reads the same way. The block says what the
// secrets would give, never that the path reaches nothing.
func TestUnlistedSecretsNeverLowerAPathBelowItsProvenReach(t *testing.T) {
	f := finding("ISSUE-714", "build", map[string]any{"uses": "some/action@v1"})
	withImpact := func(state FactState) *Situation {
		sit := unlistedSecretsJob("", nil, nil)
		j := sit.Jobs["build"]
		j.Impact = []ImpactFact{{Kind: "deploys", State: state, Evidence: "kubectl apply -f production.yaml"}}
		sit.Jobs["build"] = j
		return sit
	}
	so := "if this action is compromised, an attacker can read the secrets Plumber could not list and %s alter what the job deploys"
	for name, c := range map[string]struct {
		sit        *Situation
		base, want PathTier
		so         string
	}{
		"proven impact":      {withImpact("proven"), TierCritical, TierHigh, strings.Replace(fmt.Sprintf(so, ""), "and  alter", "and alter", 1)},
		"unconfirmed impact": {withImpact("unresolvable"), TierCritical, TierHigh, fmt.Sprintf(so, "may")},
	} {
		paths := assemblePaths([]opaengine.Finding{f}, c.sit)
		if len(paths) != 1 {
			t.Fatalf("%s: want one path, got %+v", name, paths)
		}
		p := paths[0]
		if p.BaseTier != c.base || p.Tier != c.want || p.State != PathUnverified || !reflect.DeepEqual(p.Modifiers, []string{"unresolvable"}) {
			t.Errorf("%s: want %s lowered to %s and unverified, got %+v", name, c.base, c.want, p)
		}
		b := NewPathBlock(p, nil)
		if b.So != c.so || !strings.Contains(b.ReachesShort, "unlisted secrets") {
			t.Errorf("%s: block = %+v", name, b)
		}
	}
}

// A missing protection raises a path only when the path can do damage the
// protection would have stopped: a reach holding a privilege or an impact.
// A path reaching code execution only is never raised, by a job-level gate
// or by the default-branch one.
func TestAGateNeverRaisesAPathThatReachesCodeExecutionOnly(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", DefaultBranch: "main", Jobs: map[string]JobSituation{"scan": {}}}
	findings := []opaengine.Finding{
		finding("ISSUE-703", "scan", map[string]any{"uses": "some/action@v1"}),
		finding(string(CodeSecurityJobWeakened), "scan", nil),
		finding(string(CodeSecretsOutsideEnv), "scan", nil),
		finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"}),
	}
	paths := assemblePaths(findings, sit)
	if len(paths) != 1 || paths[0].Tier != TierHigh || paths[0].ReachKind != "execution" || len(paths[0].Modifiers) != 0 || len(paths[0].GateHashes) != 0 {
		t.Errorf("want the execution-only path High and not raised, got %+v", paths)
	}

	// An impact alone is damage the protection would have stopped, and a
	// proven deploy is a real write the default branch's gate guards too.
	j := sit.Jobs["scan"]
	j.Impact = []ImpactFact{{Kind: "deploys", State: "proven", Evidence: "kubectl apply"}}
	sit.Jobs["scan"] = j
	paths = assemblePaths(findings, sit)
	if len(paths) != 1 || paths[0].BaseTier != TierHigh || paths[0].Tier != TierCritical || len(paths[0].GateHashes) != 3 {
		t.Errorf("want the deploying path raised by the job's gates and the branch's, got %+v", paths)
	}
}

// tokenImpacts is the impacts the facts layer gives a job whose token can
// write the matching scopes: one per scope, from the token.
func tokenImpacts(state FactState, kinds ...string) []ImpactFact {
	var out []ImpactFact
	for _, k := range kinds {
		out = append(out, ImpactFact{Kind: k, State: state, Evidence: "permissions: write-all", Source: "token"})
	}
	return out
}

func writeAllSituation() *Situation {
	j := JobSituation{Impact: tokenImpacts("proven", "deploys", "publishes", "writes_repo")}
	j.Privilege.SecretsState = "proven"
	j.Privilege.TokenWrite = []string{"actions", "contents", "deployments", "id-token", "packages", "pull-requests", "security-events"}
	j.Privilege.TokenWriteSource = "declared"
	return &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"build": j}}
}

// A write token is a privilege and an impact at once: a path into the job
// is Critical on its base tier, one path for the token's several impacts.
func TestAWriteTokenIsAnImpactOnOnePath(t *testing.T) {
	paths := assemblePaths([]opaengine.Finding{finding("ISSUE-703", "build", map[string]any{"uses": "some/action@v1"})}, writeAllSituation())
	if len(paths) != 1 {
		t.Fatalf("want one path for the token's three impacts, got %+v", paths)
	}
	p := paths[0]
	if p.BaseTier != TierCritical || p.Tier != TierCritical || p.State != PathProven || p.ReachKind != "impact:publishes" {
		t.Errorf("path = %+v", p)
	}
}

// What a step does and what the token allows are one reach: the entry
// still makes one path.
func TestStepAndTokenImpactsMakeOnePath(t *testing.T) {
	sit := writeAllSituation()
	j := sit.Jobs["build"]
	j.Impact = append(tokenImpacts("proven", "deploys", "writes_repo"), ImpactFact{Kind: "publishes", State: "proven", Evidence: "npm publish"})
	sit.Jobs["build"] = j
	paths := assemblePaths([]opaengine.Finding{finding("ISSUE-703", "build", map[string]any{"uses": "some/action@v1"})}, sit)
	if len(paths) != 1 || paths[0].Tier != TierCritical || paths[0].State != PathProven || len(paths[0].Reach.Impacts) != 3 {
		t.Errorf("paths = %+v", paths)
	}
}

// A GitHub fork pull_request run holds a read-only token, so the impacts
// the entry job's token gives are gone with it.
func TestAForkRunDropsTheTokenImpacts(t *testing.T) {
	sit := writeAllSituation()
	j := sit.Jobs["build"]
	j.ForkPR = []EntryFact{{Kind: EntryForkPR, State: "proven", Evidence: "on: pull_request", Subject: "pull_request"}}
	sit.Jobs["build"] = j
	paths := assemblePaths([]opaengine.Finding{entryFinding("ISSUE-207", "build", "github.event.pull_request.title")}, sit)
	if len(paths) != 1 || paths[0].ReachKind != "execution" || paths[0].Tier != TierHigh || len(paths[0].Reach.Impacts) != 0 {
		t.Errorf("want the fork run's path to reach code execution alone, got %+v", paths)
	}
}

func everySecretSituation(source string, writeScopes ...string) *Situation {
	j := JobSituation{}
	j.Privilege.SecretsState = "proven"
	j.Privilege.AllSecrets = true
	j.Privilege.TokenWrite = writeScopes
	j.Privilege.TokenWriteSource = source
	return &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"deploy": j}}
}

// A job that reads the whole secrets context, or calls a reusable workflow
// with secrets: inherit, holds every secret of the repository: a proven
// privilege, whatever their names, never "secrets Plumber could not list".
func TestEverySecretIsAProvenPrivilege(t *testing.T) {
	f := finding("ISSUE-714", "deploy", map[string]any{"uses": "acme/wf/.github/workflows/deploy.yml@main"})
	paths := assemblePaths([]opaengine.Finding{f}, everySecretSituation(""))
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	p := paths[0]
	if p.ReachKind != "secrets" || p.BaseTier != TierHigh || p.Tier != TierHigh || p.State != PathProven || len(p.Modifiers) != 0 || !p.Reach.AllSecrets {
		t.Errorf("path = %+v", p)
	}
	b := NewPathBlock(p, nil)
	if b.ReachesShort != "every secret" || b.Unverified {
		t.Errorf("block = %+v", b)
	}
	if s := PathSentence(p); !strings.Contains(s, "holding every secret of the repository: the secrets can be read and reused elsewhere.") {
		t.Errorf("sentence = %q", s)
	}

	// Beside an assumed default token, every secret keeps the path proven:
	// the tier rests on the secrets, not on the guess.
	paths = assemblePaths([]opaengine.Finding{f}, everySecretSituation("default", "contents"))
	if len(paths) != 1 || paths[0].State != PathProven || paths[0].Tier != TierHigh {
		t.Errorf("with a default token: %+v", paths)
	}
}

// A GitHub fork pull_request run holds none of the repository's secrets,
// every secret included.
func TestAForkRunHoldsNoneOfEverySecret(t *testing.T) {
	sit := everySecretSituation("")
	j := sit.Jobs["deploy"]
	j.ForkPR = []EntryFact{{Kind: EntryForkPR, State: "proven", Evidence: "on: pull_request", Subject: "pull_request"}}
	sit.Jobs["deploy"] = j
	paths := assemblePaths([]opaengine.Finding{entryFinding("ISSUE-207", "deploy", "github.event.pull_request.title")}, sit)
	if len(paths) != 1 || paths[0].Reach.AllSecrets || paths[0].ReachKind != "execution" {
		t.Errorf("paths = %+v", paths)
	}
}

// A release job restoring a cache an untrusted run can write is the entry
// of a path into that job: the cache is the subject, and the path reaches
// what the job holds and publishes.
func TestCachePoisoningIsAnEntryIntoTheJobThatRestoresTheCache(t *testing.T) {
	f := cacheFinding()
	preview, entry := privilegedPreview()
	sit := cacheSituation(map[string]JobSituation{"pr-preview/preview": preview})
	sit.Exposure = ir.VisibilityPrivate
	paths := assemblePaths([]opaengine.Finding{f, entry}, sit)
	cache := cachePaths(paths)
	if len(cache) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	p := cache[0]
	if p.EntryKind != EntryPoisonedCache || p.Entry.Subject != f.Subject || p.Tier != TierCritical || p.State != PathProven || len(p.Modifiers) != 0 {
		t.Errorf("path = %+v", p)
	}
	b := NewPathBlock(p, nil)
	if b.Entry != "npm-${{ hashFiles('**/package-lock.json') }} (cache an untrusted run can write)" ||
		b.Fix != "do not restore a cache that untrusted runs can write in a release job" {
		t.Errorf("block = %+v", b)
	}
	if s := PathSentence(p); !strings.HasPrefix(s, "A run that is not trusted can write the cache `npm-${{ hashFiles('**/package-lock.json') }}` that `release` restores, holding `NPM_TOKEN`") {
		t.Errorf("sentence = %q", s)
	}
	if line := FindingLine(f, paths); line != "Entry of path "+p.ID {
		t.Errorf("finding line = %q", line)
	}
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: []opaengine.Finding{f, entry}, Paths: paths})
	if s.OtherFindings != nil && s.OtherFindings.Count != 0 {
		t.Errorf("the entry of a path is not an other finding: %+v", s.OtherFindings)
	}
}

// The unresolved variant could not settle that the cache is on when the
// job publishes: the same entry, unverified.
func TestUnresolvedCachePoisoningIsAnUnverifiedEntry(t *testing.T) {
	f := opaengine.Finding{Code: string(CodeCachePoisoningUnresolved), Job: "release", File: ".github/workflows/release.yml", Line: 22,
		Subject: "actions/setup-java@v5", Message: "job \"release\" gates the cache of \"actions/setup-java@v5\" with an expression", Data: map[string]any{"uses": "actions/setup-java@v5"}}
	preview, entry := privilegedPreview()
	paths := cachePaths(assemblePaths([]opaengine.Finding{f, entry}, cacheSituation(map[string]JobSituation{"pr-preview/preview": preview})))
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	p := paths[0]
	if p.EntryKind != EntryPoisonedCache || p.Tier != TierHigh || p.State != PathUnverified || p.Modifiers[0] != "unresolvable" {
		t.Errorf("path = %+v", p)
	}
	if b := NewPathBlock(p, nil); b.EntryUnverified != "Plumber could not check that the cache is on when the job publishes" {
		t.Errorf("block = %+v", b)
	}
}

// The block says what the token lets an attacker do, in words, once.
func TestATokenImpactReadsAsWhatTheTokenAllows(t *testing.T) {
	p := assemblePaths([]opaengine.Finding{finding("ISSUE-701", "build", map[string]any{"uses": "some/action@v1"})}, writeAllSituation())[0]
	b := NewPathBlock(p, nil)
	if b.ReachesShort != "token: push, publish, deploy" {
		t.Errorf("ReachesShort = %q", b.ReachesShort)
	}
	s := PathSentence(p)
	if !strings.Contains(s, "holding a token that can write to the repository, publish packages and create deployments:") || strings.Contains(s, "publishes the package") {
		t.Errorf("sentence = %q", s)
	}
}

// cacheFinding is a release job restoring a cache whose key is not scoped
// to the released ref.
func cacheFinding() opaengine.Finding {
	return opaengine.Finding{Code: string(CodeCachePoisoning), Job: "release", File: ".github/workflows/release.yml", Line: 22,
		Subject: "npm-${{ hashFiles('**/package-lock.json') }}", Data: map[string]any{"uses": "actions/cache@v5"}}
}

// cacheSituation is releaseSituation, its release job restoring and saving
// npmCache, plus the jobs given, on GitHub.
// defaultScope is the cache scope of a job running on the default
// branch (a push, a schedule, a dispatch, a privileged trigger), the one a
// release run restores from.
var defaultScope = []string{"default"}

func cacheSituation(jobs map[string]JobSituation) *Situation {
	s := releaseSituation(ir.VisibilityPublic)
	s.Provider = "github"
	s.Jobs["release"] = withCaches(s.Jobs["release"], npmCache)
	for name, j := range jobs {
		s.Jobs[name] = j
	}
	return s
}

// privilegedPreview is a pull_request_target job checking out the pull
// request head: code from anyone runs in the base repository's context.
func privilegedPreview() (JobSituation, opaengine.Finding) {
	return JobSituation{PrivilegedTriggers: []string{"pull_request_target"}, CacheScopes: defaultScope},
		entryFinding("ISSUE-804", "pr-preview/preview", "github.event.pull_request.head.sha")
}

func cachePaths(paths []AttackPath) []AttackPath {
	var out []AttackPath
	for _, p := range paths {
		if p.EntryKind == EntryPoisonedCache {
			out = append(out, p)
		}
	}
	return out
}

// A poisoned cache starts a path when a job runs code from outside the team
// in a run that can save the repository's caches: here a pull_request_target
// job runs the pull request head. The block names that job, and the order of
// the findings does not matter.
func TestACachePathNeedsAJobThatCanWriteTheCache(t *testing.T) {
	preview, entry := privilegedPreview()
	sit := cacheSituation(map[string]JobSituation{"pr-preview/preview": preview})
	for _, findings := range [][]opaengine.Finding{{cacheFinding(), entry}, {entry, cacheFinding()}} {
		cache := cachePaths(assemblePaths(findings, sit))
		if len(cache) != 1 || cache[0].Tier != TierCritical || cache[0].Jobs[0] != "release" {
			t.Fatalf("want one Critical path through the cache into release, got %+v", cache)
		}
		b := NewPathBlock(cache[0], nil)
		if b.Entry != "npm-${{ hashFiles('**/package-lock.json') }} (cache an untrusted run can write)" ||
			b.EntryWriter != "a run of job `preview` from workflow `pr-preview` can write the cache" {
			t.Errorf("block = %+v", b)
		}
	}
}

// A dependency that can change on its own runs in every run of its job: on
// a push, it can save the cache. Two such jobs are both named.
func TestADependencyInAPushRunCanWriteTheCache(t *testing.T) {
	sit := cacheSituation(map[string]JobSituation{"ci/build": {RefTriggers: []string{"push"}, CacheScopes: defaultScope}, "ci/lint": {RefTriggers: []string{"schedule"}, CacheScopes: defaultScope}})
	findings := []opaengine.Finding{
		cacheFinding(),
		finding("ISSUE-701", "ci/build", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-701", "ci/lint", map[string]any{"uses": "other/action@v1"}),
	}
	cache := cachePaths(assemblePaths(findings, sit))
	if len(cache) != 1 {
		t.Fatalf("want the cache path, got %+v", cache)
	}
	if b := NewPathBlock(cache[0], nil); b.EntryWriter != "runs of jobs `build` and `lint` from workflow `ci` can write the cache" {
		t.Errorf("two jobs can write the cache, the block names both: %+v", b)
	}
}

// A fork pull request run saves only to its own merge ref's cache, and a
// job that runs on pull requests alone never saves anywhere else: with no
// other job able to write it, the cache finding starts no path and is priced
// on its own, at its severity.
func TestAForkPullRequestRunDoesNotStartACachePath(t *testing.T) {
	fork := []EntryFact{{Kind: EntryForkPR, State: "proven", Evidence: "on: pull_request", Subject: "pull_request"}}
	sit := cacheSituation(map[string]JobSituation{
		"ci/test":  {ForkPR: fork, RefTriggers: []string{"push"}, CacheScopes: defaultScope},
		"ci/check": {},
	})
	findings := []opaengine.Finding{
		cacheFinding(),
		entryFinding("ISSUE-207", "ci/test", "github.event.pull_request.title"),
		finding("ISSUE-701", "ci/check", map[string]any{"uses": "some/action@v1"}),
	}
	paths := assemblePaths(findings, sit)
	if cache := cachePaths(paths); len(cache) != 0 {
		t.Fatalf("no run that can write the cache runs untrusted code, got %+v", cache)
	}
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: findings, Paths: paths})
	if s.OtherFindings == nil || s.OtherFindings.Count != 1 || len(s.CodeLosses) != 1 || s.CodeLosses[0].Code != CodeCachePoisoning || s.CodeLosses[0].Severity != SeverityHigh {
		t.Errorf("want the cache finding priced as an other finding, got %+v", s.CodeLosses)
	}
}

// Code execution alone is High: an attacker running code in the job holds
// the runner whatever else the job carries. Medium only comes from a
// modifier lowering a High path, and a path where no code runs stays Low.
func TestCodeExecutionAloneIsHigh(t *testing.T) {
	if got := baseTier(Reach{Executes: true}, "", false); got != TierHigh {
		t.Errorf("code execution alone: %s, want high", got)
	}
	if got := baseTier(Reach{}, "", false); got != TierLow {
		t.Errorf("no code runs: %s, want low", got)
	}
	f := finding("ISSUE-703", "build", map[string]any{"uses": "some/action@v1"})
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"build": {}}}
	paths := assemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 1 || paths[0].BaseTier != TierHigh || paths[0].Tier != TierHigh || paths[0].State != PathProven {
		t.Fatalf("want one proven High path, got %+v", paths)
	}
	if so := NewPathBlock(paths[0], nil).So; so != "through the known vulnerability of this action, an attacker can execute code on the runner and poison what it caches or uploads" {
		t.Errorf("So = %q", so)
	}

	// A private repository lowers a contributor entry one step, to Medium.
	sit = &Situation{Exposure: ir.VisibilityPrivate, Provider: "github", Jobs: map[string]JobSituation{"build": {}}}
	paths = assemblePaths([]opaengine.Finding{entryFinding("ISSUE-207", "build", "github.event.issue.title")}, sit)
	if len(paths) != 1 || paths[0].BaseTier != TierHigh || paths[0].Tier != TierMedium || !reflect.DeepEqual(paths[0].Modifiers, []string{"private_exposure"}) {
		t.Errorf("want the private contributor path lowered to Medium, got %+v", paths)
	}
}

// Secrets Plumber could not list beside code execution: the tier rests on
// the code execution, so the path stays High and proven and says the
// secrets could not be listed. A missing protection that raises it only
// because of those secrets rests on them: priced Critical, it goes down
// one, unverified, never below the High the code execution proves.
func TestUnlistedSecretsBesideCodeExecutionStayHigh(t *testing.T) {
	f := finding("ISSUE-714", "build", map[string]any{"uses": "some/action@v1"})
	paths := assemblePaths([]opaengine.Finding{f}, unlistedSecretsJob("", nil, nil))
	if len(paths) != 1 || paths[0].BaseTier != TierHigh || paths[0].Tier != TierHigh || paths[0].State != PathProven || len(paths[0].Modifiers) != 0 {
		t.Fatalf("want one proven High path, got %+v", paths)
	}
	if b := NewPathBlock(paths[0], nil); b.ReachUnverified != "Plumber could not list the secrets" {
		t.Errorf("block = %+v", b)
	}

	sit := unlistedSecretsJob("", nil, nil)
	gate := finding(string(CodeSecretsOutsideEnv), "build", nil)
	paths = assemblePaths([]opaengine.Finding{f, gate}, sit)
	if len(paths) != 1 || paths[0].Tier != TierHigh || paths[0].State != PathUnverified || len(paths[0].GateHashes) != 1 ||
		!reflect.DeepEqual(paths[0].Modifiers, []string{"unresolvable", "gate:" + string(CodeSecretsOutsideEnv)}) {
		t.Errorf("want the raised path lowered back to High and unverified, got %+v", paths)
	}
}
