package control

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/getplumber/plumber/finding/identity"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

func pathOf(tier PathTier, kind EntryKind, anchor string) AttackPath {
	return AttackPath{ID: anchor + string(tier), Tier: tier, EntryKind: kind, AnchorHash: anchor, AnchorCode: "ISSUE-713", State: PathProven}
}

// The profile id names the formula, so every constant the formula reads is
// pinned here next to it (spec section 9: the profile id changes whenever a
// weight, a cap or a threshold does). A change to any value below requires
// a new PlumberScoreProfileIDV4 as well, never an edit of this table alone.
func TestProfileIDPinsTheFormulaConstants(t *testing.T) {
	if PlumberScoreProfileIDV4 != "scoring-v4" {
		t.Fatalf("profile id = %q: a new id needs this table re-pinned", PlumberScoreProfileIDV4)
	}
	inf := math.Inf(1)
	paths := pathTierSpecs()
	gates := scoreSeveritySpecs()
	cases := []struct {
		name      string
		got, want float64
	}{
		{"critical path weight", paths[TierCritical].weight, 30},
		{"critical path cap", paths[TierCritical].cap, inf},
		{"high path weight", paths[TierHigh].weight, 15},
		{"high path cap", paths[TierHigh].cap, 60},
		{"medium path weight", paths[TierMedium].weight, 6},
		{"medium path cap", paths[TierMedium].cap, 20},
		{"low path weight", paths[TierLow].weight, 3},
		{"low path cap", paths[TierLow].cap, 10},
		{"critical gate weight", gates[SeverityCritical].weight, 25},
		{"critical gate cap", gates[SeverityCritical].cap, inf},
		{"high gate weight", gates[SeverityHigh].weight, 15},
		{"high gate cap", gates[SeverityHigh].cap, 60},
		{"medium gate weight", gates[SeverityMedium].weight, 6},
		{"medium gate cap", gates[SeverityMedium].cap, 20},
		{"low gate weight", gates[SeverityLow].weight, 3},
		{"low gate cap", gates[SeverityLow].cap, 10},
		{"hygiene weight", hygieneWeight, 2},
		{"hygiene cap", hygieneCap, 10},
		{"critical path cap on final points", criticalPathCap, 30},
	}
	if len(paths) != 4 || len(gates) != 4 {
		t.Errorf("tier tables changed shape: %d path tiers, %d gate severities", len(paths), len(gates))
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %v, pinned at %v under %s", c.name, c.got, c.want, PlumberScoreProfileIDV4)
		}
	}
	// The letter thresholds: each band's lowest final points and the value
	// just below it.
	for _, b := range []struct {
		points      float64
		letter, low string
	}{{90, "A", "B"}, {71, "B", "C"}, {51, "C", "D"}, {31, "D", "E"}} {
		if got := ScoreLetterFromPoints(b.points); got != b.letter {
			t.Errorf("%v points = %s, pinned at %s", b.points, got, b.letter)
		}
		if got := ScoreLetterFromPoints(b.points - 0.01); got != b.low {
			t.Errorf("%v points = %s, pinned at %s", b.points-0.01, got, b.low)
		}
	}
}

// PathCounts names how many paths each tier holds, non-zero tiers only;
// scoring-v3 leaves it nil.
func TestV4PathCountsPerTier(t *testing.T) {
	paths := []AttackPath{
		pathOf(TierCritical, EntryMutableDependency, "a"),
		pathOf(TierMedium, EntryMutableDependency, "b"), pathOf(TierMedium, EntryUntrustedExpression, "c"),
	}
	s := ComputePlumberScoreV4(ScoreInputV4{Paths: paths})
	if want := map[string]int{"critical": 1, "medium": 2}; !reflect.DeepEqual(s.PathCounts, want) {
		t.Errorf("PathCounts = %v, want %v", s.PathCounts, want)
	}
	if empty := ComputePlumberScoreV4(ScoreInputV4{}); empty.PathCounts != nil {
		t.Errorf("no path, want nil PathCounts, got %v", empty.PathCounts)
	}
	if v3 := ComputePlumberScore(nil); v3.PathCounts != nil {
		t.Errorf("v3 must leave PathCounts nil, got %v", v3.PathCounts)
	}
}

func TestV4NoFindingsIsA100(t *testing.T) {
	s := ComputePlumberScoreV4(ScoreInputV4{})
	if s.ProfileID != PlumberScoreProfileIDV4 || s.FinalPoints != 100 || s.Score != "A" {
		t.Fatalf("%+v", s)
	}
}

func TestV4OneCriticalPathIsE30(t *testing.T) {
	s := ComputePlumberScoreV4(ScoreInputV4{Paths: []AttackPath{pathOf(TierCritical, EntryMutableDependency, "a")}})
	if s.RawPoints != 70 || s.FinalPoints != 30 || s.Score != "E" || !s.CriticalMalusApplied || s.CriticalPaths != 1 {
		t.Fatalf("%+v", s)
	}
}

// Spec worked example: the demo repository, as actually coded (one
// untrusted_expression path and three mutable_dependency paths, both
// Medium) plus an unprotected main as a gate off any path.
//
// The formula groups path losses by (tier, entryKind), not by tier alone:
// treating the four Medium paths below as one group would give "Four
// Medium paths (12 points)" and a final score of 63, but
// TestV4MediumPathsAreDampenedPerEntryKind
// below pins exactly that grouping for this same path mix (one
// untrusted_expression path, three mutable_dependency paths): 6 and
// 6x(1+0.5*log2(3)) separately, not 6x(1+0.5*log2(4)) together. Reusing
// that grouping here (it must: it is the same formula, not a special case)
// gives a path loss of 6 + 6x(1+0.5*log2(3)) = 16.7549, not 12. With the
// gate's 25, final points are 100-16.7549-25 = 58.2451, still a C (51-71
// band), just not literally 63. The expected value below is computed from
// the formula itself, the normative text.
func TestV4DemoRepositoryIsAGatedCWithoutMalus(t *testing.T) {
	paths := []AttackPath{
		pathOf(TierMedium, EntryUntrustedExpression, "inj"),
		pathOf(TierMedium, EntryMutableDependency, "img"),
		pathOf(TierMedium, EntryMutableDependency, "curl"),
		pathOf(TierMedium, EntryMutableDependency, "act"),
	}
	gate := opaengine.Finding{Code: "ISSUE-501", Data: map[string]any{"branchName": "main"}}
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: []opaengine.Finding{gate}, Paths: paths})
	wantPathLoss := dampened(6, 1) + dampened(6, 3) // untrusted_expression(1) + mutable_dependency(3)
	wantFinal := 100 - wantPathLoss - 25
	if math.Abs(s.FinalPoints-wantFinal) > 0.01 || s.Score != "C" || s.CriticalMalusApplied {
		t.Fatalf("want %v C without malus, got %+v", wantFinal, s)
	}
	if len(s.GateLosses) != 1 || s.GateLosses[0].CappedLoss != 25 {
		t.Errorf("gate losses = %+v", s.GateLosses)
	}
}

func TestV4MediumPathsAreDampenedPerEntryKind(t *testing.T) {
	// 3 medium paths of one kind: 6 x (1 + 0.5 log2 3) = 10.75; plus 1 of another kind: 6.
	paths := []AttackPath{
		pathOf(TierMedium, EntryMutableDependency, "a"), pathOf(TierMedium, EntryMutableDependency, "b"), pathOf(TierMedium, EntryMutableDependency, "c"),
		pathOf(TierMedium, EntryUntrustedExpression, "d"),
	}
	s := ComputePlumberScoreV4(ScoreInputV4{Paths: paths})
	if math.Abs(s.RawPoints-(100-10.75-6)) > 0.01 {
		t.Fatalf("raw = %v, want %v", s.RawPoints, 100-10.75-6)
	}
}

func TestV4PathCapsPerTier(t *testing.T) {
	var paths []AttackPath
	for i := 0; i < 64; i++ {
		paths = append(paths, pathOf(TierHigh, EntryMutableDependency, string(rune('a'+i))))
	}
	s := ComputePlumberScoreV4(ScoreInputV4{Paths: paths})
	if s.RawPoints != 40 { // high cap 60
		t.Fatalf("raw = %v, want 40", s.RawPoints)
	}
}

// The formula half of the section 9 invariant ("a gate alone never yields
// the E cap"): fed a gate finding and no path at all, the formula prices it
// as a gate (25) and never applies the critical cap. It says nothing about
// the paths a gate finding may anchor before the formula runs; see
// TestBranchGateAnchoredPushPathCanReachTheECapUntilRow418 for that.
func TestV4FormulaNeverCapsAGateWithNoPath(t *testing.T) {
	gates := []opaengine.Finding{{Code: "ISSUE-501", Data: map[string]any{"branchName": "main"}}}
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: gates})
	if s.CriticalMalusApplied || s.FinalPoints != 75 || s.Score != "B" {
		t.Fatalf("a critical-coded gate off any path is 75 B, got %+v", s)
	}
}

// End to end, a branch gate is also the anchor of an unprotected_push path
// (spec section 1's fact table sources that entry from the 501/505 facts),
// so a lone ISSUE-501 on a push-to-main job that holds NPM_TOKEN and
// publishes assembles one Critical path and the E cap (30). Section 9's
// "a gate alone never yields the E cap" and ruling 2 ("missing gates
// amplify paths, they do not start them") say otherwise: the contradiction
// waits on QUESTIONS row 418, and the interim is the spec as written. This
// pins the current behaviour so the ruling's change shows up here.
func TestBranchGateAnchoredPushPathCanReachTheECapUntilRow418(t *testing.T) {
	sit := &Situation{Exposure: "public", DefaultBranch: "main", Jobs: map[string]JobSituation{}}
	j := JobSituation{
		Entries: []EntryFact{{Kind: EntryUnprotectedPush, State: "proven", Evidence: "push: branches: [main]", Subject: "main"}},
		Impact:  []ImpactFact{{Kind: "publishes", State: "proven", Evidence: "npm publish"}},
	}
	j.Privilege.Secrets = []string{"NPM_TOKEN"}
	j.Privilege.SecretsState = "proven"
	sit.Jobs["release"] = j
	result := &AnalysisResult{
		Findings:  []opaengine.Finding{{Code: string(CodeBranchUnprotected), Data: map[string]any{"branchName": "main"}}},
		Situation: sit,
	}
	s := ComputeScoreForProfile("v4", result)
	if s.ProfileID != PlumberScoreProfileIDV4 || len(s.Paths) != 1 || s.Paths[0].EntryKind != EntryUnprotectedPush || s.Paths[0].Tier != TierCritical {
		t.Fatalf("want one Critical unprotected_push path anchored by the 501, got %+v", s.Paths)
	}
	if !s.CriticalMalusApplied || s.FinalPoints != 30 || s.Score != "E" {
		t.Errorf("want the E cap (30) until row 418 rules, got final %v %s malus=%v", s.FinalPoints, s.Score, s.CriticalMalusApplied)
	}
}

// hygieneFindings builds n distinct hygiene-role findings under an
// unregistered code. ISSUE-999 is deliberately not in the issue-code
// registry (RoleForCode defaults unknown codes to RoleHygiene) and not in
// finding/identity's declarations table, so identity.Of falls back to
// {code, message} alone (identity.go:181-193): an undeclared code's
// identity never reads Data or File, only Message. Varying Data (say
// Data["n"]) collapses every finding here to one identity; this varies
// Message instead, which is the only field that actually distinguishes
// them under the real recipe.
func hygieneFindings(n int) []opaengine.Finding {
	var findings []opaengine.Finding
	for i := 0; i < n; i++ {
		findings = append(findings, opaengine.Finding{Code: "ISSUE-999", Job: "j", Message: "occurrence " + strconv.Itoa(i)})
	}
	return findings
}

// Varying Data["n"] across findings would collapse them to one identity if
// IdentityInput does not include Data; varying Line or File does not work
// either: identity.go
// deliberately never reads Line for any code (it "moves whenever unrelated
// code above the finding is edited"), and for an undeclared code like
// ISSUE-999 the fallback identity is {code, message} only, so File is not
// read either. Message is the only field that varies the identity for an
// undeclared code; hygieneFindings above does that.
//
// With hygieneWeight=2 and the 0.5 log2 growth from the formula text, 50
// occurrences cost 2*(1+0.5*log2(50)) ~= 7.64, well under the cap of 10
// (which needs n=256 to bind at this weight). The n=300 case below is
// where the cap genuinely binds; n=50 is checked against the formula's
// own value instead.
func TestV4HygieneIsCheapAndCapped(t *testing.T) {
	one := ComputePlumberScoreV4(ScoreInputV4{Findings: hygieneFindings(1)})
	if one.HygieneLoss != 2 {
		t.Fatalf("one hygiene finding costs 2, got %v", one.HygieneLoss)
	}

	fifty := ComputePlumberScoreV4(ScoreInputV4{Findings: hygieneFindings(50)})
	wantFifty := dampened(hygieneWeight, 50)
	if math.Abs(fifty.HygieneLoss-wantFifty) > 0.01 || fifty.Score != "A" || fifty.HygieneCount != 50 {
		t.Fatalf("50 hygiene findings: %+v, want loss %v", fifty, wantFifty)
	}

	many := ComputePlumberScoreV4(ScoreInputV4{Findings: hygieneFindings(300)})
	if many.HygieneLoss != hygieneCap || many.FinalPoints != 90 || many.Score != "A" || many.HygieneCount != 300 {
		t.Fatalf("300 hygiene findings hit the cap at 10: %+v", many)
	}
}

func TestV4AnchorAndGateFindingsAreNotCountedTwice(t *testing.T) {
	anchor := opaengine.Finding{Code: "ISSUE-713", Job: "release", Data: map[string]any{"uses": "some/action@v1"}}
	gate := opaengine.Finding{Code: "ISSUE-305", Job: "release"}
	anchorHash, _, _ := identity.PlatformHash(anchor.IdentityInput())
	gateHash, _, _ := identity.PlatformHash(gate.IdentityInput())
	p := pathOf(TierCritical, EntryMutableDependency, anchorHash)
	p.GateHashes = []string{gateHash}
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: []opaengine.Finding{anchor, gate}, Paths: []AttackPath{p}})
	if len(s.GateLosses) != 0 || s.HygieneCount != 0 || s.RawPoints != 70 {
		t.Fatalf("consumed findings must not cost again: %+v", s)
	}
}

func TestV4DismissedFindingsCostNothing(t *testing.T) {
	f := opaengine.Finding{Code: "ISSUE-501", Dismissed: true, Data: map[string]any{"branchName": "main"}}
	if s := ComputePlumberScoreV4(ScoreInputV4{Findings: []opaengine.Finding{f}}); s.FinalPoints != 100 {
		t.Fatalf("%+v", s)
	}
}

// The v4 point total must be bit-identical across repeated runs on the
// same input: floating-point addition is not associative, so summing path
// losses while iterating the (randomized) groups map changed the low bits
// of FinalPoints from one run to the next on the same repository.
func TestV4FinalPointsAreDeterministicAcrossRepeatedRuns(t *testing.T) {
	var paths []AttackPath
	add := func(n int, tier PathTier, kind EntryKind) {
		for i := 0; i < n; i++ {
			paths = append(paths, AttackPath{
				ID: fmt.Sprintf("%s-%s-%d", tier, kind, i), Tier: tier, BaseTier: tier, EntryKind: kind,
				AnchorHash: fmt.Sprintf("anchor-%s-%s-%d", tier, kind, i),
			})
		}
	}
	add(5, TierMedium, EntryMutableDependency)
	add(1, TierMedium, EntryUntrustedExpression)
	add(3, TierHigh, EntryForkPR)
	add(1, TierHigh, EntryUnprotectedPush)
	add(7, TierLow, EntryPRTarget)
	in := ScoreInputV4{Paths: paths}

	first := ComputePlumberScoreV4(in).FinalPoints
	for i := 0; i < 2000; i++ {
		if got := ComputePlumberScoreV4(in).FinalPoints; got != first {
			t.Fatalf("run %d: FinalPoints = %v, want bit-identical %v", i, got, first)
		}
	}
}

// Counts and ContextualSeverity must agree: a gate finding that amplifies
// a path is still counted, at its registered severity, never dropped
// because its hash is consumed as a path's GateHashes.
func TestV4CountsIncludesAGateThatAmplifiesAPath(t *testing.T) {
	anchor := opaengine.Finding{Code: "ISSUE-207", Job: "build", Data: map[string]any{"expression": "x"}}
	gate := opaengine.Finding{Code: string(CodeBranchUnprotected), Data: map[string]any{"branchName": "main"}}
	anchorHash, ok := findingAnchorHash(anchor)
	if !ok {
		t.Fatal("anchor did not hash")
	}
	gateHash, ok := findingAnchorHash(gate)
	if !ok {
		t.Fatal("gate did not hash")
	}
	path := AttackPath{ID: "p1", Tier: TierHigh, AnchorHash: anchorHash, GateHashes: []string{gateHash}}
	in := ScoreInputV4{Findings: []opaengine.Finding{anchor, gate}, Paths: []AttackPath{path}}
	got := ComputePlumberScoreV4(in)
	if got.Counts.High != 1 || got.Counts.Critical != 1 {
		t.Errorf("counts = %+v, want one High (the path) and one Critical (the 501 gate it consumed)", got.Counts)
	}
	if sev := ContextualSeverity(gate, in.Paths); sev != SeverityCritical {
		t.Errorf("ContextualSeverity(gate) = %q, disagrees with Counts", sev)
	}
}

// v4Counts must take the strongest tier per anchor regardless of the
// caller's own path order: it is exported and takes any []AttackPath, not
// only AssemblePaths' own tier-sorted output.
func TestV4CountsTakesTheStrongestTierPerAnchorRegardlessOfOrder(t *testing.T) {
	high := AttackPath{ID: "p1", Tier: TierHigh, AnchorHash: "h1"}
	critical := AttackPath{ID: "p2", Tier: TierCritical, AnchorHash: "h1"}
	for _, paths := range [][]AttackPath{{high, critical}, {critical, high}} {
		got := ComputePlumberScoreV4(ScoreInputV4{Paths: paths}).Counts
		if got.Critical != 1 || got.High != 0 {
			t.Errorf("paths=%+v: counts = %+v, want exactly one Critical", paths, got)
		}
	}
}

// A privilege-role finding on a walked job costs nothing extra, the same
// as a gate a path already consumed (spec section 2, Findings on no
// path).
func TestV4PrivilegeFindingOnAWalkedJobCostsNothing(t *testing.T) {
	f := opaengine.Finding{Code: string(CodeArtipacked), Job: "release"}
	p := pathOf(TierCritical, EntryMutableDependency, "anchor")
	p.Jobs = []string{"release"}
	p.survivingJobs = []string{"release"}
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: []opaengine.Finding{f}, Paths: []AttackPath{p}})
	if s.HygieneCount != 0 || s.HygieneLoss != 0 {
		t.Errorf("a privilege finding on a walked job must cost nothing extra: %+v", s)
	}
}

func TestV4PrivilegeFindingOnAnUnwalkedJobCostsHygiene(t *testing.T) {
	f := opaengine.Finding{Code: string(CodeArtipacked), Job: "other"}
	p := pathOf(TierCritical, EntryMutableDependency, "anchor")
	p.Jobs = []string{"release"}
	p.survivingJobs = []string{"release"}
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: []opaengine.Finding{f}, Paths: []AttackPath{p}})
	if s.HygieneCount != 1 || s.HygieneLoss == 0 {
		t.Errorf("a privilege finding off any path must cost hygiene: %+v", s)
	}
}

// A privilege finding whose job IS a walked job, but whose privilege
// the platform pruning rules dropped entirely (a GitHub fork entry job
// with no pull_request_target override, say), must not ride the path's
// tier: it costs hygiene, the same as if it were off the path altogether.
func TestV4PrivilegeFindingOnAPrunedJobCostsHygiene(t *testing.T) {
	f := opaengine.Finding{Code: string(CodeArtipacked), Job: "build"}
	p := pathOf(TierCritical, EntryForkPR, "anchor")
	p.Jobs = []string{"build", "deploy"}
	p.survivingJobs = []string{"deploy"} // "build" (the fork entry job) was pruned
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: []opaengine.Finding{f}, Paths: []AttackPath{p}})
	if s.HygieneCount != 1 || s.HygieneLoss == 0 {
		t.Errorf("a privilege finding on a pruned job must cost hygiene, not ride the path: %+v", s)
	}
}

// v4Counts must bump a privilege finding on a path at that path's
// tier, exactly as ContextualSeverity does, or the two disagree on the
// same finding's contextual severity.
func TestV4CountsAgreesWithContextualSeverityForAPrivilegeFindingOnAPath(t *testing.T) {
	anchor := opaengine.Finding{Code: "ISSUE-713", Job: "release", Data: map[string]any{"uses": "some/action@v1"}}
	privilege := opaengine.Finding{Code: string(CodeArtipacked), Job: "release"}
	anchorHash, ok := findingAnchorHash(anchor)
	if !ok {
		t.Fatal("anchor did not hash")
	}
	path := AttackPath{ID: "p1", Tier: TierCritical, AnchorHash: anchorHash, Jobs: []string{"release"}, survivingJobs: []string{"release"}}
	in := ScoreInputV4{Findings: []opaengine.Finding{anchor, privilege}, Paths: []AttackPath{path}}
	got := ComputePlumberScoreV4(in)
	if got.Counts.Critical != 2 || got.Counts.Low != 0 {
		t.Errorf("counts = %+v, want two Critical (the path's anchor and the privilege finding riding it)", got.Counts)
	}
	if sev := ContextualSeverity(privilege, in.Paths); sev != SeverityCritical {
		t.Errorf("ContextualSeverity(privilege) = %q, disagrees with Counts", sev)
	}
}

// TestTierAndSeverityStringsAgree pins the string-literal agreement
// between PathTier and IssueSeverity that v4Counts's
// IssueSeverity(p.Tier) cast depends on.
func TestTierAndSeverityStringsAgree(t *testing.T) {
	cases := []struct {
		tier PathTier
		sev  IssueSeverity
	}{
		{TierCritical, SeverityCritical},
		{TierHigh, SeverityHigh},
		{TierMedium, SeverityMedium},
		{TierLow, SeverityLow},
	}
	for _, c := range cases {
		if IssueSeverity(c.tier) != c.sev {
			t.Errorf("PathTier(%q) cast to IssueSeverity = %q, want %q", c.tier, IssueSeverity(c.tier), c.sev)
		}
	}
}

// TestV3ResultOmitsV4FieldsInJSON: a scoring-v3 result marshals without
// any of the new scoring-v4 keys, since they are all omitempty and v3
// never sets them.
func TestV3ResultOmitsV4FieldsInJSON(t *testing.T) {
	v3 := ComputePlumberScore(map[ErrorCode]int{CodeBranchUnprotected: 2})
	raw, err := json.Marshal(v3)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{"paths", "pathLosses", "gateLosses", "hygieneLoss", "hygieneCount", "criticalPaths", "situation", "bestFix"} {
		if strings.Contains(string(raw), `"`+key+`"`) {
			t.Errorf("v3 result JSON carries the v4 key %q: %s", key, raw)
		}
	}
}

// TestV4PathLossesAndGateLossesAreSortedDeterministically: PathLosses
// sorted by tier desc then entry kind, PathIDs sorted within a group,
// GateLosses sorted by code, under shuffled input.
func TestV4PathLossesAndGateLossesAreSortedDeterministically(t *testing.T) {
	paths := []AttackPath{
		pathOf(TierHigh, EntryMutableDependency, "h1"),
		pathOf(TierCritical, EntryForkPR, "c1"),
		pathOf(TierCritical, EntryUntrustedExpression, "c2"),
		pathOf(TierLow, EntryMutableDependency, "l1"),
	}
	findings := []opaengine.Finding{
		{Code: "ISSUE-502", Job: "a", Message: "m1"},
		{Code: "ISSUE-501", Data: map[string]any{"branchName": "dev"}},
	}
	for trial := 0; trial < 5; trial++ {
		shuffledPaths := append([]AttackPath(nil), paths...)
		rand.Shuffle(len(shuffledPaths), func(i, j int) { shuffledPaths[i], shuffledPaths[j] = shuffledPaths[j], shuffledPaths[i] })
		shuffledFindings := append([]opaengine.Finding(nil), findings...)
		rand.Shuffle(len(shuffledFindings), func(i, j int) { shuffledFindings[i], shuffledFindings[j] = shuffledFindings[j], shuffledFindings[i] })

		s := ComputePlumberScoreV4(ScoreInputV4{Findings: shuffledFindings, Paths: shuffledPaths})

		if len(s.PathLosses) != 4 {
			t.Fatalf("trial %d: want 4 path-loss groups, got %+v", trial, s.PathLosses)
		}
		wantTiers := []PathTier{TierCritical, TierCritical, TierHigh, TierLow}
		for i, want := range wantTiers {
			if s.PathLosses[i].Tier != want {
				t.Fatalf("trial %d: PathLosses[%d].Tier = %q, want %q (%+v)", trial, i, s.PathLosses[i].Tier, want, s.PathLosses)
			}
		}
		if s.PathLosses[0].EntryKind != EntryForkPR || s.PathLosses[1].EntryKind != EntryUntrustedExpression {
			t.Fatalf("trial %d: entry kind not sorted ascending within tier: %+v", trial, s.PathLosses[:2])
		}
		for _, pl := range s.PathLosses {
			if !sort.StringsAreSorted(pl.PathIDs) {
				t.Fatalf("trial %d: path ids not sorted: %+v", trial, pl.PathIDs)
			}
		}
		if len(s.GateLosses) != 2 || s.GateLosses[0].Code >= s.GateLosses[1].Code {
			t.Fatalf("trial %d: gate losses not sorted by code: %+v", trial, s.GateLosses)
		}
	}
}

// testTwoShape is the GitLab test2 shape: one job holding the settings
// variable LEVEL is the entry of a path (a mutable image), and two
// job-less ISSUE-202 findings name LEVEL and UNRELATED.
func testTwoShape() ([]opaengine.Finding, *Situation) {
	j := JobSituation{Entries: []EntryFact{{Kind: EntryMutableDependency, State: "proven", Evidence: "node:latest", Subject: "node:latest"}}}
	j.Privilege.Secrets = []string{"LEVEL"}
	j.Privilege.SecretsState = "proven"
	sit := &Situation{Exposure: "public", Jobs: map[string]JobSituation{"est_file": j}}
	findings := []opaengine.Finding{
		{Code: "ISSUE-103", Job: "est_file", Message: "node:latest has no digest", Data: map[string]any{"image": "node:latest"}},
		{Code: string(CodeCicdVariableUnmasked), Message: "LEVEL is not masked", Data: map[string]any{"variableName": "LEVEL"}},
		{Code: string(CodeCicdVariableUnmasked), Message: "UNRELATED is not masked", Data: map[string]any{"variableName": "UNRELATED"}},
	}
	return findings, sit
}

// A job-less privilege finding (a settings variable) is on a path when its
// variable is one of the path's surviving reach secrets: consumed, at the
// path's tier, listed by PathIDsFor, and v4Counts agrees. A variable no
// path reaches stays hygiene.
func TestJobLessSettingsVariableIsOnThePathThatReachesIt(t *testing.T) {
	findings, sit := testTwoShape()
	paths := AssemblePaths(findings, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	p := paths[0]
	level, unrelated := findings[1], findings[2]

	if got := FindingLine(level, paths); got != "Privilege: on path "+p.ID {
		t.Errorf("FindingLine(LEVEL) = %q", got)
	}
	if got := ContextualSeverity(level, paths); got != IssueSeverity(p.Tier) {
		t.Errorf("ContextualSeverity(LEVEL) = %q, want the path tier %q", got, p.Tier)
	}
	if got := PathIDsFor(level, paths); len(got) != 1 || got[0] != p.ID {
		t.Errorf("PathIDsFor(LEVEL) = %v", got)
	}
	if got := RoleOnPath(level, p); got != "Privilege: on path "+p.ID {
		t.Errorf("RoleOnPath(LEVEL) = %q", got)
	}
	if got := FindingLine(unrelated, paths); got != "Privilege: on no attack path" {
		t.Errorf("FindingLine(UNRELATED) = %q", got)
	}
	if got := PathIDsFor(unrelated, paths); len(got) != 0 {
		t.Errorf("PathIDsFor(UNRELATED) = %v", got)
	}

	s := ComputePlumberScoreV4(ScoreInputV4{Findings: findings, Paths: paths})
	if s.HygieneCount != 1 {
		t.Errorf("HygieneCount = %d, want 1 (UNRELATED only, LEVEL is consumed by the path)", s.HygieneCount)
	}
	var want SeverityCounts
	for _, f := range findings {
		switch ContextualSeverity(f, paths) {
		case SeverityCritical:
			want.Critical++
		case SeverityHigh:
			want.High++
		case SeverityMedium:
			want.Medium++
		default:
			want.Low++
		}
	}
	if s.Counts != want {
		t.Errorf("Counts = %+v, want %+v (one per finding at its contextual severity)", s.Counts, want)
	}
}

// A job-less privilege finding without a variable name stays hygiene.
func TestJobLessPrivilegeFindingWithoutAVariableStaysHygiene(t *testing.T) {
	findings, sit := testTwoShape()
	bare := opaengine.Finding{Code: string(CodeCicdVariableUnmasked), Message: "a variable is not masked"}
	paths := AssemblePaths(findings, sit)
	if got := PathIDsFor(bare, paths); len(got) != 0 {
		t.Errorf("PathIDsFor = %v, want none", got)
	}
	if got := FindingLine(bare, paths); got != "Privilege: on no attack path" {
		t.Errorf("FindingLine = %q", got)
	}
}
