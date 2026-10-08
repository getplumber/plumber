package control

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/getplumber/plumber/finding/identity"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

func pathOf(tier PathTier, kind EntryKind, anchor string) AttackPath {
	return AttackPath{ID: anchor + string(tier), Tier: tier, EntryKind: kind, AnchorHash: anchor, AnchorCode: "ISSUE-701", State: PathProven}
}

// The profile id names the formula, so every constant the formula reads is
// pinned here next to it. Nothing was released under this id, so it keeps
// its name while the constants are fixed here; once released, a change to
// any value below requires a new PlumberScoreProfileIDV4 as well, never an
// edit of this table alone.
func TestProfileIDPinsTheFormulaConstants(t *testing.T) {
	if PlumberScoreProfileIDV4 != "scoring-v4" {
		t.Fatalf("profile id = %q: a new id needs this table re-pinned", PlumberScoreProfileIDV4)
	}
	paths := pathPrices()
	others := otherFindingPrices()
	caps := nestedCaps()
	cases := []struct {
		name      string
		got, want float64
	}{
		{"critical path price", paths[TierCritical], 30},
		{"high path price", paths[TierHigh], 15},
		{"medium path price", paths[TierMedium], 6},
		{"low path price", paths[TierLow], 3},
		{"critical other finding price", others[SeverityCritical], 20},
		{"high other finding price", others[SeverityHigh], 10},
		{"medium other finding price", others[SeverityMedium], 5},
		{"low other finding price", others[SeverityLow], 2},
		{"other findings cap", otherFindingsCap, 30},
		{"high, medium and low cap", caps[SeverityHigh], 69},
		{"medium and low cap", caps[SeverityMedium], 49},
		{"low cap", caps[SeverityLow], 29},
		{"critical path force", criticalPathCap, 30},
	}
	if len(paths) != 4 || len(others) != 4 || len(caps) != 3 {
		t.Errorf("tables changed shape: %d path prices, %d other prices, %d caps", len(paths), len(others), len(caps))
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

// TestV4LossArraysMarshalAsEmptyArrays pins that a run with no gate
// finding serializes losses and codeLosses as empty arrays, never null,
// like the previous formula does.
func TestV4LossArraysMarshalAsEmptyArrays(t *testing.T) {
	raw, err := json.Marshal(ComputePlumberScoreV4(ScoreInputV4{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"losses":[]`, `"codeLosses":[]`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("score JSON lacks %s: %s", want, raw)
		}
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

// Other findings are deduplicated by identity: two findings sharing one
// identity are one other finding, two distinct identities are two.
func TestOtherFindingsCollapseOnOneIdentity(t *testing.T) {
	same := opaengine.Finding{Code: "ISSUE-501", Data: map[string]any{"branchName": "main"}}
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: []opaengine.Finding{same, same}})
	if s.OtherFindings == nil || s.OtherFindings.Count != 1 || s.OtherFindings.CappedLoss != 20 || s.FinalPoints != 80 {
		t.Fatalf("want one other finding at 20, got %+v", s.OtherFindings)
	}
	dev := opaengine.Finding{Code: "ISSUE-501", Data: map[string]any{"branchName": "dev"}}
	s = ComputePlumberScoreV4(ScoreInputV4{Findings: []opaengine.Finding{same, dev}})
	if s.OtherFindings == nil || s.OtherFindings.Count != 2 || s.OtherFindings.UncappedLoss != 40 || s.FinalPoints != 70 {
		t.Fatalf("want two other findings, 40 capped at 30, got %+v", s.OtherFindings)
	}
}

// End to end, a branch gate is also the anchor of an unprotected_push path
// (spec section 1's fact table sources that entry from the 501/505 facts).
// Pushing to the branch needs an account with write access, an insider who
// amplifies but never starts a Critical path, so a push entry path is
// capped at High whatever it reaches: a lone ISSUE-501 on a push-to-main
// job that holds NPM_TOKEN and publishes is one High path (15 points, B),
// never the E cap. The cap is named on the path as push_entry_cap.
func TestAPushEntryPathNeverSetsTheECap(t *testing.T) {
	sit := &Situation{Exposure: "public", DefaultBranch: "main", Jobs: map[string]JobSituation{}}
	j := JobSituation{
		Push:   []EntryFact{{Kind: EntryUnprotectedPush, State: "proven", Evidence: "push: branches: [main]", Subject: "main"}},
		Impact: []ImpactFact{{Kind: "publishes", State: "proven", Evidence: "npm publish"}},
	}
	j.Privilege.Secrets = []string{"NPM_TOKEN"}
	j.Privilege.SecretsState = "proven"
	sit.Jobs["release"] = j
	result := &AnalysisResult{
		Findings:  []opaengine.Finding{{Code: string(CodeBranchUnprotected), Data: map[string]any{"branchName": "main"}}},
		Situation: sit,
	}
	s := ComputeScoreForProfile("v4", result)
	if s.ProfileID != PlumberScoreProfileIDV4 || len(s.Paths) != 1 || s.Paths[0].EntryKind != EntryUnprotectedPush || s.Paths[0].Tier != TierHigh {
		t.Fatalf("want one High unprotected_push path anchored by the 501, got %+v", s.Paths)
	}
	p := s.Paths[0]
	if p.BaseTier != TierCritical || !slices.Contains(p.Modifiers, "push_entry_cap") {
		t.Errorf("the cap must lower a Critical reach and say so: base %s, modifiers %v", p.BaseTier, p.Modifiers)
	}
	if s.CriticalMalusApplied || s.CriticalPaths != 0 || s.FinalPoints != 85 || s.Score != "B" {
		t.Errorf("want 85 B without the E cap, got final %v %s malus=%v", s.FinalPoints, s.Score, s.CriticalMalusApplied)
	}
}

// The cap names itself only when it lowered the tier: a push entry path
// already at High or below carries no push_entry_cap modifier.
func TestPushEntryCapIsNamedOnlyWhenItLowersTheTier(t *testing.T) {
	sit := &Situation{Exposure: "public", DefaultBranch: "main", Jobs: map[string]JobSituation{}}
	j := JobSituation{Push: []EntryFact{{Kind: EntryUnprotectedPush, State: "proven", Evidence: "push: branches: [main]", Subject: "main"}}}
	j.Privilege.Secrets = []string{"NPM_TOKEN"}
	j.Privilege.SecretsState = "proven"
	sit.Jobs["release"] = j
	paths := assemblePaths([]opaengine.Finding{{Code: string(CodeBranchUnprotected), Data: map[string]any{"branchName": "main"}}}, sit)
	if len(paths) != 1 || paths[0].Tier != TierHigh || slices.Contains(paths[0].Modifiers, "push_entry_cap") {
		t.Fatalf("a High push path is left as it is, got %+v", paths)
	}
}

// assertOneOtherFinding checks that s prices exactly one other finding,
// of code, at its registry price.
func assertOneOtherFinding(t *testing.T, s PlumberScoreResult, code ErrorCode) {
	t.Helper()
	price := otherFindingPrices()[SeverityForCode(code)]
	if s.OtherFindings == nil || s.OtherFindings.Count != 1 || len(s.CodeLosses) != 1 ||
		s.CodeLosses[0].Code != code || s.CodeLosses[0].Weight != price || s.CodeLosses[0].CappedLoss != price {
		t.Errorf("want one other finding %s at %v, got %+v, code losses %+v", code, price, s.OtherFindings, s.CodeLosses)
	}
}

// An entry-role finding that anchored no path (Paths is nil, so nothing is
// consumed) is an other finding at its registry price, counted at its
// registry severity. CodeActionUnpinned (ISSUE-701) is a
// registered RoleEntry code, so this exercises the real entry boundary: a
// regression that skipped RoleEntry the way a consumed anchor is skipped
// would understate the loss, with nothing else failing.
func TestV4EntryFindingThatAnchoredNoPathIsAnOtherFinding(t *testing.T) {
	f := opaengine.Finding{Code: string(CodeActionUnpinned), Job: "j", Data: map[string]any{"uses": "some/action@v1"}}
	if role := RoleForCode(ErrorCode(f.Code)); role != RoleEntry {
		t.Fatalf("fixture drifted: %s must be RoleEntry, got %s", f.Code, role)
	}
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: []opaengine.Finding{f}, Paths: nil})
	assertOneOtherFinding(t, s, CodeActionUnpinned)
	var want SeverityCounts
	addSeverityCount(&want, SeverityForCode(CodeActionUnpinned), 1)
	if s.Counts != want {
		t.Errorf("counts = %+v, want %+v (its registry severity)", s.Counts, want)
	}
}

func TestV4AnchorAndGateFindingsAreNotCountedTwice(t *testing.T) {
	anchor := opaengine.Finding{Code: "ISSUE-701", Job: "release", Data: map[string]any{"uses": "some/action@v1"}}
	gate := opaengine.Finding{Code: "ISSUE-305", Job: "release"}
	anchorHash, _, _ := identity.PlatformHash(anchor.IdentityInput())
	gateHash, _, _ := identity.PlatformHash(gate.IdentityInput())
	p := pathOf(TierCritical, EntryMutableDependency, anchorHash)
	p.GateHashes = []string{gateHash}
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: []opaengine.Finding{anchor, gate}, Paths: []AttackPath{p}})
	if s.OtherFindings != nil || s.RawPoints != 70 {
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
	anchor := opaengine.Finding{Code: "ISSUE-207", Job: "build", Subject: "x"}
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
	if sev := ContextualSeverity(gate, in.Paths, ""); sev != SeverityCritical {
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
	if s.OtherFindings != nil {
		t.Errorf("a privilege finding on a walked job must cost nothing extra: %+v", s)
	}
}

func TestV4PrivilegeFindingOnAnUnwalkedJobIsAnOtherFinding(t *testing.T) {
	f := opaengine.Finding{Code: string(CodeArtipacked), Job: "other"}
	p := pathOf(TierCritical, EntryMutableDependency, "anchor")
	p.Jobs = []string{"release"}
	p.survivingJobs = []string{"release"}
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: []opaengine.Finding{f}, Paths: []AttackPath{p}})
	assertOneOtherFinding(t, s, CodeArtipacked)
}

// A privilege finding whose job IS a walked job, but whose privilege
// the platform pruning rules dropped entirely (a GitHub fork entry job
// with no pull_request_target override, say), must not ride the path's
// tier: it is an other finding, the same as if it were off the path
// altogether.
func TestV4PrivilegeFindingOnAPrunedJobIsAnOtherFinding(t *testing.T) {
	f := opaengine.Finding{Code: string(CodeArtipacked), Job: "build"}
	p := pathOf(TierCritical, EntryForkPR, "anchor")
	p.Jobs = []string{"build", "deploy"}
	p.survivingJobs = []string{"deploy"} // "build" (the fork entry job) was pruned
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: []opaengine.Finding{f}, Paths: []AttackPath{p}})
	assertOneOtherFinding(t, s, CodeArtipacked)
}

// v4Counts must bump a privilege finding on a path at that path's
// tier, exactly as ContextualSeverity does, or the two disagree on the
// same finding's contextual severity.
func TestV4CountsAgreesWithContextualSeverityForAPrivilegeFindingOnAPath(t *testing.T) {
	anchor := opaengine.Finding{Code: "ISSUE-701", Job: "release", Data: map[string]any{"uses": "some/action@v1"}}
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
	if sev := ContextualSeverity(privilege, in.Paths, ""); sev != SeverityCritical {
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
	for _, key := range []string{"paths", "pathLosses", "otherFindings", "floorApplied", "floorPoints", "criticalPaths", "situation", "bestFix"} {
		if strings.Contains(string(raw), `"`+key+`"`) {
			t.Errorf("v3 result JSON carries the v4 key %q: %s", key, raw)
		}
	}
}

// settingsVariableShape is one job holding the settings variable LOG_LEVEL
// as the entry of a path (a mutable image), and two job-less ISSUE-202
// findings naming LOG_LEVEL and UNRELATED.
func settingsVariableShape() ([]opaengine.Finding, *Situation) {
	j := JobSituation{}
	j.Privilege.Secrets = []string{"LOG_LEVEL"}
	j.Privilege.SecretsState = "proven"
	sit := &Situation{Exposure: "public", Jobs: map[string]JobSituation{"check-config": j}}
	findings := []opaengine.Finding{
		{Code: "ISSUE-103", Job: "check-config", Message: "node:latest has no digest", Data: map[string]any{"image": "node:latest"}},
		{Code: string(CodeCicdVariableUnmasked), Message: "LOG_LEVEL is not masked", Data: map[string]any{"variableName": "LOG_LEVEL"}},
		{Code: string(CodeCicdVariableUnmasked), Message: "UNRELATED is not masked", Data: map[string]any{"variableName": "UNRELATED"}},
	}
	return findings, sit
}

// A job-less privilege finding (a settings variable) is on a path when its
// variable is one of the path's surviving reach secrets: consumed, at the
// path's tier, listed by PathIDsFor, and v4Counts agrees. A variable no
// path reaches is an other finding.
func TestJobLessSettingsVariableIsOnThePathThatReachesIt(t *testing.T) {
	findings, sit := settingsVariableShape()
	paths := assemblePaths(findings, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	p := paths[0]
	level, unrelated := findings[1], findings[2]

	if got := FindingLine(level, paths); got != "Privilege: on path "+p.ID {
		t.Errorf("FindingLine(LOG_LEVEL) = %q", got)
	}
	if got := ContextualSeverity(level, paths, ""); got != IssueSeverity(p.Tier) {
		t.Errorf("ContextualSeverity(LOG_LEVEL) = %q, want the path tier %q", got, p.Tier)
	}
	if got := PathIDsFor(level, paths); len(got) != 1 || got[0] != p.ID {
		t.Errorf("PathIDsFor(LOG_LEVEL) = %v", got)
	}
	if got := RoleOnPath(level, p); got != "Privilege: on path "+p.ID {
		t.Errorf("RoleOnPath(LOG_LEVEL) = %q", got)
	}
	if got := FindingLine(unrelated, paths); got != "Privilege: on no attack path" {
		t.Errorf("FindingLine(UNRELATED) = %q", got)
	}
	if got := PathIDsFor(unrelated, paths); len(got) != 0 {
		t.Errorf("PathIDsFor(UNRELATED) = %v", got)
	}

	s := ComputePlumberScoreV4(ScoreInputV4{Findings: findings, Paths: paths})
	if s.OtherFindings == nil || s.OtherFindings.Count != 1 {
		t.Errorf("other findings = %+v, want 1 (UNRELATED only, LOG_LEVEL is consumed by the path)", s.OtherFindings)
	}
	var want SeverityCounts
	for _, f := range findings {
		switch ContextualSeverity(f, paths, "") {
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

// A job-less privilege finding without a variable name is an other
// finding.
func TestJobLessPrivilegeFindingWithoutAVariableIsAnOtherFinding(t *testing.T) {
	findings, sit := settingsVariableShape()
	bare := opaengine.Finding{Code: string(CodeCicdVariableUnmasked), Message: "a variable is not masked"}
	paths := assemblePaths(findings, sit)
	if got := PathIDsFor(bare, paths); len(got) != 0 {
		t.Errorf("PathIDsFor = %v, want none", got)
	}
	if got := FindingLine(bare, paths); got != "Privilege: on no attack path" {
		t.Errorf("FindingLine = %q", got)
	}
	assertOneOtherFinding(t, ComputePlumberScoreV4(ScoreInputV4{Findings: []opaengine.Finding{bare}, Paths: paths}), CodeCicdVariableUnmasked)
}

// A merged path is priced once, and every finding anchoring it is consumed:
// two findings on one action (a known advisory, so uncapped) are one High
// path (15), two on one image (only not pinned, so held at Medium by the
// dependency cap) one Medium path (6), with no other finding left.
func TestV4MergedPathCountsOnceAndConsumesEveryAnchor(t *testing.T) {
	findings := append(pinnedActionFindings(), imageFindings()...)
	paths := assemblePaths(findings, pinnedActionSituation())
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: findings, Paths: paths})
	if len(paths) != 2 || len(s.PathLosses) != 2 || s.PathLosses[0].Count != 1 || s.PathLosses[1].Count != 1 {
		t.Fatalf("want two merged paths, one per tier, got paths %d, losses %+v", len(paths), s.PathLosses)
	}
	if s.OtherFindings != nil || s.FinalPoints != 79 {
		t.Errorf("want 79 with no other finding, got %v (other %+v)", s.FinalPoints, s.OtherFindings)
	}
	if s.Counts.High != 2 || s.Counts.Medium != 2 {
		t.Errorf("each anchoring finding is counted once at its path's tier: %+v", s.Counts)
	}
}

// A hard-coded registry password and Dependabot's insecure code execution
// carry a risk no pipeline path is needed for, so both are gates: off any
// path each is an other finding at its registry price (Critical, 20
// points apiece, 40 capped at 30), and neither ever sets the
// Critical-path cap.
func TestHardcodedCredentialsAndDependabotExecAreGates(t *testing.T) {
	findings := []opaengine.Finding{
		{Code: string(CodeContainerHardcodedCredentials), Job: "build", Message: "password literal"},
		{Code: string(CodeDependabotInsecureExec), Message: "insecure-external-code-execution: allow"},
	}
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: findings})
	if s.OtherFindings == nil || s.OtherFindings.Count != 2 || s.OtherFindings.Counts.Critical != 2 || len(s.CodeLosses) != 2 {
		t.Fatalf("want two Critical other findings, got %+v, code losses %+v", s.OtherFindings, s.CodeLosses)
	}
	if s.CriticalMalusApplied || s.FinalPoints != 70 || s.Score != "C" {
		t.Errorf("want 70 C without the E cap, got %v %s malus=%v", s.FinalPoints, s.Score, s.CriticalMalusApplied)
	}
	for _, f := range findings {
		if got := FindingLine(f, nil); got != "Gate: no path to amplify today" {
			t.Errorf("%s: FindingLine = %q", f.Code, got)
		}
	}
	text := SituationText(SituationFacts(&Situation{Exposure: "public"}, &ir.NormalizedPipeline{}))
	if want := "Repository: public. Default branch: unknown. Workflows: 0 jobs in 0 workflows."; text != want {
		t.Errorf("situation text = %q, want %q", text, want)
	}
}

// The banner legend describes the score the run actually computed: under
// the contextual score a letter speaks of exposure, never a number or kind
// of paths (a report with two Critical gates and no path at all would
// contradict a legend that claimed one), and the previous formula keeps
// its own per-issue wording, unchanged. E is the one letter that does name
// a path, and only because it is true of every E: with at least one
// Critical path it says so; otherwise (two Critical gates, say) it falls
// back to the accumulated-losses wording, so the criticalPaths count the
// caller passes in is what picks between the two.
func TestScoreLetterMeaningForFollowsTheProfile(t *testing.T) {
	want := map[string]string{
		"A": "Excellent: no significant exposure found",
		"B": "Good: minor exposure",
		"C": "Moderate: exposure worth fixing",
		"D": "Poor: significant accumulated exposure",
	}
	for letter, w := range want {
		if got := ScoreLetterMeaningFor(PlumberScoreProfileIDV4, letter, 0); got != w {
			t.Errorf("v4 %s = %q, want %q", letter, got, w)
		}
		if got := ScoreLetterMeaningFor(PlumberScoreProfileIDV4, letter, 1); got != w {
			t.Errorf("v4 %s with a critical path = %q, want %q unchanged", letter, got, w)
		}
		if got := ScoreLetterMeaningFor(PlumberScoreProfileID, letter, 0); got != ScoreLetterMeaning(letter) {
			t.Errorf("v3 %s = %q, want the previous wording %q", letter, got, ScoreLetterMeaning(letter))
		}
	}
	if got := ScoreLetterMeaningFor(PlumberScoreProfileIDV4, "E", 1); got != "Critical: a Critical attack path remains" {
		t.Errorf("v4 E with a critical path = %q", got)
	}
	if got := ScoreLetterMeaningFor(PlumberScoreProfileIDV4, "E", 0); got != "Critical: heavy accumulated losses" {
		t.Errorf("v4 E with no critical path (two Critical gates, say) = %q", got)
	}
	if got := ScoreLetterMeaningFor(PlumberScoreProfileID, "E", 0); got != ScoreLetterMeaning("E") {
		t.Errorf("v3 E = %q, want the previous wording %q", got, ScoreLetterMeaning("E"))
	}
	if got := ScoreLetterMeaningFor(PlumberScoreProfileIDV4, "Z", 0); got != "" {
		t.Errorf("unknown letter = %q, want empty", got)
	}
}

// pathsAt is n assembled paths of one tier, each with its own anchor.
func pathsAt(tier PathTier, n int) []AttackPath {
	out := make([]AttackPath, n)
	for i := range out {
		id := fmt.Sprintf("%s-%d", tier, i)
		out[i] = AttackPath{ID: id, Tier: tier, BaseTier: tier, EntryKind: EntryMutableDependency, State: PathProven,
			AnchorHash: "anchor-" + id, AnchorHashes: []string{"anchor-" + id}}
	}
	return out
}

// otherFindings is n findings of one code on n distinct identities.
func otherFindings(code string, n int) []opaengine.Finding {
	out := make([]opaengine.Finding, n)
	for i := range out {
		v := fmt.Sprintf("v%d", i)
		out[i] = opaengine.Finding{Code: code, Job: "job-" + v, File: ".gitlab-ci.yml", Line: i + 1, Message: code + " " + v,
			Data: map[string]any{"branchName": v, "condition": v, "hardcodedJob": v, "includePath": v}}
	}
	return out
}

// dismissedFindings is fs, every one dismissed.
func dismissedFindings(fs []opaengine.Finding) []opaengine.Finding {
	for i := range fs {
		fs[i].Dismissed = true
	}
	return fs
}

func joinPaths(ps ...[]AttackPath) []AttackPath {
	var out []AttackPath
	for _, p := range ps {
		out = append(out, p...)
	}
	return out
}

func joinFindings(fs ...[]opaengine.Finding) []opaengine.Finding {
	var out []opaengine.Finding
	for _, f := range fs {
		out = append(out, f...)
	}
	return out
}

// The contextual score: 100 minus the Critical items, uncapped, minus
// every other item in one nested cap by severity (high, medium and low
// items count for 69 at most, medium and low for 49, low for 29), the
// individual findings first capped at 30 together, worst first; then the
// Critical-path force. No floor ever raises the points: a run with no
// Critical item keeps at least 31, with no High at least 51, with no
// Medium at least 71, because the caps say so. ISSUE-501 is Critical,
// ISSUE-210 High, ISSUE-401 Medium, ISSUE-403 Low.
func TestContextualScoreNestedCapsAndForce(t *testing.T) {
	cases := []struct {
		name       string
		paths      []AttackPath
		findings   []opaengine.Finding
		raw, final float64
		letter     string
		force      bool
	}{
		{"no finding", nil, nil, 100, 100, "A", false},
		{"one high path", pathsAt(TierHigh, 1), nil, 85, 85, "B", false},
		{"four high paths", pathsAt(TierHigh, 4), nil, 40, 40, "D", false},
		{"five high paths count for 69", pathsAt(TierHigh, 5), nil, 31, 31, "D", false},
		{"three medium paths", pathsAt(TierMedium, 3), nil, 82, 82, "B", false},
		{"four medium paths", pathsAt(TierMedium, 4), nil, 76, 76, "B", false},
		{"three low paths", pathsAt(TierLow, 3), nil, 91, 91, "A", false},
		{"four low paths", pathsAt(TierLow, 4), nil, 88, 88, "B", false},
		{"one critical path is forced to 30", pathsAt(TierCritical, 1), nil, 70, 30, "E", true},
		{"four critical paths are uncapped", pathsAt(TierCritical, 4), nil, -20, 0, "E", true},
		{"a critical path with other losses is forced to 30", pathsAt(TierCritical, 1), otherFindings("ISSUE-403", 2), 66, 30, "E", true},
		{"a critical path below 30 keeps its own figure", joinPaths(pathsAt(TierCritical, 1), pathsAt(TierHigh, 4)), otherFindings("ISSUE-210", 4), 1, 1, "E", true},
		{"other findings at their registry price", nil, joinFindings(otherFindings("ISSUE-210", 1), otherFindings("ISSUE-401", 1), otherFindings("ISSUE-403", 1)), 83, 83, "B", false},
		{"other findings exactly at the cap", nil, otherFindings("ISSUE-210", 3), 70, 70, "C", false},
		{"other findings cap at 30", nil, otherFindings("ISSUE-210", 4), 70, 70, "C", false},
		{"a critical other finding forces nothing", nil, otherFindings("ISSUE-501", 2), 70, 70, "C", false},
		{"critical other findings are never capped by severity", pathsAt(TierHigh, 4), otherFindings("ISSUE-501", 2), 10, 10, "E", false},
		{"low items count for 29", pathsAt(TierLow, 4), otherFindings("ISSUE-403", 15), 71, 71, "B", false},
		{"low items exactly at 29", pathsAt(TierLow, 3), otherFindings("ISSUE-403", 10), 71, 71, "B", false},
		{"medium and low items count for 49", pathsAt(TierMedium, 4), otherFindings("ISSUE-401", 6), 51, 51, "C", false},
		{"medium and low items exactly at 49", pathsAt(TierMedium, 4), joinFindings(otherFindings("ISSUE-401", 5), otherFindings("ISSUE-403", 2)), 51, 51, "C", false},
		{"high paths and a high finding count for 69", pathsAt(TierHigh, 4), otherFindings("ISSUE-210", 1), 31, 31, "D", false},
		{"high, medium and low items exactly at 69", pathsAt(TierHigh, 4), joinFindings(otherFindings("ISSUE-401", 1), otherFindings("ISSUE-403", 2)), 31, 31, "D", false},
		{"a dismissed critical costs nothing", pathsAt(TierHigh, 4), joinFindings(otherFindings("ISSUE-210", 1), dismissedFindings(otherFindings("ISSUE-501", 2))), 31, 31, "D", false},
		{"dismissed findings cost nothing", pathsAt(TierHigh, 1), dismissedFindings(otherFindings("ISSUE-210", 3)), 85, 85, "B", false},
		{"the demo repository", joinPaths(pathsAt(TierHigh, 4), pathsAt(TierMedium, 1)), nil, 34, 34, "D", false},
		{"one high and four medium paths", joinPaths(pathsAt(TierHigh, 1), pathsAt(TierMedium, 4)), nil, 61, 61, "C", false},
		{"the private GitLab test project", pathsAt(TierHigh, 1), joinFindings(otherFindings("ISSUE-501", 1), otherFindings("ISSUE-210", 2), otherFindings("ISSUE-401", 9)), 55, 55, "C", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := ComputePlumberScoreV4(ScoreInputV4{Findings: tc.findings, Paths: tc.paths})
			if s.RawPointsUnclamped != tc.raw || s.FinalPoints != tc.final || s.Score != tc.letter {
				t.Errorf("raw %v final %v letter %s, want %v %v %s", s.RawPointsUnclamped, s.FinalPoints, s.Score, tc.raw, tc.final, tc.letter)
			}
			if s.CriticalMalusApplied != tc.force {
				t.Errorf("force %v, want %v", s.CriticalMalusApplied, tc.force)
			}
			if s.FloorApplied || s.FloorPoints != 0 {
				t.Errorf("no floor is ever set, got %v at %v", s.FloorApplied, s.FloorPoints)
			}
		})
	}
}

// The worked checks of the nested caps, each figure by hand:
// loss = Critical items + min(69, High + min(49, Medium + min(29, Low))).
func TestNestedCapsWorkedChecks(t *testing.T) {
	cases := []struct {
		name     string
		paths    []AttackPath
		findings []opaengine.Finding
		raw      float64 // 100 minus the nested loss
		final    float64
		letter   string
		force    bool
	}{
		// 75 counts for 69.
		{"5 high paths", pathsAt(TierHigh, 5), nil, 31, 31, "D", false},
		// 60 + 6 = 66, under 69.
		{"4 high and 1 medium paths", joinPaths(pathsAt(TierHigh, 4), pathsAt(TierMedium, 1)), nil, 34, 34, "D", false},
		// 60 counts for 49.
		{"10 medium paths", pathsAt(TierMedium, 10), nil, 51, 51, "C", false},
		// 30 + min(29, 36) = 59.
		{"2 high and 12 low paths", joinPaths(pathsAt(TierHigh, 2), pathsAt(TierLow, 12)), nil, 41, 41, "D", false},
		// 30 + 15 = 45, 55, forced to 30.
		{"1 critical and 1 high paths", joinPaths(pathsAt(TierCritical, 1), pathsAt(TierHigh, 1)), nil, 55, 30, "E", true},
		// 20, then 10 of the 100 High within the 30: no Critical path, no force.
		{"1 critical and 10 high individual findings", nil, joinFindings(otherFindings("ISSUE-501", 1), otherFindings("ISSUE-210", 10)), 70, 70, "C", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := ComputePlumberScoreV4(ScoreInputV4{Findings: tc.findings, Paths: tc.paths})
			if s.RawPointsUnclamped != tc.raw || s.FinalPoints != tc.final || s.Score != tc.letter || s.CriticalMalusApplied != tc.force {
				t.Errorf("raw %v final %v %s force %v, want %v %v %s %v", s.RawPointsUnclamped, s.FinalPoints, s.Score, s.CriticalMalusApplied, tc.raw, tc.final, tc.letter, tc.force)
			}
		})
	}
	five := ComputePlumberScoreV4(ScoreInputV4{Paths: pathsAt(TierHigh, 5)}).FinalPoints
	lowered := ComputePlumberScoreV4(ScoreInputV4{Paths: joinPaths(pathsAt(TierHigh, 4), pathsAt(TierMedium, 1))}).FinalPoints
	if lowered < five {
		t.Errorf("lowering a High path to Medium costs points: %v, then %v", five, lowered)
	}
}

// Moving one item a tier down never lowers the final points, whatever the
// rest of the run holds: a path from Critical to High, High to Medium,
// Medium to Low, or a Low path fixed; the same for an individual finding.
// The counts are drawn at random from a fixed seed so a failure replays.
func TestLoweringAnItemNeverCosts(t *testing.T) {
	tiers := []PathTier{TierCritical, TierHigh, TierMedium, TierLow}
	codes := []string{"ISSUE-501", "ISSUE-210", "ISSUE-401", "ISSUE-403"}
	build := func(paths, others [4]int) ScoreInputV4 {
		var in ScoreInputV4
		for i, n := range paths {
			in.Paths = append(in.Paths, pathsAt(tiers[i], n)...)
		}
		for i, n := range others {
			in.Findings = append(in.Findings, otherFindings(codes[i], n)...)
		}
		return in
	}
	rng := rand.New(rand.NewPCG(7, 11))
	for range 2000 {
		var paths, others [4]int
		for i := range paths {
			paths[i], others[i] = rng.IntN(7), rng.IntN(7)
		}
		before := ComputePlumberScoreV4(build(paths, others)).FinalPoints
		for i := range 4 {
			for _, path := range []bool{true, false} {
				counts := &others
				if path {
					counts = &paths
				}
				if counts[i] == 0 {
					continue
				}
				saved := *counts
				counts[i]--
				if i < 3 {
					counts[i+1]++
				}
				after := ComputePlumberScoreV4(build(paths, others)).FinalPoints
				*counts = saved
				if after < before {
					t.Fatalf("paths %v, findings %v: lowering a %s (path %v) moves %v to %v", paths, others, tiers[i], path, before, after)
				}
			}
		}
	}
}

// What each tier takes off is its part of the nested cap, read from the
// lowest tier up: Low first up to 29, then Medium up to what is left of
// 49, then High up to what is left of 69. Within a severity, the paths
// and the individual findings share that part by their prices, and each
// code keeps its share of the individual findings' part, so the
// subtraction always adds up.
func TestNestedCapsAttributeEachTier(t *testing.T) {
	s := ComputePlumberScoreV4(ScoreInputV4{Paths: joinPaths(pathsAt(TierHigh, 5), pathsAt(TierMedium, 2), pathsAt(TierLow, 12))})
	want := map[PathTier]float64{TierHigh: 69 - 41, TierMedium: 12, TierLow: 29}
	for _, pl := range s.PathLosses {
		if pl.CappedLoss != want[pl.Tier] {
			t.Errorf("%s paths take off %v, want %v", pl.Tier, pl.CappedLoss, want[pl.Tier])
		}
	}
	if caps := map[PathTier]float64{TierHigh: 69, TierMedium: 49, TierLow: 29}; len(s.PathLosses) != 3 || s.PathLosses[0].Cap != caps[s.PathLosses[0].Tier] {
		t.Errorf("each tier names the nested cap that holds it: %+v", s.PathLosses)
	}
	if s.RawPointsUnclamped != 31 {
		t.Errorf("raw = %v, want 31", s.RawPointsUnclamped)
	}

	// 4 High paths (60) and 2 High findings (20) share the 69 by price.
	mixed := ComputePlumberScoreV4(ScoreInputV4{Paths: pathsAt(TierHigh, 4), Findings: otherFindings("ISSUE-210", 2)})
	paths, other := BucketLosses(&mixed)
	if math.Abs(paths-69*60.0/80) > 1e-9 || math.Abs(other-69*20.0/80) > 1e-9 || mixed.RawPointsUnclamped != 31 {
		t.Errorf("paths %v, other %v, raw %v", paths, other, mixed.RawPointsUnclamped)
	}
	if o := mixed.OtherFindings; o.UncappedLoss != 20 || o.CapApplied || math.Abs(mixed.CodeLosses[0].CappedLoss-other) > 1e-9 {
		t.Errorf("other findings %+v, code losses %+v", o, mixed.CodeLosses)
	}

	// The 30 is spent worst first: a Critical (20), then 10 of the High.
	worst := ComputePlumberScoreV4(ScoreInputV4{Findings: joinFindings(otherFindings("ISSUE-501", 1), otherFindings("ISSUE-210", 3), otherFindings("ISSUE-403", 2))})
	got := map[ErrorCode]float64{}
	for _, cl := range worst.CodeLosses {
		got[cl.Code] = cl.CappedLoss
	}
	if got["ISSUE-501"] != 20 || got["ISSUE-210"] != 10 || got["ISSUE-403"] != 0 || !worst.OtherFindings.CapApplied || worst.OtherFindings.CappedLoss != 30 {
		t.Errorf("code losses %v, other findings %+v", got, worst.OtherFindings)
	}
}

// The cap applies only above 30: three High other findings cost exactly
// 30 with the cap not applied, a fourth is absorbed by it.
func TestOtherFindingsCapAppliesOnlyAboveIt(t *testing.T) {
	at := ComputePlumberScoreV4(ScoreInputV4{Findings: otherFindings("ISSUE-210", 3)}).OtherFindings
	if at == nil || at.UncappedLoss != 30 || at.CappedLoss != 30 || at.CapApplied {
		t.Errorf("at the cap = %+v", at)
	}
	over := ComputePlumberScoreV4(ScoreInputV4{Findings: otherFindings("ISSUE-210", 4)}).OtherFindings
	if over == nil || over.UncappedLoss != 40 || over.CappedLoss != 30 || !over.CapApplied {
		t.Errorf("over the cap = %+v", over)
	}
}

// Dismissed findings cost nothing.
func TestContextualScoreDismissedOnlyIsAHundred(t *testing.T) {
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: dismissedFindings(otherFindings("ISSUE-501", 3))})
	if s.FinalPoints != 100 || s.OtherFindings != nil || s.FloorApplied {
		t.Errorf("score = %+v", s)
	}
}

// The JSON score object carries the two buckets and none of the removed
// per-group fields.
func TestContextualScoreJSONCarriesTheTwoBuckets(t *testing.T) {
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: otherFindings("ISSUE-401", 1), Paths: pathsAt(TierHigh, 1)})
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, want := range []string{
		`"pathLosses":[{"tier":"high","count":1,"weight":15,"cap":69,"cappedLoss":15,"pathIds":["high-0"]}]`,
		`"otherFindings":{"count":1,"counts":{"critical":0,"high":0,"medium":1,"low":0},"uncappedLoss":5,"cap":30,"cappedLoss":5,"capApplied":false}`,
		`"codeLosses":[{"code":"ISSUE-401","severity":"medium","count":1,"weight":5,"uncappedLoss":5,"cappedLoss":5}]`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("JSON lacks %s:\n%s", want, got)
		}
	}
	for _, gone := range []string{`"gateLosses"`, `"hygieneLoss"`, `"hygieneCount"`} {
		if strings.Contains(got, gone) {
			t.Errorf("JSON still carries %s", gone)
		}
	}
}

// When the cap applies, each code keeps its share of the capped bucket, so
// the per-code losses still add up to what the bucket took off.
func TestOtherFindingsCodesShareTheCappedBucket(t *testing.T) {
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: joinFindings(otherFindings("ISSUE-501", 1), otherFindings("ISSUE-210", 2), otherFindings("ISSUE-401", 9))})
	if s.OtherFindings == nil || s.OtherFindings.UncappedLoss != 85 || s.OtherFindings.CappedLoss != 30 || !s.OtherFindings.CapApplied {
		t.Fatalf("other findings = %+v", s.OtherFindings)
	}
	if s.OtherFindings.Counts != (SeverityCounts{Critical: 1, High: 2, Medium: 9}) || s.OtherFindings.Count != 12 {
		t.Errorf("counts = %+v", s.OtherFindings)
	}
	var sum float64
	for _, cl := range s.CodeLosses {
		sum += cl.CappedLoss
	}
	if math.Abs(sum-30) > 1e-9 {
		t.Errorf("per-code shares sum to %v, want 30", sum)
	}
}

// A finding on no path shows its registry severity, the price it pays.
func TestOtherFindingShowsItsRegistrySeverity(t *testing.T) {
	f := otherFindings("ISSUE-501", 1)[0]
	if got := ContextualSeverity(f, nil, ""); got != SeverityCritical {
		t.Errorf("ContextualSeverity = %s, want critical", got)
	}
	if c := ComputePlumberScoreV4(ScoreInputV4{Findings: []opaengine.Finding{f}}).Counts; c.Critical != 1 || c.Low != 0 {
		t.Errorf("counts = %+v", c)
	}
}
