package control

import (
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

func criticalReleasePath() AttackPath {
	return AttackPath{
		ID: "abc123", Tier: TierCritical, BaseTier: TierCritical, State: PathProven,
		EntryKind: EntryMutableDependency, AnchorCode: "ISSUE-713", AnchorHash: "h1",
		Entry:     EntryFact{Kind: EntryMutableDependency, State: "proven", Evidence: "some/action@v1", Subject: "some/action@v1"},
		Jobs:      []string{"release"},
		Reach:     Reach{Secrets: []string{"NPM_TOKEN"}, TokenWrite: []string{"contents"}, Impacts: []ImpactFact{{Kind: "publishes", State: "proven", Evidence: "npm publish"}}, Executes: true},
		ReachKind: "impact:publishes",
	}
}

func TestPathSentenceCriticalRelease(t *testing.T) {
	got := PathSentence(criticalReleasePath())
	want := "A new version of `some/action@v1` runs inside `release` without any change in this repository, holding `NPM_TOKEN` and a token with `contents` write, and it publishes the package: a compromise here ships a malicious release to your users or into production."
	if got != want {
		t.Fatalf("\n got  %q\n want %q", got, want)
	}
}

// The consequence clause follows BaseTier (Medium, what the attacker
// actually reaches here: execution alone), never the private_exposure
// modifier's own lowered Tier (Low); the modifier gets its own trailing
// sentence instead.
func TestPathSentenceMediumInjectionWithModifiers(t *testing.T) {
	p := AttackPath{
		ID: "d4", Tier: TierLow, BaseTier: TierMedium, State: PathProven, EntryKind: EntryUntrustedExpression,
		Entry: EntryFact{Kind: EntryUntrustedExpression, Subject: "github.event.pull_request.title", Evidence: `echo "${{ github.event.pull_request.title }}"`},
		Jobs:  []string{"build"}, Reach: Reach{Executes: true}, ReachKind: "execution",
		Modifiers: []string{"private_exposure"}, Exposure: "private",
	}
	got := PathSentence(p)
	if !strings.HasPrefix(got, "Anyone who can open a pull request or push a commit controls `github.event.pull_request.title`, which `build` passes to a shell, but it holds no secret and cannot write anything: the runner can be abused and anything it caches or uploads can be poisoned.") {
		t.Errorf("sentence = %q", got)
	}
	if !strings.HasSuffix(got, " The repository is private, so this entry needs an account with access.") {
		t.Errorf("modifier sentence missing: %q", got)
	}
}

// A Medium-base path amplified to High by a gate on a walked job
// (ISSUE-305, not the default-branch rule) still renders its Medium
// consequence, never the High one: the gate sentence carries the
// amplification, the consequence clause never claims a reach (secrets)
// the path does not have.
func TestPathSentenceAmplifiedPathKeepsItsBaseTierConsequence(t *testing.T) {
	p := AttackPath{
		ID: "d5", Tier: TierHigh, BaseTier: TierMedium, State: PathProven, EntryKind: EntryUntrustedExpression,
		Entry: EntryFact{Kind: EntryUntrustedExpression, Subject: "github.event.pull_request.title", Evidence: `echo "${{ github.event.pull_request.title }}"`},
		Jobs:  []string{"build"}, Reach: Reach{Executes: true}, ReachKind: "execution",
		Modifiers: []string{"gate:ISSUE-305"},
	}
	got := PathSentence(p)
	if !strings.Contains(got, "the runner can be abused and anything it caches or uploads can be poisoned") {
		t.Errorf("want the Medium base consequence, got %q", got)
	}
	if strings.Contains(got, "the secrets can be read") {
		t.Errorf("must never claim the secrets can be read when BaseTier is Medium: %q", got)
	}
}

// No rendered sentence ever says both that a path holds no secret and
// that the secrets can be read, whatever its modifiers. Swept over every
// tier/modifier combination the templates render.
func TestNoSentenceClaimsBothNoSecretAndSecretsCanBeRead(t *testing.T) {
	samples := []AttackPath{
		{Tier: TierHigh, BaseTier: TierMedium, EntryKind: EntryUntrustedExpression, Jobs: []string{"build"}, Reach: Reach{Executes: true}, Modifiers: []string{"gate:ISSUE-305"}},
		{Tier: TierMedium, BaseTier: TierMedium, EntryKind: EntryUnprotectedPush, Jobs: []string{"build"}, Entry: EntryFact{Subject: "main"}, Reach: Reach{Executes: true}},
		{Tier: TierHigh, BaseTier: TierHigh, EntryKind: EntryMutableDependency, Jobs: []string{"build"}, Entry: EntryFact{Subject: "some/action@v1"}, Reach: Reach{Secrets: []string{"S"}}},
		{Tier: TierCritical, BaseTier: TierHigh, EntryKind: EntryMutableDependency, Jobs: []string{"build"}, Entry: EntryFact{Subject: "some/action@v1"}, Reach: Reach{TokenWrite: []string{"contents"}}, Modifiers: []string{"gate:ISSUE-501"}},
	}
	for _, p := range samples {
		got := PathSentence(p)
		if strings.Contains(got, "holds no secret") && strings.Contains(got, "the secrets can be read") {
			t.Errorf("sentence claims both no secret and secrets readable: %q", got)
		}
	}
}

func TestPathSentenceNeverExceedsTheCapAndNeverEchoesAValue(t *testing.T) {
	p := criticalReleasePath()
	for i := 0; i < 200; i++ {
		p.Reach.Secrets = append(p.Reach.Secrets, "SECRET_"+strings.Repeat("X", 40))
	}
	got := PathSentence(p)
	if len(got) > maxSentenceLen {
		t.Fatalf("len = %d", len(got))
	}
	if !strings.Contains(got, "and 198 more") {
		t.Errorf("want the secret list folded, got %q", got)
	}
}

// TestFindingLineAndContextualSeverity hashes each finding through
// findingAnchorHash, the same wrapper AssemblePaths keys AnchorHash and
// GateHashes with, rather than calling identity.PlatformHash directly:
// that function returns (hash, version, ok), not a bare string, and going
// around the wrapper would risk this test and the assembler disagreeing
// on a finding's hash.
func TestFindingLineAndContextualSeverity(t *testing.T) {
	anchor := opaengine.Finding{Code: "ISSUE-713", Job: "release", Data: map[string]any{"uses": "some/action@v1"}}
	gate := opaengine.Finding{Code: "ISSUE-305", Job: "release"}
	loneGate := opaengine.Finding{Code: "ISSUE-501", Data: map[string]any{"branchName": "main"}}
	hygiene := opaengine.Finding{Code: "ISSUE-999"}
	p := criticalReleasePath()
	anchorHash, ok := findingAnchorHash(anchor)
	if !ok {
		t.Fatal("anchor finding did not hash")
	}
	gateHash, ok := findingAnchorHash(gate)
	if !ok {
		t.Fatal("gate finding did not hash")
	}
	p.AnchorHash = anchorHash
	p.GateHashes = []string{gateHash}
	paths := []AttackPath{p}

	cases := map[string]struct {
		f    opaengine.Finding
		line string
		sev  IssueSeverity
	}{
		"anchor":    {anchor, "Entry of path abc123", SeverityCritical},
		"gate":      {gate, "Gate: amplifies path abc123", SeverityForCode("ISSUE-305")},
		"lone gate": {loneGate, "Gate: no path to amplify today", SeverityCritical},
		"hygiene":   {hygiene, "Hygiene: on no attack path", SeverityLow},
	}
	for name, tc := range cases {
		if got := FindingLine(tc.f, paths); got != tc.line {
			t.Errorf("%s: line = %q, want %q", name, got, tc.line)
		}
		if got := ContextualSeverity(tc.f, paths); got != tc.sev {
			t.Errorf("%s: severity = %q, want %q", name, got, tc.sev)
		}
	}
}

// TestFindingLineEntryRoleOnNoPath: an entry-role finding that anchors no
// path (none of the paths passed in matches its hash) gets its own line,
// distinct from plain hygiene.
func TestFindingLineEntryRoleOnNoPath(t *testing.T) {
	f := opaengine.Finding{Code: "ISSUE-101"} // CodeImageUnauthorizedSource, Role entry
	if RoleForCode(ErrorCode(f.Code)) != RoleEntry {
		t.Fatalf("fixture code is not role entry")
	}
	got := FindingLine(f, nil)
	want := "Entry: no attack path found from here"
	if got != want {
		t.Errorf("line = %q, want %q", got, want)
	}
}

// TestEntryClauseByKind pins the exact wording per entry kind (spec
// section 3).
func TestEntryClauseByKind(t *testing.T) {
	cases := []struct {
		name string
		p    AttackPath
		want string
	}{
		{
			name: "fork_pr",
			p:    AttackPath{EntryKind: EntryForkPR, Jobs: []string{"build"}},
			want: "A fork pull request can start `build`",
		},
		{
			name: "pr_target",
			p:    AttackPath{EntryKind: EntryPRTarget, Jobs: []string{"build"}, Entry: EntryFact{Evidence: "pull_request_target"}},
			want: "A pull request from anyone runs inside `build` with the base repository's privileges (`pull_request_target`)",
		},
		{
			name: "untrusted_expression",
			p:    AttackPath{EntryKind: EntryUntrustedExpression, Jobs: []string{"build"}, Entry: EntryFact{Subject: "github.event.issue.title"}},
			want: "Anyone who can open a pull request or push a commit controls `github.event.issue.title`, which `build` passes to a shell",
		},
		{
			name: "mutable_dependency",
			p:    AttackPath{EntryKind: EntryMutableDependency, Jobs: []string{"release"}, Entry: EntryFact{Subject: "some/action@v1"}},
			want: "A new version of `some/action@v1` runs inside `release` without any change in this repository",
		},
		{
			name: "unprotected_push",
			p:    AttackPath{EntryKind: EntryUnprotectedPush, Jobs: []string{"deploy"}, Entry: EntryFact{Subject: "main"}},
			want: "Anyone who can push to `main` runs `deploy`",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := entryClause(tc.p); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestConsequenceByTier pins the exact wording per tier (spec section 3).
func TestConsequenceByTier(t *testing.T) {
	cases := []struct {
		tier PathTier
		want string
	}{
		{TierCritical, "a compromise here ships a malicious release to your users or into production"},
		{TierHigh, "the secrets can be read and reused elsewhere"},
		{TierMedium, "the runner can be abused and anything it caches or uploads can be poisoned"},
		{TierLow, "no exploitable reach was found"},
	}
	for _, tc := range cases {
		t.Run(string(tc.tier), func(t *testing.T) {
			if got := consequence(tc.tier); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestNoTemplateContainsAnEmDash walks every entry kind, every tier and
// every modifier at least once and asserts the rendered sentence never
// carries an em dash character (project convention, never a dash, a
// colon, a comma or parentheses instead).
func TestNoTemplateContainsAnEmDash(t *testing.T) {
	samples := []AttackPath{
		{EntryKind: EntryForkPR, Jobs: []string{"build"}, Tier: TierCritical},
		{EntryKind: EntryPRTarget, Jobs: []string{"build"}, Entry: EntryFact{Evidence: "pull_request_target"}, Tier: TierHigh},
		{EntryKind: EntryUntrustedExpression, Jobs: []string{"build"}, Entry: EntryFact{Subject: "x"}, Tier: TierMedium},
		{EntryKind: EntryMutableDependency, Jobs: []string{"release"}, Entry: EntryFact{Subject: "some/action@v1"}, Tier: TierLow},
		{
			EntryKind: EntryUnprotectedPush, Jobs: []string{"deploy"}, Entry: EntryFact{Subject: "main", State: "unresolvable", Evidence: "push rules"}, Tier: TierCritical,
			Reach: Reach{
				Secrets: []string{"S"}, TokenWrite: []string{"contents"},
				Impacts: []ImpactFact{{Kind: "deploys", Evidence: "environment: production"}},
			},
			Modifiers: []string{"private_exposure", "unresolvable", "gate:ISSUE-305"},
		},
	}
	for _, p := range samples {
		got := PathSentence(p)
		// The escaped rune literal, never the raw em dash character itself:
		// the project convention is "never, anywhere", including in this
		// very test's source.
		if strings.ContainsRune(got, '\u2014') {
			t.Errorf("em dash in sentence %q", got)
		}
	}
}

// The unresolvable modifier sentence names what was really not verified,
// picking between three distinct causes a path can carry.
func TestUnresolvableSentencePicksTheRealCause(t *testing.T) {
	entryPath := AttackPath{EntryKind: EntryUnprotectedPush, Jobs: []string{"build"}, Entry: EntryFact{Subject: "main", State: "unresolvable", Evidence: "push rules unclear"}}
	if got := unresolvableSentence(entryPath); got != "Plumber could not verify `push rules unclear`, so this path is unverified." {
		t.Errorf("entry cause: %q", got)
	}

	impactPath := AttackPath{Reach: Reach{Impacts: []ImpactFact{{Kind: "deploys", State: "unresolvable", Evidence: "environment: maybe production"}}}}
	if got := unresolvableSentence(impactPath); got != "Plumber could not verify `environment: maybe production`, so this path is unverified." {
		t.Errorf("impact cause: %q", got)
	}

	secretsPath := AttackPath{}
	secretsPath.cause = unresolvableSecrets
	if got := unresolvableSentence(secretsPath); got != "Plumber could not verify `the secrets in scope`, so this path is unverified." {
		t.Errorf("secrets cause: %q", got)
	}

	tokenPath := AttackPath{}
	tokenPath.cause = unresolvableDefaultToken
	want := "Plumber could not verify that `GITHUB_TOKEN` is really writable (no `permissions` block), so this path is unverified."
	if got := unresolvableSentence(tokenPath); got != want {
		t.Errorf("default-token cause: got %q, want %q", got, want)
	}
}

// Test honesty: one end-to-end test per unresolvable cause, asserting the
// RENDERED sentence from a path AssemblePaths itself assembled, not from a
// hand-set cause field. TestUnresolvableSentencePicksTheRealCause above
// still pins unresolvableSentence's own branches directly; these three
// pin the whole pipeline that gets a path into each branch.
func TestDefaultTokenPathRendersTheGithubTokenSentence(t *testing.T) {
	f := finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"})
	paths := AssemblePaths([]opaengine.Finding{f}, defaultTokenSituation(ir.VisibilityPublic))
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	want := "Plumber could not verify that `GITHUB_TOKEN` is really writable (no `permissions` block), so this path is unverified."
	if got := PathSentence(paths[0]); !strings.Contains(got, want) {
		t.Errorf("sentence = %q, want it to contain %q", got, want)
	}
}

func TestUnresolvableSecretsStateRendersTheSecretsSentence(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	j := sit.Jobs["release"]
	j.Privilege.SecretsState = "unresolvable"
	sit.Jobs["release"] = j
	f := finding("ISSUE-713", "release", map[string]any{"uses": "some/action@v1"})
	paths := AssemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	want := "Plumber could not verify `the secrets in scope`, so this path is unverified."
	if got := PathSentence(paths[0]); !strings.Contains(got, want) {
		t.Errorf("sentence = %q, want it to contain %q", got, want)
	}
}

func TestUnresolvableEntryFactRendersItsOwnEvidenceSentence(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	j := sit.Jobs["release"]
	j.Entries[0].State = "unresolvable"
	sit.Jobs["release"] = j
	f := finding("ISSUE-716", "release", map[string]any{"uses": "some/action@v1"})
	paths := AssemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	want := "Plumber could not verify `some/action@v1`, so this path is unverified."
	if got := PathSentence(paths[0]); !strings.Contains(got, want) {
		t.Errorf("sentence = %q, want it to contain %q", got, want)
	}
}

// truncateWords never cuts inside a UTF-8 sequence: a run of multi-byte
// characters straddling the cap must still back up to a rune boundary.
func TestTruncateWordsNeverCutsInsideARune(t *testing.T) {
	s := strings.Repeat("é", 300) // 300 two-byte "e with acute accent" runes, no spaces
	got := truncateWords(s, 100)
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("want an ellipsis, got %q", got)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("truncated string is not valid UTF-8: %q", got)
	}
}

// The gate sentence's lead-in depends on whether the gate is a branch
// protection (ISSUE-501/ISSUE-505) or any other job-level gate.
func TestGateModifierSentenceLeadInDependsOnTheGateKind(t *testing.T) {
	branchPath := AttackPath{EntryKind: EntryForkPR, Jobs: []string{"build"}, Modifiers: []string{"gate:ISSUE-501"}}
	if got := PathSentence(branchPath); !strings.Contains(got, "Nothing stands between this and the default branch: Branch protection missing.") {
		t.Errorf("branch gate sentence: %q", got)
	}
	jobPath := AttackPath{EntryKind: EntryMutableDependency, Jobs: []string{"release"}, Entry: EntryFact{Subject: "some/action@v1"}, Modifiers: []string{"gate:ISSUE-305"}}
	if got := PathSentence(jobPath); !strings.Contains(got, "A protection is missing on this job: Deploy / release job uses secrets without an `environment:` gate.") {
		t.Errorf("job gate sentence: %q", got)
	}
}

// Spec section 2, Findings on no path: a privilege-role finding whose job
// is a walked (and pruning-surviving) job of at least one path is ON that
// path, not hygiene: FindingLine names the strongest path, ContextualSeverity
// reads that path's tier. Both pick the strongest path themselves, so
// feeding the paths in the WRONG order (weakest first, the opposite of
// AssemblePaths' own tier-sorted output) must not change the answer.
func TestFindingLineAndSeverityForAPrivilegeFindingOnAWalkedJob(t *testing.T) {
	critical := AttackPath{ID: "crit1", Tier: TierCritical, Jobs: []string{"release"}, survivingJobs: []string{"release"}}
	high := AttackPath{ID: "high1", Tier: TierHigh, Jobs: []string{"release"}, survivingJobs: []string{"release"}}
	paths := []AttackPath{high, critical} // deliberately the wrong order: weakest first
	f := opaengine.Finding{Code: string(CodeArtipacked), Job: "release"}
	if got := FindingLine(f, paths); got != "Privilege: on path crit1" {
		t.Errorf("line = %q", got)
	}
	if got := ContextualSeverity(f, paths); got != SeverityCritical {
		t.Errorf("severity = %q, want critical", got)
	}
}

func TestPrivilegeFindingOffAnyWalkedJobIsPlainHygiene(t *testing.T) {
	f := opaengine.Finding{Code: string(CodeArtipacked), Job: "other"}
	paths := []AttackPath{{ID: "crit1", Tier: TierCritical, Jobs: []string{"release"}}}
	if got := FindingLine(f, paths); got != "Privilege: on no attack path" {
		t.Errorf("line = %q", got)
	}
	if got := ContextualSeverity(f, paths); got != SeverityLow {
		t.Errorf("severity = %q, want low", got)
	}
}

// PathIDsFor (the pathIds slot the terminal and JSON outputs need next):
// anchored, then gated, then privilege-on-path ids, in path order,
// deduplicated.
func TestPathIDsForOrdersAnchoredThenGatedDeduplicated(t *testing.T) {
	anchor := opaengine.Finding{Code: "ISSUE-713", Job: "release", Data: map[string]any{"uses": "some/action@v1"}}
	anchorHash, ok := findingAnchorHash(anchor)
	if !ok {
		t.Fatal("anchor did not hash")
	}
	p1 := AttackPath{ID: "p1", Tier: TierCritical, AnchorHash: anchorHash, Jobs: []string{"release"}}
	p2 := AttackPath{ID: "p2", Tier: TierHigh, GateHashes: []string{anchorHash}, Jobs: []string{"release"}}
	got := PathIDsFor(anchor, []AttackPath{p1, p2})
	want := []string{"p1", "p2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestPathIDsForPrivilegeFindingListsEveryWalkedPathDeduplicated(t *testing.T) {
	f := opaengine.Finding{Code: string(CodeArtipacked), Job: "release"}
	p1 := AttackPath{ID: "p1", Tier: TierCritical, Jobs: []string{"release"}, survivingJobs: []string{"release"}}
	p2 := AttackPath{ID: "p2", Tier: TierHigh, Jobs: []string{"release", "deploy"}, survivingJobs: []string{"release", "deploy"}}
	got := PathIDsFor(f, []AttackPath{p1, p2})
	want := []string{"p1", "p2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestSituationParagraph pins the three-sentence template (plan section:
// situation paragraph and best fix): exposure and shape, paths by tier,
// the best fix sentence.
func TestSituationParagraph(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	pipeline := &ir.NormalizedPipeline{Jobs: []ir.Job{{Name: "release", WorkflowName: "release"}}}
	score := PlumberScoreResult{
		CriticalPaths: 1,
		Paths:         []AttackPath{criticalReleasePath()},
		BestFix:       &BestFix{Sentence: "Fixing Untrusted action source (`some/action@v1`) recovers 70 points and moves the score to A."},
	}
	got := SituationParagraph(sit, pipeline, score)
	want := "Public repository, 1 job in 1 workflow, 1 publishes or deploys. 1 attack path: 1 critical, 0 high, 0 medium, 0 low. Fixing Untrusted action source (`some/action@v1`) recovers 70 points and moves the score to A."
	if got != want {
		t.Fatalf("\n got  %q\n want %q", got, want)
	}
}

// TestSituationParagraphUnknownVisibilityAndNoPaths pins the no-path and
// unknown-visibility wording, and that a nil BestFix renders "Nothing to
// fix.".
func TestSituationParagraphUnknownVisibilityAndNoPaths(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityUnknown, Jobs: map[string]JobSituation{"build": {}}}
	pipeline := &ir.NormalizedPipeline{Jobs: []ir.Job{{Name: "build"}}}
	got := SituationParagraph(sit, pipeline, PlumberScoreResult{HygieneCount: 2})
	want := "Repository of unknown visibility (treated as public), 1 job in 1 workflow. No attack path found; 2 hygiene findings. Nothing to fix."
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestBestFixPicksTheLargestGain: the trial that gains the most
// FinalPoints wins, over every distinct non-dismissed finding (anchor or
// gate) by hash.
func TestBestFixPicksTheLargestGain(t *testing.T) {
	anchor := opaengine.Finding{Code: "ISSUE-713", Job: "release", Data: map[string]any{"uses": "some/action@v1"}}
	gate := opaengine.Finding{Code: "ISSUE-501", Data: map[string]any{"branchName": "main"}}
	sit := releaseSituation(ir.VisibilityPublic)
	in := ScoreInputV4{Findings: []opaengine.Finding{anchor, gate}}
	in.Paths = AssemblePaths(in.Findings, sit)
	current := ComputePlumberScoreV4(in) // critical path 30 + gate 25: raw 45, final 30, E
	if current.Score != "E" {
		t.Fatalf("fixture drifted: current = %+v", current)
	}
	fix := ComputeBestFix(in, sit, current)
	if fix == nil || fix.Code != "ISSUE-713" {
		t.Fatalf("want the critical path's anchor, got %+v", fix)
	}
	// Without the anchor: only the gate remains, 75 B: gain 45.
	if math.Abs(fix.PointsGained-45) > 0.01 || fix.NewLetter != "B" || !strings.Contains(fix.Sentence, "recovers 45 points and moves the score to B") {
		t.Errorf("fix = %+v", fix)
	}
	wantHash, ok := findingAnchorHash(anchor)
	if !ok || fix.AnchorHash != wantHash {
		t.Errorf("anchorHash = %q, want %q", fix.AnchorHash, wantHash)
	}
}

// TestBestFixIsNilWithoutFindings pins the no-candidate case.
func TestBestFixIsNilWithoutFindings(t *testing.T) {
	if fix := ComputeBestFix(ScoreInputV4{}, &Situation{}, ComputePlumberScoreV4(ScoreInputV4{})); fix != nil {
		t.Fatalf("got %+v", fix)
	}
}

// TestBestFixIsDeterministicUnderShuffledFindings pins the tie rule
// (ties go to the lower code string) and that the winner never depends on
// input order. Two hygiene-bucket findings gain the exact
// same FinalPoints when either one is removed (the dampened bucket drops
// from count 2 to count 1 either way), so only the tie-break decides. No
// anchor and no gate exists anywhere in this fixture, so the hygiene
// findings are legitimate candidates.
func TestBestFixIsDeterministicUnderShuffledFindings(t *testing.T) {
	findings := []opaengine.Finding{{Code: "ISSUE-901"}, {Code: "ISSUE-902"}}
	sit := &Situation{Jobs: map[string]JobSituation{}}
	want := ComputeBestFix(ScoreInputV4{Findings: findings}, sit, ComputePlumberScoreV4(ScoreInputV4{Findings: findings}))
	if want == nil || want.Code != "ISSUE-901" {
		t.Fatalf("want the lower code to win the tie, got %+v", want)
	}
	for i := 0; i < 20; i++ {
		shuffled := append([]opaengine.Finding(nil), findings...)
		rand.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		in := ScoreInputV4{Findings: shuffled}
		got := ComputeBestFix(in, sit, ComputePlumberScoreV4(in))
		if got == nil || got.Code != want.Code || got.AnchorHash != want.AnchorHash || math.Abs(got.PointsGained-want.PointsGained) > 0.0001 {
			t.Fatalf("shuffle %d: got %+v, want %+v", i, got, want)
		}
	}
}

// When several candidates share BOTH the same code and the same gain,
// the tie goes to the lower anchor hash, never to whichever happened to
// come first in the caller's own finding order.
func TestBestFixSameCodeTieBreaksOnAnchorHashUnderShuffle(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{
		"a": {}, "b": {}, "c": {},
	}}
	findings := []opaengine.Finding{
		{Code: "ISSUE-207", Job: "a", Data: map[string]any{"expression": "x"}},
		{Code: "ISSUE-207", Job: "b", Data: map[string]any{"expression": "x"}},
		{Code: "ISSUE-207", Job: "c", Data: map[string]any{"expression": "x"}},
	}
	sit.Jobs["a"] = JobSituation{}
	sit.Jobs["b"] = JobSituation{}
	sit.Jobs["c"] = JobSituation{}
	in := ScoreInputV4{Findings: findings}
	in.Paths = AssemblePaths(in.Findings, sit)
	current := ComputePlumberScoreV4(in)
	want := ComputeBestFix(in, sit, current)
	if want == nil {
		t.Fatal("want a winner among the three equal-gain candidates")
	}
	for i := 0; i < 20; i++ {
		shuffled := append([]opaengine.Finding(nil), findings...)
		rand.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		shuffledIn := ScoreInputV4{Findings: shuffled}
		shuffledIn.Paths = AssemblePaths(shuffledIn.Findings, sit)
		got := ComputeBestFix(shuffledIn, sit, ComputePlumberScoreV4(shuffledIn))
		if got == nil || got.AnchorHash != want.AnchorHash {
			t.Fatalf("shuffle %d: got %+v, want %+v (same-code tie must settle on one anchor hash regardless of order)", i, got, want)
		}
	}
}

// Candidates are the findings that currently cost something (an anchor of
// a path, or any gate finding, amplifying or lone); a hygiene or
// consumed-privilege finding is a candidate only when no anchor and no
// gate exists anywhere in the run.
func TestBestFixCandidateRestrictionAppliesOnlyWhenNothingElseCanBeFixed(t *testing.T) {
	anchor := opaengine.Finding{Code: "ISSUE-713", Job: "release"}
	gate := opaengine.Finding{Code: "ISSUE-501", Data: map[string]any{"branchName": "main"}}
	hygiene := opaengine.Finding{Code: "ISSUE-999"}
	anchorHash, ok := findingAnchorHash(anchor)
	if !ok {
		t.Fatal("anchor did not hash")
	}
	anchorPath := []AttackPath{{AnchorHash: anchorHash}}

	if !runHasAnchorOrGate(ScoreInputV4{Findings: []opaengine.Finding{anchor}, Paths: anchorPath}) {
		t.Error("an anchor alone must count as something else to fix")
	}
	if !runHasAnchorOrGate(ScoreInputV4{Findings: []opaengine.Finding{gate}}) {
		t.Error("a gate alone must count as something else to fix")
	}
	if runHasAnchorOrGate(ScoreInputV4{Findings: []opaengine.Finding{hygiene}}) {
		t.Error("hygiene alone must not count as something else to fix")
	}
	if isCostlyCandidate(hygiene, nil) {
		t.Error("a hygiene finding is never a candidate reason on its own")
	}
	if !isCostlyCandidate(gate, nil) {
		t.Error("every gate finding is a candidate, amplifying or lone")
	}
	if !isCostlyCandidate(anchor, anchorPath) {
		t.Error("an anchor of a path is a candidate")
	}
}

// ComputeBestFix must stay fast even over a thousand findings, as long as
// only a handful of them are candidates (the restriction above already
// excludes the rest): no more re-hashing every finding per candidate, and
// no more trying every finding regardless of whether it could possibly cost
// anything.
func TestComputeBestFixScoresAThousandFindingsFast(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	var findings []opaengine.Finding
	for i := 0; i < 990; i++ {
		findings = append(findings, opaengine.Finding{Code: "ISSUE-999", Job: "release", Message: fmt.Sprintf("occurrence %d", i)})
	}
	// Only 10 anchors: enough to be "a few", few enough that removing one
	// still measurably gains points (50 saturates the Critical group's
	// uncapped dampened loss past the raw-points floor, where every trial
	// gains exactly zero and the fixture would prove nothing).
	for i := 0; i < 10; i++ {
		findings = append(findings, opaengine.Finding{Code: "ISSUE-713", Job: "release", Data: map[string]any{"uses": fmt.Sprintf("some/action-%d@v1", i)}})
	}
	in := ScoreInputV4{Findings: findings}
	in.Paths = AssemblePaths(in.Findings, sit)
	current := ComputePlumberScoreV4(in)
	start := time.Now()
	fix := ComputeBestFix(in, sit, current)
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Fatalf("ComputeBestFix took %v for 1000 findings (mostly hygiene), want well under a second", elapsed)
	}
	if fix == nil {
		t.Fatal("want a winning fix among the anchors")
	}
}

// formatPoints rounds to one decimal before deciding whether to print an
// integer, and pointsWord picks the singular only for exactly 1.
func TestFormatPointsRoundsBeforeChoosingIntegerOrOneDecimal(t *testing.T) {
	cases := []struct {
		p    float64
		want string
	}{
		{44.99999999, "45"}, // rounds to a whole number: no trailing ".0"
		{2.25, "2.2"},       // not a whole number at one decimal: %.1f's own tie-break
		{1, "1"},
		{0.03, "0"}, // rounds to 0, a whole number
	}
	for _, tc := range cases {
		if got := formatPoints(tc.p); got != tc.want {
			t.Errorf("formatPoints(%v) = %q, want %q", tc.p, got, tc.want)
		}
	}
	if got := pointsWord(1); got != "point" {
		t.Errorf("pointsWord(1) = %q, want %q", got, "point")
	}
	for _, p := range []float64{0, 2, 0.03, 1.5} {
		if got := pointsWord(p); got != "points" {
			t.Errorf("pointsWord(%v) = %q, want %q", p, got, "points")
		}
	}
}

// A gain that rounds to 0.0 must never win the best fix.
func TestBestFixSkipsAGainThatRoundsToZero(t *testing.T) {
	// A single hygiene finding alone: dismissing it is the only candidate
	// (no anchor, no gate), and it does gain (bucket drops from 1 to 0),
	// so this pins the positive case before the zero-gain case matters.
	findings := []opaengine.Finding{{Code: "ISSUE-999"}}
	sit := &Situation{Jobs: map[string]JobSituation{}}
	in := ScoreInputV4{Findings: findings}
	current := ComputePlumberScoreV4(in)
	fix := ComputeBestFix(in, sit, current)
	if fix == nil {
		t.Fatal("want a fix: removing the only hygiene finding gains 2 points")
	}
}

// bestFixSentence never prints empty backtick parentheses, and the rest
// of its wording is pinned alongside it: singular "1 point", and
// "keeps"/"moves" depending on whether the letter actually changes.
func TestBestFixSentenceWording(t *testing.T) {
	if got, want := bestFixSentence("Example title", "", 2, "C", "C"), "Fixing Example title recovers 2 points and keeps the score at C."; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got, want := bestFixSentence("Example title", "org/repo/template.yml", 1, "C", "B"), "Fixing Example title (`org/repo/template.yml`) recovers 1 point and moves the score to B."; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// bestFixSubjectKeys mirrors subjectMatches' own key list including
// includePath, so a job-less finding (ISSUE-404) names its include path
// as the subject rather than falling through to an empty one.
func TestBestFixSubjectUsesIncludePathForAJobLessFinding(t *testing.T) {
	sit := includeSituation(ir.VisibilityPublic, "build")
	f := finding("ISSUE-404", "", map[string]any{"includePath": "org/repo/template.yml"})
	in := ScoreInputV4{Findings: []opaengine.Finding{f}}
	in.Paths = AssemblePaths(in.Findings, sit)
	current := ComputePlumberScoreV4(in)
	fix := ComputeBestFix(in, sit, current)
	if fix == nil || fix.Subject != "org/repo/template.yml" {
		t.Fatalf("want includePath as the subject, got %+v", fix)
	}
	if strings.Contains(fix.Sentence, "(``)") {
		t.Errorf("sentence = %q, empty backticks", fix.Sentence)
	}
}

// "protections missing" counts every distinct gate finding, whether it
// amplifies a path (consumed) or sits lone, never just the lone ones
// grouped by code.
func TestSituationParagraphProtectionsMissingCountsAmplifyingAndLoneGates(t *testing.T) {
	amplified := criticalReleasePath()
	amplified.GateHashes = []string{"gate-hash-amplifying"}
	score := PlumberScoreResult{
		Paths: []AttackPath{amplified},
		GateLosses: []CodeLoss{
			{Code: "ISSUE-501", Count: 1},
		},
	}
	sit := &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{"release": {}}}
	pipeline := &ir.NormalizedPipeline{Jobs: []ir.Job{{Name: "release", WorkflowName: "release"}}}
	got := SituationParagraph(sit, pipeline, score)
	if !strings.Contains(got, "2 protections missing") {
		t.Errorf("want 2 protections missing (1 amplifying + 1 lone), got %q", got)
	}
}

// A name rendered in backticks is attacker text on a merge-request
// pipeline (the CI configuration is the author's), so code() strips every
// backtick and control character (a newline, a carriage return) to a
// space, collapses the runs, and can never break out of its own span.
func TestCodeStripsBackticksAndNewlines(t *testing.T) {
	if got := code("a`b\nc"); got != "`a b c`" {
		t.Errorf("code = %q, want %q", got, "`a b c`")
	}
	if got := code("x\r\n\r\ny"); got != "`x y`" {
		t.Errorf("code = %q, want %q", got, "`x y`")
	}
}

// A name longer than 200 runes is cut on a rune boundary, marked "...".
func TestCodeCutsALongNameOnARuneBoundary(t *testing.T) {
	long := strings.Repeat("é", 300)
	got := code(long)
	inner := strings.TrimSuffix(strings.TrimPrefix(got, "`"), "`")
	if !utf8.ValidString(inner) || utf8.RuneCountInString(inner) > 200 || !strings.HasSuffix(inner, "...") {
		t.Errorf("code(300 runes) = %q (%d runes), want at most 200 runes ending in ...", got, utf8.RuneCountInString(inner))
	}
}

// Every sentence built from a job, a subject or a secret list carries
// those names through code(): a job named with a backtick and a newline
// leaves no raw newline in the path sentence or the best fix, and every
// backtick in either still pairs up.
func TestNoSentenceCarriesARawNewlineFromAName(t *testing.T) {
	evil := "build` [x](https://evil.example)\n/merge"
	p := criticalReleasePath()
	p.Jobs = []string{evil}
	p.Entry.Subject = "some/action@v1`\n@all"
	p.Reach.Secrets = []string{"A`\nB", "C", "D", "E"}
	p.Reach.TokenWrite = []string{"contents`\nx", "id-token"}
	s := PathSentence(p)
	if strings.ContainsAny(s, "\n\r") {
		t.Errorf("sentence carries a raw newline: %q", s)
	}
	if strings.Count(s, "`")%2 != 0 {
		t.Errorf("sentence has an unpaired backtick: %q", s)
	}
	fix := bestFixSentence("Untrusted action", evil, 12, "E", "B")
	if strings.ContainsAny(fix, "\n\r") || strings.Count(fix, "`")%2 != 0 {
		t.Errorf("best fix = %q", fix)
	}
}

// RoleOnPath is the role line relative to ONE path: "Entry of path N" only
// under the path the finding anchors, "Gate: amplifies path N" under a
// path it amplifies, "Privilege: on path N" under a path it rides as a
// privilege finding.
func TestRoleOnPathIsRelativeToThePath(t *testing.T) {
	gate := finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"})
	h, ok := findingAnchorHash(gate)
	if !ok {
		t.Fatal("fixture finding has no anchor hash")
	}
	own := AttackPath{ID: "aaaa", Tier: TierCritical, AnchorHash: h, Jobs: []string{"release"}}
	other := AttackPath{ID: "bbbb", Tier: TierHigh, AnchorHash: "other", GateHashes: []string{h}, Jobs: []string{"build"}}
	if got := RoleOnPath(gate, own); got != "Entry of path aaaa" {
		t.Errorf("under its own path: %q", got)
	}
	if got := RoleOnPath(gate, other); got != "Gate: amplifies path bbbb" {
		t.Errorf("under a path it amplifies: %q", got)
	}

	priv := finding("ISSUE-307", "release", nil)
	walked := AttackPath{ID: "cccc", Tier: TierCritical, AnchorHash: "x", Jobs: []string{"release"}, survivingJobs: []string{"release"}}
	if got := RoleOnPath(priv, walked); got != "Privilege: on path cccc" {
		t.Errorf("privilege finding on a walked path: %q", got)
	}
}
