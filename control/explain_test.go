package control

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/getplumber/plumber/configuration"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

func criticalReleasePath() AttackPath {
	return AttackPath{
		ID: "abc123", Tier: TierCritical, BaseTier: TierCritical, State: PathProven,
		EntryKind: EntryMutableDependency, AnchorCode: "ISSUE-701", AnchorHash: "h1",
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

// The entry clause of an untrusted expression names who actually controls
// it: an issue body is written by whoever opens or edits the issue, not by
// someone opening a pull request. Pull request and commit expressions keep
// the general wording.
func TestUntrustedExpressionEntryClauseNamesWhoControlsIt(t *testing.T) {
	for subject, want := range map[string]string{
		"github.event.issue.title":                 "Anyone who can open or edit an issue controls `github.event.issue.title`",
		"github.event.issue.body":                  "Anyone who can open or edit an issue controls `github.event.issue.body`",
		"github.event.comment.body":                "Anyone who can comment on an issue or a pull request controls `github.event.comment.body`",
		"github.event.review.body":                 "Anyone who can review a pull request controls `github.event.review.body`",
		"github.event.review_comment.body":         "Anyone who can review a pull request controls `github.event.review_comment.body`",
		"github.event.discussion.title":            "Anyone who can open or edit a discussion controls `github.event.discussion.title`",
		"github.event.pages[0].page_name":          "Anyone who can edit the wiki controls `github.event.pages[0].page_name`",
		"github.event.pull_request.title":          "Anyone who can open a pull request or push a commit controls `github.event.pull_request.title`",
		"github.head_ref":                          "Anyone who can open a pull request or push a commit controls `github.head_ref`",
		"github.event.head_commit.message":         "Anyone who can open a pull request or push a commit controls `github.event.head_commit.message`",
		"CI_MERGE_REQUEST_TITLE":                   "Anyone who can open a merge request controls `CI_MERGE_REQUEST_TITLE`",
		"CI_COMMIT_MESSAGE":                        "Anyone who can open a pull request or push a commit controls `CI_COMMIT_MESSAGE`",
		"github.event.issue.pull_request.html_url": "Anyone who can open or edit an issue controls `github.event.issue.pull_request.html_url`",
	} {
		p := AttackPath{
			Tier: TierMedium, BaseTier: TierMedium, EntryKind: EntryUntrustedExpression,
			Entry: EntryFact{Kind: EntryUntrustedExpression, Subject: subject},
			Jobs:  []string{"build"}, Reach: Reach{Executes: true}, ReachKind: "execution",
		}
		if got := PathSentence(p); !strings.HasPrefix(got, want+", which `build` passes to a shell") {
			t.Errorf("%s: sentence = %q, want prefix %q", subject, got, want)
		}
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

func TestPathSentenceNeverExceedsTheCapAndFoldsALongSecretList(t *testing.T) {
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
	anchor := opaengine.Finding{Code: "ISSUE-701", Job: "release", Data: map[string]any{"uses": "some/action@v1"}}
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
		"hygiene":   {hygiene, "Hygiene: on no attack path", SeverityForCode("ISSUE-999")},
	}
	for name, tc := range cases {
		if got := FindingLine(tc.f, paths); got != tc.line {
			t.Errorf("%s: line = %q, want %q", name, got, tc.line)
		}
		if got := ContextualSeverity(tc.f, paths, ""); got != tc.sev {
			t.Errorf("%s: severity = %q, want %q", name, got, tc.sev)
		}
	}
}

// TestFindingLineEntryRoleOnNoPath: an entry-role finding that anchors no
// path (none of the paths passed in matches its hash) gets its own line,
// distinct from plain hygiene.
func TestFindingLineEntryRoleOnNoPath(t *testing.T) {
	f := opaengine.Finding{Code: "ISSUE-102"} // CodeImageForbiddenTag, Role entry
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
			p:    AttackPath{EntryKind: EntryPRTarget, Jobs: []string{"build"}, Entry: EntryFact{Subject: "github.event.pull_request.head.sha"}},
			want: "A pull request from anyone runs inside `build` with the base repository's privileges, checking out `github.event.pull_request.head.sha`",
		},
		{
			name: "untrusted_expression",
			p:    AttackPath{EntryKind: EntryUntrustedExpression, Jobs: []string{"build"}, Entry: EntryFact{Subject: "github.event.issue.title"}},
			want: "Anyone who can open or edit an issue controls `github.event.issue.title`, which `build` passes to a shell",
		},
		{
			name: "mutable_dependency",
			p:    AttackPath{EntryKind: EntryMutableDependency, Jobs: []string{"release"}, Entry: EntryFact{Subject: "some/action@v1"}},
			want: "A new version of `some/action@v1` runs inside `release` without any change in this repository",
		},
		{
			name: "unprotected_push",
			p:    AttackPath{EntryKind: EntryUnprotectedPush, Jobs: []string{"deploy"}, Entry: EntryFact{Subject: "main"}},
			want: "Anyone with write access to `main` runs `deploy`",
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
// Critical, Medium and Low never depend on the reach's own shape; High
// does, so each case carries the Reach that produces it.
func TestConsequenceByTier(t *testing.T) {
	cases := []struct {
		tier PathTier
		r    Reach
		want string
	}{
		{TierCritical, Reach{}, "a compromise here ships a malicious release to your users or into production"},
		{TierHigh, Reach{Secrets: []string{"S"}}, "the secrets can be read and reused elsewhere"},
		{TierMedium, Reach{}, "the runner can be abused and anything it caches or uploads can be poisoned"},
		{TierLow, Reach{}, "no exploitable reach was found"},
	}
	for _, tc := range cases {
		t.Run(string(tc.tier), func(t *testing.T) {
			if got := consequence(tc.tier, tc.r); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestConsequenceHighFollowsTheReachNotTheTierAlone pins the ways a
// High-tier path can actually reach something (spec section 3): secrets
// win when present, a write token stands in when there is no secret (its
// own scopes deciding the wording, see TestConsequenceHighTokenWording
// AbusePerScope), and an impact alone (the deploy/publish/write/sign
// itself is the damage, control/paths.go's baseTier) names the thing
// altered rather than claiming secrets or a token that the path does not
// have.
func TestConsequenceHighFollowsTheReachNotTheTierAlone(t *testing.T) {
	cases := []struct {
		name string
		r    Reach
		want string
	}{
		{"secrets", Reach{Secrets: []string{"NPM_TOKEN"}}, "the secrets can be read and reused elsewhere"},
		{"secrets and token, secrets still wins", Reach{Secrets: []string{"NPM_TOKEN"}, TokenWrite: []string{"contents"}}, "the secrets can be read and reused elsewhere"},
		{"token, no secret", Reach{TokenWrite: []string{"contents"}}, "the token can write to the repository or its packages"},
		{"impact, neither secret nor token", Reach{Impacts: []ImpactFact{{Kind: "deploys"}}}, "what this job deploys or publishes can be altered"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := consequence(TierHigh, tc.r); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestConsequenceHighTokenWordingAbusePerScope pins the write-token wording
// at High: a token whose scopes include contents or packages can write to
// the repository or its packages, as before; any other write scope alone
// (id-token, security-events, and the like) cannot write anything of that
// shape, so the wording says only that the token's write permissions can
// be abused, never naming the repository or packages it cannot touch.
func TestConsequenceHighTokenWordingAbusePerScope(t *testing.T) {
	cases := []struct {
		name  string
		scope []string
		want  string
	}{
		{"contents alone", []string{"contents"}, "the token can write to the repository or its packages"},
		{"packages alone", []string{"packages"}, "the token can write to the repository or its packages"},
		{"contents and id-token", []string{"contents", "id-token"}, "the token can write to the repository or its packages"},
		{"id-token alone", []string{"id-token"}, "the token's write permissions can be abused"},
		{"id-token and security-events", []string{"id-token", "security-events"}, "the token's write permissions can be abused"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := consequence(TierHigh, Reach{TokenWrite: tc.scope}); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestConsequenceCriticalIsTheReleaseWording pins the Critical wording:
// a job holding a secret or a write token whose run publishes, deploys,
// writes to the repository or signs a release ships what it changes, so
// every impact reads as the release sentence.
func TestConsequenceCriticalIsTheReleaseWording(t *testing.T) {
	for _, kind := range []string{"publishes", "deploys", "writes_repo", "signs_or_releases"} {
		r := Reach{Secrets: []string{"NPM_TOKEN"}, Impacts: []ImpactFact{{Kind: kind}}}
		if got := consequence(TierCritical, r); got != "a compromise here ships a malicious release to your users or into production" {
			t.Errorf("%s: got %q", kind, got)
		}
	}
}

// TestPathSentenceHighTokenOnlyNeverClaimsSecrets renders a full High-tier
// path whose reach is a write token alone (control/paths.go's baseTier:
// tokenWrite without impact, no secret in scope): the sentence must name
// the token, never fabricate a secret the path does not hold.
func TestPathSentenceHighTokenOnlyNeverClaimsSecrets(t *testing.T) {
	p := AttackPath{
		ID: "tok1", Tier: TierHigh, BaseTier: TierHigh, State: PathProven,
		EntryKind: EntryMutableDependency,
		Entry:     EntryFact{Subject: "some/action@v1"},
		Jobs:      []string{"release"},
		Reach:     Reach{TokenWrite: []string{"contents"}},
	}
	got := PathSentence(p)
	want := "A new version of `some/action@v1` runs inside `release` without any change in this repository, holding a token with `contents` write: the token can write to the repository or its packages."
	if got != want {
		t.Fatalf("\n got  %q\n want %q", got, want)
	}
}

// TestPathSentenceHighImpactOnlyNeverClaimsSecretsOrToken renders a full
// High-tier path whose reach is an impact alone, no secret and no write
// token (a public deploy job with no declared privilege, the deliberate
// scope decision baseTier's comment names): the sentence must name what
// the job does, never fabricate a secret or a token it does not hold.
func TestPathSentenceHighImpactOnlyNeverClaimsSecretsOrToken(t *testing.T) {
	p := AttackPath{
		ID: "imp1", Tier: TierHigh, BaseTier: TierHigh, State: PathProven,
		EntryKind: EntryForkPR,
		Jobs:      []string{"deploy"},
		Reach:     Reach{Impacts: []ImpactFact{{Kind: "deploys", Evidence: "environment: production"}}},
	}
	got := PathSentence(p)
	want := "A fork pull request can start `deploy`, where it holds no secret but deploys to `production`: what this job deploys or publishes can be altered."
	if got != want {
		t.Fatalf("\n got  %q\n want %q", got, want)
	}
}

// TestPathSentenceImpactClauseWritesRepoSignsOrReleasesAndBareDeploy pins
// impactClause's wording for the three impact kinds no rendered-output
// test exercised yet (explain.go:133): writes_repo, signs_or_releases, and
// deploys with no environment evidence (the fallback branch, not the
// environment-qualified one TestPathSentenceHighImpactOnlyNeverClaims-
// SecretsOrToken already covers).
func TestPathSentenceImpactClauseWritesRepoSignsOrReleasesAndBareDeploy(t *testing.T) {
	cases := []struct {
		kind string
		want string
	}{
		{"writes_repo", "holds no secret but pushes to the repository:"},
		{"signs_or_releases", "holds no secret but signs or publishes releases:"},
		{"deploys", "holds no secret but deploys:"},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			p := AttackPath{
				ID: "imp-" + tc.kind, Tier: TierHigh, BaseTier: TierHigh, State: PathProven,
				EntryKind: EntryForkPR,
				Jobs:      []string{"deploy"},
				Reach:     Reach{Impacts: []ImpactFact{{Kind: tc.kind}}},
			}
			got := PathSentence(p)
			if !strings.Contains(got, tc.want) {
				t.Errorf("%s: PathSentence = %q, want it to contain %q", tc.kind, got, tc.want)
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
	if got := unresolvableSentence(secretsPath); got != "Plumber could not verify which secrets are in scope, so this path is unverified." {
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
	f := finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"})
	sit := defaultTokenSituation(ir.VisibilityPublic)
	j := sit.Jobs["release"]
	j.Impact = tokenImpacts("proven", "writes_repo")
	sit.Jobs["release"] = j
	paths := assemblePaths([]opaengine.Finding{f}, sit)
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
	// No listed secret and no token: the unlisted secrets are the only
	// privilege, so the path is unverified.
	j.Privilege.Secrets, j.Privilege.TokenWrite = nil, nil
	sit.Jobs["release"] = j
	f := finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"})
	paths := assemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	want := "Plumber could not verify which secrets are in scope, so this path is unverified."
	if got := PathSentence(paths[0]); !strings.Contains(got, want) {
		t.Errorf("sentence = %q, want it to contain %q", got, want)
	}
}

// TestUnresolvableSecretsWithNoNamedSecretNeverSaysHoldsNone pins the real
// shape an unresolvable SecretsState takes when Plumber has no secret name
// to go on at all (GitLab: the settings-variable listing could not be
// fetched, so Privilege.Secrets stays empty): the reach clause must not
// say "holds no secret", which would read as a clean pipeline right next
// to the trailing sentence saying the opposite. It says instead that
// Plumber could not list what the job holds, and the existing unverified
// sentence (TestUnresolvableSecretsStateRendersTheSecretsSentence) still
// follows it unchanged.
func TestUnresolvableSecretsWithNoNamedSecretNeverSaysHoldsNone(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	j := sit.Jobs["release"]
	j.Privilege.Secrets = nil
	j.Privilege.SecretsState = "unresolvable"
	j.Privilege.TokenWrite = nil
	sit.Jobs["release"] = j
	f := finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"})
	paths := assemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	got := PathSentence(paths[0])
	if strings.Contains(got, "holds no secret") {
		t.Errorf("must not claim a clean reach when secrets could not be listed: %q", got)
	}
	if !strings.Contains(got, "holding secrets Plumber could not list") {
		t.Errorf("want the unresolvable-secrets reach clause, got %q", got)
	}
	if !strings.Contains(got, "Plumber could not verify which secrets are in scope, so this path is unverified.") {
		t.Errorf("the unverified trailing sentence must still follow, got %q", got)
	}
}

// TestUnresolvableSecretsReachClauseAddsTheTokenPart pins the "(plus the
// token part when present)" half: a surviving write token alongside
// unresolvable, unnamed secrets still names the token, the same join the
// proven-secrets branch uses.
func TestUnresolvableSecretsReachClauseAddsTheTokenPart(t *testing.T) {
	p := AttackPath{Reach: Reach{TokenWrite: []string{"contents"}}}
	p.cause = unresolvableSecrets
	got := reachClause(p)
	want := "holding secrets Plumber could not list and a token with `contents` write"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestUnresolvableEntryFactRendersItsOwnEvidenceSentence(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	f := finding("ISSUE-716", "release", map[string]any{"uses": "some/action@v1"})
	f.Message = "could not fetch the action source to verify it"
	paths := assemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	want := "Plumber could not verify `could not fetch the action source to verify it`, so this path is unverified."
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

// TestPushEntryCapModifierSentence pins the push_entry_cap modifier's own
// trailing sentence (control/paths.go only names the modifier when the cap
// actually lowered the tier, this is its wording): a plain sentence, not a
// gate and not the unresolvable wording, naming why a push path never
// exceeds High.
func TestPushEntryCapModifierSentence(t *testing.T) {
	p := AttackPath{EntryKind: EntryUnprotectedPush, Jobs: []string{"release"}, Entry: EntryFact{Subject: "main"}, Modifiers: []string{"push_entry_cap"}}
	got := PathSentence(p)
	if !strings.HasSuffix(got, "Pushing to this branch needs write access, so this path is capped at High.") {
		t.Errorf("push_entry_cap sentence: %q", got)
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
	if got := ContextualSeverity(f, paths, ""); got != SeverityCritical {
		t.Errorf("severity = %q, want critical", got)
	}
}

func TestPrivilegeFindingOffAnyWalkedJobIsPlainHygiene(t *testing.T) {
	f := opaengine.Finding{Code: string(CodeArtipacked), Job: "other"}
	paths := []AttackPath{{ID: "crit1", Tier: TierCritical, Jobs: []string{"release"}}}
	if got := FindingLine(f, paths); got != "Privilege: on no attack path" {
		t.Errorf("line = %q", got)
	}
	if got := ContextualSeverity(f, paths, ""); got != SeverityLow {
		t.Errorf("severity = %q, want low", got)
	}
}

// PathIDsFor (the pathIds slot the terminal and JSON outputs need next):
// anchored, then gated, then privilege-on-path ids, in path order,
// deduplicated.
func TestPathIDsForOrdersAnchoredThenGatedDeduplicated(t *testing.T) {
	anchor := opaengine.Finding{Code: "ISSUE-701", Job: "release", Data: map[string]any{"uses": "some/action@v1"}}
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

// TestSituationFactsGitHub pins the labelled facts on a GitHub run and
// their text form: visibility, the default branch with its protection,
// the jobs and how many publish or deploy.
func TestSituationFactsGitHub(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{
		"release/publish": {Impact: []ImpactFact{{Kind: "publishes", State: "proven"}}},
		"ci/test":         {},
	}}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub, DefaultBranch: "main",
		Branches: []ir.Branch{{Name: "main", Protected: false}},
		Jobs:     []ir.Job{{Name: "release/publish", WorkflowName: "release"}, {Name: "ci/test", WorkflowName: "ci"}},
	}
	got := SituationFacts(sit, pipeline)
	want := []SituationFact{
		{"Repository", "public"},
		{"Default branch", "main, not protected"},
		{"Workflows", "2 jobs in 2 workflows, 1 publishes or deploys"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("facts = %+v", got)
	}
	if text := SituationText(got); text != "Repository: public. Default branch: main, not protected. Workflows: 2 jobs in 2 workflows, 1 publishes or deploys." {
		t.Errorf("text = %q", text)
	}
}

// TestSituationFactsGitLabUnknowns pins the GitLab wording ("pipeline")
// and every unknown: visibility scored as public, no default branch, a
// default branch the run holds no protection for.
func TestSituationFactsGitLabUnknowns(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityUnknown, Jobs: map[string]JobSituation{"build": {}}}
	got := SituationFacts(sit, &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, Jobs: []ir.Job{{Name: "build"}}})
	want := []SituationFact{
		{"Repository", "unknown visibility, scored as public"},
		{"Default branch", "unknown"},
		{"Pipeline", "1 job in 1 pipeline"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("facts = %+v", got)
	}
	got = SituationFacts(&Situation{Exposure: ir.VisibilityPrivate}, &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, DefaultBranch: "main"})
	if got[0].Value != "private" || got[1].Value != "main, protection unknown" {
		t.Errorf("facts = %+v", got)
	}
}

// TestSituationFactsProtectedBranchAndPluralImpact pins the protected
// default branch and the plural verb when several jobs publish or deploy.
func TestSituationFactsProtectedBranchAndPluralImpact(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{
		"release": {Impact: []ImpactFact{{Kind: "publishes", State: "proven"}}},
		"deploy":  {Impact: []ImpactFact{{Kind: "deploys", State: "proven"}}},
	}}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab, DefaultBranch: "main",
		Branches: []ir.Branch{{Name: "dev"}, {Name: "main", Protected: true}},
		Jobs:     []ir.Job{{Name: "release"}, {Name: "deploy"}},
	}
	got := SituationText(SituationFacts(sit, pipeline))
	if want := "Repository: public. Default branch: main, protected. Pipeline: 2 jobs in 1 pipeline, 2 publish or deploy."; got != want {
		t.Errorf("\n got  %q\n want %q", got, want)
	}
}

// TestBestFixPicksTheLargestGain: the trial that gains the most
// FinalPoints wins, over every distinct non-dismissed finding (anchor or
// gate) by hash.
func TestBestFixPicksTheLargestGain(t *testing.T) {
	anchor := opaengine.Finding{Code: "ISSUE-703", Job: "release", Data: map[string]any{"uses": "some/action@v1"}}
	gate := opaengine.Finding{Code: "ISSUE-501", Data: map[string]any{"branchName": "main"}}
	sit := releaseSituation(ir.VisibilityPublic)
	in := ScoreInputV4{Findings: []opaengine.Finding{anchor, gate}}
	in.Paths = assemblePaths(in.Findings, sit)
	current := ComputePlumberScoreV4(in) // critical path 30 + other finding 20: raw 50, final 30, E
	if current.Score != "E" {
		t.Fatalf("fixture drifted: current = %+v", current)
	}
	fix := ComputeBestFix(in, sit, current)
	if fix == nil || fix.Code != "ISSUE-703" {
		t.Fatalf("want the critical path's anchor, got %+v", fix)
	}
	// Without the anchor: only the gate remains, an other finding at 20,
	// 80 B: gain 50.
	if math.Abs(fix.PointsGained-50) > 0.01 || fix.NewLetter != "B" || !strings.Contains(fix.Sentence, "recovers 50 points and moves the score to B") {
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
// input order. Two other findings of one severity gain the exact same
// FinalPoints when either one is removed (two unregistered codes, both
// priced at the Medium price), so only the tie-break decides.
func TestBestFixIsDeterministicUnderShuffledFindings(t *testing.T) {
	findings := []opaengine.Finding{{Code: "ISSUE-998"}, {Code: "ISSUE-999"}}
	sit := &Situation{Jobs: map[string]JobSituation{}}
	want := ComputeBestFix(ScoreInputV4{Findings: findings}, sit, ComputePlumberScoreV4(ScoreInputV4{Findings: findings}))
	if want == nil || want.Code != "ISSUE-998" {
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
		{Code: "ISSUE-207", Job: "a", Subject: "x"},
		{Code: "ISSUE-207", Job: "b", Subject: "x"},
		{Code: "ISSUE-207", Job: "c", Subject: "x"},
	}
	sit.Jobs["a"] = JobSituation{}
	sit.Jobs["b"] = JobSituation{}
	sit.Jobs["c"] = JobSituation{}
	in := ScoreInputV4{Findings: findings}
	in.Paths = assemblePaths(in.Findings, sit)
	current := ComputePlumberScoreV4(in)
	want := ComputeBestFix(in, sit, current)
	if want == nil {
		t.Fatal("want a winner among the three equal-gain candidates")
	}
	for i := 0; i < 20; i++ {
		shuffled := append([]opaengine.Finding(nil), findings...)
		rand.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		shuffledIn := ScoreInputV4{Findings: shuffled}
		shuffledIn.Paths = assemblePaths(shuffledIn.Findings, sit)
		got := ComputeBestFix(shuffledIn, sit, ComputePlumberScoreV4(shuffledIn))
		if got == nil || got.AnchorHash != want.AnchorHash {
			t.Fatalf("shuffle %d: got %+v, want %+v (same-code tie must settle on one anchor hash regardless of order)", i, got, want)
		}
	}
}

// ComputeBestFix must stay fast even over a thousand findings, every one
// of them a candidate: no re-hashing every finding per candidate trial.
func TestComputeBestFixScoresAThousandFindingsFast(t *testing.T) {
	sit := releaseSituation(ir.VisibilityPublic)
	var findings []opaengine.Finding
	for i := 0; i < 990; i++ {
		findings = append(findings, opaengine.Finding{Code: "ISSUE-999", Job: "release", Message: fmt.Sprintf("occurrence %d", i)})
	}
	// Only 2 anchors, few enough that removing one still measurably gains
	// points: two Critical paths (60) and the capped other findings (30)
	// leave 10, one path less leaves 40, forced to 30. More Critical paths
	// push the raw points past zero, where every trial gains exactly zero
	// and the fixture would prove nothing. Each action is its own entry,
	// so each anchors its own path (findings sharing one entry subject
	// would anchor one path together).
	for i := 0; i < 2; i++ {
		uses := fmt.Sprintf("some/action-%d@v1", i)
		findings = append(findings, opaengine.Finding{Code: "ISSUE-701", Job: "release", Data: map[string]any{"uses": uses}})
	}
	in := ScoreInputV4{Findings: findings}
	in.Paths = assemblePaths(in.Findings, sit)
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
	in.Paths = assemblePaths(in.Findings, sit)
	current := ComputePlumberScoreV4(in)
	fix := ComputeBestFix(in, sit, current)
	if fix == nil || fix.Subject != "org/repo/template.yml" {
		t.Fatalf("want includePath as the subject, got %+v", fix)
	}
	if strings.Contains(fix.Sentence, "(``)") {
		t.Errorf("sentence = %q, empty backticks", fix.Sentence)
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

// twoActionReleaseResult is the release job of releaseSituation pulling two
// mutable actions, with a gate (ISSUE-305) and a privilege finding
// (ISSUE-307) on the same job: two Critical mutable_dependency paths that
// share one loss group, each amplified by the gate and carrying the
// privilege finding.
func twoActionReleaseResult() *AnalysisResult {
	sit := releaseSituation(ir.VisibilityPublic)
	return &AnalysisResult{
		Situation: sit,
		Findings: []opaengine.Finding{
			finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"}),
			finding("ISSUE-701", "release", map[string]any{"uses": "other/action@v2"}),
			finding("ISSUE-305", "release", nil),
			finding("ISSUE-307", "release", nil),
		},
	}
}

// The JSON report's plumberScore.paths[] carries the fields spec section 4
// lists: the path's sentence, its findingIds (the anchor's hash, then the
// gates', then the consumed privilege findings') and its loss, the path's
// tier price.
func TestScoreJSONPathsCarrySentenceFindingIDsAndLoss(t *testing.T) {
	result := twoActionReleaseResult()
	score := ScoreV4WithExplanations(result)
	if len(score.Paths) != 2 {
		t.Fatalf("fixture drifted: want two paths, got %+v", score.Paths)
	}
	hashOf := func(code string) string {
		for _, f := range result.Findings {
			if f.Code == code {
				h, _ := findingAnchorHash(f)
				return h
			}
		}
		t.Fatalf("no %s finding", code)
		return ""
	}
	raw, err := json.Marshal(score)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Paths []struct {
			ID         string   `json:"id"`
			AnchorHash string   `json:"anchorHash"`
			Sentence   string   `json:"sentence"`
			FindingIDs []string `json:"findingIds"`
			Loss       *float64 `json:"loss"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	wantLoss := 6.0 // two Medium paths at 6 each: the dependency cap holds an action that is only not pinned at Medium
	for i, p := range got.Paths {
		if p.Sentence == "" || p.Sentence != PathSentence(score.Paths[i]) {
			t.Errorf("path %s sentence = %q, want PathSentence's %q", p.ID, p.Sentence, PathSentence(score.Paths[i]))
		}
		want := []string{p.AnchorHash, hashOf("ISSUE-305"), hashOf("ISSUE-307")}
		if !reflect.DeepEqual(p.FindingIDs, want) {
			t.Errorf("path %s findingIds = %v, want anchor, gate, privilege %v", p.ID, p.FindingIDs, want)
		}
		if p.Loss == nil || *p.Loss != wantLoss {
			t.Errorf("path %s loss = %v, want %v", p.ID, p.Loss, wantLoss)
		}
	}
}

// A path that never went through the scoring step still marshals
// findingIds as an array, never null.
func TestAttackPathFindingIDsMarshalAsAnArray(t *testing.T) {
	raw, err := json.Marshal(AttackPath{ID: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"findingIds":[]`) {
		t.Errorf("want findingIds as an empty array: %s", raw)
	}
}

// bestFix.pointsGained in the JSON report is rounded to one decimal, the
// same rounding the best-fix sentence and the push apply.
func TestBestFixJSONRoundsPointsGainedToOneDecimal(t *testing.T) {
	raw, err := json.Marshal(BestFix{PointsGained: 49.03421571533792})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"pointsGained":49`) || strings.Contains(string(raw), "49.03") {
		t.Errorf("want pointsGained rounded to 49.0: %s", raw)
	}
	raw, _ = json.Marshal(BestFix{PointsGained: 2.25001})
	if !strings.Contains(string(raw), `"pointsGained":2.3`) {
		t.Errorf("want pointsGained rounded to 2.3: %s", raw)
	}
}

// Spec section 9: no sentence contains a SettingsVariables value. The
// reason is structural: ir.SettingsVariable carries a variable's name and
// flags and no value field at all (the collector never projects one, per
// the #370 variable-sensitivity tiers), so nothing downstream can echo a
// value it was never given. The field check pins that structure; the run
// below drives a GitLab pipeline whose settings variables TOKEN_A and
// TOKEN_B reach a path, and checks that every sentence, the situation
// paragraph and the best fix name the variables and never carry the
// decoy, the value those variables hold at the provider, which is nowhere
// in the IR.
func TestNoSentenceContainsASettingsVariableValue(t *testing.T) {
	typ := reflect.TypeOf(ir.SettingsVariable{})
	var fields []string
	for i := 0; i < typ.NumField(); i++ {
		fields = append(fields, typ.Field(i).Name)
	}
	if want := []string{"Name", "Type", "Environment", "Protected", "Masked"}; !reflect.DeepEqual(fields, want) {
		t.Fatalf("ir.SettingsVariable fields = %v, want %v: a new field must never carry a value", fields, want)
	}

	old := ScoreProfile
	ScoreProfile = "v4"
	defer func() { ScoreProfile = old }()
	const decoy = "decoy-value-7f3a91"
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab, ProjectPath: "grp/app", DefaultBranch: "main",
		Jobs: []ir.Job{{
			Name: "release", OriginFile: ".gitlab-ci.yml",
			Image:   &ir.Image{Name: "node", Tag: "latest"},
			Scripts: []string{"npm publish --token $TOKEN_A"},
		}},
		SettingsVariables: []ir.SettingsVariable{
			{Name: "TOKEN_A", Type: "env_var", Environment: "*", Protected: true, Masked: true},
			{Name: "TOKEN_B", Type: "env_var", Environment: "*", Masked: true},
		},
		SettingsVariablesKnown: true,
	}
	raw, err := json.Marshal(pipeline)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), decoy) {
		t.Fatal("fixture drifted: the decoy must be nowhere in the IR")
	}
	pc := defaultGitHubConfig(t)
	scoped, score, ok := ReEvaluateForConfig(&AnalysisResult{CiValid: true, Pipeline: pipeline}, &configuration.Configuration{PlumberConfig: pc}, "gitlab", pc)
	if !ok || score.ProfileID != PlumberScoreProfileIDV4 || len(score.Paths) == 0 {
		t.Fatalf("fixture drifted: want a v4 score with paths, got ok=%v %+v", ok, score)
	}
	texts := []string{score.Situation}
	if score.BestFix != nil {
		texts = append(texts, score.BestFix.Sentence)
	}
	for _, p := range score.Paths {
		texts = append(texts, PathSentence(p), p.Sentence)
	}
	for _, f := range scoped.Findings {
		if e, ok := f.Data["explanation"].(string); ok {
			texts = append(texts, e)
		}
	}
	named := false
	for _, txt := range texts {
		if strings.Contains(txt, decoy) {
			t.Errorf("a sentence carries a settings variable value: %q", txt)
		}
		if strings.Contains(txt, "`TOKEN_A`") || strings.Contains(txt, "`TOKEN_B`") {
			named = true
		}
	}
	if !named {
		t.Errorf("want the settings variables named in at least one sentence, got %q", texts)
	}
}

// Every anchor of a merged path reads as its entry: the role line, the
// path ids, the contextual severity and the path's findingIds name each
// one, and the best fix sees that removing one anchor leaves the path.
func TestEveryAnchorOfAMergedPathReadsAsItsEntry(t *testing.T) {
	findings := pinnedActionFindings()
	result := &AnalysisResult{Findings: findings, Situation: pinnedActionSituation()}
	s := ScoreV4WithExplanations(result)
	if len(result.Paths) != 1 {
		t.Fatalf("want one merged path, got %+v", result.Paths)
	}
	p := result.Paths[0]
	for _, f := range findings {
		if got := FindingLine(f, result.Paths); got != "Entry of path "+p.ID {
			t.Errorf("%s: FindingLine = %q, want the entry of %s", f.Code, got, p.ID)
		}
		if got := RoleOnPath(f, p); got != "Entry of path "+p.ID {
			t.Errorf("%s: RoleOnPath = %q", f.Code, got)
		}
		if got := PathIDsFor(f, result.Paths); !reflect.DeepEqual(got, []string{p.ID}) {
			t.Errorf("%s: PathIDsFor = %v", f.Code, got)
		}
		if got := ContextualSeverity(f, result.Paths, ""); got != SeverityHigh {
			t.Errorf("%s: ContextualSeverity = %s, want high", f.Code, got)
		}
	}
	if !reflect.DeepEqual(s.Paths[0].FindingIDs, p.AnchorHashes) {
		t.Errorf("findingIds = %v, want every anchor %v", s.Paths[0].FindingIDs, p.AnchorHashes)
	}
	// Fixing one of two anchors would leave the path; the fix is the path
	// itself, both anchors together.
	if s.BestFix == nil || s.BestFix.PathID != p.ID || s.BestFix.PointsGained != 15 || s.BestFix.NewPoints != 100 {
		t.Errorf("the best fix is the merged path, both anchors together: %+v", s.BestFix)
	}
}

// imagePathSituation is one job holding a secret, no impact: an image
// entry there is a High path the dependency cap holds at Medium.
func imagePathSituation() *Situation {
	j := JobSituation{}
	j.Privilege.Secrets = []string{"API_KEY"}
	j.Privilege.SecretsState = "proven"
	return &Situation{Exposure: ir.VisibilityPrivate, Provider: "gitlab", Jobs: map[string]JobSituation{"check": j}}
}

// alpineImageFindings are the two findings a mutable image on the job
// "check" gives, one entry between them.
func alpineImageFindings() []opaengine.Finding {
	return []opaengine.Finding{
		{Code: "ISSUE-102", Job: "check", File: ".gitlab-ci.yml", Line: 1, Data: map[string]any{"link": "docker.io/alpine:latest", "tag": "latest"}},
		{Code: "ISSUE-103", Job: "check", File: ".gitlab-ci.yml", Line: 1, Data: map[string]any{"link": "docker.io/alpine:latest", "imageRepo": "docker.io/alpine", "tag": "latest"}},
	}
}

// Fixing a path dismisses every finding anchoring it: neither image
// finding alone removes the path, the two together do.
func TestBestFixDismissesEveryAnchorOfAPath(t *testing.T) {
	findings, sit := alpineImageFindings(), imagePathSituation()
	paths := assemblePaths(findings, sit)
	in := ScoreInputV4{Findings: findings, Paths: paths}
	current := ComputePlumberScoreV4(in)
	fix := ComputeBestFix(in, sit, current)
	if len(paths) != 1 || fix == nil {
		t.Fatalf("paths %+v, fix %+v", paths, fix)
	}
	if fix.PathID != paths[0].ID || fix.PointsGained != 6 || fix.NewPoints != 100 || fix.NewLetter != "A" {
		t.Errorf("fix = %+v", fix)
	}
	if fix.Subject != "docker.io/alpine:latest" || fix.Code != "ISSUE-102" {
		t.Errorf("fix names %s %q", fix.Code, fix.Subject)
	}
}

// While the other findings stay over their cap, fixing one recovers
// nothing: the path is the best fix.
func TestBestFixSkipsOtherFindingsWhileTheirCapHolds(t *testing.T) {
	sit := imagePathSituation()
	findings := append(alpineImageFindings(), otherFindings("ISSUE-210", 4)...)
	paths := assemblePaths(findings, sit)
	in := ScoreInputV4{Findings: findings, Paths: paths}
	fix := ComputeBestFix(in, sit, ComputePlumberScoreV4(in))
	if fix == nil || fix.PathID == "" || fix.PointsGained != 6 || fix.NewPoints != 70 {
		t.Errorf("fix = %+v", fix)
	}
}

// With no path, the best fix is the other finding that recovers the most.
func TestBestFixCanBeAnOtherFinding(t *testing.T) {
	sit := imagePathSituation()
	findings := joinFindings(otherFindings("ISSUE-210", 1), otherFindings("ISSUE-401", 1))
	in := ScoreInputV4{Findings: findings}
	fix := ComputeBestFix(in, sit, ComputePlumberScoreV4(in))
	if fix == nil || fix.PathID != "" || fix.Code != "ISSUE-210" || fix.PointsGained != 10 || fix.NewPoints != 95 {
		t.Errorf("fix = %+v", fix)
	}
}

// Other findings of one code all gain the same when fixed, so the best
// fix is the one with the lowest hash, whatever the finding order.
func TestBestFixAmongOtherFindingsOfOneCodeIsTheLowestHash(t *testing.T) {
	findings := otherFindings("ISSUE-401", 3)
	lowest := ""
	for _, f := range findings {
		if h, _ := findingAnchorHash(f); lowest == "" || h < lowest {
			lowest = h
		}
	}
	sit := &Situation{Jobs: map[string]JobSituation{}}
	for i := 0; i < 10; i++ {
		shuffled := append([]opaengine.Finding(nil), findings...)
		rand.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		in := ScoreInputV4{Findings: shuffled}
		fix := ComputeBestFix(in, sit, ComputePlumberScoreV4(in))
		if fix == nil || fix.AnchorHash != lowest || fix.PointsGained != 5 || fix.NewPoints != 90 {
			t.Fatalf("shuffle %d: fix = %+v, want the lowest hash %s gaining 5", i, fix, lowest)
		}
	}
}

// gitlabImagePath is the path a mutable image gives on a job holding seven
// secrets: High, held at Medium by the dependency cap, priced at 6.
func gitlabImagePath() (AttackPath, []opaengine.Finding) {
	findings := alpineImageFindings()
	j := JobSituation{}
	j.Privilege.Secrets = []string{"GITLAB_TOKEN", "LW_ACCESS_TOKEN", "S1", "S2", "S3", "S4", "S5"}
	j.Privilege.SecretsState = "proven"
	sit := &Situation{Exposure: ir.VisibilityPrivate, Provider: "gitlab", Jobs: map[string]JobSituation{"check": j}}
	paths := assemblePaths(findings, sit)
	paths[0].Loss = 6
	return paths[0], findings
}

func TestPathBlockReadsAPathOut(t *testing.T) {
	p, findings := gitlabImagePath()
	got := NewPathBlock(p, findings)
	want := PathBlock{
		Tier: TierMedium, Loss: 6,
		Entry:        "docker.io/alpine:latest (mutable image tag)",
		EntrySubject: "docker.io/alpine:latest",
		Branches:     []PathBlockBranch{{Job: "job `check`", Reach: "7 secrets"}},
		RunsIn:       "job check",
		ReachesShort: "7 secrets",
		So:           "if this image is compromised, an attacker can read 7 secrets of the repository",
		Cap:          "Capped at Medium: it needs a dependency compromise first",
		Fix:          "pin the image by digest",
		Findings: []PathBlockFinding{
			{Code: "ISSUE-102", Title: LookupCode("ISSUE-102").Title, Location: ".gitlab-ci.yml:1"},
			{Code: "ISSUE-103", Title: LookupCode("ISSUE-103").Title, Location: ".gitlab-ci.yml:1"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("block = %+v\nwant  %+v", got, want)
	}
}

func TestPathsWorstFirst(t *testing.T) {
	in := []AttackPath{{ID: "b", Tier: TierMedium}, {ID: "a", Tier: TierMedium}, {ID: "c", Tier: TierCritical}}
	var ids []string
	for _, p := range PathsWorstFirst(in) {
		ids = append(ids, p.ID)
	}
	if !reflect.DeepEqual(ids, []string{"c", "a", "b"}) || in[0].ID != "b" {
		t.Errorf("order %v, input changed: %v", ids, in[0].ID)
	}
}

// An unverified path says in one short line what could not be checked:
// about its entry, or about what it reaches.
func TestPathBlockSaysWhatCouldNotBeVerified(t *testing.T) {
	entry := AttackPath{State: PathUnverified, EntryKind: EntryMutableDependency, AnchorCode: "ISSUE-716", Jobs: []string{"j"},
		Entry: EntryFact{Subject: "o/a@v1", State: "unresolvable"}}
	if b := NewPathBlock(entry, nil); !b.Unverified || b.EntryUnverified != "Plumber could not check what it runs" || b.ReachUnverified != "" {
		t.Errorf("entry: %+v", b)
	}
	token := AttackPath{State: PathUnverified, EntryKind: EntryMutableDependency, AnchorCode: "ISSUE-701", Jobs: []string{"j"},
		Entry: EntryFact{Subject: "o/a@v1"}, Reach: Reach{TokenWrite: []string{"contents"}}, cause: unresolvableDefaultToken}
	if b := NewPathBlock(token, nil); b.ReachUnverified != "Plumber could not check that the token can write (no permissions block)" || b.EntryUnverified != "" {
		t.Errorf("token: %+v", b)
	}
	secrets := AttackPath{State: PathUnverified, EntryKind: EntryMutableDependency, AnchorCode: "ISSUE-701", Jobs: []string{"j"},
		Entry: EntryFact{Subject: "o/a@v1"}, cause: unresolvableSecrets}
	b := NewPathBlock(secrets, nil)
	if b.ReachesShort != "unlisted secrets" || b.ReachUnverified != "Plumber could not list the secrets" || b.EntryUnverified != "" {
		t.Errorf("secrets: %+v", b)
	}
}

// The privilege findings a path rides are listed under it after its
// anchors, folded to one line per code, so every finding on a path shows
// somewhere in the report.
func TestPathBlockListsThePrivilegeFindingsItRides(t *testing.T) {
	findings := alpineImageFindings()
	j := JobSituation{}
	j.Privilege.Secrets = []string{"A_TOKEN", "B_TOKEN"}
	j.Privilege.SecretsState = "proven"
	for _, name := range []string{"A_TOKEN", "B_TOKEN"} {
		findings = append(findings, opaengine.Finding{Code: "ISSUE-201", Job: "check", Data: map[string]any{"variableName": name}})
	}
	result := &AnalysisResult{
		Findings:  findings,
		Situation: &Situation{Exposure: ir.VisibilityPrivate, Provider: "gitlab", Jobs: map[string]JobSituation{"check": j}},
		Pipeline:  &ir.NormalizedPipeline{Provider: ir.ProviderGitLab},
	}
	s := ScoreV4WithExplanations(result)
	if len(s.Paths) != 1 {
		t.Fatalf("paths = %+v", s.Paths)
	}
	got := NewPathBlock(s.Paths[0], findings).Findings
	if len(got) != 3 || got[0].Code != "ISSUE-102" || got[1].Code != "ISSUE-103" {
		t.Fatalf("findings = %+v", got)
	}
	if got[2] != (PathBlockFinding{Code: "ISSUE-201", Title: LookupCode("ISSUE-201").Title, Count: 2}) {
		t.Errorf("privilege line = %+v", got[2])
	}
}

// A path of several entry jobs names them all.
func TestRunsInNamesTheEntryJobs(t *testing.T) {
	if got := NewPathBlock(AttackPath{Jobs: []string{"build", "deploy"}, Entry: EntryFact{Subject: "x"}}, nil).RunsIn; got != "job build" {
		t.Errorf("runs in: %q, want the entry job alone", got)
	}
	two := AttackPath{Jobs: []string{"build", "lint", "deploy"}, Branches: []PathBranch{{Job: "build", Jobs: []string{"build", "deploy"}}, {Job: "lint", Jobs: []string{"lint"}}}, Entry: EntryFact{Subject: "x"}}
	if got := NewPathBlock(two, nil).RunsIn; got != "jobs build, lint" {
		t.Errorf("runs in: %q, want the entry jobs", got)
	}
}

func TestScoreSummaries(t *testing.T) {
	p, _ := gitlabImagePath()
	score := &PlumberScoreResult{
		ProfileID: PlumberScoreProfileIDV4, Score: "C", RawPoints: 55, FinalPoints: 55, Paths: []AttackPath{p},
		PathLosses:    []PathLoss{{Tier: TierHigh, Count: 1, Weight: 15, Cap: 69, CappedLoss: 15, PathIDs: []string{p.ID}}},
		OtherFindings: &OtherFindingsLoss{Count: 12, Counts: SeverityCounts{Critical: 1, High: 2, Medium: 9}, UncappedLoss: 85, Cap: 30, CappedLoss: 30, CapApplied: true},
		BestFix:       &BestFix{Code: "ISSUE-102", Subject: "docker.io/alpine:latest", PathID: p.ID, PointsGained: 15, NewPoints: 70, NewLetter: "C"},
	}
	if paths, other := BucketLosses(score); paths != 15 || other != 30 {
		t.Errorf("BucketLosses = %v, %v", paths, other)
	}
	if got := OtherFindingsSummary(score); got != "1 critical, 2 high, 9 medium" {
		t.Errorf("OtherFindingsSummary = %q", got)
	}
	if got := BestFixSummary(score); got != "pin the image by digest (image docker.io/alpine:latest), +15 pts, 70 / 100 (C)" {
		t.Errorf("BestFixSummary = %q", got)
	}
	if got := ScoreAdjustment(score); got != "" {
		t.Errorf("ScoreAdjustment = %q, want none", got)
	}
	if got := ScoreAdjustment(&PlumberScoreResult{Score: "E", RawPoints: 70, FinalPoints: 30, CriticalMalusApplied: true, CriticalMalusMax: 30}); got != "Capped at 30: a Critical attack path remains." {
		t.Errorf("force = %q", got)
	}
	if got := ScoreAdjustment(&PlumberScoreResult{Score: "C", RawPoints: 51, FinalPoints: 51}); got != "" {
		t.Errorf("the caps hold the score, no line raises it: %q", got)
	}
	if got := ScoreAdjustment(&PlumberScoreResult{Score: "E", RawPoints: 25, FinalPoints: 25, CriticalMalusApplied: true, CriticalMalusMax: 30}); got != "" {
		t.Errorf("a cap that changed nothing = %q", got)
	}
	none := &PlumberScoreResult{BestFix: &BestFix{Code: "ISSUE-210", Subject: "ci/x", PointsGained: 10, NewPoints: 95, NewLetter: "A"}}
	if got := OtherFindingsSummary(none); got != "none" {
		t.Errorf("no other finding = %q", got)
	}
	if got := BestFixSummary(none); got != "gate on a check the actor cannot spoof (ci/x), +10 pts, 95 / 100 (A)" {
		t.Errorf("finding fix = %q", got)
	}
	if got := BestFixSummary(&PlumberScoreResult{}); got != "nothing to fix" {
		t.Errorf("no fix = %q", got)
	}
}

// A best fix that is a finding, not a path, says what to do when the code
// has a known fix: a gate that amplifies a path, or an entry no path
// starts from. A branch finding is about whichever branch it names.
func TestBestFixSummaryOfAFindingSaysWhatToDo(t *testing.T) {
	for _, tc := range []struct {
		fix  BestFix
		want string
	}{
		{BestFix{Code: CodeBranchUnprotected, Subject: "main", PointsGained: 55, NewPoints: 85, NewLetter: "B"}, "protect the branch (main), +55 pts, 85 / 100 (B)"},
		{BestFix{Code: CodeBranchNonCompliant, Subject: "dev", PointsGained: 20, NewPoints: 75, NewLetter: "B"}, "fix the branch protection settings (dev), +20 pts, 75 / 100 (B)"},
		{BestFix{Code: CodeImageForbiddenTag, Subject: "node:latest", PointsGained: 5, NewPoints: 95, NewLetter: "A"}, "pin the image by digest (node:latest), +5 pts, 95 / 100 (A)"},
	} {
		if got := BestFixSummary(&PlumberScoreResult{BestFix: &tc.fix}); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.fix.Code, got, tc.want)
		}
	}
}

// A subtraction that goes below zero says the score stops there, so the
// figures on the final screen still add up by hand.
func TestScoreAdjustmentBelowZero(t *testing.T) {
	s := &PlumberScoreResult{Score: "E", RawPointsUnclamped: -87, RawPoints: 0, FinalPoints: 0, CriticalMalusApplied: true, CriticalMalusMax: 30}
	if got := ScoreAdjustment(s); got != "The score does not go below 0." {
		t.Errorf("below zero = %q", got)
	}
}

// A cap that kept less than the prices add up to is said under the
// subtraction: one line per nested cap that held, the widest first, then
// one for the individual findings; nothing when no cap held.
func TestCapNotes(t *testing.T) {
	const (
		highNote   = "high, medium and low items count for 69 at most"
		mediumNote = "medium and low items count for 49 at most"
		lowNote    = "low items count for 29 at most"
		otherNote  = "individual findings count for 30 at most"
	)
	for _, tc := range []struct {
		name     string
		paths    []AttackPath
		findings []opaengine.Finding
		want     []string
	}{
		{"5 high paths", pathsAt(TierHigh, 5), nil, []string{highNote}},
		{"4 high paths, under the cap", pathsAt(TierHigh, 4), nil, nil},
		{"10 medium paths", pathsAt(TierMedium, 10), nil, []string{mediumNote}},
		{"2 high and 12 low paths", joinPaths(pathsAt(TierHigh, 2), pathsAt(TierLow, 12)), nil, []string{lowNote}},
		{"every cap", joinPaths(pathsAt(TierHigh, 5), pathsAt(TierLow, 12)), otherFindings("ISSUE-210", 4), []string{highNote, lowNote, otherNote}},
		{"high findings over their 30", nil, otherFindings("ISSUE-210", 4), []string{otherNote}},
		{"critical items are never capped", pathsAt(TierCritical, 3), otherFindings("ISSUE-403", 1), nil},
	} {
		s := ComputePlumberScoreV4(ScoreInputV4{Paths: tc.paths, Findings: tc.findings})
		if got := CapNotes(&s); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: CapNotes = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A path's cost is the price of its tier, never a share of the nested
// cap: ten Medium paths cost 6 each while their tier takes 49 off.
func TestPathLossIsTheTierPrice(t *testing.T) {
	var paths []AttackPath
	var ids []string
	for _, id := range strings.Split("abcdefghij", "") {
		paths = append(paths, AttackPath{ID: id, Tier: TierMedium})
		ids = append(ids, id)
	}
	fillPathReportFields(paths, []PathLoss{{Tier: TierMedium, Count: 10, Weight: 6, Cap: 49, CappedLoss: 49, PathIDs: ids}}, nil)
	for _, p := range paths {
		if p.Loss != 6 {
			t.Errorf("path %s loss = %v, want the Medium price 6", p.ID, p.Loss)
		}
	}
}

// A path that holds nothing reads the same way in its block and on its
// summary line: code execution without secrets.
func TestPathThatHoldsNothingReadsCodeExecution(t *testing.T) {
	p := AttackPath{ID: "x", Tier: TierMedium, EntryKind: EntryMutableDependency, AnchorCode: "ISSUE-701", Entry: EntryFact{Subject: "o/a@v1"}, Jobs: []string{"build"}}
	b := NewPathBlock(p, nil)
	if b.ReachesShort != "code execution without secrets" || len(b.Branches) != 1 || b.Branches[0].Reach != "code execution on the runner, no secret and no write token" {
		t.Errorf("block = %+v", b)
	}
	if got := PathSummary(p); got != "o/a@v1 (mutable external action) in job build, reaches code execution without secrets" {
		t.Errorf("PathSummary = %q", got)
	}
}

// A commit SHA in an action reference shows as its first 12 characters in
// the block and on the summary line, and in a best fix naming it.
func TestPathBlockShortensACommitSHA(t *testing.T) {
	sha := "2d756ea4c53f7f6b397767d8723b3a10a9f35bf2"
	p := AttackPath{ID: "x", Tier: TierMedium, EntryKind: EntryMutableDependency, AnchorCode: "ISSUE-703", Entry: EntryFact{Subject: "tj-actions/changed-files@" + sha}, Jobs: []string{"build"}}
	if got := NewPathBlock(p, nil).Entry; got != "tj-actions/changed-files@2d756ea4c53f (external action with a known vulnerability)" {
		t.Errorf("Entry = %q", got)
	}
	want := PathRow{Entry: "tj-actions/changed-files@2d756ea4c53f (external action with a known vulnerability)", Jobs: "build", Reaches: "code execution without secrets"}
	if got := PathRowOf(p); got != want {
		t.Errorf("PathRowOf = %+v", got)
	}
	fix := &PlumberScoreResult{BestFix: &BestFix{Code: "ISSUE-713", Subject: "tj-actions/changed-files@" + sha, PointsGained: 5, NewPoints: 95, NewLetter: "A"}}
	if got := BestFixSummary(fix); strings.Contains(got, sha) || !strings.Contains(got, "@2d756ea4c53f)") {
		t.Errorf("BestFixSummary = %q", got)
	}
}

// When the points a best fix recovers differ from the price of what it
// fixes, the reason is read off the two score computations.
func TestBestFixReason(t *testing.T) {
	high := AttackPath{ID: "h", Tier: TierHigh}
	medium := func(id string) AttackPath { return AttackPath{ID: id, Tier: TierMedium} }
	mediums := []AttackPath{medium("a"), medium("b"), medium("c"), medium("d")}
	cases := []struct {
		name       string
		cur, trial PlumberScoreResult
		fix        BestFix
		want       string
	}{
		{
			name: "a finding that then stands alone",
			cur: PlumberScoreResult{Paths: append([]AttackPath{high}, mediums...), FinalPoints: 65, RawPointsUnclamped: 65, RawPoints: 65, PathLosses: []PathLoss{
				{Tier: TierHigh, Count: 1, Weight: 15, Cap: 69, CappedLoss: 15}, {Tier: TierMedium, Count: 4, Weight: 6, Cap: 49, CappedLoss: 20}}},
			trial: PlumberScoreResult{Paths: mediums, FinalPoints: 78, RawPointsUnclamped: 78, RawPoints: 78,
				PathLosses:    []PathLoss{{Tier: TierMedium, Count: 4, Weight: 6, Cap: 49, CappedLoss: 20}},
				OtherFindings: &OtherFindingsLoss{Count: 1, CappedLoss: 2}},
			fix:  BestFix{PathID: "h", PointsGained: 13},
			want: "+13 pts: the path's 15, less 2 for a finding that then stands alone",
		},
		{
			name: "the path drops a tier and the cap is lifted",
			cur: PlumberScoreResult{Paths: []AttackPath{{ID: "c", Tier: TierCritical}}, FinalPoints: 30, RawPointsUnclamped: 70, RawPoints: 70, CriticalMalusApplied: true, CriticalMalusMax: 30,
				PathLosses: []PathLoss{{Tier: TierCritical, Count: 1, Weight: 30, CappedLoss: 30}}},
			trial: PlumberScoreResult{Paths: []AttackPath{{ID: "c", Tier: TierHigh}}, FinalPoints: 85, RawPointsUnclamped: 85, RawPoints: 85,
				PathLosses: []PathLoss{{Tier: TierHigh, Count: 1, Weight: 15, Cap: 69, CappedLoss: 15}}},
			fix:  BestFix{Code: "ISSUE-501", PointsGained: 55},
			want: "+55 pts: the path drops to High and the cap is lifted",
		},
		{
			name: "a nested cap held",
			cur: PlumberScoreResult{Paths: mediums, FinalPoints: 51, RawPointsUnclamped: 51, RawPoints: 51,
				PathLosses: []PathLoss{{Tier: TierMedium, Count: 9, Weight: 6, Cap: 49, CappedLoss: 49}}},
			trial: PlumberScoreResult{Paths: mediums[1:], FinalPoints: 52, RawPointsUnclamped: 52, RawPoints: 52,
				PathLosses: []PathLoss{{Tier: TierMedium, Count: 8, Weight: 6, Cap: 49, CappedLoss: 48}}},
			fix:  BestFix{PathID: "a", PointsGained: 1},
			want: "+1 pts: the path's 6, of which 1 counts, medium and low items counting for 49 at most",
		},
		{
			name: "a finding under the widest cap",
			cur: PlumberScoreResult{Paths: []AttackPath{high}, FinalPoints: 31, RawPointsUnclamped: 31, RawPoints: 31,
				PathLosses:    []PathLoss{{Tier: TierHigh, Count: 4, Weight: 15, Cap: 69, CappedLoss: 60 * 69 / 70.0}},
				OtherFindings: &OtherFindingsLoss{Count: 1, UncappedLoss: 10, Cap: 30, CappedLoss: 10 * 69 / 70.0},
				CodeLosses:    []CodeLoss{{Code: "ISSUE-210", Severity: SeverityHigh, Count: 1, Weight: 10, UncappedLoss: 10, CappedLoss: 10 * 69 / 70.0}}},
			trial: PlumberScoreResult{Paths: []AttackPath{high}, FinalPoints: 40, RawPointsUnclamped: 40, RawPoints: 40,
				PathLosses: []PathLoss{{Tier: TierHigh, Count: 4, Weight: 15, Cap: 69, CappedLoss: 60}}},
			fix:  BestFix{Code: "ISSUE-210", PointsGained: 9},
			want: "+9 pts: the finding's 10, of which 9 counts, high, medium and low items counting for 69 at most",
		},
		{
			name: "below zero, then held by the force",
			cur: PlumberScoreResult{Paths: []AttackPath{{ID: "c1", Tier: TierCritical}, {ID: "c2", Tier: TierCritical}}, FinalPoints: 0, RawPointsUnclamped: -20, RawPoints: 0, CriticalMalusApplied: true, CriticalMalusMax: 30,
				PathLosses: []PathLoss{{Tier: TierCritical, Count: 4, Weight: 30, CappedLoss: 120}}},
			trial: PlumberScoreResult{FinalPoints: 30, RawPointsUnclamped: 40, RawPoints: 40, CriticalMalusApplied: true, CriticalMalusMax: 30,
				PathLosses: []PathLoss{{Tier: TierCritical, Count: 2, Weight: 30, CappedLoss: 60}}},
			fix:  BestFix{PathID: "c1", PointsGained: 30},
			want: "+30 pts: 60 off the attack paths, but the score was 20 below 0 and stays capped at 30",
		},
		{
			name: "the price, nothing to explain",
			cur: PlumberScoreResult{Paths: []AttackPath{high}, FinalPoints: 85, RawPointsUnclamped: 85, RawPoints: 85,
				PathLosses: []PathLoss{{Tier: TierHigh, Count: 1, Weight: 15, Cap: 69, CappedLoss: 15}}},
			trial: PlumberScoreResult{FinalPoints: 100, RawPointsUnclamped: 100, RawPoints: 100},
			fix:   BestFix{PathID: "h", PointsGained: 15},
		},
		{
			name:  "an other finding at its price",
			cur:   PlumberScoreResult{FinalPoints: 95, RawPointsUnclamped: 95, RawPoints: 95, OtherFindings: &OtherFindingsLoss{Count: 1, CappedLoss: 5}},
			trial: PlumberScoreResult{FinalPoints: 100, RawPointsUnclamped: 100, RawPoints: 100},
			fix:   BestFix{Code: "ISSUE-401", PointsGained: 5},
		},
		{
			name: "a change no rule explains",
			cur: PlumberScoreResult{Paths: []AttackPath{high}, FinalPoints: 85, RawPointsUnclamped: 85, RawPoints: 85,
				PathLosses: []PathLoss{{Tier: TierHigh, Count: 1, Weight: 15, Cap: 69, CappedLoss: 15}}},
			trial: PlumberScoreResult{FinalPoints: 92, RawPointsUnclamped: 100, RawPoints: 100},
			fix:   BestFix{PathID: "h", PointsGained: 7},
		},
	}
	for _, c := range cases {
		if got := bestFixReason(&c.cur, &c.trial, &c.fix); got != c.want {
			t.Errorf("%s: reason = %q, want %q", c.name, got, c.want)
		}
	}
}

// highPathsSituation is n jobs each holding a secret, each running an
// action of its own that fetches remote code: n High paths, 15 each.
func highPathsSituation(n int) (*Situation, []opaengine.Finding) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{}}
	var findings []opaengine.Finding
	for i := 1; i <= n; i++ {
		job := fmt.Sprintf("job%d", i)
		j := JobSituation{}
		j.Privilege.Secrets = []string{"TOKEN"}
		j.Privilege.SecretsState = "proven"
		sit.Jobs[job] = j
		findings = append(findings, finding("ISSUE-714", job, map[string]any{"uses": fmt.Sprintf("o/a%d@v1", i)}))
	}
	return sit, findings
}

// When no single fix moves the final points (six High paths, 90 of prices
// counted for 69, and still 75 with one fewer), the best fix is still named: the candidate that
// recovers the most of the prices before the caps, ties broken by the
// report order (path 1 first), with zero points gained and a plain sentence saying why the
// score does not move yet. Never "nothing to fix" while a path exists.
func TestBestFixWhenNoFixMovesTheScoreNamesTheLargestPrice(t *testing.T) {
	sit, findings := highPathsSituation(6)
	in := ScoreInputV4{Findings: findings, Paths: assemblePaths(findings, sit)}
	current := ComputePlumberScoreV4(in)
	if current.FinalPoints != 31 || len(in.Paths) != 6 {
		t.Fatalf("fixture drifted: %+v", current)
	}
	fix := ComputeBestFix(in, sit, current)
	if fix == nil {
		t.Fatal("no best fix while five paths exist")
	}
	if first := PathsWorstFirst(in.Paths)[0]; fix.PathID != first.ID || fix.PointsGained != 0 || fix.NewPoints != 31 || fix.NewLetter != current.Score {
		t.Errorf("fix = %+v, want path 1 with nothing gained", fix)
	}
	current.BestFix = fix
	current.Paths = in.Paths
	if got := BestFixSummary(&current); !strings.HasSuffix(got, "). The score stays at 31 while high, medium and low items count for 69 at most.") || strings.Contains(got, "nothing to fix") {
		t.Errorf("BestFixSummary = %q", got)
	}
	if !strings.Contains(fix.Sentence, "does not move the score yet") {
		t.Errorf("sentence = %q", fix.Sentence)
	}
	raw, _ := json.Marshal(fix)
	if !strings.Contains(string(raw), `"pointsGained":0`) || !strings.Contains(string(raw), `"newPoints":31`) {
		t.Errorf("JSON = %s", raw)
	}
}

// The same holds for other findings over their cap, and for the nested
// cap holding the score: the line says which.
func TestBestFixWhenNoFixMovesTheScoreSaysWhy(t *testing.T) {
	others := otherFindings("ISSUE-210", 4) // 40 of prices kept at 30
	in := ScoreInputV4{Findings: others}
	current := ComputePlumberScoreV4(in)
	fix := ComputeBestFix(in, &Situation{Jobs: map[string]JobSituation{}}, current)
	if fix == nil || fix.PathID != "" || fix.Code != "ISSUE-210" || fix.PointsGained != 0 {
		t.Fatalf("fix = %+v", fix)
	}
	current.BestFix = fix
	if got := BestFixSummary(&current); !strings.HasSuffix(got, ". The score stays at 70 until fewer individual findings remain.") {
		t.Errorf("BestFixSummary = %q", got)
	}

	// Five High paths and the other findings over their 30: 75 and 30 of
	// High prices count for 69, 31 with no floor. One path fewer, or one
	// finding fewer, leaves the nested cap holding.
	sit, findings := highPathsSituation(5)
	findings = append(findings, others...)
	in = ScoreInputV4{Findings: findings, Paths: assemblePaths(findings, sit)}
	current = ComputePlumberScoreV4(in)
	if current.FinalPoints != 31 || current.FloorApplied {
		t.Fatalf("fixture drifted: %+v", current)
	}
	fix = ComputeBestFix(in, sit, current)
	current.BestFix, current.Paths = fix, in.Paths
	if fix == nil || fix.PathID == "" || !strings.HasSuffix(BestFixSummary(&current), ". The score stays at 31 while high, medium and low items count for 69 at most.") {
		t.Errorf("fix = %+v, summary %q", fix, BestFixSummary(&current))
	}

	// Only Critical items take the score below 0 now: the nested cap keeps
	// every other item at 69. Five Critical paths cost 150; one fewer is
	// still 120, so what holds the score is the rest taking it below 0.
	sit = &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{}}
	findings = nil
	for i := 1; i <= 5; i++ {
		job := fmt.Sprintf("release%d", i)
		sit.Jobs[job] = releaseSituation(ir.VisibilityPublic).Jobs["release"]
		findings = append(findings, finding("ISSUE-703", job, map[string]any{"uses": fmt.Sprintf("o/c%d@v1", i)}))
	}
	in = ScoreInputV4{Findings: findings, Paths: assemblePaths(findings, sit)}
	current = ComputePlumberScoreV4(in)
	if current.FinalPoints != 0 || current.RawPointsUnclamped != -50 || current.CriticalPaths != 5 {
		t.Fatalf("fixture drifted: %+v", current)
	}
	fix = ComputeBestFix(in, sit, current)
	current.BestFix, current.Paths = fix, in.Paths
	if fix == nil || fix.PathID == "" || !strings.HasSuffix(BestFixSummary(&current), ". The score stays at 0 while the rest takes it below 0.") {
		t.Errorf("fix = %+v, summary %q", fix, BestFixSummary(&current))
	}
}

// A table row names the entry by what an attacker controls, without the
// word the block opens with where the reference says it on its own, and
// says what the path reaches in a few words, joined with semicolons.
func TestPathRowReadsTheEntryAndTheReachCompactly(t *testing.T) {
	row := func(code, subject string, r Reach, cause unresolvableCause) PathRow {
		kind, _ := EntryKindForCode(ErrorCode(code))
		if code == string(CodeBranchUnprotected) {
			kind = EntryUnprotectedPush
		}
		r.Executes = true
		return PathRowOf(AttackPath{ID: "x", Tier: TierHigh, EntryKind: kind, AnchorCode: ErrorCode(code),
			Entry: EntryFact{Subject: subject}, Jobs: []string{"build"}, Reach: r, cause: cause})
	}
	token := func(kinds ...string) []ImpactFact {
		var out []ImpactFact
		for _, k := range kinds {
			out = append(out, ImpactFact{Kind: k, State: "proven", Source: impactFromToken})
		}
		return out
	}
	writeAll := []string{"actions", "contents", "deployments", "id-token", "packages", "pull-requests", "security-events"}
	for _, c := range []struct {
		name, code, subject string
		reach               Reach
		cause               unresolvableCause
		entry, reaches      string
	}{
		{"action", "ISSUE-701", "tj-actions/changed-files@v45.0.0", Reach{AllSecrets: true, TokenWrite: writeAll, Impacts: token("deploys", "publishes", "writes_repo")}, "",
			"tj-actions/changed-files@v45.0.0 (mutable external action)", "every secret; token: push, publish, deploy"},
		{"image", "ISSUE-102", "node:latest", Reach{Secrets: []string{"A", "B", "C"}, TokenWrite: []string{"contents", "packages"}}, "",
			"node:latest (mutable image tag)", "3 secrets; token: write"},
		{"script", "ISSUE-411", "https://get.example.com/install.sh", Reach{Secrets: []string{"NPM_TOKEN"}, TokenWrite: []string{"id-token"},
			Impacts: []ImpactFact{{Kind: "publishes", State: "proven"}, {Kind: "deploys", State: "proven"}, {Kind: "signs_or_releases", State: "proven"}}}, "",
			"https://get.example.com/install.sh (script downloaded and run at build time)", "1 secret; OIDC token; publishing; deployment; releases"},
		{"expression", "ISSUE-207", "github.event.pull_request.title", Reach{}, "", "github.event.pull_request.title (user-controlled input injected in a script)", "code execution without secrets"},
		{"push", string(CodeBranchUnprotected), "main", Reach{TokenWrite: []string{"contents"}, Impacts: token("writes_repo")}, "", "main (branch anyone with write access can push to, not protected)", "token: push"},
		{"cache", "ISSUE-705", "npm-key", Reach{Secrets: []string{"NPM_TOKEN"}, Impacts: []ImpactFact{{Kind: "publishes", State: "proven"}}}, "", "npm-key (cache an untrusted run can write)", "1 secret; publishing"},
		{"checkout", "ISSUE-804", "github.event.pull_request.head.sha", Reach{TokenWrite: []string{"pull-requests"}}, "",
			"github.event.pull_request.head.sha (pull request code checked out in a privileged workflow)", "token: write"},
		{"workflow", "ISSUE-701", "acme/shared/.github/workflows/deploy.yml@main", Reach{AllSecrets: true}, "", "acme/shared/.github/workflows/deploy.yml@main (mutable external reusable workflow)", "every secret"},
		{"unlisted", "ISSUE-102", "alpine:latest", Reach{}, unresolvableSecrets, "alpine:latest (mutable image tag)", "unlisted secrets"},
	} {
		got := row(c.code, c.subject, c.reach, c.cause)
		if got.Entry != c.entry || got.Reaches != c.reaches {
			t.Errorf("%s: row = %+v, want entry %q, reaches %q", c.name, got, c.entry, c.reaches)
		}
	}
}

// The table's entry is the block's Entry line for every code that anchors
// a path: the subject, a commit SHA shown as 12 characters, then what it
// is.
func TestTheTableEntryIsTheEntryLine(t *testing.T) {
	sha := "1c9b1f1aaa22bbbbccccddddeeeeffff00001111"
	for _, c := range []struct {
		code     ErrorCode
		kind     EntryKind
		subject  string
		evidence string
	}{
		{CodeBranchUnprotected, EntryUnprotectedPush, "main", ""},
		{CodeBranchNonCompliant, EntryUnprotectedPush, "main", ""},
		{CodeTemplateInjection, EntryUntrustedExpression, "github.event.pull_request.title", ""},
		{CodeGitHubEnvInjection, EntryUntrustedExpression, "github.event.pull_request.title", "writes a user-controlled template expression into $GITHUB_ENV or $GITHUB_PATH; an attacker can hijack later steps"},
		{CodeGitHubEnvInjection, EntryUntrustedExpression, "github.head_ref", "binds an untrusted value to $DIR and writes it to $GITHUB_PATH; an attacker controls a directory placed on PATH"},
		{CodeUnsafeGithubContextDump, EntryUntrustedExpression, "toJson(github)", ""},
		{CodeUnsafeVariableExpansion, EntryUntrustedExpression, "CI_MERGE_REQUEST_TITLE", ""},
		{CodeImageForbiddenTag, EntryMutableDependency, "node:latest", ""},
		{CodeImageNotPinnedByDigest, EntryMutableDependency, "node:20", ""},
		{CodeKnownVulnerableAction, EntryMutableDependency, "tj-actions/changed-files@v45.0.0", ""},
		{CodeImpostorCommit, EntryMutableDependency, "owner/repo@" + sha, ""},
		{CodeActionObfuscatedRemoteExec, EntryMutableDependency, "owner/repo@v2", ""},
		{CodeActionMutableRemoteExec, EntryMutableDependency, "owner/repo@main", ""},
		{CodeActionRemoteExecUnverified, EntryMutableDependency, "owner/repo@v3", ""},
		{CodeActionUnpinned, EntryMutableDependency, "owner/repo@v4", ""},
		{CodeActionUnpinned, EntryMutableDependency, "owner/repo/.github/workflows/x.yml@main", ""},
		{CodeRefConfusion, EntryMutableDependency, "owner/repo@v1", ""},
		{CodeUnverifiedScriptExecution, EntryMutableDependency, "https://example.com/install.sh", ""},
		{CodePullRequestTargetWithHeadCheckout, EntryPRTarget, "github.event.pull_request.head.sha", ""},
		{CodeDangerousTriggers, EntryPRTarget, "", ""},
		{CodeCachePoisoning, EntryPoisonedCache, "npm-key", ""},
		{CodeCachePoisoningUnresolved, EntryPoisonedCache, "npm-key", ""},
		{CodeIncludeForbiddenVersion, EntryMutableDependency, "group/templates@main", ""},
		{CodeImageNotPinnedByDigest, EntryMutableDependency, "${{ matrix.image }}", ""},
		{CodeImageForbiddenTag, EntryMutableDependency, "$BUILD_IMAGE", ""},
		{CodeActionUnpinned, EntryMutableDependency, "owner/repo@${{ inputs.ref }}", ""},
	} {
		state := FactState("")
		if c.kind == EntryMutableDependency && computedAtRunTime(c.code, c.subject) {
			state = "unresolvable"
		}
		p := AttackPath{ID: "x", Tier: TierHigh, EntryKind: c.kind, AnchorCode: c.code, Jobs: []string{"build"},
			Entry: EntryFact{Subject: c.subject, Evidence: c.evidence, State: state}}
		got := PathRowOf(p).Entry
		if want := NewPathBlock(p, nil).Entry; got != want {
			t.Errorf("%s %q: table entry %q, want the Entry line %q", c.code, c.subject, got, want)
		}
		if !strings.Contains(got, ShortenCommitSHA(c.subject)) {
			t.Errorf("%s: subject %q is not in the entry %q", c.code, c.subject, got)
		}
	}
}

// A path several entry codes anchor reads as the most serious one: a
// known vulnerability, then an impostor commit, then a hidden remote
// fetch, then a fetch at run time, then a reference not pinned.
func TestTheTableEntryFollowsTheMostSeriousAnchor(t *testing.T) {
	for _, c := range []struct {
		codes []ErrorCode
		want  string
	}{
		{[]ErrorCode{CodeActionUnpinned, CodeActionObfuscatedRemoteExec, CodeKnownVulnerableAction}, "o/a@v1 (external action with a known vulnerability)"},
		{[]ErrorCode{CodeActionUnpinned, CodeActionObfuscatedRemoteExec, CodeImpostorCommit}, "o/a@v1 (external action pinned to a commit that is not in its repository)"},
		{[]ErrorCode{CodeActionUnpinned, CodeActionObfuscatedRemoteExec}, "o/a@v1 (external action that downloads obfuscated code at run time)"},
		{[]ErrorCode{CodeActionMutableRemoteExec, CodeActionUnpinned}, "o/a@v1 (external action that downloads code at run time from a mutable source)"},
	} {
		g := &pathGroup{anchor: pathAnchor{kind: EntryMutableDependency, fact: EntryFact{Subject: "o/a@v1"}}, codes: map[ErrorCode]bool{},
			hashes: map[string]bool{"h": true}, jobs: []string{"build"}, reach: Reach{Executes: true}}
		for _, code := range c.codes {
			g.codes[code] = true
		}
		p := g.path("", nil, &Situation{Jobs: map[string]JobSituation{}}, g.hashes)
		if got := PathRowOf(p).Entry; got != c.want {
			t.Errorf("%v: entry %q, want %q", c.codes, got, c.want)
		}
	}
}
