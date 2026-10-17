package control

import (
	"slices"
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// A job whose secrets could not be listed at all (no named secret, no
// allSecrets, SecretsState unknown) still claims it: the gap would
// otherwise read as fully proven everywhere a claim is read (the JSON,
// the push body, the explain section, the terminal Note).
func TestClaimsNameSecretsThatCouldNotBeListedAtAll(t *testing.T) {
	f := finding("ISSUE-714", "build", map[string]any{"uses": "some/action@v1"})
	p := onePath(t, assemblePaths([]opaengine.Finding{f}, unlistedSecretsJob("", nil, nil)))

	var secret *Claim
	for i := range p.Claims {
		if p.Claims[i].Kind == "secret" {
			secret = &p.Claims[i]
		}
	}
	if secret == nil || secret.State != ClaimUnknown || secret.Subject != "secrets Plumber could not list" || secret.Source != "unlisted" {
		t.Errorf("secret claim = %+v, want {secret, secrets Plumber could not list, unknown, unlisted}", secret)
	}
	if note := claimsNote(p.Claims); note != "Plumber could not read: secrets Plumber could not list" {
		t.Errorf("note = %q", note)
	}

	// A job with SecretsState proven and no named secrets has nothing
	// unlisted to claim: no secret claim at all.
	provenJob := JobSituation{}
	provenJob.Privilege.SecretsState = "proven"
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"build": provenJob}}
	p2 := onePath(t, assemblePaths([]opaengine.Finding{f}, sit))
	for _, c := range p2.Claims {
		if c.Kind == "secret" {
			t.Errorf("a job with no secret and a proven SecretsState claims %+v, want none", c)
		}
	}
}

// A fed job (not the entry job) whose secrets could not be listed claims
// the gap under its own name, "in job <fed>", so the note says which job
// of the walk Plumber could not read, never the entry job's bare gap.
func TestClaimsQualifyUnlistedSecretsOfAFedJob(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{}}
	build := JobSituation{
		Push:  []EntryFact{{Kind: EntryUnprotectedPush, State: "proven", Evidence: "push: branches: [main]", Subject: "main"}},
		Feeds: []string{"deploy"},
	}
	build.Privilege.SecretsState = "proven"
	sit.Jobs["build"] = build
	deploy := JobSituation{}
	deploy.Privilege.TokenWrite = []string{"contents"}
	deploy.Privilege.TokenWriteSource = "declared"
	deploy.Privilege.TokenWriteState = "proven"
	deploy.Privilege.SecretsState = FactUnknown
	sit.Jobs["deploy"] = deploy

	f := finding("ISSUE-703", "build", map[string]any{"uses": "some/action@v1"})
	p := onePath(t, assemblePaths([]opaengine.Finding{f}, sit))
	var secrets []Claim
	for _, c := range p.Claims {
		if c.Kind == "secret" {
			secrets = append(secrets, c)
		}
	}
	want := Claim{Kind: "secret", Subject: "secrets Plumber could not list in job deploy", State: ClaimUnknown, Source: "unlisted"}
	if len(secrets) != 1 || secrets[0] != want {
		t.Fatalf("secret claims = %+v, want exactly %+v (jobs %v)", secrets, want, p.Jobs)
	}
	if note := claimsNote(p.Claims); note != "Plumber could not read: secrets Plumber could not list in job deploy" {
		t.Errorf("note = %q", note)
	}
}

// A fed job whose own listing is unknown still claims the gap even when
// every secret it names was already claimed off an earlier part: the
// entry job names FOO (proven), the fed job's listing is unknown and
// names only FOO too, so deduplication on the secret name leaves the
// fed job with no claim of its own at all unless the gap claim fires.
// Losing it would read the fed job as fully proven, though Plumber never
// read its listing.
func TestClaimsKeepTheGapWhenTheFedJobNamesOnlyAnAlreadyClaimedSecret(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{}}
	build := JobSituation{
		Push:  []EntryFact{{Kind: EntryUnprotectedPush, State: "proven", Evidence: "push: branches: [main]", Subject: "main"}},
		Feeds: []string{"deploy"},
	}
	build.Privilege.SecretsState = "proven"
	build.Privilege.Secrets = []string{"FOO"}
	sit.Jobs["build"] = build
	deploy := JobSituation{}
	deploy.Privilege.SecretsState = FactUnknown
	deploy.Privilege.Secrets = []string{"FOO"}
	sit.Jobs["deploy"] = deploy

	f := finding("ISSUE-703", "build", map[string]any{"uses": "some/action@v1"})
	p := onePath(t, assemblePaths([]opaengine.Finding{f}, sit))
	var secrets []Claim
	for _, c := range p.Claims {
		if c.Kind == "secret" {
			secrets = append(secrets, c)
		}
	}
	gap := Claim{Kind: "secret", Subject: "secrets Plumber could not list in job deploy", State: ClaimUnknown, Source: "unlisted"}
	if !slices.Contains(secrets, gap) {
		t.Fatalf("secret claims = %+v, want the gap claim %+v among them (jobs %v)", secrets, gap, p.Jobs)
	}
}

// An environment a walked job runs behind is one claim: unknown when its
// approval rule could not be read (then named in the note), proven when
// it was, either way (then absent from the note).
func TestClaimsNameTheEnvironmentAndItsState(t *testing.T) {
	f := entryFinding("ISSUE-804", "eval/pr-evaluation", "github.event.pull_request.head.sha")
	for protected, state := range map[string]ClaimState{"unknown": ClaimUnknown, "true": ClaimProven, "false": ClaimProven} {
		p := onePath(t, assemblePaths([]opaengine.Finding{f}, environmentJob(protected)))
		var envs []Claim
		for _, c := range p.Claims {
			if c.Kind == "environment" {
				envs = append(envs, c)
			}
		}
		want := Claim{Kind: "environment", Subject: "eval-gate", State: state}
		if len(envs) != 1 || envs[0] != want {
			t.Errorf("%s: environment claims = %+v, want exactly %+v", protected, envs, want)
		}
		note := claimsNote(p.Claims)
		if state == ClaimUnknown && note != "Plumber could not read: eval-gate" {
			t.Errorf("%s: note = %q, want it to name eval-gate alone", protected, note)
		}
		if state == ClaimProven && strings.Contains(note, "eval-gate") {
			t.Errorf("%s: note = %q, a proven environment must not be named", protected, note)
		}
	}
}

// The Note names assumed claims first, then the unknown ones: an assumed
// token reads "Plumber assumed the token can write: <scopes>", ahead of
// what Plumber could not read.
func TestClaimsNoteNamesAssumedClaimsBeforeUnknownOnes(t *testing.T) {
	claims := []Claim{
		{Kind: "secret", Subject: "secrets Plumber could not list", State: ClaimUnknown, Source: "unlisted"},
		{Kind: "token", Subject: "contents, packages", State: ClaimAssumed, Source: "unknown"},
		{Kind: "impact", Subject: "deploys", State: ClaimProven},
	}
	want := "Plumber assumed the token can write: contents, packages. Plumber could not read: secrets Plumber could not list"
	if got := claimsNote(claims); got != want {
		t.Errorf("note = %q, want %q", got, want)
	}
	if got := claimsNote(claims[1:]); got != "Plumber assumed the token can write: contents, packages" {
		t.Errorf("assumed-only note = %q", got)
	}
}

// Past four subjects of one state the Note names the first four and counts
// the rest, deduplicating a subject two claims share; four or fewer are
// all named.
func TestClaimsNoteNamesFourSubjectsThenCountsTheRest(t *testing.T) {
	var claims []Claim
	for _, s := range []string{"A", "B", "C", "D", "E", "F", "E"} {
		claims = append(claims, Claim{Kind: "secret", Subject: s, State: ClaimUnknown})
	}
	if got, want := claimsNote(claims), "Plumber could not read: A, B, C, D and 2 more"; got != want {
		t.Errorf("note = %q, want %q", got, want)
	}
	if got, want := claimsNote(claims[:4]), "Plumber could not read: A, B, C, D"; got != want {
		t.Errorf("four subjects note = %q, want %q", got, want)
	}
}

// An impact the facts could not confirm (a publish decided by an
// expression) claims unknown, never proven: the impact claim carries the
// impact's own state.
func TestImpactClaimCarriesTheImpactsOwnState(t *testing.T) {
	f := finding("ISSUE-714", "build", map[string]any{"uses": "some/action@v1"})
	job := JobSituation{Impact: []ImpactFact{
		{Kind: "publishes", State: FactUnknown, Evidence: "docker/build-push-action push: ${{ inputs.push }}"},
		{Kind: "deploys", State: "proven", Evidence: "deploy step"},
	}}
	job.Privilege.SecretsState = "proven"
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"build": job}}
	p := onePath(t, assemblePaths([]opaengine.Finding{f}, sit))
	got := map[string]ClaimState{}
	for _, c := range p.Claims {
		if c.Kind == "impact" {
			got[c.Subject] = c.State
		}
	}
	if got["publishes"] != ClaimUnknown || got["deploys"] != ClaimProven {
		t.Errorf("impact claims = %v, want publishes unknown, deploys proven", got)
	}
}

// tokenReachSituation is two jobs, "build" (the push entry, feeding
// "deploy") and "deploy", both declaring the "contents" write scope with
// their own token source and state, for tokenClaim's source-selection
// tests.
func tokenReachSituation(buildSource string, buildState FactState, deploySource string, deployState FactState) *Situation {
	build := JobSituation{
		Push:  []EntryFact{{Kind: EntryUnprotectedPush, State: "proven", Evidence: "push: branches: [main]", Subject: "main"}},
		Feeds: []string{"deploy"},
	}
	build.Privilege.TokenWrite = []string{"contents"}
	build.Privilege.TokenWriteSource = buildSource
	build.Privilege.TokenWriteState = buildState
	deploy := JobSituation{}
	deploy.Privilege.TokenWrite = []string{"contents"}
	deploy.Privilege.TokenWriteSource = deploySource
	deploy.Privilege.TokenWriteState = deployState
	return &Situation{Exposure: ir.VisibilityPublic, Jobs: map[string]JobSituation{"build": build, "deploy": deploy}}
}

// The token claim's source is the source of the job that contributed the
// worst state, the first such job in walk order; when the shared state is
// itself the gap (unknown), every distinct source behind it is named,
// joined by a comma, in walk order.
func TestTokenClaimSourceFollowsTheWorstState(t *testing.T) {
	f := finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"})

	// build declared/proven, deploy unknown/unknown: the gap is deploy's
	// alone, a default token whose scope was never read: assumed.
	sit := tokenReachSituation("declared", "proven", "unknown", FactUnknown)
	p := onePath(t, assemblePaths([]opaengine.Finding{f}, sit))
	var token *Claim
	for i := range p.Claims {
		if p.Claims[i].Kind == "token" {
			token = &p.Claims[i]
		}
	}
	if token == nil || token.State != ClaimAssumed || token.Source != "unknown" {
		t.Errorf("token claim = %+v, want {assumed, unknown}", token)
	}

	// build log/proven, deploy effect/proven: both proven, build is first
	// in walk order.
	sit = tokenReachSituation("log", "proven", "effect", "proven")
	p = onePath(t, assemblePaths([]opaengine.Finding{f}, sit))
	token = nil
	for i := range p.Claims {
		if p.Claims[i].Kind == "token" {
			token = &p.Claims[i]
		}
	}
	if token == nil || token.State != ClaimProven || token.Source != "log" {
		t.Errorf("token claim = %+v, want {proven, log}", token)
	}
}

// A run-time fetch with no guard and no checksum or signature is a
// download claim naming the fetch host as unguarded: the character of
// the download is itself a settled fact, so the claim is proven.
func TestDownloadClaimNamesAnUnguardedRunTimeFetch(t *testing.T) {
	f := finding("ISSUE-714", "release", map[string]any{
		"uses":     "dtolnay/rust-toolchain@deadbeef",
		"fetchUrl": "https://raw.githubusercontent.com/anchore/grype/main/install.sh",
	})
	p := onePath(t, AssemblePaths([]opaengine.Finding{f}, releaseSituation(ir.VisibilityPublic), "me/repo"))
	want := Claim{Kind: "download", Subject: p.Entry.Subject, State: ClaimProven, Source: "unguarded"}
	if !slices.Contains(p.Claims, want) {
		t.Errorf("claims = %+v, want %+v among them", p.Claims, want)
	}
}

// A preinstalled-tool guard still names the download claim's source even
// when the runner family that guard runs on could not be resolved: the
// guard is simply not one of this anchor's reasons to be suppressed, and
// the unknown runner's own gap is the entry claim's, not this one's.
func TestDownloadClaimNamesAGuardOnAnUnknownRunnerFamily(t *testing.T) {
	f := finding("ISSUE-714", "build", map[string]any{
		"uses":          "dtolnay/rust-toolchain@deadbeef",
		"downloadGuard": "rustup",
		"runsOn":        []any{"self-hosted"},
	})
	p := onePath(t, assemblePaths([]opaengine.Finding{f}, oneJobSituation("build")))
	want := Claim{Kind: "download", Subject: p.Entry.Subject, State: ClaimProven, Source: "guarded"}
	if !slices.Contains(p.Claims, want) {
		t.Errorf("claims = %+v, want %+v among them", p.Claims, want)
	}
}

// edgeFeedSituation is tokenReachSituation's build feeding deploy with
// the FeedsVia kinds given, for the edge claim's subject and join tests.
func edgeFeedSituation(kinds []string) *Situation {
	sit := tokenReachSituation("log", "proven", "log", "proven")
	build := sit.Jobs["build"]
	build.FeedsVia = map[string][]string{"deploy": kinds}
	sit.Jobs["build"] = build
	return sit
}

// A walked edge claims its exact subject, from to (kind), proven: a
// FeedsVia kind is a static fact the collector already settled.
func TestEdgeClaimNamesTheWalkedEdge(t *testing.T) {
	f := finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"})
	p := onePath(t, assemblePaths([]opaengine.Finding{f}, edgeFeedSituation([]string{FeedArtifactExecuted})))
	want := Claim{Kind: "edge", Subject: "build -> deploy (artifact_executed)", State: ClaimProven}
	if !slices.Contains(p.Claims, want) {
		t.Errorf("claims = %+v, want %+v among them", p.Claims, want)
	}
}

// Two FeedsVia kinds recorded on the same edge join into one claim
// subject with "+".
func TestEdgeClaimJoinsTwoFeedsViaKindsOnTheSameEdge(t *testing.T) {
	f := finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"})
	p := onePath(t, assemblePaths([]opaengine.Finding{f}, edgeFeedSituation([]string{FeedArtifactExecuted, FeedOutputExecuted})))
	want := Claim{Kind: "edge", Subject: "build -> deploy (artifact_executed+output_executed)", State: ClaimProven}
	if !slices.Contains(p.Claims, want) {
		t.Errorf("claims = %+v, want %+v among them", p.Claims, want)
	}
}

// A FeedCache edge whose fed job's cache writer state is unknown claims
// unknown, the one exception edgeClaim carries for an otherwise static
// fact. cacheWriterReaches never settles that state today (it always
// reports "proven", control/cachewriters.go), so there is no finding
// shape that reaches this branch through AssemblePaths; edgeClaim is
// called directly over a hand-built path, the way other tests in this
// package already reach into an AttackPath's own unexported fields for a
// single assertion.
func TestEdgeClaimReadsAnUnknownCacheWriterStateAsUnknown(t *testing.T) {
	p := AttackPath{}
	p.cacheWriterStates = map[string]string{"deploy": "unknown"}
	got := edgeClaim(&p, "build", "deploy", []string{FeedCache})
	want := Claim{Kind: "edge", Subject: "build -> deploy (cache)", State: ClaimUnknown}
	if got != want {
		t.Errorf("edge claim = %+v, want %+v", got, want)
	}
}
