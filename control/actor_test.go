package control

import (
	"context"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// gatedJob is a pull_request_target job checking out the pull request
// head while holding a secret (a Critical for an outsider), its gate set
// to g.
func gatedJob(g *ir.Gate) *Situation {
	j := JobSituation{PrivilegedTriggers: []string{"pull_request_target"}, Gate: g}
	j.Privilege.Secrets = []string{"CLOUD_TOKEN"}
	j.Privilege.SecretsState = "proven"
	return &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"ci/cloud": j}}
}

func headCheckout() opaengine.Finding {
	return checkoutOf("github.event.pull_request.head.sha")
}

// checkoutOf is the ISSUE-804 finding of a checkout of ref in ci/cloud,
// carrying the ref the way the rule does.
func checkoutOf(ref string) opaengine.Finding {
	f := entryFinding("ISSUE-804", "ci/cloud", ref)
	f.Data = map[string]any{"ref": "${{ " + ref + " }}"}
	return f
}

func onePath(t *testing.T, paths []AttackPath) AttackPath {
	t.Helper()
	if len(paths) != 1 {
		t.Fatalf("want one path, got %+v", paths)
	}
	return paths[0]
}

// The clickhouse-go shape: a label gate and a checkout of the head commit
// the maintainer labelled. A maintainer approves the very commit that
// runs, so the path holds at Medium, and the block names the gate.
func TestLabelGateOnThePinnedHeadIsMedium(t *testing.T) {
	sit := gatedJob(&ir.Gate{Class: ir.GateMaintainerApproved, Reason: "label tests:run-cloud", PinnedSha: true})
	p := onePath(t, assemblePaths([]opaengine.Finding{headCheckout()}, sit))
	if p.Tier != TierMedium || p.BaseTier != TierCritical || p.State != PathProven || !slices.Contains(p.Modifiers, "pinned_head_cap") {
		t.Errorf("path = %+v", p)
	}
	if p.Entry.Actor != "maintainer_approved" || p.Entry.Gate != "label tests:run-cloud" || !p.Entry.PinnedSha {
		t.Errorf("entry = %+v", p.Entry)
	}
	b := NewPathBlock(p, nil)
	if !strings.HasPrefix(b.So, "as anyone whose pull request a maintainer labels `tests:run-cloud`, an attacker") {
		t.Errorf("So = %q", b.So)
	}
	if !strings.HasSuffix(b.Entry, ", gated by the label `tests:run-cloud`)") {
		t.Errorf("Entry = %q", b.Entry)
	}
	if b.Fix != checkoutFix+", and keep the gate" {
		t.Errorf("Fix = %q", b.Fix)
	}
	if b.Cap == "" {
		t.Errorf("no cap line")
	}
}

// The Frogbot shape: an environment whose rules require an approval. The
// path holds at Medium when the approved head commit is what runs, at
// High when the checkout follows a moving ref.
func TestEnvironmentApprovalCapsThePath(t *testing.T) {
	for _, tc := range []struct {
		ref      string
		tier     PathTier
		modifier string
	}{{"github.event.pull_request.head.sha", TierMedium, "pinned_head_cap"}, {"github.event.pull_request.head.ref", TierHigh, "maintainer_cap"}} {
		sit := gatedJob(&ir.Gate{Class: ir.GateMaintainerApproved, Reason: "environment frogbot requires reviewers", PinnedSha: true})
		p := onePath(t, assemblePaths([]opaengine.Finding{checkoutOf(tc.ref)}, sit))
		if p.Tier != tc.tier || !slices.Contains(p.Modifiers, tc.modifier) {
			t.Errorf("%s: path = %+v", tc.ref, p)
		}
		b := NewPathBlock(p, nil)
		if !strings.HasPrefix(b.So, "as anyone whose deployment a maintainer approves in `frogbot`") {
			t.Errorf("So = %q", b.So)
		}
		if !strings.Contains(b.Entry, ", approved in environment `frogbot`)") {
			t.Errorf("Entry = %q", b.Entry)
		}
	}
}

// The same environment without a rule protects nothing: the outsider's
// path stands, Critical, in today's words.
func TestEnvironmentWithoutARuleStaysCritical(t *testing.T) {
	sit := gatedJob(&ir.Gate{Class: ir.GateOutsider, PinnedSha: true})
	p := onePath(t, assemblePaths([]opaengine.Finding{headCheckout()}, sit))
	if p.Tier != TierCritical || len(p.Modifiers) != 0 || p.Entry.Actor != "outsider" {
		t.Errorf("path = %+v", p)
	}
	b := NewPathBlock(p, nil)
	if !strings.HasPrefix(b.So, "as anyone who opens a pull request, an attacker") || b.Fix != checkoutFix {
		t.Errorf("So = %q, Fix = %q", b.So, b.Fix)
	}
	if b.Entry != "github.event.pull_request.head.sha ("+pullRequestCheckout+")" {
		t.Errorf("Entry = %q", b.Entry)
	}
}

// The dependabot shape (the pull request's author is a bot, whose pull
// requests come from the repository's own branches) and a same-repository
// gate: no outsider gets in, so no path; the finding stays an individual
// one, at Low, with the note.
func TestBotAuthorAndSameRepoGatesAnchorNothing(t *testing.T) {
	for _, g := range []*ir.Gate{
		{Class: ir.GateMaintainerApproved, Reason: "author dependabot[bot]", PinnedSha: true},
		{Class: ir.GateSameRepo, Reason: "same repository"},
	} {
		sit := gatedJob(g)
		findings := []opaengine.Finding{headCheckout()}
		if paths := assemblePaths(findings, sit); len(paths) != 0 {
			t.Errorf("%s: want no path, got %+v", g.Reason, paths)
		}
		markGatedFindings(findings, sit)
		if sev := ContextualSeverity(findings[0], nil, ""); sev != SeverityLow {
			t.Errorf("%s: severity %s, want low", g.Reason, sev)
		}
		if note, _ := findings[0].Data["gateNote"].(string); note != "gated to the repository's own branches" {
			t.Errorf("%s: note %q", g.Reason, note)
		}
	}
}

// A job the privileged run never executes (its condition names other
// events: ir.GateNoOutsider) lets no outsider in: no path, and the
// finding stays an individual one, at Low, with the note naming the
// repository's own events.
func TestEventGateAnchorsNothing(t *testing.T) {
	sit := gatedJob(&ir.Gate{Class: ir.GateNoOutsider, Reason: "event push"})
	findings := []opaengine.Finding{headCheckout()}
	if paths := assemblePaths(findings, sit); len(paths) != 0 {
		t.Errorf("want no path, got %+v", paths)
	}
	markGatedFindings(findings, sit)
	if sev := ContextualSeverity(findings[0], nil, ""); sev != SeverityLow {
		t.Errorf("severity %s, want low", sev)
	}
	if note, _ := findings[0].Data["gateNote"].(string); note != "gated to the repository's own events" {
		t.Errorf("note %q", note)
	}
}

// A job of a reusable workflow carries no privileged trigger of its own
// (its run is its caller's), so its gate (ir.ClassifyGates: its callers'
// gates) decides who reaches an untrusted expression in it: a call made
// on the repository's own events only admits no path; an ungated call
// from a pull_request_target run is an outsider's.
func TestCalledJobGateHoldsItsUntrustedExpression(t *testing.T) {
	called := func(g *ir.Gate) *Situation {
		j := JobSituation{Gate: g}
		j.Privilege.Secrets = []string{"NPM_TOKEN"}
		j.Privilege.SecretsState = "proven"
		return &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"_warm/warm": j}}
	}
	expression := func() opaengine.Finding {
		return entryFinding("ISSUE-207", "_warm/warm", "github.event.pull_request.title")
	}

	sit := called(&ir.Gate{Class: ir.GateNoOutsider, Reason: "event push"})
	findings := []opaengine.Finding{expression()}
	if paths := assemblePaths(findings, sit); len(paths) != 0 {
		t.Errorf("push-only call: want no path, got %+v", paths)
	}
	markGatedFindings(findings, sit)
	if note, _ := findings[0].Data["gateNote"].(string); note != "gated to the repository's own events" {
		t.Errorf("push-only call: note %q", note)
	}

	p := onePath(t, assemblePaths([]opaengine.Finding{expression()}, called(&ir.Gate{Class: ir.GateOutsider})))
	// The pull request title is an outsider's here, never only an insider's
	// (no push cap held over the path).
	if p.Entry.Actor != "outsider" || p.insider || p.ceiling != TierCritical {
		t.Errorf("ungated call: insider %v, ceiling %s, entry = %+v", p.insider, p.ceiling, p.Entry)
	}
}

// A human author gate is a maintainer's choice of who runs it: the path
// stands, capped, and names the author.
func TestHumanAuthorGateNamesTheAuthor(t *testing.T) {
	sit := gatedJob(&ir.Gate{Class: ir.GateMaintainerApproved, Reason: "author octocat"})
	p := onePath(t, assemblePaths([]opaengine.Finding{checkoutOf("github.event.pull_request.head.ref")}, sit))
	if p.Tier != TierHigh {
		t.Errorf("path = %+v", p)
	}
	b := NewPathBlock(p, nil)
	if !strings.HasPrefix(b.So, "as `octocat`, and only `octocat`, an attacker") || !strings.Contains(b.Entry, ", author `octocat` only)") {
		t.Errorf("So = %q, Entry = %q", b.So, b.Entry)
	}
}

// A bot as the actor (github.actor, github.triggering_actor) is no proof
// the pull request is the bot's: an outsider can make Dependabot the actor
// of a synchronize event on their own fork pull request. The path stays,
// capped at High as a maintainer's gate, naming the bot.
func TestBotActorGateKeepsACappedPath(t *testing.T) {
	sit := gatedJob(&ir.Gate{Class: ir.GateMaintainerApproved, Reason: "actor dependabot[bot]"})
	findings := []opaengine.Finding{checkoutOf("github.event.pull_request.head.ref")}
	p := onePath(t, assemblePaths(findings, sit))
	if p.Tier != TierHigh || !slices.Contains(p.Modifiers, "maintainer_cap") {
		t.Errorf("path = %+v", p)
	}
	b := NewPathBlock(p, nil)
	if !strings.HasPrefix(b.So, "as anyone who can make `dependabot[bot]` the actor, an attacker") {
		t.Errorf("So = %q", b.So)
	}
	markGatedFindings(findings, sit)
	if _, marked := findings[0].Data["gateNote"]; marked {
		t.Errorf("an actor gate marked the finding: %+v", findings[0].Data)
	}
}

// Pinning is the anchoring checkout's own: a job checking out the head
// commit in one step and the head branch in another holds the branch
// checkout at High, whatever the other step pins; a finding without a ref
// reads the job, pinned only when every head checkout is a SHA.
func TestPinningIsTheAnchoringCheckouts(t *testing.T) {
	sit := gatedJob(&ir.Gate{Class: ir.GateMaintainerApproved, Reason: "label safe", PinnedSha: true})
	if p := onePath(t, assemblePaths([]opaengine.Finding{checkoutOf("github.event.pull_request.head.ref")}, sit)); p.Tier != TierHigh || p.Entry.PinnedSha {
		t.Errorf("head.ref checkout: %+v", p)
	}
	noRef := opaengine.Finding{Code: "ISSUE-802", Job: "ci/cloud", File: ".github/workflows/ci.yml", Line: 10, Message: "job checks out fork code"}
	for _, pinned := range []bool{true, false} {
		sit := gatedJob(&ir.Gate{Class: ir.GateMaintainerApproved, Reason: "label safe", PinnedSha: pinned})
		p := onePath(t, assemblePaths([]opaengine.Finding{noRef}, sit))
		want := TierHigh
		if pinned {
			want = TierMedium
		}
		if p.Tier != want || p.Entry.PinnedSha != pinned {
			t.Errorf("no ref, job pinned %v: %+v", pinned, p)
		}
	}
}

// A pinned checkout says nothing about an expression injected into a
// script: an untrusted expression behind a maintainer's gate holds at
// High, never at the pinned head ceiling.
func TestUntrustedExpressionBehindAGateStaysHigh(t *testing.T) {
	sit := gatedJob(&ir.Gate{Class: ir.GateMaintainerApproved, Reason: "label safe", PinnedSha: true})
	p := onePath(t, assemblePaths([]opaengine.Finding{entryFinding("ISSUE-207", "ci/cloud", "github.event.pull_request.title")}, sit))
	if p.EntryKind != EntryUntrustedExpression || p.BaseTier != TierCritical || p.Tier != TierHigh || !slices.Contains(p.Modifiers, "maintainer_cap") || p.Entry.PinnedSha {
		t.Errorf("path = %+v", p)
	}
	if b := NewPathBlock(p, nil); !strings.HasPrefix(b.So, "as anyone whose pull request a maintainer labels `safe`") {
		t.Errorf("So = %q", b.So)
	}
}

// The label wording names what the maintainer labels: a pull request on
// the pull request triggers, a discussion on the discussion ones, an
// issue on an issue comment.
func TestLabelWordingFollowsTheTrigger(t *testing.T) {
	for trigger, want := range map[string]string{
		"pull_request_target": "as anyone whose pull request a maintainer labels `safe`",
		"discussion_comment":  "as anyone whose discussion a maintainer labels `safe`",
		"issue_comment":       "as anyone whose issue a maintainer labels `safe`",
	} {
		sit := gatedJob(&ir.Gate{Class: ir.GateMaintainerApproved, Reason: "label safe"})
		j := sit.Jobs["ci/cloud"]
		j.PrivilegedTriggers = []string{trigger}
		sit.Jobs["ci/cloud"] = j
		p := onePath(t, assemblePaths([]opaengine.Finding{checkoutOf("github.event.pull_request.head.ref")}, sit))
		if got := soActor(p, "action"); got != want {
			t.Errorf("%s: %q, want %q", trigger, got, want)
		}
	}
}

// markGatedFindings touches only an entry finding on a job no outsider can
// make run: a maintainer's gate, an unknown gate, another job and a
// finding that is no entry stay as they are.
func TestMarkGatedFindingsTouchesOnlyNoOutsiderEntries(t *testing.T) {
	for _, g := range []*ir.Gate{
		{Class: ir.GateMaintainerApproved, Reason: "label safe"},
		{Class: ir.GateUnknown, Unknown: []string{"inputs.mode"}},
		{Class: ir.GateOutsider},
	} {
		findings := []opaengine.Finding{headCheckout()}
		markGatedFindings(findings, gatedJob(g))
		if _, marked := findings[0].Data["gateNote"]; marked {
			t.Errorf("%s gate marked the finding", g.Class)
		}
	}
	sit := gatedJob(&ir.Gate{Class: ir.GateSameRepo, Reason: "same repository"})
	sit.Jobs["ci/open"] = JobSituation{PrivilegedTriggers: []string{"pull_request_target"}}
	other := checkoutOf("github.event.pull_request.head.sha")
	other.Job = "ci/open"
	hygiene := finding("ISSUE-801", "ci/cloud", nil)
	findings := []opaengine.Finding{other, hygiene}
	markGatedFindings(findings, sit)
	for _, f := range findings {
		if _, marked := f.Data["gateNote"]; marked {
			t.Errorf("%s on %s marked", f.Code, f.Job)
		}
	}
}

// The head-checkout policy's own fork guard (Data "forkGuard") is a
// downgrade, never a suppression, and only where the gate classifier
// decided nothing for the job (no JobSituation.Gate): the finding is then
// priced Low with the gate note. A job with a classified gate is decided
// by that gate alone (noOutsiderGate): the jfrog-cli-evidence shape, a
// fork-guarded checkout in a job behind a maintainer's label, anchors a
// maintainer-approved path and carries neither the note nor the
// downgrade.
func TestMarkGatedFindingsDowngradesTheForkGuardedHeadCheckout(t *testing.T) {
	guarded := func() opaengine.Finding {
		f := headCheckout()
		f.Data["forkGuard"] = true
		return f
	}

	findings := []opaengine.Finding{guarded()}
	markGatedFindings(findings, gatedJob(nil))
	if findings[0].Data["occurrenceSeverity"] != string(SeverityLow) || findings[0].Data["gateNote"] != gatedNote {
		t.Errorf("no classified gate: data = %+v, want occurrenceSeverity low and the gate note", findings[0].Data)
	}

	findings = []opaengine.Finding{guarded()}
	markGatedFindings(findings, gatedJob(&ir.Gate{Class: ir.GateMaintainerApproved, Reason: "label safe to test"}))
	if _, noted := findings[0].Data["gateNote"]; noted {
		t.Errorf("label gate: data = %+v, want no gate note", findings[0].Data)
	}
	if _, low := findings[0].Data["occurrenceSeverity"]; low {
		t.Errorf("label gate: data = %+v, want no downgrade", findings[0].Data)
	}
}

// A gate on one job never holds an entry into another.
func TestAGateHoldsOnlyItsOwnJob(t *testing.T) {
	sit := gatedJob(&ir.Gate{Class: ir.GateSameRepo, Reason: "same repository"})
	open := sit.Jobs["ci/cloud"]
	open.Gate = nil
	sit.Jobs["ci/open"] = open
	f := checkoutOf("github.event.pull_request.head.sha")
	f.Job = "ci/open"
	p := onePath(t, assemblePaths([]opaengine.Finding{f}, sit))
	if p.Tier != TierCritical || p.Entry.Actor != "outsider" {
		t.Errorf("path = %+v", p)
	}
}

// A gate the condition evaluator cannot decide (an input of a manual run)
// keeps the outsider's entry, unverified and one tier down, and keeps
// the references it could not read for the Note line.
func TestUnknownGateIsAnUnverifiedOutsider(t *testing.T) {
	sit := gatedJob(&ir.Gate{Class: ir.GateUnknown, Unknown: []string{"inputs.mode"}})
	p := onePath(t, assemblePaths([]opaengine.Finding{headCheckout()}, sit))
	if p.Tier != TierHigh || p.BaseTier != TierCritical || p.State != PathUnverified || p.Entry.Actor != "unknown" {
		t.Errorf("path = %+v", p)
	}
	if !slices.Equal(p.unknownRefs, []string{"inputs.mode"}) {
		t.Errorf("unknownRefs = %v", p.unknownRefs)
	}
	b := NewPathBlock(p, nil)
	if !b.Unverified || !strings.HasPrefix(b.So, "as anyone who opens a pull request, an attacker") || b.Fix != checkoutFix {
		t.Errorf("block = %+v", b)
	}
}

// An unknown gate on an entry that is itself unresolved drops one tier,
// not two.
func TestUnknownGateOnAnUnresolvedEntryDropsOneTier(t *testing.T) {
	sit := gatedJob(&ir.Gate{Class: ir.GateUnknown, Unknown: []string{"inputs.mode"}})
	j := sit.Jobs["ci/cloud"]
	j.Privilege.Secrets = nil
	j.Impact = []ImpactFact{{Kind: "publishes", State: FactUnknown, Evidence: "npm publish"}}
	sit.Jobs["ci/cloud"] = j
	p := onePath(t, assemblePaths([]opaengine.Finding{headCheckout()}, sit))
	if p.State != PathUnverified || TierRank(p.Tier) != TierRank(p.BaseTier)-1 {
		t.Errorf("path = %+v", p)
	}
}

// The clickhouse-go workflow end to end: the collector's job, the gate
// pass, the policies and the situation module carry the label gate to
// the assembly, which holds the path at Medium.
func TestLabelGateReachesTheAssemblyEndToEnd(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider:   ir.ProviderGitHub,
		Visibility: ir.VisibilityPublic,
		Jobs: []ir.Job{{
			Name:         "cloud/test",
			OriginFile:   ".github/workflows/cloud.yml",
			Triggers:     []string{"pull_request_target"},
			TriggerTypes: map[string][]string{"pull_request_target": {"labeled"}},
			If:           "github.event.label.name == 'tests:run-cloud'",
			Conditions:   []string{"github.event.label.name == 'tests:run-cloud'"},
			Permissions:  map[string]string{"contents": "read"},
			Uses:         []ir.Action{{Uses: "actions/checkout@v5", With: map[string]any{"ref": "${{ github.event.pull_request.head.sha }}"}}},
			Scripts:      []string{"make test TOKEN=${{ secrets.CLOUD_TOKEN }}"},
		}},
	}
	ir.ClassifyGates(p)
	conf := defaultConf(t)
	quiet := logrus.New()
	quiet.SetOutput(io.Discard)
	findings, failures := evaluatePolicies(logrus.NewEntry(quiet), conf, "github", p)
	if len(failures) > 0 {
		t.Fatalf("policy failures: %+v", failures)
	}
	sit, err := EvaluateSituation(context.Background(), p, buildEngineConfig(conf.PlumberConfig.ControlsFor("github"), ""))
	if err != nil {
		t.Fatal(err)
	}
	var target *AttackPath
	for _, path := range assemblePaths(findings, sit) {
		if path.EntryKind == EntryPRTarget {
			target = &path
			break
		}
	}
	if target == nil {
		t.Fatalf("no pr_target path among %d findings", len(findings))
	}
	if target.Tier != TierMedium || target.Entry.Actor != "maintainer_approved" || target.Entry.Gate != "label tests:run-cloud" {
		t.Errorf("path = %+v", *target)
	}
}

// endToEnd runs job the way a GitHub analysis does past the collection:
// the gate pass, the policies, the situation, the gated findings, the
// assembly.
func endToEnd(t *testing.T, job ir.Job) ([]opaengine.Finding, []AttackPath) {
	t.Helper()
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Visibility: ir.VisibilityPublic, Jobs: []ir.Job{job}}
	ir.ClassifyGates(p)
	conf := defaultConf(t)
	quiet := logrus.New()
	quiet.SetOutput(io.Discard)
	findings, failures := evaluatePolicies(logrus.NewEntry(quiet), conf, "github", p)
	if len(failures) > 0 {
		t.Fatalf("policy failures: %+v", failures)
	}
	sit, err := EvaluateSituation(context.Background(), p, buildEngineConfig(conf.PlumberConfig.ControlsFor("github"), ""))
	if err != nil {
		t.Fatal(err)
	}
	markGatedFindings(findings, sit)
	return findings, assemblePaths(findings, sit)
}

// A head.sha checkout and a head.ref checkout of one labelled job are one
// finding identity, so one path: the branch checkout runs whatever was
// pushed after the label, so the path is not pinned, in either step
// order.
func TestTwoHeadCheckoutsAreNotPinnedEndToEnd(t *testing.T) {
	sha := ir.Action{Uses: "actions/checkout@v5", Line: 12, With: map[string]any{"ref": "${{ github.event.pull_request.head.sha }}"}}
	ref := ir.Action{Uses: "actions/checkout@v5", Line: 20, With: map[string]any{"ref": "${{ github.event.pull_request.head.ref }}"}}
	for _, steps := range [][]ir.Action{{sha, ref}, {ref, sha}} {
		_, paths := endToEnd(t, ir.Job{
			Name:         "ci/cloud",
			OriginFile:   ".github/workflows/cloud.yml",
			Triggers:     []string{"pull_request_target"},
			TriggerTypes: map[string][]string{"pull_request_target": {"labeled"}},
			If:           "github.event.label.name == 'ok'",
			Conditions:   []string{"github.event.label.name == 'ok'"},
			Permissions:  map[string]string{"contents": "read"},
			Uses:         steps,
			Scripts:      []string{"make test TOKEN=${{ secrets.CLOUD_TOKEN }}"},
		})
		var target []AttackPath
		for _, p := range paths {
			if p.EntryKind == EntryPRTarget {
				target = append(target, p)
			}
		}
		if len(target) == 0 {
			t.Fatalf("%s first: no pr_target path", steps[0].With["ref"])
		}
		for _, p := range target {
			if p.Tier != TierHigh || slices.Contains(p.Modifiers, "pinned_head_cap") {
				t.Errorf("%s first: path %s %v %v", steps[0].With["ref"], p.Entry.Subject, p.Tier, p.Modifiers)
			}
		}
	}
}

// A job anyone reaches through an issue keeps an injected issue title an
// outsider's, whatever label gates its pull_request_target run.
func TestIssueTriggerKeepsTheInjectionCritical(t *testing.T) {
	cond := "github.event_name == 'issues' || github.event.label.name == 'ok'"
	_, paths := endToEnd(t, ir.Job{
		Name:         "triage/run",
		OriginFile:   ".github/workflows/triage.yml",
		Triggers:     []string{"issues", "pull_request_target"},
		TriggerTypes: map[string][]string{"pull_request_target": {"labeled"}},
		If:           cond,
		Conditions:   []string{cond},
		Permissions:  map[string]string{"contents": "read"},
		Scripts:      []string{"echo \"${{ github.event.issue.title }}\" && deploy --token ${{ secrets.DEPLOY_TOKEN }}"},
	})
	var target *AttackPath
	for i := range paths {
		if paths[i].EntryKind == EntryUntrustedExpression {
			target = &paths[i]
		}
	}
	if target == nil {
		t.Fatalf("no untrusted_expression path among %+v", paths)
	}
	if target.Tier != TierCritical || target.Entry.Actor != "outsider" {
		t.Errorf("path = %v %v actor %q gate %q", target.Tier, target.Modifiers, target.Entry.Actor, target.Entry.Gate)
	}
}

// The jfrog dependabot-auto-merge shape end to end: gated on the pull
// request's author being Dependabot, no path, and ISSUE-804 an individual
// Low with the note; gated on the actor being Dependabot instead, the path
// stays, capped at High.
func TestDependabotGatesEndToEnd(t *testing.T) {
	run := func(cond string) ([]opaengine.Finding, []AttackPath) {
		p := &ir.NormalizedPipeline{
			Provider:   ir.ProviderGitHub,
			Visibility: ir.VisibilityPublic,
			Jobs: []ir.Job{{
				Name:        "automerge/dependabot",
				OriginFile:  ".github/workflows/automerge.yml",
				Triggers:    []string{"pull_request_target"},
				If:          cond,
				Conditions:  []string{cond},
				Permissions: map[string]string{"contents": "read"},
				Uses:        []ir.Action{{Uses: "actions/checkout@v5", With: map[string]any{"ref": "${{ github.event.pull_request.head.ref }}"}}},
				Scripts:     []string{"make update-all TOKEN=${{ secrets.CLI_ACTION_TOKEN }}"},
			}},
		}
		ir.ClassifyGates(p)
		conf := defaultConf(t)
		quiet := logrus.New()
		quiet.SetOutput(io.Discard)
		findings, _ := evaluatePolicies(logrus.NewEntry(quiet), conf, "github", p)
		sit, err := EvaluateSituation(context.Background(), p, buildEngineConfig(conf.PlumberConfig.ControlsFor("github"), ""))
		if err != nil {
			t.Fatal(err)
		}
		markGatedFindings(findings, sit)
		var out []AttackPath
		for _, path := range assemblePaths(findings, sit) {
			if path.EntryKind == EntryPRTarget {
				out = append(out, path)
			}
		}
		return findings, out
	}
	findings, paths := run("github.event.pull_request.user.login == 'dependabot[bot]'")
	if len(paths) != 0 {
		t.Errorf("author gate: paths %+v", paths)
	}
	found := false
	for _, f := range findings {
		if f.Code == "ISSUE-804" {
			found = true
			if sev := ContextualSeverity(f, nil, ""); sev != SeverityLow || f.Data["gateNote"] != gatedNote {
				t.Errorf("ISSUE-804: %s, %v", sev, f.Data)
			}
		}
	}
	if !found {
		t.Error("no ISSUE-804 finding")
	}
	_, paths = run("github.actor == 'dependabot[bot]'")
	if len(paths) != 1 || paths[0].Tier != TierHigh || paths[0].Entry.Gate != "actor dependabot[bot]" {
		t.Errorf("actor gate: paths %+v", paths)
	}
}
