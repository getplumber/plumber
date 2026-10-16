package control

import (
	"context"
	"slices"
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// readOnlyJob is a GitHub job declaring `contents: read`: no write scope,
// its token settled by the declaration, no secret, its secrets listed.
func readOnlyJob() JobSituation {
	var j JobSituation
	j.RefTriggers = []string{"push"}
	j.CacheScopes = []string{"default"}
	j.Privilege.SecretsState = "proven"
	j.Privilege.TokenWriteSource = "declared"
	j.Privilege.TokenWriteState = "proven"
	return j
}

// untrustedMutableAction is an action off a full commit SHA from an owner
// outside the authorized list, in job: the dependency holds at High.
func untrustedMutableAction(job string) []opaengine.Finding {
	uses := map[string]any{"uses": "someone/action@v1"}
	return []opaengine.Finding{finding("ISSUE-701", job, uses), finding("ISSUE-713", job, uses)}
}

// Code execution alone, on a runner that saves nothing and uploads
// nothing, is Low: the attacker holds a runner that is thrown away.
func TestCodeExecutionAloneOnAnEphemeralRunnerIsLow(t *testing.T) {
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"ci/build": readOnlyJob()}}
	p := onePath(t, assemblePaths(untrustedMutableAction("ci/build"), sit))
	if p.BaseTier != TierLow || p.Tier != TierLow || p.State != PathProven {
		t.Fatalf("want a proven Low path, got tier %s base %s state %s", p.Tier, p.BaseTier, p.State)
	}
	b := NewPathBlock(p, nil)
	if !strings.Contains(b.So, "can execute code on an ephemeral runner") || strings.Contains(b.So, "caches or uploads") {
		t.Errorf("So = %q", b.So)
	}
	if len(b.Branches) != 1 || b.Branches[0].Reach != "code execution on the runner; nothing else proven" {
		t.Errorf("branches = %+v", b.Branches)
	}
}

// The same runner saving a cache that a release job holding NPM_TOKEN
// restores: the proven cache edge reaches a privileged job, High.
func TestACacheSaveRestoredByAPrivilegedJobIsHigh(t *testing.T) {
	build := readOnlyJob()
	build.Caches = []CacheFact{{Key: "deps", Family: "deps", Mode: "both", Uses: "actions/cache@v3", Line: 12}}
	build.Feeds = []string{"release/publish"}
	build.FeedsVia = map[string][]string{"release/publish": {FeedCache}}
	release := readOnlyJob()
	release.Caches = []CacheFact{{Key: "deps", Family: "deps", Mode: "restore", Uses: "actions/cache/restore@v3", Line: 8}}
	release.Privilege.Secrets = []string{"NPM_TOKEN"}
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"ci/build": build, "release/publish": release}}
	var dep *AttackPath
	paths := assemblePaths(untrustedMutableAction("ci/build"), sit)
	for i := range paths {
		if paths[i].EntryKind == EntryMutableDependency {
			dep = &paths[i]
		}
	}
	if dep == nil {
		t.Fatalf("no dependency path in %+v", paths)
	}
	if dep.Tier != TierHigh || !slices.Contains(dep.Reach.Secrets, "NPM_TOKEN") {
		t.Errorf("want High reaching NPM_TOKEN, got tier %s base %s reach %+v", dep.Tier, dep.BaseTier, dep.Reach)
	}
	if so := NewPathBlock(*dep, nil).So; strings.Contains(so, "ephemeral") {
		t.Errorf("So = %q", so)
	}
}

// A runner that saves a cache still reads as able to poison it, even
// when nothing proven restores it: the path stays Low.
func TestACacheSaveKeepsThePoisonSentence(t *testing.T) {
	build := readOnlyJob()
	build.Caches = []CacheFact{{Key: "deps", Family: "deps", Mode: "save", Uses: "actions/cache/save@v3", Line: 12}}
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"ci/build": build}}
	p := onePath(t, assemblePaths(untrustedMutableAction("ci/build"), sit))
	if p.Tier != TierLow {
		t.Errorf("tier = %s, want low", p.Tier)
	}
	if so := NewPathBlock(p, nil).So; !strings.Contains(so, "poison what it caches or uploads") {
		t.Errorf("So = %q", so)
	}
	upload := readOnlyJob()
	upload.Uploads = true
	sit = &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"ci/build": upload}}
	p = onePath(t, assemblePaths(untrustedMutableAction("ci/build"), sit))
	if so := NewPathBlock(p, nil).So; !strings.Contains(so, "poison what it caches or uploads") {
		t.Errorf("upload So = %q", so)
	}
}

// Secrets that could not be listed, and a write token nothing settled,
// stay in the reach but add no tier.
func TestUnprovenPrivilegeAddsNoTier(t *testing.T) {
	unlisted := readOnlyJob()
	unlisted.Privilege.Secrets = []string{"DEPLOY_KEY"}
	unlisted.Privilege.SecretsState = FactUnknown
	assumed := readOnlyJob()
	assumed.Privilege.TokenWrite = []string{"contents"}
	assumed.Privilege.TokenWriteSource = "unknown"
	assumed.Privilege.TokenWriteState = FactUnknown
	for name, js := range map[string]JobSituation{"unlisted secrets": unlisted, "assumed token": assumed} {
		sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"ci/build": js}}
		p := onePath(t, assemblePaths(untrustedMutableAction("ci/build"), sit))
		if p.BaseTier != TierLow || p.Tier != TierLow {
			t.Errorf("%s: tier %s base %s, want low", name, p.Tier, p.BaseTier)
		}
		if len(p.Reach.Secrets)+len(p.Reach.TokenWrite) == 0 {
			t.Errorf("%s: the unproven item left the reach: %+v", name, p.Reach)
		}
	}
}

func pushOnlySituation(js JobSituation) *Situation {
	js.Push = []EntryFact{{Kind: EntryUnprotectedPush, State: "proven", Evidence: "push: branches: [main]", Subject: "main"}}
	return &Situation{Exposure: ir.VisibilityPublic, Provider: "github", DefaultBranch: "main", Jobs: map[string]JobSituation{"ci/build": js}}
}

// An unprotected default branch whose only job holds no secret and a
// read-only token proves no escalation: no path, and the branch finding
// is priced on its own.
func TestAPushEntryWithoutAnEscalationFormsNoPath(t *testing.T) {
	f := finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"})
	sit := pushOnlySituation(readOnlyJob())
	paths := assemblePaths([]opaengine.Finding{f}, sit)
	if len(paths) != 0 {
		t.Fatalf("want no path, got %+v", paths)
	}
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: []opaengine.Finding{f}, Paths: paths})
	if !slices.ContainsFunc(s.CodeLosses, func(c CodeLoss) bool { return c.Code == CodeBranchUnprotected }) {
		t.Errorf("want ISSUE-501 priced on its own, got %+v", s.CodeLosses)
	}
}

// The same branch with a job holding a deploy secret is a High path.
func TestAPushEntryReachingADeploySecretIsHigh(t *testing.T) {
	js := readOnlyJob()
	js.Privilege.Secrets = []string{"DEPLOY_KEY"}
	f := finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"})
	p := onePath(t, assemblePaths([]opaengine.Finding{f}, pushOnlySituation(js)))
	if p.EntryKind != EntryUnprotectedPush || p.Tier != TierHigh {
		t.Errorf("want a High push path, got %s %s", p.EntryKind, p.Tier)
	}
}

// pypiPublish is the release job of a Python package: it publishes
// through pypa/gh-action-pypi-publish, holding a token that requests an
// OIDC credential, and the action's pinned version carries an advisory
// rated severity.
func pypiPublish(severity string) ([]opaengine.Finding, *Situation) {
	js := readOnlyJob()
	js.Privilege.Secrets = []string{"PYPI_TOKEN"}
	js.Impact = []ImpactFact{{Kind: "publishes", State: "proven", Evidence: "pypa/gh-action-pypi-publish"}}
	data := map[string]any{"uses": "pypa/gh-action-pypi-publish@v1.12.4", "advisories": []any{"GHSA-low1-aaaa-bbbb"}}
	if severity != "" {
		data["advisorySeverities"] = map[string]any{"GHSA-low1-aaaa-bbbb": severity}
	}
	sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"release/publish": js}}
	return []opaengine.Finding{finding("ISSUE-703", "release/publish", data)}, sit
}

// An advisory's own severity caps the path it anchors: low at Medium,
// medium at High, high, critical or a severity not read at all leave it.
func TestAdvisorySeverityCapsTheKnownVulnerablePath(t *testing.T) {
	for _, tc := range []struct {
		severity string
		tier     PathTier
		capped   bool
	}{{"low", TierMedium, true}, {"medium", TierHigh, true}, {"high", TierCritical, false}, {"critical", TierCritical, false}, {"", TierCritical, false}} {
		findings, sit := pypiPublish(tc.severity)
		p := onePath(t, assemblePaths(findings, sit))
		if p.BaseTier != TierCritical || p.Tier != tc.tier || slices.Contains(p.Modifiers, "advisory_cap") != tc.capped {
			t.Errorf("severity %q: tier %s base %s modifiers %v, want %s", tc.severity, p.Tier, p.BaseTier, p.Modifiers, tc.tier)
		}
		if !tc.capped {
			continue
		}
		want := "The published advisory on this version is rated " + tc.severity + ", so this path is capped at " + tierTitle(tc.tier) + "."
		if s := PathSentence(p); !strings.Contains(s, want) {
			t.Errorf("severity %q: sentence %q, want %q", tc.severity, s, want)
		}
		if b := NewPathBlock(p, nil); b.Cap != "Capped at "+tierTitle(tc.tier)+": the published advisory is rated "+tc.severity {
			t.Errorf("severity %q: cap %q", tc.severity, b.Cap)
		}
	}
}

// A maintainer-approved entry on the pinned head commit stays Medium.
func TestAMaintainerApprovedPinnedEntryStaysMedium(t *testing.T) {
	sit := gatedJob(&ir.Gate{Class: ir.GateMaintainerApproved, Reason: "label tests:run-cloud", PinnedSha: true})
	p := onePath(t, assemblePaths([]opaengine.Finding{headCheckout()}, sit))
	if p.Tier != TierMedium || p.BaseTier != TierCritical {
		t.Errorf("tier %s base %s, want medium from critical", p.Tier, p.BaseTier)
	}
}

// gitlabPipeline is one GitLab job, build, running script, with the
// settings variables given (their listing known).
func gitlabPipeline(script string, vars ...ir.SettingsVariable) *ir.NormalizedPipeline {
	return &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab, Visibility: ir.VisibilityPublic,
		SettingsVariablesKnown: true, SettingsVariables: vars,
		Jobs: []ir.Job{{Name: "build", Scripts: []string{script}}},
	}
}

// A GitLab contents write is granted only on a positive signal (a script
// running git push, a protected CI_PUSH_TOKEN reaching the job): it is a
// proven write, and a mutable dependency entering the job is High. A job
// with neither signal holds nothing and stays Low.
func TestAGitLabContentsWriteSignalIsAProvenPrivilege(t *testing.T) {
	pushToken := ir.SettingsVariable{Name: "CI_PUSH_TOKEN", Type: "env_var", Environment: "*", Protected: true}
	for name, c := range map[string]struct {
		p    *ir.NormalizedPipeline
		tier PathTier
	}{
		"git push":             {gitlabPipeline("git push origin HEAD:main"), TierHigh},
		"protected push token": {gitlabPipeline("make release", pushToken), TierHigh},
		"neither":              {gitlabPipeline("make test"), TierLow},
	} {
		sit, err := EvaluateSituation(context.Background(), c.p, map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		p := onePath(t, assemblePaths(untrustedMutableAction("build"), sit))
		if p.Tier != c.tier {
			t.Errorf("%s: tier %s base %s, want %s (reach %+v)", name, p.Tier, p.BaseTier, c.tier, p.Reach)
		}
		// The write itself is the proven privilege, whatever impact the
		// step adds.
		provenWrite := slices.ContainsFunc(partsOf(p.Reach), func(part reachPart) bool {
			return !part.tokenUnknown && slices.Contains(part.scopes, "contents")
		})
		if provenWrite != (c.tier == TierHigh) {
			t.Errorf("%s: proven contents write %v, reach %+v", name, provenWrite, p.Reach)
		}
	}
}

// A token whose write a run's own log or a bot-authored write settled is
// proven: High, like a declared one.
func TestALogOrEffectTokenIsAProvenPrivilege(t *testing.T) {
	for _, source := range []string{"log", "effect"} {
		js := readOnlyJob()
		js.Privilege.TokenWrite = []string{"contents"}
		js.Privilege.TokenWriteSource, js.Privilege.TokenWriteState = source, "proven"
		sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"ci/build": js}}
		if p := onePath(t, assemblePaths(untrustedMutableAction("ci/build"), sit)); p.Tier != TierHigh {
			t.Errorf("%s: tier %s, want high", source, p.Tier)
		}
	}
}

// An output the fed job runs carries its proven secret into the reach:
// High. An output it only compares crosses no code: Low.
func TestAnExecutedOutputReachesTheFedSecretAComparedOneDoesNot(t *testing.T) {
	for kind, want := range map[string]PathTier{FeedOutputExecuted: TierHigh, FeedOutputCompared: TierLow} {
		build := readOnlyJob()
		build.Feeds = []string{"release/publish"}
		build.FeedsVia = map[string][]string{"release/publish": {kind}}
		release := readOnlyJob()
		release.Privilege.Secrets = []string{"NPM_TOKEN"}
		sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"ci/build": build, "release/publish": release}}
		var dep *AttackPath
		paths := assemblePaths(untrustedMutableAction("ci/build"), sit)
		for i := range paths {
			if paths[i].Jobs[0] == "ci/build" {
				dep = &paths[i]
			}
		}
		if dep == nil || dep.Tier != want {
			t.Errorf("%s: want %s, got %+v", kind, want, dep)
		}
	}
}

// A poisoned cache path takes the restoring job's secret through a proven
// edge from the job granted cache write: High. A restorer whose
// cache-mode turns restoring off (write-only, none) is no edge, and no
// path.
func TestACacheWriterEdgeAddsTierOnlyWhenProven(t *testing.T) {
	for name, c := range map[string]struct {
		restores bool
		paths    int
	}{"restores": {true, 1}, "restoring off": {false, 0}} {
		writer := readOnlyJob()
		release := withCaches(readOnlyJob(), npmCache)
		release.RestoresCache = c.restores
		release.Privilege.Secrets = []string{"NPM_TOKEN"}
		sit := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"ci/build": writer, "release": release}}
		grant := cacheFinding()
		grant.Job, grant.Subject = "ci/build", "ci/build"
		cache := cachePaths(assemblePaths(append(untrustedMutableAction("ci/build"), grant), sit))
		if len(cache) != c.paths || (c.paths == 1 && (cache[0].Tier != TierHigh || cache[0].cacheWriterStates["release"] != "proven")) {
			t.Errorf("%s: want %d High cache path, got %+v", name, c.paths, cache)
		}
	}
}

// advisoryPath is pypiPublish anchored by an ISSUE-703 finding naming
// every id of sevs, each rated as given ("" leaves it unrated).
func advisoryPath(t *testing.T, sevs map[string]string, extra ...opaengine.Finding) AttackPath {
	t.Helper()
	findings, sit := pypiPublish("")
	sit.DefaultBranch = "main"
	var ids []any
	rated := map[string]any{}
	for id, s := range sevs {
		ids = append(ids, id)
		if s != "" {
			rated[id] = s
		}
	}
	findings[0].Data["advisories"] = ids
	findings[0].Data["advisorySeverities"] = rated
	var dep *AttackPath
	paths := assemblePaths(append(findings, extra...), sit)
	for i := range paths {
		if paths[i].EntryKind == EntryMutableDependency {
			dep = &paths[i]
		}
	}
	if dep == nil {
		t.Fatalf("no dependency path in %+v", paths)
	}
	return *dep
}

// The worst of several advisories caps the path; one advisory with no
// severity read caps nothing.
func TestTheWorstAdvisoryCapsAndAnUnratedOneCapsNothing(t *testing.T) {
	if p := advisoryPath(t, map[string]string{"GHSA-a": "low", "GHSA-b": "medium"}); p.Tier != TierHigh || !slices.Contains(p.Modifiers, "advisory_cap") {
		t.Errorf("low and medium: tier %s modifiers %v, want High capped", p.Tier, p.Modifiers)
	}
	if p := advisoryPath(t, map[string]string{"GHSA-a": "low", "GHSA-b": ""}); p.Tier != TierCritical || slices.Contains(p.Modifiers, "advisory_cap") {
		t.Errorf("low and unrated: tier %s modifiers %v, want Critical uncapped", p.Tier, p.Modifiers)
	}
	if p := advisoryPath(t, map[string]string{"GHSA-a": "low", "GHSA-b": "unknown"}); p.Tier != TierCritical {
		t.Errorf("low and unknown: tier %s, want Critical uncapped", p.Tier)
	}
}

// A missing branch protection raising the path never lifts it over the
// advisory cap: the lowest ceiling wins.
func TestTheAdvisoryCapHoldsAgainstABranchGate(t *testing.T) {
	gate := finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"})
	for sev, want := range map[string]PathTier{"low": TierMedium, "medium": TierHigh} {
		p := advisoryPath(t, map[string]string{"GHSA-a": sev}, gate)
		if p.Tier != want || !slices.Contains(p.Modifiers, "gate:"+string(CodeBranchUnprotected)) || !slices.Contains(p.Modifiers, "advisory_cap") {
			t.Errorf("%s: tier %s modifiers %v, want %s with the gate and the cap", sev, p.Tier, p.Modifiers, want)
		}
	}
}
