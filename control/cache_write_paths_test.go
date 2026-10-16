package control

import (
	"reflect"
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// npmCache is a cache a job restores and saves.
var npmCache = CacheFact{Key: "npm-${{ hashFiles('**/package-lock.json') }}", Mode: "both", Uses: "actions/cache@v5", Line: 22}

// defaultScope is the cache scope of a job whose runs save for the default
// branch (a push, a schedule, a dispatch, an untrusted trigger granted
// cache-mode: write), the scope every other run restores from.
var defaultScope = []string{"default"}

// withCaches is js saving or restoring caches.
func withCaches(js JobSituation, caches ...CacheFact) JobSituation {
	js.Caches = caches
	return js
}

// triageWriter is triage/label: an issue_comment job granted cache-mode:
// write, so its runs save for the default branch.
var triageWriter = JobSituation{PrivilegedTriggers: []string{"issue_comment"}, CacheScopes: defaultScope}

// cacheFinding is ISSUE-705 on triage/label: cache write granted on an
// untrusted trigger, set on the job.
func cacheFinding() opaengine.Finding {
	return opaengine.Finding{Code: string(CodeCachePoisoning), Job: "triage/label", File: ".github/workflows/triage.yml", Line: 6,
		Subject: "triage/label", Data: map[string]any{"cacheMode": "write", "cacheModeLevel": "job"}}
}

// commentInjection is the comment body reaching a shell in triage/label:
// code from anyone runs in the job granted cache write.
func commentInjection() opaengine.Finding {
	return entryFinding("ISSUE-207", "triage/label", "github.event.comment.body")
}

// cacheSituation is releaseSituation, its release job restoring and saving
// npmCache, plus the writer triage/label and the jobs given, on GitHub.
func cacheSituation(jobs map[string]JobSituation) *Situation {
	s := releaseSituation(ir.VisibilityPublic)
	s.Provider = "github"
	release := withCaches(s.Jobs["release"], npmCache)
	release.RestoresCache = true
	s.Jobs["release"] = release
	s.Jobs["triage/label"] = triageWriter
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

// cachePathOf assembles findings over sit and returns the poisoned cache
// path, failing the test when there is none or more than one.
func cachePathOf(t *testing.T, findings []opaengine.Finding, sit *Situation) AttackPath {
	t.Helper()
	cache := cachePaths(assemblePaths(findings, sit))
	if len(cache) != 1 {
		t.Fatalf("want one cache path, got %+v", cache)
	}
	return cache[0]
}

// A job granted cache write on an untrusted trigger, and run by anyone
// through a comment body, is the entry of a path into every job restoring
// a cache: the writer is the subject, and the path reaches what the
// restoring job holds and publishes. The order of the findings does not
// matter.
func TestACacheWriteGrantIsAnEntryIntoTheJobsRestoringACache(t *testing.T) {
	sit := cacheSituation(nil)
	for _, findings := range [][]opaengine.Finding{{cacheFinding(), commentInjection()}, {commentInjection(), cacheFinding()}} {
		paths := assemblePaths(findings, sit)
		p := cachePathOf(t, findings, sit)
		if p.Entry.Subject != "triage/label" || p.Tier != TierCritical || p.State != PathProven || len(p.Modifiers) != 0 ||
			!reflect.DeepEqual(p.Jobs, []string{"triage/label", "release"}) || p.ReachKind != "impact:publishes" {
			t.Errorf("path = %+v", p)
		}
		b := NewPathBlock(p, nil)
		if b.Entry != "triage/label (cache write granted to an untrusted trigger)" ||
			b.Fix != "set cache-mode: read on jobs untrusted triggers run" {
			t.Errorf("block entry %q, fix %q", b.Entry, b.Fix)
		}
		s := PathSentence(p)
		if !strings.HasPrefix(s, "Code running in `triage/label` can write caches that `release` restores, since `cache-mode: write` lifts GitHub's read-only cache access for its untrusted triggers") ||
			strings.Contains(s, "shared across branches") {
			t.Errorf("sentence = %q", s)
		}
		if line := FindingLine(cacheFinding(), paths); line != "Entry of path "+p.ID {
			t.Errorf("finding line = %q", line)
		}
	}
}

// Every live job restoring a cache is reached, the writer itself never.
func TestEveryJobRestoringACacheIsReached(t *testing.T) {
	sit := cacheSituation(map[string]JobSituation{
		"ci/test":   {RestoresCache: true},
		"ci/dead":   {RestoresCache: true, Dead: true},
		"ci/saver":  withCaches(JobSituation{}, CacheFact{Key: "k", Mode: "save"}),
		"ci/lint":   {},
		"bot/write": {RestoresCache: false},
	})
	w := sit.Jobs["triage/label"]
	w.RestoresCache = true
	sit.Jobs["triage/label"] = w
	p := cachePathOf(t, []opaengine.Finding{cacheFinding(), commentInjection()}, sit)
	if !reflect.DeepEqual(p.Jobs, []string{"triage/label", "ci/test", "release"}) {
		t.Errorf("jobs = %v, want the writer then every live restorer", p.Jobs)
	}
	if s := PathSentence(p); !strings.HasPrefix(s, "Code running in `triage/label` can write caches that `ci/test` and `release` restore, since") {
		t.Errorf("sentence = %q", s)
	}
}

// The cache path reaches what the restoring jobs hold, never the writer's
// own privileges: those belong to the path that enters the writer, so a
// lint job restoring a cache adds code execution there and nothing more.
func TestACachePathReachesTheRestorersNotTheWriter(t *testing.T) {
	w := triageWriter
	w.Privilege.Secrets, w.Privilege.SecretsState = []string{"DEPLOY_KEY"}, "proven"
	sit := cacheSituation(map[string]JobSituation{"triage/label": w, "ci/lint": {RestoresCache: true}})
	delete(sit.Jobs, "release")
	p := cachePathOf(t, []opaengine.Finding{cacheFinding(), commentInjection()}, sit)
	if len(p.Reach.Secrets) != 0 || p.ReachKind != "execution" {
		t.Errorf("reach = %+v (%s), want the lint job's code execution alone", p.Reach, p.ReachKind)
	}
	if s := PathSentence(p); strings.Contains(s, "DEPLOY_KEY") {
		t.Errorf("sentence names the writer's secret: %q", s)
	}
}

// The grant alone is no way in: with no other path running code from
// outside the team in the writer, the cache finding starts no path and is
// priced on its own, at its severity.
func TestACacheWriteGrantNobodyEntersStartsNoPath(t *testing.T) {
	findings := []opaengine.Finding{cacheFinding()}
	paths := assemblePaths(findings, cacheSituation(nil))
	if cache := cachePaths(paths); len(cache) != 0 {
		t.Fatalf("no path enters the writer, got %+v", cache)
	}
	s := ComputePlumberScoreV4(ScoreInputV4{Findings: findings, Paths: paths})
	if s.OtherFindings == nil || s.OtherFindings.Count != 1 || len(s.CodeLosses) != 1 || s.CodeLosses[0].Code != CodeCachePoisoning || s.CodeLosses[0].Severity != SeverityHigh {
		t.Errorf("want the cache finding priced as an other finding, got %+v", s.CodeLosses)
	}
}

// A writer nobody restores from reaches nothing through the cache: no job
// restores one, the only restorer is dead, or its cache-mode takes
// restoring away (write-only, none: RestoresCache unset).
func TestACacheNobodyRestoresStartsNoPath(t *testing.T) {
	for name, release := range map[string]func(JobSituation) JobSituation{
		"no restorer":   func(j JobSituation) JobSituation { j.RestoresCache = false; return j },
		"dead restorer": func(j JobSituation) JobSituation { j.Dead = true; return j },
	} {
		sit := cacheSituation(nil)
		sit.Jobs["release"] = release(sit.Jobs["release"])
		if cache := cachePaths(assemblePaths([]opaengine.Finding{cacheFinding(), commentInjection()}, sit)); len(cache) != 0 {
			t.Errorf("%s: want no cache path, got %+v", name, cache)
		}
	}
}

// A writer entered only by a path capped at Medium (a reference not
// pinned) holds the cache at Medium: poisoning it takes that dependency's
// compromise first.
func TestACacheWrittenThroughAMediumPathIsMedium(t *testing.T) {
	p := cachePathOf(t, []opaengine.Finding{
		cacheFinding(), finding("ISSUE-701", "triage/label", map[string]any{"uses": "some/action@v1"}),
	}, cacheSituation(nil))
	if p.BaseTier != TierCritical || p.Tier != TierMedium || !reflect.DeepEqual(p.Modifiers, []string{"dependency_cap", "cache_writer_cap"}) {
		t.Errorf("want Critical held at Medium through the writer, got %s %s %v", p.BaseTier, p.Tier, p.Modifiers)
	}
	if b := NewPathBlock(p, nil); b.Cap != "Capped at Medium: the job that writes the cache needs a dependency compromise first" {
		t.Errorf("cap = %q", b.Cap)
	}
}

// The strongest path entering the writer holds the cache: a contributor's
// comment body leaves it uncapped beside an unpinned action.
func TestACacheTakesTheStrongestCeilingOfItsWriter(t *testing.T) {
	p := cachePathOf(t, []opaengine.Finding{
		cacheFinding(), commentInjection(), finding("ISSUE-701", "triage/label", map[string]any{"uses": "some/action@v1"}),
	}, cacheSituation(nil))
	if p.Tier != TierCritical || len(p.Modifiers) != 0 {
		t.Errorf("want Critical, uncapped, got %s %v", p.Tier, p.Modifiers)
	}
}

// A fork pull request run saves only to its own merge ref's cache: a
// writer whose only way in is a fork pull request is no writer, so the
// cache finding starts no path.
func TestAForkPullRequestEntryWritesNoCache(t *testing.T) {
	fork := []EntryFact{{Kind: EntryForkPR, State: "proven", Evidence: "on: pull_request", Subject: "pull_request"}}
	w := triageWriter
	w.ForkPR = fork
	w.PrivilegedTriggers = nil
	w.RefTriggers = []string{"push"}
	sit := cacheSituation(map[string]JobSituation{"triage/label": w})
	findings := []opaengine.Finding{cacheFinding(), entryFinding("ISSUE-207", "triage/label", "github.event.pull_request.title")}
	if cache := cachePaths(assemblePaths(findings, sit)); len(cache) != 0 {
		t.Fatalf("a fork pull request run writes no cache other runs read, got %+v", cache)
	}
}

// A fork pull request run saves only in its merge ref's scope: an entry
// that holds only in such a run never reaches a job through a cache it
// saves, while an edge of another kind stays walked, and an entry that
// also holds in a push run (a dependency) still reaches the job restoring
// the cache.
func TestAForkRunReachesNoJobThroughTheCache(t *testing.T) {
	fork := []EntryFact{{Kind: EntryForkPR, State: "proven", Evidence: "on: pull_request", Subject: "pull_request"}}
	sit := cacheSituation(map[string]JobSituation{
		"ci/test": {ForkPR: fork, RefTriggers: []string{"push"}, CacheScopes: defaultScope, Feeds: []string{"release"}, FeedsVia: map[string][]string{"release": {FeedCache}}},
	})
	title := entryFinding("ISSUE-207", "ci/test", "github.event.pull_request.title")
	if p := assemblePaths([]opaengine.Finding{title}, sit); len(p) != 1 || len(p[0].Jobs) != 1 {
		t.Errorf("the pull request title reaches no job through the cache, got %+v", p)
	}
	dep := assemblePaths([]opaengine.Finding{finding("ISSUE-701", "ci/test", map[string]any{"uses": "some/action@v1"})}, sit)
	if len(dep) != 1 || len(dep[0].Jobs) != 2 || dep[0].Jobs[1] != "release" {
		t.Errorf("a dependency also runs on push and reaches release through the cache, got %+v", dep)
	}
	j := sit.Jobs["ci/test"]
	j.FeedsVia = map[string][]string{"release": {FeedArtifact, FeedCache}}
	sit.Jobs["ci/test"] = j
	if p := assemblePaths([]opaengine.Finding{title}, sit); len(p) != 1 || len(p[0].Jobs) != 2 {
		t.Errorf("an artifact edge stays walked, got %+v", p)
	}
}

// The best fix names the cache-mode grant and the job it is on.
func TestTheBestFixNamesTheCacheModeGrant(t *testing.T) {
	p := wordingPath(EntryPoisonedCache, "triage/label", CodeCachePoisoning)
	p.ID = "cache"
	got := BestFixSummary(&PlumberScoreResult{BestFix: &BestFix{PathID: "cache", Stays: "stays"}, Paths: []AttackPath{p}})
	if !strings.Contains(got, "set cache-mode: read on jobs untrusted triggers run (cache-mode: write in triage/label)") {
		t.Errorf("best fix = %q", got)
	}
}
