package control

import (
	"reflect"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// pushWriter is a job running on a push to the default branch: an entry
// into it can write the caches a release run reads.
var pushWriter = JobSituation{RefTriggers: []string{"push"}, CacheScopes: defaultScope}

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

// A cache whose writers are entered only by paths capped at Medium (a
// reference not pinned) holds at Medium: poisoning it takes that
// dependency's compromise first.
func TestACacheWrittenThroughMediumPathsOnlyIsMedium(t *testing.T) {
	sit := cacheSituation(map[string]JobSituation{"ci/build": pushWriter, "ci/lint": pushWriter})
	p := cachePathOf(t, []opaengine.Finding{
		cacheFinding(),
		finding("ISSUE-701", "ci/build", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-701", "ci/lint", map[string]any{"uses": "other/action@v1"}),
	}, sit)
	if p.BaseTier != TierCritical || p.Tier != TierMedium || !reflect.DeepEqual(p.Modifiers, []string{"dependency_cap", "cache_writer_cap"}) {
		t.Errorf("want Critical held at Medium through the writers, got %s %s %v", p.BaseTier, p.Tier, p.Modifiers)
	}
	if b := NewPathBlock(p, nil); b.Cap != "Capped at Medium: the jobs that can write the cache need a dependency compromise first" {
		t.Errorf("cap = %q", b.Cap)
	}
}

// One writer entered by a High-capped path lifts the ceiling to High: the
// strongest ceiling among the writers holds.
func TestACacheTakesTheStrongestCeilingOfItsWriters(t *testing.T) {
	sit := cacheSituation(map[string]JobSituation{"ci/build": pushWriter, "ci/lint": pushWriter})
	p := cachePathOf(t, []opaengine.Finding{
		cacheFinding(),
		finding("ISSUE-701", "ci/build", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-714", "ci/lint", map[string]any{"uses": "other/action@v1"}),
	}, sit)
	if p.Tier != TierHigh || !reflect.DeepEqual(p.Modifiers, []string{"dependency_cap", "cache_writer_cap"}) {
		t.Errorf("want High through the writer a High path enters, got %s %v", p.Tier, p.Modifiers)
	}
}

// A writer an unprotected push enters holds the cache at High, the push
// cap applying through it.
func TestACacheWrittenThroughAPushHoldsAtHigh(t *testing.T) {
	sit := cacheSituation(map[string]JobSituation{"ci/build": {RefTriggers: []string{"push"}, CacheScopes: defaultScope, Push: []EntryFact{{Kind: EntryUnprotectedPush, State: "proven", Subject: "main"}}}})
	sit.DefaultBranch = "main"
	p := cachePathOf(t, []opaengine.Finding{cacheFinding(), finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"})}, sit)
	if p.Tier != TierHigh || !reflect.DeepEqual(p.Modifiers, []string{"gate:ISSUE-501", "push_entry_cap", "cache_writer_cap"}) {
		t.Errorf("want High through the push, got %s %v", p.Tier, p.Modifiers)
	}
}

// A writer a contributor reaches leaves the cache uncapped.
func TestACacheWrittenThroughAContributorEntryIsUncapped(t *testing.T) {
	preview, entry := privilegedPreview()
	sit := cacheSituation(map[string]JobSituation{"pr-preview/preview": preview, "ci/build": pushWriter})
	p := cachePathOf(t, []opaengine.Finding{cacheFinding(), entry, finding("ISSUE-701", "ci/build", map[string]any{"uses": "some/action@v1"})}, sit)
	if p.Tier != TierCritical || len(p.Modifiers) != 0 {
		t.Errorf("want Critical, uncapped, got %s %v", p.Tier, p.Modifiers)
	}
}

// The restoring job is never its own cache's writer: entered by another
// path, it already holds what the cache would give. With no other writer
// the cache starts no path and its finding is priced on its own.
func TestTheRestoringJobAloneWritesNoCache(t *testing.T) {
	sit := cacheSituation(nil)
	release := sit.Jobs["release"]
	release.RefTriggers = []string{"push"}
	sit.Jobs["release"] = release
	findings := []opaengine.Finding{cacheFinding(), finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"})}
	paths := assemblePaths(findings, sit)
	if cache := cachePaths(paths); len(cache) != 0 {
		t.Fatalf("the restoring job alone writes no cache, got %+v", cache)
	}
	score := ComputePlumberScoreV4(ScoreInputV4{Findings: findings, Paths: paths})
	if score.OtherFindings == nil || score.OtherFindings.Count != 1 {
		t.Errorf("the cache finding is an individual finding, got %+v", score.OtherFindings)
	}
}

// The writers a cache path names are its writers only: never the job
// restoring it.
func TestTheWritersNoteNamesNoRestoringJob(t *testing.T) {
	sit := cacheSituation(map[string]JobSituation{"ci/build": pushWriter})
	release := sit.Jobs["release"]
	release.RefTriggers = []string{"push"}
	sit.Jobs["release"] = release
	p := cachePathOf(t, []opaengine.Finding{
		cacheFinding(),
		finding("ISSUE-701", "release", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-701", "ci/build", map[string]any{"uses": "other/action@v1"}),
	}, sit)
	if !reflect.DeepEqual(p.cacheWriters, []string{"ci/build"}) {
		t.Errorf("writers = %v", p.cacheWriters)
	}
}
