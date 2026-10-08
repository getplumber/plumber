package control

import (
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// npmCache is the cache cacheFinding's step declares: the release job
// restores and saves it, and a writer saving it can poison it.
var npmCache = CacheFact{Key: "npm-${{ hashFiles('**/package-lock.json') }}", Mode: "both", Uses: "actions/cache@v5", Line: 22}

// rustFamily is a rust-cache key family declared at line 22.
func rustFamily(key, mode string) CacheFact {
	return CacheFact{Key: key, Mode: mode, Prefix: true, Uses: "Swatinem/rust-cache@v2", Line: 22}
}

// withCaches is js saving or restoring caches.
func withCaches(js JobSituation, caches ...CacheFact) JobSituation {
	js.Caches = caches
	return js
}

// rustCacheFinding is a release job restoring a rust-cache key family: the
// control names the action itself, the key being nothing the step spells.
func rustCacheFinding(job string) opaengine.Finding {
	return opaengine.Finding{Code: string(CodeCachePoisoning), Job: job, File: ".github/workflows/release.yml", Line: 22,
		Subject: "Swatinem/rust-cache@v2", Data: map[string]any{"uses": "Swatinem/rust-cache@v2"}}
}

// A writer of a poisoned cache is a job entered by another path in a run
// whose cache a release run reads, whatever caches it declares: code there
// holds the run's cache token and can save any key. Every such job is
// named.
func TestAScopedEnteredJobWritesTheCacheWhateverItSaves(t *testing.T) {
	preview, entry := privilegedPreview()
	sit := cacheSituation(map[string]JobSituation{
		"pr-preview/preview": preview,
		"ci/build":           {RefTriggers: []string{"push"}, CacheScopes: defaultScope},
		"ci/lint":            withCaches(JobSituation{RefTriggers: []string{"push"}, CacheScopes: defaultScope}, CacheFact{Key: "lint-cache", Mode: "both", Uses: "actions/cache@v5", Line: 9}),
	})
	findings := []opaengine.Finding{
		cacheFinding(), entry,
		finding("ISSUE-701", "ci/build", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-701", "ci/lint", map[string]any{"uses": "other/action@v1"}),
	}
	cache := cachePaths(assemblePaths(findings, sit))
	if len(cache) != 1 {
		t.Fatalf("want the cache path, got %+v", cache)
	}
	if b := NewPathBlock(cache[0], nil); b.EntryWriter != "runs of jobs `build` and `lint` from workflow `ci` and `preview` from workflow `pr-preview` can write the cache" {
		t.Errorf("every scoped entered job writes the cache: %+v", b.EntryWriter)
	}
}

// A job entered by another path that declares no cache at all still
// writes the cache: the path stands on it alone.
func TestAJobSavingNoMatchingCacheStillWrites(t *testing.T) {
	sit := cacheSituation(map[string]JobSituation{
		"ci/build": {RefTriggers: []string{"push"}, CacheScopes: defaultScope},
	})
	findings := []opaengine.Finding{
		cacheFinding(),
		finding("ISSUE-701", "ci/build", map[string]any{"uses": "some/action@v1"}),
	}
	cache := cachePaths(assemblePaths(findings, sit))
	if len(cache) != 1 || NewPathBlock(cache[0], nil).EntryWriter != "a run of job `build` from workflow `ci` can write the cache" {
		t.Errorf("a push run entered by a dependency writes the cache, got %+v", cache)
	}
}

// A job that runs on pull requests alone saves in the pull request's scope,
// never one the release run reads, even when it saves the very key.
func TestAPullRequestOnlyWriterDoesNotCount(t *testing.T) {
	sit := cacheSituation(map[string]JobSituation{
		"ci/test": withCaches(JobSituation{}, npmCache),
	})
	findings := []opaengine.Finding{
		cacheFinding(),
		finding("ISSUE-701", "ci/test", map[string]any{"uses": "some/action@v1"}),
	}
	if cache := cachePaths(assemblePaths(findings, sit)); len(cache) != 0 {
		t.Errorf("a pull request run writes no cache the release run reads, got %+v", cache)
	}
}

// A writer saving another key family still counts: the entry is the
// family the release job restores, not the action, and the writers are
// every scoped entered job.
func TestAWriterOfAnotherKeyFamilyCounts(t *testing.T) {
	release := cacheSituation(nil).Jobs["release"]
	sit := cacheSituation(map[string]JobSituation{
		"release":                withCaches(release, rustFamily("${{ matrix.job.os }}", "both")),
		"playground/build-macos": withCaches(JobSituation{RefTriggers: []string{"workflow_dispatch"}, CacheScopes: defaultScope}, rustFamily("${{ matrix.job.os }}", "both")),
		"ci/build":               withCaches(JobSituation{RefTriggers: []string{"push"}, CacheScopes: defaultScope}, rustFamily("v0-rust", "both")),
	})
	findings := []opaengine.Finding{
		rustCacheFinding("release"),
		finding("ISSUE-701", "playground/build-macos", map[string]any{"uses": "some/action@v1"}),
		finding("ISSUE-701", "ci/build", map[string]any{"uses": "other/action@v1"}),
	}
	cache := cachePaths(assemblePaths(findings, sit))
	if len(cache) != 1 {
		t.Fatalf("want the cache path, got %+v", cache)
	}
	b := NewPathBlock(cache[0], nil)
	if b.Entry != "Rust build cache, key prefix ${{ matrix.job.os }} (cache an untrusted run can write)" {
		t.Errorf("entry = %q", b.Entry)
	}
	if b.EntryWriter != "runs of jobs `build` from workflow `ci` and `build-macos` from workflow `playground` can write the cache" {
		t.Errorf("writer = %q", b.EntryWriter)
	}
}

// With no scoped entered job at all, no branch has a writer: the path is
// gone, every branch with it, and the cache findings are priced on their
// own.
func TestABranchWithNoWriterLeavesThePath(t *testing.T) {
	release := cacheSituation(nil).Jobs["release"]
	fork := []EntryFact{{Kind: EntryForkPR, State: "proven", Evidence: "on: pull_request", Subject: "pull_request"}}
	sit := cacheSituation(map[string]JobSituation{
		"other/release": withCaches(release, npmCache),
		"ci/test":       withCaches(JobSituation{ForkPR: fork}, npmCache),
	})
	second := cacheFinding()
	second.Job = "other/release"
	findings := []opaengine.Finding{cacheFinding(), second, entryFinding("ISSUE-207", "ci/test", "github.event.pull_request.title")}
	if cache := cachePaths(assemblePaths(findings, sit)); len(cache) != 0 {
		t.Errorf("no run that can write the cache runs untrusted code, got %+v", cache)
	}
}

// The entry of a poisoned cache path names the cache: the key family of a
// caching action, the manager of a setup action, the literal key of
// actions/cache.
func TestThePoisonedCacheEntryNamesTheCache(t *testing.T) {
	cases := []struct {
		name  string
		cache CacheFact
		f     opaengine.Finding
		want  string
		words string // how the sentence names the cache
	}{
		{"rust-cache", rustFamily("rustdesk-lib-cache-android-${{ matrix.job.target }}", "both"), rustCacheFinding("release"),
			"Rust build cache, key prefix rustdesk-lib-cache-android-${{ matrix.job.target }}",
			"can write the Rust build cache under the key prefix `rustdesk-lib-cache-android-${{ matrix.job.target }}` that `release` restores"},
		{"setup-node", CacheFact{Key: "setup-node-npm", Mode: "both", Prefix: true, Uses: "actions/setup-node@v5", Line: 22}, setupFinding("actions/setup-node@v5"),
			"npm cache of setup-node", "can write the npm cache of setup-node that `release` restores"},
		{"setup-go", CacheFact{Key: "setup-go", Mode: "both", Prefix: true, Uses: "actions/setup-go@v5", Line: 22}, setupFinding("actions/setup-go@v5"),
			"cache of setup-go", "can write the cache of setup-go that `release` restores"},
		{"setup-gradle", CacheFact{Key: "gradle", Mode: "both", Prefix: true, Uses: "gradle/actions/setup-gradle@v5", Line: 22}, setupFinding("gradle/actions/setup-gradle@v5"),
			"Gradle cache of setup-gradle", "can write the Gradle cache of setup-gradle that `release` restores"},
		{"pnpm", CacheFact{Key: "pnpm/action-setup", Mode: "both", Prefix: true, Uses: "pnpm/action-setup@v5", Line: 22}, setupFinding("pnpm/action-setup@v5"),
			"cache of pnpm/action-setup", "can write the cache of pnpm/action-setup that `release` restores"},
		{"actions/cache", npmCache, cacheFinding(), "npm-${{ hashFiles('**/package-lock.json') }}",
			"can write the cache `npm-${{ hashFiles('**/package-lock.json') }}` that `release` restores"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			release := cacheSituation(nil).Jobs["release"]
			writer := c.cache
			writer.Line = 3
			sit := cacheSituation(map[string]JobSituation{
				"release":            withCaches(release, c.cache),
				"pr-preview/preview": withCaches(JobSituation{PrivilegedTriggers: []string{"pull_request_target"}, CacheScopes: defaultScope}, writer),
			})
			_, entry := privilegedPreview()
			cache := cachePaths(assemblePaths([]opaengine.Finding{c.f, entry}, sit))
			if len(cache) != 1 || cache[0].Entry.Subject != c.want {
				t.Fatalf("want one path entered by %q, got %+v", c.want, cache)
			}
			if s := PathSentence(cache[0]); !strings.Contains(s, c.words) {
				t.Errorf("sentence = %q, want it to say %q", s, c.words)
			}
		})
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

// The best fix names a cache Plumber named by that name alone, and a
// literal key as the cache it is.
func TestTheBestFixNamesTheCache(t *testing.T) {
	for subject, want := range map[string]string{
		"pnpm cache of setup-node":             "(pnpm cache of setup-node)",
		"Rust build cache, key prefix v0-rust": "(Rust build cache, key prefix v0-rust)",
		"npm-key":                              "(cache npm-key)",
	} {
		p := wordingPath(EntryPoisonedCache, subject, CodeCachePoisoning)
		p.ID = "cache"
		got := BestFixSummary(&PlumberScoreResult{BestFix: &BestFix{PathID: "cache", Stays: "stays"}, Paths: []AttackPath{p}})
		if !strings.Contains(got, want) {
			t.Errorf("best fix = %q, want it to name %q", got, want)
		}
	}
}

// setupFinding is a release job restoring the built-in cache of a setup
// action: the control names the action.
func setupFinding(uses string) opaengine.Finding {
	return opaengine.Finding{Code: string(CodeCachePoisoning), Job: "release", File: ".github/workflows/release.yml", Line: 22,
		Subject: uses, Data: map[string]any{"uses": uses}}
}
