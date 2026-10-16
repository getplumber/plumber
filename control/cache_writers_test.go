package control

import (
	"reflect"
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// The writer's declared save names the cache when its key template
// matches what the restoring job reads: the sentence says which cache
// code in the writer can write, the edge itself being the grant's.
func TestADeclaredMatchingSaveNamesTheCache(t *testing.T) {
	w := withCaches(triageWriter, npmCache)
	p := cachePathOf(t, []opaengine.Finding{cacheFinding(), commentInjection()}, cacheSituation(map[string]JobSituation{"triage/label": w}))
	if s := PathSentence(p); !strings.HasPrefix(s, "Code running in `triage/label` can write the cache `npm-${{ hashFiles('**/package-lock.json') }}` that `release` restores, since `cache-mode: write` lifts") {
		t.Errorf("sentence = %q", s)
	}
}

// A writer declaring no save, a save of another key family, or a save it
// turned off (cache: false records the step as restore only) still writes
// the cache: code in a run granted write can save any key. The sentence
// then names no cache.
func TestAWriterWithoutAMatchingSaveStillWritesUnnamed(t *testing.T) {
	other := CacheFact{Key: "lint-cache", Mode: "both", Uses: "actions/cache@v5"}
	off := npmCache
	off.Mode = "restore"
	for name, w := range map[string]JobSituation{
		"no save":      triageWriter,
		"other family": withCaches(triageWriter, other),
		"save off":     withCaches(triageWriter, off),
	} {
		p := cachePathOf(t, []opaengine.Finding{cacheFinding(), commentInjection()}, cacheSituation(map[string]JobSituation{"triage/label": w}))
		if s := PathSentence(p); !strings.HasPrefix(s, "Code running in `triage/label` can write caches that `release` restores, since") {
			t.Errorf("%s: sentence = %q", name, s)
		}
	}
}

// Restorers reading different caches leave the sentence unnamed, even
// when the writer's save matches one of them.
func TestRestorersOfDifferentCachesReadUnnamed(t *testing.T) {
	lint := withCaches(JobSituation{RestoresCache: true}, CacheFact{Key: "lint-cache", Mode: "restore", Uses: "actions/cache@v5"})
	w := withCaches(triageWriter, npmCache)
	p := cachePathOf(t, []opaengine.Finding{cacheFinding(), commentInjection()}, cacheSituation(map[string]JobSituation{"triage/label": w, "ci/lint": lint}))
	if s := PathSentence(p); !strings.HasPrefix(s, "Code running in `triage/label` can write caches that `ci/lint` and `release` restore, since") {
		t.Errorf("sentence = %q", s)
	}
}

// A pull_request_target entry runs in the default branch's context, and a
// job granted cache write saves there: the writer is entered from the
// base context.
func TestAPullRequestTargetEntryWritesThroughTheGrant(t *testing.T) {
	head := entryFinding("ISSUE-804", "triage/label", "github.event.pull_request.head.sha")
	p := cachePathOf(t, []opaengine.Finding{cacheFinding(), head}, cacheSituation(nil))
	if !reflect.DeepEqual(p.Jobs, []string{"triage/label", "release"}) {
		t.Errorf("jobs = %v", p.Jobs)
	}
}

// A job whose runs save nothing (cache-mode read or none, or a low-trust
// event without the grant: no save scope) writes no cache, whatever code
// runs in it.
func TestAJobSavingNothingWritesNoCache(t *testing.T) {
	w := triageWriter
	w.CacheScopes = nil
	sit := cacheSituation(map[string]JobSituation{"triage/label": w})
	if cache := cachePaths(assemblePaths([]opaengine.Finding{cacheFinding(), commentInjection()}, sit)); len(cache) != 0 {
		t.Errorf("a run saving nothing writes no cache, got %+v", cache)
	}
}

// The entered run's scope is the event proving the entry: a fork pull
// request run saves in its merge ref's scope, a base-context run in the
// default branch's when the job saves there, and any other entry in every
// scope the job saves under.
func TestCacheWriterScopeIsTheEnteredRunsScope(t *testing.T) {
	js := JobSituation{CacheScopes: []string{"default", "pull_request"}}
	for kind, want := range map[EntryKind][]string{
		EntryForkPR: {"pull_request"}, EntryPRTarget: {"default"}, EntryMutableDependency: {"default", "pull_request"},
	} {
		if got := cacheWriterScope(kind, js); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: scope %v, want %v", kind, got, want)
		}
	}
	if got := cacheWriterScope(EntryPRTarget, JobSituation{CacheScopes: []string{"pull_request"}}); got != nil {
		t.Errorf("a base-context run of a job saving only in pull requests saves nothing, got %v", got)
	}
}

// Every edge from the writer to a job it reaches carries its state, the
// same whatever order the branches are walked in.
func TestCacheEdgesCarryTheirState(t *testing.T) {
	sit := cacheSituation(map[string]JobSituation{"ci/test": {RestoresCache: true}})
	for i := 0; i < 10; i++ {
		p := cachePathOf(t, []opaengine.Finding{cacheFinding(), commentInjection()}, sit)
		if !reflect.DeepEqual(p.cacheWriterStates, map[string]string{"ci/test": "proven", "release": "proven"}) {
			t.Fatalf("states = %v", p.cacheWriterStates)
		}
	}
	if got := weakerCacheWriterState("proven", "unknown"); got != "unknown" {
		t.Errorf("unknown must win, got %q", got)
	}
}
