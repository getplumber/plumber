package situation_test

import (
	"reflect"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// cacheFeeds runs the facts policy on two jobs, the writer saving saved and
// the reader restoring restored, and returns the writer's feeds.
func cacheFeeds(t *testing.T, saved, restored ir.CacheRef) []string {
	t.Helper()
	r := evaluate(t, &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{
		{Name: "writer", Caches: []ir.CacheRef{saved}},
		{Name: "reader", Caches: []ir.CacheRef{restored}},
	}}, nil)
	return r.Jobs["writer"].Feeds
}

// TestTwoKeyFamiliesOnOnePrefixFeedEachOther pins the cache edge between
// two key families (Prefix on both sides, a caching action keying on a
// fixed prefix then a run-time hash): the saved key is the saved prefix
// followed by something, and the restore takes the most recent cache under
// the restored prefix, so they can meet when the prefixes are equal or one
// starts with the other, and never otherwise.
func TestTwoKeyFamiliesOnOnePrefixFeedEachOther(t *testing.T) {
	family := func(key, mode string) ir.CacheRef { return ir.CacheRef{Key: key, Mode: mode, Prefix: true} }
	cases := []struct {
		name            string
		saved, restored ir.CacheRef
		feeds           bool
	}{
		{"equal prefixes", family("${{ matrix.os }}-build", "both"), family("${{ matrix.os }}-build", "both"), true},
		{"the saved prefix is longer", family("v0-rust-build", "save"), family("v0-rust", "restore"), true},
		{"the restored prefix is longer", family("v0-rust", "save"), family("v0-rust-build", "restore"), true},
		{"different families", family("${{ matrix.os }}-build", "both"), family("lib-android-build", "both"), false},
		{"a restore-only family writes nothing", family("v0-rust", "restore"), family("v0-rust", "restore"), false},
		{"an exact key under the restored prefix", ir.CacheRef{Key: "v0-rust-abc", Mode: "save"}, family("v0-rust", "restore"), true},
		{"an exact restore is not a family", family("v0-rust", "save"), ir.CacheRef{Key: "v0-rust-build", Mode: "restore"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := cacheFeeds(t, c.saved, c.restored)
			if want := c.feeds; (len(got) == 1 && got[0] == "reader") != want {
				t.Errorf("writer.feeds = %v, want feeding reader: %v", got, want)
			}
		})
	}
}

// TestFeedsViaCacheBetweenKeyFamilies pins that an edge between two key
// families is a cache edge, and only that.
func TestFeedsViaCacheBetweenKeyFamilies(t *testing.T) {
	jobs := []ir.Job{
		{Name: "a", Caches: []ir.CacheRef{{Key: "v0-rust", Mode: "both", Prefix: true}}},
		{Name: "b", Caches: []ir.CacheRef{{Key: "v0-rust-b", Mode: "restore", Prefix: true}}},
	}
	want := map[string][]string{"b": {"cache"}}
	if got := feedsViaOf(t, jobs, "a"); !reflect.DeepEqual(got, want) {
		t.Errorf("a.feedsVia = %v, want %v", got, want)
	}
}

// TestTheJobCachesAreAFact pins that every cache a job declares is in its
// facts, with the step that declares it, so the paths can match what a
// release job restores against what another job saves. Jobs sharing a
// name merge their caches. Key is what the edges match on, family the
// name a path prints (the key itself when the collector gives none).
func TestTheJobCachesAreAFact(t *testing.T) {
	r := evaluate(t, &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{
		{Name: "release", Caches: []ir.CacheRef{{Key: "v0-rust-release", Family: "v0-rust", Mode: "both", Prefix: true, Uses: "Swatinem/rust-cache@v2", Line: 12}}},
		{Name: "release", Caches: []ir.CacheRef{{Key: "deps", Mode: "restore", Uses: "actions/cache/restore@v5", Line: 30}}},
		{Name: "lint"},
	}}, nil)
	want := []cacheFact{
		{Key: "deps", Family: "deps", Mode: "restore", Uses: "actions/cache/restore@v5", Line: 30},
		{Key: "v0-rust-release", Family: "v0-rust", Mode: "both", Prefix: true, Uses: "Swatinem/rust-cache@v2", Line: 12},
	}
	if got := r.Jobs["release"].Caches; !reflect.DeepEqual(got, want) {
		t.Errorf("release.caches = %+v, want %+v", got, want)
	}
	if got := r.Jobs["lint"].Caches; len(got) != 0 {
		t.Errorf("lint declares no cache, got %+v", got)
	}
}
