package github

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// fakeRepo is what a fake GitHub knows about one repository. A ref
// missing from refs is absent: no tag, no branch, no object.
type fakeRepo struct {
	unreadable error
	info       repoCacheEntry
	releases   []releaseFact
	refs       map[string]refFacts
	advisories []advisoryInfo
	// advisoryErr fails the advisory lookup, as storeAdvisories records it.
	advisoryErr error
	tags        map[string]string
}

// worldClient is a metadata client whose loaders answer from world, keyed
// by owner/repo, and record what they were asked.
func worldClient(t *testing.T, world map[string]*fakeRepo) (*GitHubMetadataClient, *[][]repoRequest, *[][]repoKey) {
	t.Helper()
	c := NewGitHubMetadataClientForHost("")
	c.disabled = false
	c.rest, c.gql = nil, nil
	c.dotcom = true
	var loads [][]repoRequest
	var tagLoads [][]repoKey
	c.load = func(reqs []repoRequest) {
		loads = append(loads, slices.Clone(reqs))
		for _, r := range reqs {
			key := r.owner + "/" + r.repo
			w := world[key]
			if w == nil {
				w = &fakeRepo{unreadable: errors.New("Could not resolve to a Repository")}
			}
			if r.info {
				entry := w.info
				entry.fetched, entry.err = true, w.unreadable
				c.repoCache[key] = entry
				c.releases[key] = w.releases
			}
			if r.advisories {
				if w.advisoryErr != nil {
					c.storeAdvisories(r.owner, r.repo, nil, w.advisoryErr)
				} else {
					c.advisoryCache[key] = w.advisories
				}
			}
			for _, ref := range r.refs {
				f, ok := w.refs[ref]
				switch {
				case w.unreadable != nil:
					f = refFacts{failed: true}
				case !ok:
					f = refFacts{objectChecked: true}
				}
				c.refFacts[key+"@"+ref] = &f
			}
		}
	}
	c.loadTags = func(repos []repoKey) {
		tagLoads = append(tagLoads, slices.Clone(repos))
		for _, r := range repos {
			key := r.owner + "/" + r.repo
			if w := world[key]; w != nil && w.tags != nil {
				c.sha2tagCache[key] = w.tags
			} else {
				c.sha2tagCache[key] = map[string]string{}
			}
		}
	}
	return c, &loads, &tagLoads
}

func commitObj(oid string) *gitObject { return &gitObject{Typename: "Commit", Oid: oid} }

func tagObj(oid string, target *gitObject) *gitObject {
	return &gitObject{Typename: "Tag", Oid: oid, Target: target}
}

func ptr[T any](v T) *T { return &v }

var (
	shaA = strings.Repeat("a", 40)
	shaB = strings.Repeat("b", 40)
	shaC = strings.Repeat("c", 40)
)

// TestPrefetch_OneLoadForEveryReference: every reference of a run is asked
// in one load, one request per repository, each ref once, whatever the
// sub-path; an unsafe reference is never asked.
func TestPrefetch_OneLoadForEveryReference(t *testing.T) {
	c, loads, _ := worldClient(t, map[string]*fakeRepo{})
	c.Prefetch([]string{"a/x@v1", "a/x/sub@v1", "a/x@v2", "b/y/.github/workflows/w.yml@main", "c/z@../../evil", "./local"})
	if len(*loads) != 1 {
		t.Fatalf("loads = %d, want 1", len(*loads))
	}
	got := (*loads)[0]
	want := []repoRequest{
		{owner: "a", repo: "x", info: true, advisories: true, refs: []string{"v1", "v2"}},
		{owner: "b", repo: "y", info: true, advisories: true, refs: []string{"main"}},
	}
	if len(got) != len(want) {
		t.Fatalf("requests = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i].owner != want[i].owner || got[i].repo != want[i].repo || got[i].info != want[i].info ||
			got[i].advisories != want[i].advisories || !slices.Equal(got[i].refs, want[i].refs) {
			t.Errorf("request %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	// A second prefetch of the same references asks nothing.
	c.Prefetch([]string{"a/x@v1", "b/y@main"})
	if len(*loads) != 1 {
		t.Errorf("loads = %d after a repeated prefetch, want 1", len(*loads))
	}
}

// TestPrefetch_ListsTagsOnlyForAShaPinWithAdvisories: the tag listing maps a
// SHA pin to a version for the advisory filter, so it is read only where a
// SHA pin meets advisories, in one batch.
func TestPrefetch_ListsTagsOnlyForAShaPinWithAdvisories(t *testing.T) {
	adv := []advisoryInfo{{GhsaID: "GHSA-x", VulnerableRange: "< 2"}}
	c, _, tagLoads := worldClient(t, map[string]*fakeRepo{
		"a/sha-adv":   {advisories: adv, refs: map[string]refFacts{shaA: {objectChecked: true, object: commitObj(shaA)}}},
		"b/sha-clean": {refs: map[string]refFacts{shaB: {objectChecked: true, object: commitObj(shaB)}}},
		"c/tag-adv":   {advisories: adv},
		"d/sha-adv2":  {advisories: adv},
	})
	c.Prefetch([]string{"a/sha-adv@" + shaA, "b/sha-clean@" + shaB, "c/tag-adv@v1", "d/sha-adv2@" + shaC})
	if len(*tagLoads) != 1 {
		t.Fatalf("tag loads = %d, want 1", len(*tagLoads))
	}
	if got := (*tagLoads)[0]; !slices.Equal(got, []repoKey{{"a", "sha-adv"}, {"d", "sha-adv2"}}) {
		t.Errorf("tag listing for %v, want a/sha-adv and d/sha-adv2", got)
	}
}

// TestPrefetch_LoadsEachLatestReleaseTagInOneMoreLoad: the latest release
// is only known once the releases are read, and its commit (ISSUE-709's
// LatestReleaseSha) comes from that tag's ref, so every repository's
// latest tag is loaded in one more load, never one per repository; a tag
// already asked is not asked again.
func TestPrefetch_LoadsEachLatestReleaseTagInOneMoreLoad(t *testing.T) {
	c, loads, _ := worldClient(t, map[string]*fakeRepo{
		"a/x": {releases: []releaseFact{{tag: "v2.0.0"}, {tag: "v1.0.0"}}, refs: map[string]refFacts{"v2.0.0": {tag: commitObj(shaB)}}},
		"b/y": {releases: []releaseFact{{tag: "v3.1.0"}}},
		"c/z": {},
	})
	c.Prefetch([]string{"a/x@v1.0.0", "b/y@v3.1.0", "c/z@main"})
	if len(*loads) != 2 {
		t.Fatalf("loads = %+v, want 2", *loads)
	}
	second := (*loads)[1]
	if len(second) != 1 || second[0].owner != "a" || !slices.Equal(second[0].refs, []string{"v2.0.0"}) || second[0].info {
		t.Errorf("second load = %+v, want a/x@v2.0.0 only", second)
	}
	n := len(*loads)
	if m := c.Resolve("a/x@v1.0.0"); m.LatestTag != "v2.0.0" || m.LatestReleaseSha != shaB {
		t.Errorf("latest = %q %q, want v2.0.0 %s", m.LatestTag, m.LatestReleaseSha, shaB)
	}
	if len(*loads) != n {
		t.Errorf("Resolve loaded %d more times, want 0", len(*loads)-n)
	}
}

// TestResolve_LoadsWhatWasNotPrefetched: a reference no prefetch asked is
// loaded on its own, through the same loader.
func TestResolve_LoadsWhatWasNotPrefetched(t *testing.T) {
	c, loads, _ := worldClient(t, map[string]*fakeRepo{"o/r": {}})
	c.Resolve("o/r@v1")
	if len(*loads) == 0 {
		t.Fatal("no load")
	}
	asked := map[string]bool{}
	for _, reqs := range *loads {
		for _, r := range reqs {
			asked["info"] = asked["info"] || r.info
			for _, ref := range r.refs {
				asked[ref] = true
			}
		}
	}
	if !asked["info"] || !asked["v1"] {
		t.Errorf("loads = %+v, want the repository and v1", *loads)
	}
	n := len(*loads)
	c.Resolve("o/r@v1")
	if len(*loads) != n {
		t.Error("a resolved reference was loaded again")
	}
}

// TestResolve_TagFromFacts: an annotated tag reads as a tag on the commit
// it points at; a branch of the same name makes it ambiguous (ISSUE-402);
// the release says whether it is immutable; the latest release and its
// commit come from the release listing.
func TestResolve_TagFromFacts(t *testing.T) {
	c, _, _ := worldClient(t, map[string]*fakeRepo{"o/r": {
		info:     repoCacheEntry{stars: 7, fullName: "o/r"},
		releases: []releaseFact{{tag: "v1.1.0"}, {tag: "v2.0.0-rc1"}, {tag: "v1.0.0"}},
		refs: map[string]refFacts{
			"v1.0.0": {
				tag:     tagObj("tagobject", commitObj(shaA)),
				branch:  true,
				release: ptr(true),
			},
			"v1.1.0": {tag: commitObj(shaB)},
		},
	}})
	m := c.Resolve("o/r@v1.0.0")
	if m.RefKind != "tag" || !m.RefExists || m.TagSha != shaA || !m.RefIsAmbiguous || !m.RefIsImmutableRelease {
		t.Errorf("meta = %+v", m)
	}
	if m.LatestTag != "v1.1.0" || m.LatestReleaseSha != shaB || m.StargazersCount != 7 {
		t.Errorf("latest = %q %q, stars %d", m.LatestTag, m.LatestReleaseSha, m.StargazersCount)
	}
}

// TestResolve_LightweightTagAndBranch: a lightweight tag is its commit; a
// branch-only ref is a branch.
func TestResolve_LightweightTagAndBranch(t *testing.T) {
	c, _, _ := worldClient(t, map[string]*fakeRepo{"o/r": {refs: map[string]refFacts{
		"v1":   {tag: commitObj(shaA)},
		"main": {branch: true, objectChecked: true, object: commitObj(shaB)},
	}}})
	if m := c.Resolve("o/r@v1"); m.RefKind != "tag" || m.TagSha != shaA || m.RefIsAmbiguous || m.RefIsImmutableRelease {
		t.Errorf("v1 = %+v", m)
	}
	if m := c.Resolve("o/r@main"); m.RefKind != "branch" || !m.RefExists {
		t.Errorf("main = %+v", m)
	}
}

// TestResolve_CommitPinsFromFacts covers the SHA pin outcomes ISSUE-707
// reads: present, absent on a readable repository, and every case where
// absence is not proven.
func TestResolve_CommitPinsFromFacts(t *testing.T) {
	cases := []struct {
		name       string
		repo       *fakeRepo
		wantKind   string
		wantAbsent bool
		wantCommit string
	}{
		{"commit", &fakeRepo{refs: map[string]refFacts{shaA: {objectChecked: true, object: commitObj(shaA)}}}, "commit", false, ""},
		{"absent on a readable repo", &fakeRepo{}, "", true, ""},
		{"unreadable repo", &fakeRepo{unreadable: errors.New("Could not resolve")}, "", false, ""},
		{"failed query", &fakeRepo{refs: map[string]refFacts{shaA: {failed: true}}}, "", false, ""},
		{"tag object to a commit", &fakeRepo{refs: map[string]refFacts{shaA: {objectChecked: true, object: tagObj(shaA, commitObj(shaB))}}}, "commit", false, shaB},
		{"tag object chain", &fakeRepo{refs: map[string]refFacts{shaA: {objectChecked: true, object: tagObj(shaA, tagObj(shaC, commitObj(shaB)))}}}, "commit", false, shaB},
		{"tag object to a tree", &fakeRepo{refs: map[string]refFacts{shaA: {objectChecked: true, object: tagObj(shaA, &gitObject{Typename: "Tree", Oid: shaB})}}}, "", false, ""},
		{"tag object chain cut short", &fakeRepo{refs: map[string]refFacts{shaA: {objectChecked: true, object: tagObj(shaA, tagObj(shaC, nil))}}}, "", false, ""},
		{"tree", &fakeRepo{refs: map[string]refFacts{shaA: {objectChecked: true, object: &gitObject{Typename: "Tree", Oid: shaA}}}}, "", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _, _ := worldClient(t, map[string]*fakeRepo{"o/r": tc.repo})
			m := c.Resolve("o/r@" + shaA)
			if m.RefKind != tc.wantKind || m.RefKnownAbsent != tc.wantAbsent || m.RefCommitSha != tc.wantCommit {
				t.Errorf("meta = kind %q absent %v commit %q, want %q %v %q", m.RefKind, m.RefKnownAbsent, m.RefCommitSha, tc.wantKind, tc.wantAbsent, tc.wantCommit)
			}
		})
	}
}

// TestResolve_UncheckedObjectAbstains: a ref no object lookup could be sent
// for is never reported absent.
func TestResolve_UncheckedObjectAbstains(t *testing.T) {
	c, _, _ := worldClient(t, map[string]*fakeRepo{"o/r": {refs: map[string]refFacts{"odd~ref": {}}}})
	if m := c.Resolve("o/r@odd~ref"); m.RefKnownAbsent || m.RefExists {
		t.Errorf("meta = %+v, want unknown", m)
	}
}

// TestResolveTagSha_FromFacts: the `# vX` comment's tag resolves through
// the same facts, peeled to its commit.
func TestResolveTagSha_FromFacts(t *testing.T) {
	c, _, _ := worldClient(t, map[string]*fakeRepo{"o/r": {refs: map[string]refFacts{"v4.1.0": {tag: tagObj("obj", commitObj(shaA))}}}})
	if got := c.ResolveTagSha("o/r", "v4.1.0"); got != shaA {
		t.Errorf("ResolveTagSha = %q, want %q", got, shaA)
	}
	if got := c.ResolveTagSha("o/r", "v9"); got != "" {
		t.Errorf("ResolveTagSha(v9) = %q, want empty", got)
	}
}

// TestResolve_ShaPinMapsToItsVersionForAdvisories: a SHA pin is placed in
// an advisory's range through the tag listing.
func TestResolve_ShaPinMapsToItsVersionForAdvisories(t *testing.T) {
	c, _, _ := worldClient(t, map[string]*fakeRepo{"o/r": {
		advisories: []advisoryInfo{{GhsaID: "GHSA-old", VulnerableRange: "< 2.0.0", Severity: "high"}},
		refs:       map[string]refFacts{shaA: {objectChecked: true, object: commitObj(shaA)}},
		tags:       map[string]string{shaA: "v1.5.0"},
	}})
	m := c.Resolve("o/r@" + shaA)
	if !slices.Equal(m.Advisories, []string{"GHSA-old"}) || m.AdvisorySeverities["GHSA-old"] != "high" {
		t.Errorf("advisories = %v %v", m.Advisories, m.AdvisorySeverities)
	}
}

// Test_latestReleaseTag_picksTheHighestCleanSemver pins the ISSUE-709
// latest-release pick across the releases listing: the highest semver
// wins (v10.0.0 over v3.x, never a lexical order or the listing order), a
// draft or a prerelease is skipped whatever its version, and a
// clean-looking release whose semver carries a prerelease segment
// (`v3.1.0-node20`, published with prerelease false) is rejected.
func Test_latestReleaseTag_picksTheHighestCleanSemver(t *testing.T) {
	releases := []releaseFact{
		{tag: "v2.0.0"}, {tag: "v3.1.0-node20"}, {tag: "v99.0.0", draft: true}, {tag: "v98.0.0", prerelease: true},
		{tag: "codeql-bundle-v2.25.2"}, {tag: "v9.9.9"}, {tag: "v10.0.0"},
	}
	c, _, _ := worldClient(t, map[string]*fakeRepo{"acme/widget": {releases: releases}})
	if got := c.latestReleaseTag("acme", "widget"); got != "v10.0.0" {
		t.Fatalf("latestReleaseTag = %q, want v10.0.0", got)
	}
	// The guard on its own: a listing whose only higher entry is
	// `v3.1.0-node20` still answers the clean v2.0.0.
	if got := latestSemverRelease([]releaseFact{{tag: "v2.0.0"}, {tag: "v3.1.0-node20"}}); got != "v2.0.0" {
		t.Fatalf("latestSemverRelease = %q, want v2.0.0", got)
	}
}

// Test_resolveTag_dereferencesAnAnnotatedTag: an annotated tag names a tag
// object, and the commit it points at is what the ref-version-mismatch
// enrichment compares, never the tag object's own SHA. A lightweight tag
// answers its commit directly.
func Test_resolveTag_dereferencesAnAnnotatedTag(t *testing.T) {
	c, _, _ := worldClient(t, map[string]*fakeRepo{"foo/bar": {
		refs: map[string]refFacts{
			"v7": {tag: tagObj(shaA, commitObj(shaB))},
			"v8": {tag: commitObj(shaC)},
		},
	}})
	if sha, ok := c.resolveTag("foo", "bar", "v7"); !ok || sha != shaB {
		t.Fatalf("resolveTag(v7) = %q %v, want the dereferenced commit %q", sha, ok, shaB)
	}
	if sha, ok := c.resolveTag("foo", "bar", "v8"); !ok || sha != shaC {
		t.Fatalf("resolveTag(v8) = %q %v, want %q", sha, ok, shaC)
	}
}

// Test_commitResolves_triState is the ISSUE-707 correctness guard: a
// commit lookup must distinguish a definitive answer (the SHA is absent
// upstream, or names an object that is no commit) from a lookup that
// failed or could not be sent. Only the confirmed-absent case may drive
// impostor-commit.
func Test_commitResolves_triState(t *testing.T) {
	c, _, _ := worldClient(t, map[string]*fakeRepo{"actions/checkout": {refs: map[string]refFacts{
		shaA:    {objectChecked: true, object: commitObj(shaA)},
		shaB:    {objectChecked: true, object: tagObj(shaB, commitObj(shaA))},
		shaC:    {failed: true},
		"odd~1": {},
	}}})
	cases := []struct {
		name        string
		ref         string
		wantExists  bool
		wantChecked bool
	}{
		{"present SHA resolves", shaA, true, true},
		{"absent SHA is confirmed", strings.Repeat("d", 40), false, true},
		{"tag object is no commit", shaB, false, true},
		{"failed lookup is unverified", shaC, false, false},
		{"ref no lookup was sent for is unverified", "odd~1", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exists, checked := c.commitResolves("actions", "checkout", tc.ref)
			if exists != tc.wantExists || checked != tc.wantChecked {
				t.Fatalf("commitResolves = (exists=%v, checked=%v), want (exists=%v, checked=%v)", exists, checked, tc.wantExists, tc.wantChecked)
			}
		})
	}
}

// Test_tagObjectResolves covers the ISSUE-401 dereference step. A pin
// can name an annotated tag OBJECT rather than the commit that tag points
// at (what `git rev-parse v1.2.3` returns without `^{commit}`). The
// tri-state contract matches commitResolves: checked is true only on a
// definitive answer.
func Test_tagObjectResolves(t *testing.T) {
	const (
		tagObjectSHA = "7088e561eb65bb68695d245aa206f005ef30921d"
		commitSHA    = "a7487c7e89a18df4991f7f222e4898a00d66ddda"
		absentSHA    = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
		gatedSHA     = "ffffffffffffffffffffffffffffffffffffffff"
		nestedSHA    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		treeTagSHA   = "2222222222222222222222222222222222222222"
		deepSHA      = "3333333333333333333333333333333333333333"
	)
	deep := commitObj(commitSHA)
	for range maxTagObjectDepth + 1 {
		deep = tagObj(deepSHA, deep)
	}
	c, _, _ := worldClient(t, map[string]*fakeRepo{"pnpm/action-setup": {refs: map[string]refFacts{
		tagObjectSHA: {objectChecked: true, object: tagObj(tagObjectSHA, commitObj(commitSHA))},
		gatedSHA:     {failed: true},
		nestedSHA:    {objectChecked: true, object: tagObj(nestedSHA, tagObj(tagObjectSHA, commitObj(commitSHA)))},
		treeTagSHA:   {objectChecked: true, object: tagObj(treeTagSHA, &gitObject{Typename: "Tree", Oid: commitSHA})},
		deepSHA:      {objectChecked: true, object: deep},
	}}})
	cases := []struct {
		name        string
		sha         string
		wantCommit  string
		wantExists  bool
		wantChecked bool
	}{
		{"annotated tag object dereferences to its commit", tagObjectSHA, commitSHA, true, true},
		{"absent SHA is confirmed", absentSHA, "", false, true},
		{"failed lookup is unverified", gatedSHA, "", false, false},
		// ^{commit} semantics: a tag object may point at another tag
		// object, and the walk must follow it to the commit.
		{"nested tag object dereferences through to the commit", nestedSHA, commitSHA, true, true},
		{"a chain past the depth cap abstains", deepSHA, "", false, false},
		{"tag object pointing at a tree is not a commit pin", treeTagSHA, "", false, false},
		// A non-SHA ref cannot be a tag object SHA, so the answer is
		// definitive without a lookup.
		{"non-SHA ref is definitively not a tag object", "v99", "", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			commit, exists, checked := c.tagObjectResolves("pnpm", "action-setup", tc.sha)
			if commit != tc.wantCommit || exists != tc.wantExists || checked != tc.wantChecked {
				t.Fatalf("tagObjectResolves = (%q, exists=%v, checked=%v), want (%q, exists=%v, checked=%v)",
					commit, exists, checked, tc.wantCommit, tc.wantExists, tc.wantChecked)
			}
		})
	}
}
