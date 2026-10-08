package situation_test

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/internal/testsupport/pipelines"
)

// feedsOf runs the facts policy on one GitHub workflow file's worth of
// jobs (one originFile, so the artifact branch applies) and returns the
// producer's feeds, sorted.
func feedsOf(t *testing.T, jobs []ir.Job, producer string) []string {
	t.Helper()
	for i := range jobs {
		jobs[i].OriginFile = ".github/workflows/release.yml"
	}
	r := evaluate(t, &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: jobs}, nil)
	got := append([]string{}, r.Jobs[producer].Feeds...)
	sort.Strings(got)
	return got
}

// TestArtifactExpressionNameMatchesOnlyItsLiteralParts pins the feeds edge
// for an artifact whose name holds an expression: it is wired to a
// consumer only when the literal text around the expression agrees with
// what the consumer downloads, never to every download of the run. A
// download with no name and no pattern takes every artifact of the run
// and stays fed by every producer.
func TestArtifactExpressionNameMatchesOnlyItsLiteralParts(t *testing.T) {
	jobs := []ir.Job{
		{Name: "windows-depends", Artifacts: []ir.ArtifactRef{{Name: "depends-${{ matrix.os }}-amd64", Mode: "produce"}}},
		{Name: "windows-app", Artifacts: []ir.ArtifactRef{{Pattern: "depends-windows*", Mode: "consume"}}},
		{Name: "docker-merge", Artifacts: []ir.ArtifactRef{{Pattern: "digest-*", Mode: "consume"}}},
		{Name: "release", Artifacts: []ir.ArtifactRef{{Pattern: "bundles-*", Mode: "consume"}}},
		{Name: "linux-only", Artifacts: []ir.ArtifactRef{{Name: "depends-linux-amd64", Mode: "consume"}}},
		{Name: "other-arch", Artifacts: []ir.ArtifactRef{{Name: "depends-linux-arm64", Mode: "consume"}}},
		{Name: "everything", Artifacts: []ir.ArtifactRef{{Mode: "consume"}}},
		{Name: "same-shape", Artifacts: []ir.ArtifactRef{{Name: "depends-${{ matrix.target }}-amd64", Mode: "consume"}}},
		{Name: "other-shape", Artifacts: []ir.ArtifactRef{{Name: "bundle-${{ matrix.os }}", Mode: "consume"}}},
	}
	want := []string{"everything", "linux-only", "same-shape", "windows-app"}
	if got := feedsOf(t, jobs, "windows-depends"); !reflect.DeepEqual(got, want) {
		t.Errorf("windows-depends.feeds = %v, want %v", got, want)
	}
}

// TestArtifactLiteralNameNeverMatchesALongerExpression pins that a plain
// produced name is matched against the consumer's name or pattern as a
// whole: `dist` is not `dist-${{ matrix.x }}` nor `dist-*`.
func TestArtifactLiteralNameNeverMatchesALongerExpression(t *testing.T) {
	jobs := []ir.Job{
		{Name: "build", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "produce"}}},
		{Name: "expr", Artifacts: []ir.ArtifactRef{{Name: "dist-${{ matrix.x }}", Mode: "consume"}}},
		{Name: "glob", Artifacts: []ir.ArtifactRef{{Pattern: "dist-*", Mode: "consume"}}},
		{Name: "exact", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "consume"}}},
		{Name: "pattern", Artifacts: []ir.ArtifactRef{{Pattern: "di*", Mode: "consume"}}},
	}
	want := []string{"exact", "pattern"}
	if got := feedsOf(t, jobs, "build"); !reflect.DeepEqual(got, want) {
		t.Errorf("build.feeds = %v, want %v", got, want)
	}
}

// TestDownloadArtifactPatternIsRecorded pins that the collector records a
// download-artifact step's `pattern:` input, so a download narrowed by a
// pattern is not read as a download of every artifact.
func TestDownloadArtifactPatternIsRecorded(t *testing.T) {
	file := filepath.Join(t.TempDir(), "release.yml")
	if err := os.WriteFile(file, []byte(`name: Release
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v5
        with:
          name: bundles-linux
          path: dist
  merge:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v5
        with:
          pattern: digest-*
          merge-multiple: true
`), 0o644); err != nil {
		t.Fatal(err)
	}
	p := pipelines.GitHubFromFiles(t, []string{file})
	r := evaluate(t, p, nil)
	if _, ok := r.Jobs["release/merge"]; !ok {
		t.Fatalf("no release/merge job in %v", r.Jobs)
	}
	if got := r.Jobs["release/build"].Feeds; len(got) != 0 {
		t.Errorf("a download narrowed to digest-* must not be fed by bundles-linux, got %v", got)
	}
}

// TestCacheEdgesFollowTheRunOrder pins that a cache edge goes from a
// writer to a reader only. Two jobs that both restore and save the same
// key (actions/cache) are a cycle; when one needs the other, the earlier
// one saves the key first and the later one then restores it with an
// exact hit and saves nothing, so only the earlier one feeds the later
// one. With no order between them, either can save first, and both
// edges stay.
func TestCacheEdgesFollowTheRunOrder(t *testing.T) {
	ordered := evaluate(t, &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{
		{Name: "a", Caches: []ir.CacheRef{{Key: "deps", Mode: "both"}}},
		{Name: "mid", Needs: []string{"a"}},
		{Name: "b", Needs: []string{"mid"}, Caches: []ir.CacheRef{{Key: "deps", Mode: "both"}}},
	}}, nil)
	if got := ordered.Jobs["a"].Feeds; !reflect.DeepEqual(got, []string{"b"}) {
		t.Errorf("a.feeds = %v, want [b] (a bare needs is no edge)", got)
	}
	if got := ordered.Jobs["b"].Feeds; len(got) != 0 {
		t.Errorf("b runs after a and cannot write the cache a restores, got b.feeds = %v", got)
	}

	unordered := evaluate(t, &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{
		{Name: "a", Caches: []ir.CacheRef{{Key: "deps", Mode: "both"}}},
		{Name: "b", Caches: []ir.CacheRef{{Key: "deps", Mode: "both"}}},
	}}, nil)
	if got := unordered.Jobs["a"].Feeds; !reflect.DeepEqual(got, []string{"b"}) {
		t.Errorf("unordered a.feeds = %v, want [b]", got)
	}
	if got := unordered.Jobs["b"].Feeds; !reflect.DeepEqual(got, []string{"a"}) {
		t.Errorf("unordered b.feeds = %v, want [a]", got)
	}

	// A restore-only job never writes: it feeds no one, whatever the order.
	readOnly := evaluate(t, &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{
		{Name: "writer", Caches: []ir.CacheRef{{Key: "deps", Mode: "save"}}},
		{Name: "reader", Caches: []ir.CacheRef{{Key: "deps", Mode: "restore"}}},
	}}, nil)
	if got := readOnly.Jobs["reader"].Feeds; len(got) != 0 {
		t.Errorf("reader.feeds = %v, want none", got)
	}
}

// feedsViaOf runs the facts policy on one GitHub workflow file's worth of
// jobs and returns the producer's feedsVia fact: per fed job, the kinds of
// edge that link the two.
func feedsViaOf(t *testing.T, jobs []ir.Job, producer string) map[string][]string {
	t.Helper()
	for i := range jobs {
		jobs[i].OriginFile = ".github/workflows/release.yml"
	}
	r := evaluate(t, &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: jobs}, nil)
	return r.Jobs[producer].FeedsVia
}

// TestFeedsViaArtifact pins the artifact kind: build uploads the artifact
// publish downloads, with no needs and no cache between them.
func TestFeedsViaArtifact(t *testing.T) {
	jobs := []ir.Job{
		{Name: "build", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "produce"}}},
		{Name: "publish", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "consume"}}},
	}
	want := map[string][]string{"publish": {"artifact"}}
	if got := feedsViaOf(t, jobs, "build"); !reflect.DeepEqual(got, want) {
		t.Errorf("build.feedsVia = %v, want %v", got, want)
	}
}

// TestFeedsViaCache pins the cache kind: a saves the key b restores.
func TestFeedsViaCache(t *testing.T) {
	jobs := []ir.Job{
		{Name: "a", Caches: []ir.CacheRef{{Key: "deps", Mode: "save"}}},
		{Name: "b", Caches: []ir.CacheRef{{Key: "deps", Mode: "restore"}}},
	}
	want := map[string][]string{"b": {"cache"}}
	if got := feedsViaOf(t, jobs, "a"); !reflect.DeepEqual(got, want) {
		t.Errorf("a.feedsVia = %v, want %v", got, want)
	}
}

// TestFeedsViaOutput pins the output kind on GitHub: b reads a's job
// outputs (needs.a.outputs.*) in a script, a with: value, an env value or
// an if:, the edge job outputs travel along. A bare needs: orders the two
// jobs and hands over nothing, so it is no edge. On GitLab, needs: also
// downloads the needed job's artifacts, so it stays an edge there.
func TestFeedsViaOutput(t *testing.T) {
	jobs := []ir.Job{
		{Name: "ci/a"},
		{Name: "ci/script", Needs: []string{"ci/a"}, Scripts: []string{"echo ${{ needs.a.outputs.version }}"}},
		{Name: "ci/with", Needs: []string{"ci/a"}, Uses: []ir.Action{{Uses: "x/y@v1", With: map[string]any{"tag": "${{ needs.a.outputs.tag }}"}}}},
		{Name: "ci/env", Needs: []string{"ci/a"}, Variables: map[string]string{"V": "${{ needs.a.outputs.v }}"}},
		{Name: "ci/if", Needs: []string{"ci/a"}, If: "needs.a.outputs.release == 'true'", Conditions: []string{"needs.a.outputs.release == 'true'"}},
		{Name: "ci/bare", Needs: []string{"ci/a"}, Scripts: []string{"make"}},
		{Name: "ci/other", Needs: []string{"ci/a"}, Scripts: []string{"echo ${{ needs.ab.outputs.v }}"}},
	}
	want := map[string][]string{"ci/env": {"output"}, "ci/if": {"output"}, "ci/script": {"output"}, "ci/with": {"output"}}
	if got := feedsViaOf(t, jobs, "ci/a"); !reflect.DeepEqual(got, want) {
		t.Errorf("a.feedsVia = %v, want %v", got, want)
	}
	gl := evaluate(t, &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, Jobs: []ir.Job{
		{Name: "build"}, {Name: "deploy", Needs: []string{"build"}},
	}}, nil)
	if got := gl.Jobs["build"].FeedsVia; !reflect.DeepEqual(got, map[string][]string{"deploy": {"output"}}) {
		t.Errorf("GitLab build.feedsVia = %v, want deploy via output", got)
	}
}

// TestFeedsViaTwoKindsOnOnePair pins that every kind linking one pair is
// listed, sorted: build uploads the artifact publish downloads and saves
// the cache key publish restores, and feeds still names publish once. A
// job feeding nothing carries an empty fact.
func TestFeedsViaTwoKindsOnOnePair(t *testing.T) {
	jobs := []ir.Job{
		{Name: "build", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "produce"}}, Caches: []ir.CacheRef{{Key: "deps", Mode: "save"}}},
		{Name: "publish", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "consume"}}, Caches: []ir.CacheRef{{Key: "deps", Mode: "restore"}}},
	}
	want := map[string][]string{"publish": {"artifact", "cache"}}
	if got := feedsViaOf(t, jobs, "build"); !reflect.DeepEqual(got, want) {
		t.Errorf("build.feedsVia = %v, want %v", got, want)
	}
	if got := feedsOf(t, jobs, "build"); !reflect.DeepEqual(got, []string{"publish"}) {
		t.Errorf("build.feeds = %v, want [publish]", got)
	}
	if got := feedsViaOf(t, jobs, "publish"); len(got) != 0 {
		t.Errorf("publish.feedsVia = %v, want empty", got)
	}
}
