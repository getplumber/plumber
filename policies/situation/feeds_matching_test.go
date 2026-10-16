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

// TestFeedsViaArtifact pins the artifact_executed kind: build uploads the
// artifact publish downloads, with no needs and no cache between them.
// publish runs no script and calls no action on the download, so its
// consumption is unknown, read conservatively as artifact_executed (the
// safe error: crossing with the full reach, never pretending the artifact
// is only moved).
func TestFeedsViaArtifact(t *testing.T) {
	jobs := []ir.Job{
		{Name: "build", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "produce"}}},
		{Name: "publish", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "consume"}}},
	}
	want := map[string][]string{"publish": {"artifact_executed"}}
	if got := feedsViaOf(t, jobs, "build"); !reflect.DeepEqual(got, want) {
		t.Errorf("build.feedsVia = %v, want %v", got, want)
	}
}

// TestFeedsViaArtifactOnGitLabStaysTheBareKind pins that the typed
// artifact_executed/artifact_altered split is GitHub-only: a GitLab
// produce/consume pair keeps the untyped "artifact" kind, whatever the
// consumer job does, this task not touching GitLab's own model.
func TestFeedsViaArtifactOnGitLabStaysTheBareKind(t *testing.T) {
	gl := evaluate(t, &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{
			{Name: "build", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "produce"}}},
			{Name: "deploy", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "consume"}}},
		},
	}, nil)
	want := map[string][]string{"deploy": {"artifact"}}
	if got := gl.Jobs["build"].FeedsVia; !reflect.DeepEqual(got, want) {
		t.Errorf("GitLab build.feedsVia = %v, want %v", got, want)
	}
}

// TestFeedsViaArtifactAltered pins the artifact_altered kind: build
// uploads dist, release downloads it and only ships it on with a release
// action, running no script of its own: the download is moved, released
// or published, never executed.
func TestFeedsViaArtifactAltered(t *testing.T) {
	jobs := []ir.Job{
		{Name: "build", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "produce"}}},
		{
			Name:      "release",
			Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "consume"}},
			Uses:      []ir.Action{{Uses: "softprops/action-gh-release@v1", With: map[string]any{"files": "dist/*"}}},
		},
	}
	want := map[string][]string{"release": {"artifact_altered"}}
	if got := feedsViaOf(t, jobs, "build"); !reflect.DeepEqual(got, want) {
		t.Errorf("build.feedsVia = %v, want %v", got, want)
	}
}

// TestFeedsViaArtifactExecutedWhenConsumerAlsoRunsAScript pins that a
// known release/upload action alone never reads as artifact_altered when
// the consumer also runs a script beyond that pattern: one unrelated run
// step makes the whole edge artifact_executed, the conservative default.
func TestFeedsViaArtifactExecutedWhenConsumerAlsoRunsAScript(t *testing.T) {
	jobs := []ir.Job{
		{Name: "build", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "produce"}}},
		{
			Name:      "release",
			Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "consume"}},
			Uses:      []ir.Action{{Uses: "softprops/action-gh-release@v1", With: map[string]any{"files": "dist/*"}}},
			Scripts:   []string{"./dist/app --self-test"},
		},
	}
	want := map[string][]string{"release": {"artifact_executed"}}
	if got := feedsViaOf(t, jobs, "build"); !reflect.DeepEqual(got, want) {
		t.Errorf("build.feedsVia = %v, want %v", got, want)
	}
}

// TestFeedsViaArtifactExecutedThroughAChainedCommand pins that a chained
// command is read segment by segment: "npm ci && npm publish" is not
// alter-only just because its second half is a recognized publish
// command, since "npm ci" runs arbitrary install/build logic first.
func TestFeedsViaArtifactExecutedThroughAChainedCommand(t *testing.T) {
	jobs := []ir.Job{
		{Name: "build", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "produce"}}},
		{
			Name:      "release",
			Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "consume"}},
			Scripts:   []string{"npm ci && npm publish"},
		},
	}
	want := map[string][]string{"release": {"artifact_executed"}}
	if got := feedsViaOf(t, jobs, "build"); !reflect.DeepEqual(got, want) {
		t.Errorf("build.feedsVia = %v, want %v", got, want)
	}
}

// TestFeedsViaArtifactAlteredThroughAChainedCommand pins the opposite:
// every segment of "sha256sum dist/* && gh release upload v1 dist/*" is
// itself a recognized alter-only command (hashing, then releasing), so
// the edge stays artifact_altered even though the script has two parts.
func TestFeedsViaArtifactAlteredThroughAChainedCommand(t *testing.T) {
	jobs := []ir.Job{
		{Name: "build", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "produce"}}},
		{
			Name:      "release",
			Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "consume"}},
			Scripts:   []string{"sha256sum dist/* && gh release upload v1 dist/*"},
		},
	}
	want := map[string][]string{"release": {"artifact_altered"}}
	if got := feedsViaOf(t, jobs, "build"); !reflect.DeepEqual(got, want) {
		t.Errorf("build.feedsVia = %v, want %v", got, want)
	}
}

// TestFeedsViaArtifactExecutedWhenConsumerRunsAnotherAction pins that a
// consumer whose own scripts are only echo/cat lines (both alter-only on
// their own) still reads as artifact_executed when it also calls a
// third-party or local action beyond checkout and the artifact actions
// themselves: that action can run anything, so it is never read as a
// sign the download was only moved, listed or hashed. This is the real
// shape of the GitHub changed-files "test" job (corpus reviewdog-2025):
// actions/checkout, actions/download-artifact, several `uses: ./` runs,
// and run: steps that only echo or cat a step's own output.
func TestFeedsViaArtifactExecutedWhenConsumerRunsAnotherAction(t *testing.T) {
	jobs := []ir.Job{
		{Name: "build", Artifacts: []ir.ArtifactRef{{Name: "build-assets", Mode: "produce"}}},
		{
			Name:      "test",
			Artifacts: []ir.ArtifactRef{{Name: "build-assets", Mode: "consume"}},
			Uses: []ir.Action{
				{Uses: "actions/checkout@v4"},
				{Uses: "actions/download-artifact@v4", With: map[string]any{"name": "build-assets"}},
				{Uses: "./"},
			},
			Scripts: []string{"echo '${{ toJSON(steps.changed-files.outputs) }}'", "cat .github/outputs/all_changed_files.json"},
		},
	}
	want := map[string][]string{"test": {"artifact_executed"}}
	if got := feedsViaOf(t, jobs, "build"); !reflect.DeepEqual(got, want) {
		t.Errorf("build.feedsVia = %v, want %v: the local action './' can run anything, never alter-only", got, want)
	}
}

// TestFeedsViaArtifactExecutedThroughCommandSubstitution pins that a
// command substitution inside an otherwise alter-only verb's argument
// still executes the download first: "echo $(./dist/evil.sh)" matches
// "^echo\b" on its own, but the substitution runs the artifact's own
// script before echo ever sees its output.
func TestFeedsViaArtifactExecutedThroughCommandSubstitution(t *testing.T) {
	jobs := []ir.Job{
		{Name: "build", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "produce"}}},
		{
			Name:      "release",
			Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "consume"}},
			Scripts:   []string{"echo $(./dist/evil.sh)"},
		},
	}
	want := map[string][]string{"release": {"artifact_executed"}}
	if got := feedsViaOf(t, jobs, "build"); !reflect.DeepEqual(got, want) {
		t.Errorf("build.feedsVia = %v, want %v: $(...) runs the artifact before echo does", got, want)
	}
}

// TestFeedsViaArtifactExecutedThroughBacktickSubstitution pins the same
// bypass in its backtick spelling.
func TestFeedsViaArtifactExecutedThroughBacktickSubstitution(t *testing.T) {
	jobs := []ir.Job{
		{Name: "build", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "produce"}}},
		{
			Name:      "release",
			Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "consume"}},
			Scripts:   []string{"echo `./dist/evil.sh`"},
		},
	}
	want := map[string][]string{"release": {"artifact_executed"}}
	if got := feedsViaOf(t, jobs, "build"); !reflect.DeepEqual(got, want) {
		t.Errorf("build.feedsVia = %v, want %v: backticks run the artifact before echo does", got, want)
	}
}

// TestFeedsViaArtifactAlteredWithShellPreamble pins that the harmless
// shell preamble lines (set -e and its variants) that commonly precede a
// release command do not themselves disqualify an alter-only read.
func TestFeedsViaArtifactAlteredWithShellPreamble(t *testing.T) {
	jobs := []ir.Job{
		{Name: "build", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "produce"}}},
		{
			Name:      "release",
			Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "consume"}},
			Scripts:   []string{"set -euo pipefail\ngh release upload v1 dist/*"},
		},
	}
	want := map[string][]string{"release": {"artifact_altered"}}
	if got := feedsViaOf(t, jobs, "build"); !reflect.DeepEqual(got, want) {
		t.Errorf("build.feedsVia = %v, want %v: a set preamble line never disqualifies the release line after it", got, want)
	}
}

// TestFeedsViaArtifactExecutedWhenExportSubstitutes pins that the
// preamble allow-list never covers a substitution: "export X=$(cat
// dist/v)" reads the same leading keyword (export) as a plain
// assignment, but the substitution inside its value still executes.
func TestFeedsViaArtifactExecutedWhenExportSubstitutes(t *testing.T) {
	jobs := []ir.Job{
		{Name: "build", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "produce"}}},
		{
			Name:      "release",
			Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "consume"}},
			Scripts:   []string{"export X=$(cat dist/v)"},
		},
	}
	want := map[string][]string{"release": {"artifact_executed"}}
	if got := feedsViaOf(t, jobs, "build"); !reflect.DeepEqual(got, want) {
		t.Errorf("build.feedsVia = %v, want %v: $(...) in the exported value still executes", got, want)
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

// TestFeedsViaOutput pins the two output kinds on GitHub: b reads a's job
// outputs (needs.a.outputs.*) in a script, a with: value or an env value,
// each a read that runs the value (output_executed); an if: alone only
// compares it (output_compared), letting no code cross. A bare needs:
// orders the two jobs and hands over nothing, so it is no edge. On
// GitLab, needs: also downloads the needed job's artifacts, so it stays
// the one "output" edge there.
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
	want := map[string][]string{
		"ci/env": {"output_executed"}, "ci/if": {"output_compared"},
		"ci/script": {"output_executed"}, "ci/with": {"output_executed"},
	}
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

// TestFeedsViaOutputExecutedWinsOverCompared pins that when a job both
// compares a needs output in an if: and runs it in a script, the edge is
// output_executed alone: the stronger kind wins, output_compared never
// also listed.
func TestFeedsViaOutputExecutedWinsOverCompared(t *testing.T) {
	jobs := []ir.Job{
		{Name: "a"},
		{
			Name: "b", Needs: []string{"a"},
			If:      "needs.a.outputs.release == 'true'",
			Scripts: []string{"echo ${{ needs.a.outputs.version }}"},
		},
	}
	want := map[string][]string{"b": {"output_executed"}}
	if got := feedsViaOf(t, jobs, "a"); !reflect.DeepEqual(got, want) {
		t.Errorf("a.feedsVia = %v, want %v", got, want)
	}
}

// TestFeedsViaTwoKindsOnOnePair pins that every kind linking one pair is
// listed, sorted: build uploads the artifact publish downloads (publish
// runs no script and calls no action on it, so it reads as
// artifact_executed, the conservative default) and saves the cache key
// publish restores, and feeds still names publish once. A job feeding
// nothing carries an empty fact.
func TestFeedsViaTwoKindsOnOnePair(t *testing.T) {
	jobs := []ir.Job{
		{Name: "build", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "produce"}}, Caches: []ir.CacheRef{{Key: "deps", Mode: "save"}}},
		{Name: "publish", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "consume"}}, Caches: []ir.CacheRef{{Key: "deps", Mode: "restore"}}},
	}
	want := map[string][]string{"publish": {"artifact_executed", "cache"}}
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
