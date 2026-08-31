package platform

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeResolver records what ResolveRunConfig asked for and answers with a
// canned result or error.
type fakeResolver struct {
	calls  []ResolveRequest
	result *ResolvedConfig
	err    error
}

func (f *fakeResolver) ResolveConfig(_, sha, digest, digestVersion string) (*ResolvedConfig, error) {
	f.calls = append(f.calls, ResolveRequest{Sha: sha, ConfigDigest: digest, DigestVersion: digestVersion})
	return f.result, f.err
}

// snapWith builds a snapshot carrying a merged config and an anchor.
func snapWith(t *testing.T, mergedYAML, digest, version, sha, ref string) Snapshot {
	t.Helper()
	data := &SnapshotData{MergedYaml: mergedYAML}
	if sha != "" || ref != "" || digest != "" {
		data.ResolutionAnchor = &ResolutionAnchor{Ref: ref, Sha: sha, ConfigDigest: digest, DigestVersion: version}
	}
	return Snapshot{Data: data}
}

// resolveRunConfigSync is the settled form the older tests were written
// against: start the resolution and wait for its outcome. Production keeps
// only the early-fired entry point, so the sync spelling lives with the
// tests that want it.
func resolveRunConfigSync(c resolver, snap Snapshot, projectPath, sha, localDigest, digestAbortReason string) *ConfigResolution {
	out := StartRunConfigResolution(c, snap, projectPath, sha, localDigest, digestAbortReason)
	out.join()
	return out
}

func TestCompareDigest(t *testing.T) {
	anchor := &ResolutionAnchor{Ref: "main", Sha: "s", ConfigDigest: "aaa", DigestVersion: "1"}
	cases := []struct {
		name          string
		anchor        *ResolutionAnchor
		digest, ver   string
		want          DigestStatus
		wantDivergent bool
	}{
		{"exact match", anchor, "aaa", "1", DigestMatch, false},
		{"different digest", anchor, "bbb", "1", DigestDiverged, true},
		{"same digest, different version is NOT comparable", anchor, "aaa", "2", DigestDiverged, true},
		{"no anchor at all", nil, "aaa", "1", DigestNoAnchor, true},
		{"anchor without a digest", &ResolutionAnchor{Ref: "main", Sha: "s"}, "aaa", "1", DigestNoAnchor, true},
		{"local computation aborted", anchor, "", "", DigestNotComputed, true},
		{"local digest without a version", anchor, "aaa", "", DigestNotComputed, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CompareDigest(tc.anchor, tc.digest, tc.ver)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if got.Divergent() != tc.wantDivergent {
				t.Fatalf("Divergent() = %v, want %v", got.Divergent(), tc.wantDivergent)
			}
		})
	}
}

// TestResolveRunConfig_MatchUsesSnapshotWithNoCall is the nominal path: a
// branch that does not touch CI config must evaluate against the snapshot
// and cost ZERO extra platform calls.
func TestResolveRunConfig_MatchUsesSnapshotWithNoCall(t *testing.T) {
	f := &fakeResolver{}
	snap := snapWith(t, "stages:\n  - build\n", "aaa", "1", "sha1", "main")

	got := resolveRunConfigSync(f, snap, "grp/proj", "sha1", "aaa", "")

	if got.Source != SourceSnapshot {
		t.Fatalf("source: got %q, want %q", got.Source, SourceSnapshot)
	}
	if got.MergedYAML != "stages:\n  - build\n" {
		t.Fatalf("merged yaml: %q", got.MergedYAML)
	}
	if got.Digest != DigestMatch {
		t.Fatalf("digest status: %q", got.Digest)
	}
	if len(f.calls) != 0 {
		t.Fatalf("a digest-equal branch must make NO resolve call, made %d", len(f.calls))
	}
	if !got.Available() {
		t.Fatal("a snapshot-sourced config is available")
	}
	if got.AnchorSha != "sha1" || got.AnchorRef != "main" {
		t.Fatalf("anchor not carried through for reporting: %+v", got)
	}
}

// TestResolveRunConfig_DivergentResolvesThisBranch: a branch that changes
// its CI config must be evaluated against ITS OWN resolved config, never
// the default branch's.
func TestResolveRunConfig_DivergentResolvesThisBranch(t *testing.T) {
	f := &fakeResolver{result: &ResolvedConfig{
		MergedYaml: "stages:\n  - test\n", ResolvedSha: "branchsha", Valid: true, Source: "resolved",
	}}
	snap := snapWith(t, "stages:\n  - build\n", "aaa", "1", "defaultsha", "main")

	got := resolveRunConfigSync(f, snap, "grp/proj", "branchsha", "bbb", "")

	if got.Source != SourceResolved {
		t.Fatalf("source: got %q, want %q", got.Source, SourceResolved)
	}
	if got.MergedYAML != "stages:\n  - test\n" {
		t.Fatalf("a divergent branch must evaluate its OWN config, got %q", got.MergedYAML)
	}
	if len(f.calls) != 1 {
		t.Fatalf("want exactly 1 resolve call, got %d", len(f.calls))
	}
	if f.calls[0].Sha != "branchsha" || f.calls[0].ConfigDigest != "bbb" || f.calls[0].DigestVersion != "1" {
		t.Fatalf("resolve request: %+v", f.calls[0])
	}
}

// TestResolveRunConfig_AbortedDigestOmitsThePair: with no local digest the
// platform must be told to resolve fresh, not to serve a cache entry keyed
// on a digest the CLI never computed.
func TestResolveRunConfig_AbortedDigestOmitsThePair(t *testing.T) {
	f := &fakeResolver{result: &ResolvedConfig{MergedYaml: "a: 1\n", ResolvedSha: "s", Valid: true, Source: "resolved"}}
	snap := snapWith(t, "b: 2\n", "aaa", "1", "s0", "main")

	got := resolveRunConfigSync(f, snap, "grp/proj", "s", "", "overflow")

	if got.Digest != DigestNotComputed {
		t.Fatalf("digest status: %q", got.Digest)
	}
	if got.DigestAbortReason != "overflow" {
		t.Fatalf("abort reason must be carried for reporting, got %q", got.DigestAbortReason)
	}
	if len(f.calls) != 1 {
		t.Fatalf("want 1 resolve call, got %d", len(f.calls))
	}
	if f.calls[0].ConfigDigest != "" || f.calls[0].DigestVersion != "" {
		t.Fatalf("an aborted digest must be sent as an ABSENT pair, got %+v", f.calls[0])
	}
	if got.Source != SourceResolved {
		t.Fatalf("source: %q", got.Source)
	}
}

// TestResolveRunConfig_UnavailableNeverBlocks: every way a resolution can
// fail lands on SourceUnavailable with a machine-readable reason, and none
// of them returns an error the run could fail on.
func TestResolveRunConfig_UnavailableNeverBlocks(t *testing.T) {
	snap := snapWith(t, "b: 2\n", "aaa", "1", "s0", "main")
	cases := []struct {
		name       string
		err        error
		wantReason string
	}{
		{"resolver busy", &UnavailableError{Reason: ReasonResolverBusy}, ReasonResolverBusy},
		{"resolution unavailable", &UnavailableError{Reason: ReasonResolutionUnavailable}, ReasonResolutionUnavailable},
		{"a 404 (endpoint absent on an older platform)", &StatusError{StatusCode: 404, Status: "404 Not Found"}, ReasonResolutionUnavailable},
		{"a 500", &StatusError{StatusCode: 500, Status: "500 Internal Server Error"}, ReasonResolutionUnavailable},
		{"a transport error", errors.New("dial tcp: connection refused"), ReasonResolutionUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveRunConfigSync(&fakeResolver{err: tc.err}, snap, "grp/proj", "s", "bbb", "")
			if got.Source != SourceUnavailable {
				t.Fatalf("source: got %q, want %q", got.Source, SourceUnavailable)
			}
			if got.Reason != tc.wantReason {
				t.Fatalf("reason: got %q, want %q", got.Reason, tc.wantReason)
			}
			if got.Available() {
				t.Fatal("an unavailable resolution is not available")
			}
			if got.MergedYAML != "" {
				t.Fatalf("an unavailable resolution must carry NO config, got %q", got.MergedYAML)
			}
		})
	}
}

// TestResolveRunConfig_MatchButEmptySnapshotConfigIsUnavailable: a digest
// that matches an anchor whose snapshot carries no merged config is not a
// clean pipeline, it is no data. Reporting it as a usable empty config
// would turn every merged-config control into a silent pass.
func TestResolveRunConfig_MatchButEmptySnapshotConfigIsUnavailable(t *testing.T) {
	f := &fakeResolver{}
	snap := snapWith(t, "", "aaa", "1", "s", "main")

	got := resolveRunConfigSync(f, snap, "grp/proj", "s", "aaa", "")

	if got.Source != SourceUnavailable {
		t.Fatalf("source: got %q, want %q", got.Source, SourceUnavailable)
	}
	if got.Reason != ReasonResolutionUnavailable {
		t.Fatalf("reason: %q", got.Reason)
	}
}

// TestResolveRunConfig_NoSnapshotAtAllResolves: a project the platform has
// never collected has no anchor, which is divergent - the branch's config
// must be resolved rather than assumed absent.
func TestResolveRunConfig_NoSnapshotAtAllResolves(t *testing.T) {
	f := &fakeResolver{result: &ResolvedConfig{MergedYaml: "a: 1\n", ResolvedSha: "s", Valid: true, Source: "resolved"}}

	got := resolveRunConfigSync(f, Snapshot{}, "grp/proj", "s", "aaa", "")

	if got.Digest != DigestNoAnchor {
		t.Fatalf("digest status: %q", got.Digest)
	}
	if got.Source != SourceResolved || len(f.calls) != 1 {
		t.Fatalf("an anchor-less snapshot must resolve, got source %q after %d calls", got.Source, len(f.calls))
	}
}

// TestResolveRunConfig_InvalidMergeIsReportedAsResolved: the git host
// reporting the user's config as INVALID is an actionable answer about
// their own config, not an unavailable platform. Collapsing the two would
// tell an operator to check the platform when their YAML is broken.
func TestResolveRunConfig_InvalidMergeIsReportedAsResolved(t *testing.T) {
	f := &fakeResolver{result: &ResolvedConfig{MergedYaml: "", ResolvedSha: "s", Valid: false, Source: "resolved"}}
	snap := snapWith(t, "b: 2\n", "aaa", "1", "s0", "main")

	got := resolveRunConfigSync(f, snap, "grp/proj", "s", "bbb", "")

	if got.Source != SourceResolved {
		t.Fatalf("source: got %q, want %q", got.Source, SourceResolved)
	}
	if got.Valid {
		t.Fatal("Valid must carry the host's INVALID verdict through")
	}
	if got.Reason != "" {
		t.Fatalf("an invalid merge is not an unavailability reason, got %q", got.Reason)
	}
}

// TestResolveRunConfig_CacheHitShaMayDiffer pins that a cache hit's
// resolved_sha is recorded as-is. Asserting equality with the requested sha
// would reject every legitimate cache hit.
func TestResolveRunConfig_CacheHitShaMayDiffer(t *testing.T) {
	f := &fakeResolver{result: &ResolvedConfig{MergedYaml: "a: 1\n", ResolvedSha: "OTHER", Valid: true, Source: "cache"}}
	snap := snapWith(t, "b: 2\n", "aaa", "1", "s0", "main")

	got := resolveRunConfigSync(f, snap, "grp/proj", "REQUESTED", "bbb", "")

	if got.ResolvedSha != "OTHER" || !got.FromCache {
		t.Fatalf("cache hit not recorded faithfully: %+v", got)
	}
	if got.Source != SourceResolved {
		t.Fatalf("source: %q", got.Source)
	}
}

// TestResolveRunConfig_NilResolverIsUnavailable: standalone mode reaching
// this path with no platform client must degrade, never panic.
func TestResolveRunConfig_NilResolverIsUnavailable(t *testing.T) {
	got := resolveRunConfigSync(nil, snapWith(t, "b: 2\n", "aaa", "1", "s", "main"), "grp/proj", "s", "bbb", "")
	if got.Source != SourceUnavailable || got.Reason != ReasonResolutionUnavailable {
		t.Fatalf("got %+v", got)
	}
}

// TestSnapshotDataRawBlobsStayRaw guards the package boundary: the settings
// blobs must remain undecoded here so this package never grows a dependency
// on the GitLab provider's types.
func TestSnapshotDataRawBlobsStayRaw(t *testing.T) {
	var d SnapshotData
	const body = `{"branch_protection":{"protections":[{"protectionPattern":"main"}]},"variables":{"items":[]},"mr_approvals":{"rules":[]}}`
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var probe struct {
		Protections []struct {
			ProtectionPattern string `json:"protectionPattern"`
		} `json:"protections"`
	}
	if err := json.Unmarshal(d.BranchProtection, &probe); err != nil {
		t.Fatalf("the raw blob must still be valid JSON for its owner to decode: %v", err)
	}
	if len(probe.Protections) != 1 || probe.Protections[0].ProtectionPattern != "main" {
		t.Fatalf("raw blob content lost: %+v", probe)
	}
}

// TestResolveRunConfig_NoShaSkipsTheCall: the endpoint requires a sha and
// refuses an empty one, so sending the request anyway would turn a knowable
// local state into an opaque remote 400.
func TestResolveRunConfig_NoShaSkipsTheCall(t *testing.T) {
	f := &fakeResolver{result: &ResolvedConfig{MergedYaml: "a: 1\n", Valid: true, Source: "resolved"}}
	snap := snapWith(t, "b: 2\n", "aaa", "1", "s0", "main")

	got := resolveRunConfigSync(f, snap, "grp/proj", "   ", "bbb", "")

	if len(f.calls) != 0 {
		t.Fatalf("an empty sha must not reach the endpoint, made %d call(s)", len(f.calls))
	}
	if got.Source != SourceUnavailable || got.Reason != ReasonResolutionUnavailable {
		t.Fatalf("got %+v", got)
	}
}

// blockingResolver blocks every ResolveConfig call until released, so a test
// can hold the platform's answer open and observe what the CLI does in the
// meantime.
type blockingResolver struct {
	release chan struct{}
	out     *ResolvedConfig
}

func (b *blockingResolver) ResolveConfig(projectPath, sha, digest, digestVersion string) (*ResolvedConfig, error) {
	<-b.release
	return b.out, nil
}

// TestStartRunConfigResolution_DivergentDoesNotBlock pins the early-fire
// contract (#368: the resolve request "can be fired EARLY ... and collected
// only when evaluation needs the config"): on a divergent digest,
// StartRunConfigResolution returns while the platform is still thinking, and
// the first accessor that needs the outcome joins on it.
func TestStartRunConfigResolution_DivergentDoesNotBlock(t *testing.T) {
	res := &blockingResolver{
		release: make(chan struct{}),
		out: &ResolvedConfig{MergedYaml: "resolved: yes\n", ResolvedSha: "beef",
			Valid: true, Source: "resolved"},
	}
	snap := snapWith(t, "anchor-yaml", "f"+strings.Repeat("0", 63), "1", "anchorsha", "main")

	done := make(chan *ConfigResolution, 1)
	go func() {
		done <- StartRunConfigResolution(res, snap, "org/repo", "abc123", strings.Repeat("1", 64), "")
	}()
	var out *ConfigResolution
	select {
	case out = <-done:
		// returned while the resolver is still blocked: the early fire.
	case <-time.After(2 * time.Second):
		t.Fatal("StartRunConfigResolution blocked on the resolve call instead of firing it early")
	}
	if out.Settled() {
		t.Fatal("resolution reports settled while the platform has not answered")
	}

	joined := make(chan struct{})
	go func() {
		out.join()
		close(joined)
	}()
	select {
	case <-joined:
		t.Fatal("join returned before the platform answered")
	case <-time.After(50 * time.Millisecond):
	}

	close(res.release)
	select {
	case <-joined:
	case <-time.After(2 * time.Second):
		t.Fatal("join did not complete after the platform answered")
	}
	if out.Source != SourceResolved || out.MergedYAML != "resolved: yes\n" || out.ResolvedSha != "beef" {
		t.Fatalf("joined resolution mismatch: %+v", out)
	}
	if !out.Settled() {
		t.Fatal("resolution must report settled after join")
	}
}

// TestStartRunConfigResolution_MatchSettlesImmediately: the nominal
// digest-match path involves no request, so it is settled the moment the
// function returns and behaves exactly like the synchronous path.
func TestStartRunConfigResolution_MatchSettlesImmediately(t *testing.T) {
	digest := strings.Repeat("2", 64)
	snap := snapWith(t, "anchor-yaml", digest, "1", "anchorsha", "main")
	out := StartRunConfigResolution(nil, snap, "org/repo", "abc123", digest, "")
	if !out.Settled() {
		t.Fatal("a digest match must settle immediately")
	}
	if out.Source != SourceSnapshot || out.MergedYAML != "anchor-yaml" {
		t.Fatalf("match path mismatch: %+v", out)
	}
}
