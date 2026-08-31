package platform

import (
	"strings"
	"time"
)

// ConfigSource names where a run's merged CI configuration came from. It is
// reported in verbose output and decides which controls can be evaluated at
// all, so it is a fact about the run, not a diagnostic.
type ConfigSource string

const (
	// SourceSnapshot: the checkout's config digest equals the snapshot's
	// resolution anchor, so this branch's config IS the one the platform
	// already resolved. The nominal path for every branch that does not
	// touch CI config, and it costs no extra call.
	SourceSnapshot ConfigSource = "snapshot"

	// SourceResolved: the digests diverged and the platform resolved this
	// branch's own config through its resolve endpoint.
	SourceResolved ConfigSource = "resolved"

	// SourceUnavailable: no merged configuration could be obtained. Controls
	// that depend on one report not_evaluable with Reason; every other
	// control still evaluates, and the run is never blocked by this.
	SourceUnavailable ConfigSource = "unavailable"
)

// DigestStatus records how the local digest compared to the snapshot's
// anchor. It exists to make the verbose line say WHY a branch took the path
// it did, rather than only which path.
type DigestStatus string

const (
	// DigestMatch: local digest and version both equal the anchor's.
	DigestMatch DigestStatus = "match"

	// DigestDiverged: both sides produced a digest and they differ - this
	// branch really does change the CI config.
	DigestDiverged DigestStatus = "diverged"

	// DigestNoAnchor: the snapshot carries no digest to compare against
	// (the platform could not compute one, or there is no snapshot at all).
	// Treated as divergent: there is nothing to match.
	DigestNoAnchor DigestStatus = "no-anchor"

	// DigestNotComputed: the CLI's own computation aborted - a traversal
	// past the file cap, an unreadable file, or a CI config rooted in
	// another project. Treated as divergent, and the resolve request then
	// omits the digest pair entirely so the platform resolves fresh rather
	// than serving a cache entry keyed on a digest that was never produced.
	DigestNotComputed DigestStatus = "not-computed"
)

// Divergent reports whether this status means "do not reuse the snapshot's
// merged config". Only an exact match is non-divergent: every uncertain
// state - no anchor, no local digest - resolves rather than assumes, because
// assuming would evaluate a branch against the wrong configuration.
func (d DigestStatus) Divergent() bool { return d != DigestMatch }

// CompareDigest classifies a locally computed digest against the snapshot's
// anchor.
//
// localDigest is "" when the CLI's own computation aborted; the caller
// passes the abort through rather than substituting a placeholder, because
// a missing digest and a differing digest lead to the same decision but
// must be reported differently.
func CompareDigest(anchor *ResolutionAnchor, localDigest, localVersion string) DigestStatus {
	if strings.TrimSpace(localDigest) == "" || strings.TrimSpace(localVersion) == "" {
		return DigestNotComputed
	}
	if !anchor.HasDigest() {
		return DigestNoAnchor
	}
	if anchor.Matches(localDigest, localVersion) {
		return DigestMatch
	}
	return DigestDiverged
}

// ConfigResolution is the outcome of the whole branch-aware decision: which
// merged configuration this run evaluates against, and how it got there.
type ConfigResolution struct {
	// Source is the lane that supplied MergedYAML.
	Source ConfigSource

	// MergedYAML is the resolved CI configuration, empty when Source is
	// SourceUnavailable (and possibly empty when the git host reported the
	// config INVALID - see Valid).
	MergedYAML string

	// Digest is how the local computation compared to the anchor.
	Digest DigestStatus

	// LocalDigest / DigestVersion are what the CLI computed from its
	// checkout, empty when the computation aborted.
	LocalDigest   string
	DigestVersion string

	// DigestAbortReason is "overflow" or "read_failure" when Digest is
	// DigestNotComputed, so the operator learns which one happened.
	DigestAbortReason string

	// AnchorSha / AnchorRef / AnchorDigest are what the snapshot's config
	// was resolved against, carried for the verbose line even when the
	// digests diverged - an operator comparing two digests needs both.
	AnchorSha    string
	AnchorRef    string
	AnchorDigest string

	// ResolvedSha is the sha the platform resolved at, when Source is
	// SourceResolved. On a cache hit it may legitimately differ from the
	// sha that was requested.
	ResolvedSha string

	// FromCache reports whether a SourceResolved result was served from the
	// platform's cache rather than freshly resolved.
	FromCache bool

	// Valid is false when the git host reported the CI config merge as
	// INVALID. That is a user error in their own config, not a resolution
	// failure, and MergedYAML may then be empty.
	Valid bool

	// Reason names why Source is SourceUnavailable, using the platform's
	// own vocabulary (ReasonResolutionUnavailable / ReasonResolverBusy) so
	// the not_evaluable findings it produces are machine-readable.
	Reason string

	// ShaFromAnchor records that the sha the resolve request asked about was
	// the snapshot anchor's, because the environment carried none (an
	// analyze outside CI). The run then evaluates the project's REMOTE state
	// at that commit, and the describe output says so: without the note, a
	// "digest diverges" line next to an anchor-sha resolution reads as a
	// contradiction to an operator whose divergence is local uncommitted
	// edits. Set by the caller that chose the sha, before any reader runs;
	// the resolving goroutine never touches it.
	ShaFromAnchor bool

	// done is closed when the resolve request the early fire started has
	// completed and every outcome field above is final. It is nil on every
	// path that never fires a request (a digest match, a missing client or
	// sha), which settles the resolution at construction. The channel close
	// is the happens-before edge between the resolving goroutine's writes
	// and any reader: outcome fields must only be read after Settled()
	// answers true or join() returns.
	done chan struct{}
}

// Settled reports whether the resolution's outcome fields are final. A
// resolution that never fired a request is settled from birth; one whose
// request is still in flight is not, and its outcome fields must not be
// read yet.
func (r *ConfigResolution) Settled() bool {
	if r == nil || r.done == nil {
		return true
	}
	select {
	case <-r.done:
		return true
	default:
		return false
	}
}

// SettledWithin waits up to d for the resolution to settle and reports
// whether it did. It exists for the one reader that wants the outcome if it
// is cheap but has something honest to print when it is not: the pre-run
// describe line.
func (r *ConfigResolution) SettledWithin(d time.Duration) bool {
	if r == nil || r.done == nil {
		return true
	}
	select {
	case <-r.done:
		return true
	case <-time.After(d):
		return false
	}
}

// join blocks until the resolution settles. The first accessor that needs
// the outcome calls it; everything before that runs concurrently with the
// platform's resolve, which is the point of firing early.
func (r *ConfigResolution) join() {
	if r != nil && r.done != nil {
		<-r.done
	}
}

// Available reports whether a merged configuration was obtained at all.
// Controls that read the merged config must report not_evaluable when this
// is false, never pass: an empty job list from an unavailable config is not
// evidence of a clean pipeline.
func (r *ConfigResolution) Available() bool {
	return r != nil && r.Source != SourceUnavailable
}

// resolver is the subset of Client that ResolveRunConfig needs, so the
// decision can be tested without a transport.
type resolver interface {
	ResolveConfig(projectPath, sha, digest, digestVersion string) (*ResolvedConfig, error)
}

// ResolveRunConfig executes the branch-aware decision procedure for one run:
//
//  1. Compare the checkout's digest against the snapshot's anchor.
//  2. On a match, evaluate against the snapshot's merged_yaml - the nominal
//     path for every branch that does not touch CI config, costing no call.
//  3. On any divergence (including "no anchor" and "no local digest"), ask
//     the platform to resolve THIS branch's config at sha.
//  4. If that resolution is unavailable, report it: merged-config-dependent
//     controls degrade to not_evaluable and everything else still runs.
//
// A digest that could not be computed is passed to the platform as an
// absent pair, which tells it to resolve fresh instead of serving a cache
// entry keyed on a digest the CLI never produced.
//
// This never returns an error: every failure mode is a ConfigResolution the
// caller can report and continue from. Platform availability must not gate
// a pipeline.
func ResolveRunConfig(c resolver, snap Snapshot, projectPath, sha, localDigest, digestAbortReason string) *ConfigResolution {
	out := StartRunConfigResolution(c, snap, projectPath, sha, localDigest, digestAbortReason)
	out.join()
	return out
}

// StartRunConfigResolution is ResolveRunConfig fired EARLY (#368): the
// digest comparison and every decision that needs no request settle before
// it returns, and on the one path that does need a request - a divergent
// digest with a client and a sha to ask about - the request is already in
// flight when it returns. The first accessor that needs the outcome joins
// on it, so the platform's resolve overlaps whatever runs in between
// instead of stalling the run up front; a hung endpoint costs its timeout
// in parallel with local work rather than before any of it starts.
//
// Read outcome fields (Source, MergedYAML, ResolvedSha, FromCache, Valid,
// Reason) only after Settled() answers true or join() returns; the
// digest-side fields are final at return.
func StartRunConfigResolution(c resolver, snap Snapshot, projectPath, sha, localDigest, digestAbortReason string) *ConfigResolution {
	anchor := snap.Anchor()
	out := &ConfigResolution{
		LocalDigest:       localDigest,
		DigestAbortReason: digestAbortReason,
		Valid:             true,
	}
	if localDigest != "" {
		out.DigestVersion = digestVersionForLocal()
	}
	if anchor != nil {
		out.AnchorSha, out.AnchorRef, out.AnchorDigest = anchor.Sha, anchor.Ref, anchor.ConfigDigest
	}
	out.Digest = CompareDigest(anchor, out.LocalDigest, out.DigestVersion)

	if !out.Digest.Divergent() {
		out.Source = SourceSnapshot
		if snap.Data != nil {
			out.MergedYAML = snap.Data.MergedYaml
		}
		// A matching digest over a snapshot that carries no merged config
		// is not a usable config: report it unavailable rather than
		// evaluating against an empty pipeline.
		if out.MergedYAML == "" {
			out.Source = SourceUnavailable
			out.Reason = ReasonResolutionUnavailable
		}
		return out
	}

	// No client, or no commit to resolve at. The resolve endpoint requires a
	// sha and refuses an empty one, so sending the request anyway would turn
	// a knowable local state into an opaque remote 400.
	if c == nil || strings.TrimSpace(sha) == "" {
		out.Source = SourceUnavailable
		out.Reason = ReasonResolutionUnavailable
		return out
	}

	out.done = make(chan struct{})
	go func() {
		defer close(out.done)
		completeFromResolve(out, c, projectPath, sha)
	}()
	return out
}

// completeFromResolve performs the resolve request and writes the outcome
// fields. It runs on the resolving goroutine; the done-channel close that
// follows it is what publishes these writes to readers.
func completeFromResolve(out *ConfigResolution, c resolver, projectPath, sha string) {
	resolved, err := c.ResolveConfig(projectPath, sha, out.LocalDigest, out.DigestVersion)
	if err != nil {
		out.Source = SourceUnavailable
		if reason, ok := IsUnavailable(err); ok {
			out.Reason = reason
		} else {
			// A transport error, a 4xx, a 5xx: every one of them means the
			// same thing to the run - no resolved config - and none of them
			// may block it.
			out.Reason = ReasonResolutionUnavailable
		}
		return
	}

	out.Source = SourceResolved
	out.MergedYAML = resolved.MergedYaml
	out.ResolvedSha = resolved.ResolvedSha
	out.FromCache = resolved.Source == "cache"
	out.Valid = resolved.Valid
	// An INVALID merge is a real answer about the user's own config, not an
	// unavailable resolution: keep Source as resolved so the run reports
	// "your CI config does not merge", which is actionable, rather than
	// "the platform was unreachable", which is not.
	if !resolved.Valid && resolved.MergedYaml == "" {
		out.MergedYAML = ""
	}
}

// digestVersionForLocal is the version paired with every digest this CLI
// computes. Split out so the pairing is stated once and the resolution
// logic never hard-codes it inline.
func digestVersionForLocal() string { return LocalDigestVersion }

// LocalDigestVersion is the digest_version this CLI computes under. It must
// equal the cidigest package's Version; the two are checked against each
// other in the wiring layer's tests rather than by importing cidigest here,
// which would give this package a dependency it does not otherwise need.
const LocalDigestVersion = "1"
