package platform

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// RunContext is everything platform mode resolved BEFORE collection began:
// the project's policy set, the cached settings snapshot, and which merged
// CI configuration this run evaluates against.
//
// A nil *RunContext means standalone mode - the CLI's default and unchanged
// behaviour. Every consumer must treat nil as "no platform", never as an
// error, so the standalone path stays exactly what it is today.
type RunContext struct {
	// Endpoint is the platform base URL this run is bound to.
	Endpoint string

	// ProjectPath is the path the context was fetched for.
	ProjectPath string

	// Context is the fetched /context response. Nil when the fetch itself
	// failed, in which case platform mode degrades to a name-only push and
	// the standalone collection lanes.
	Context *ProjectContext

	// Config is the branch-aware merged-config decision for this run.
	Config *ConfigResolution

	// ContextErr records why Context is nil, for the operator-facing line.
	ContextErr error

	// client is the authenticated client this run resolved with. It holds
	// the CI OIDC id-token, which is why it is unexported and why
	// RunContext carries no json tags and is never serialized: the token
	// must not reach an artifact, a log line, or a pushed body.
	client *Client
}

// SetClient attaches the authenticated client, so the later result push
// reuses this run's token instead of minting a second one.
func (r *RunContext) SetClient(c *Client) {
	if r != nil {
		r.client = c
	}
}

// Client returns the authenticated client, or nil when platform mode never
// established one.
func (r *RunContext) Client() *Client {
	if r == nil {
		return nil
	}
	return r.client
}

// Policies returns the resolved policy set, or nil when no context was
// fetched. The platform guarantees the set is never empty when a context
// WAS fetched: an unassigned project resolves to the derived default.
func (r *RunContext) Policies() []Policy {
	if r == nil || r.Context == nil {
		return nil
	}
	return r.Context.Policies
}

// Snapshot returns the cached settings snapshot, or a zero Snapshot when
// none was fetched. The zero value is honestly empty (no CollectedAt, no
// Data), which every reader already handles.
func (r *RunContext) Snapshot() Snapshot {
	if r == nil || r.Context == nil {
		return Snapshot{}
	}
	return r.Context.Snapshot
}

// MergedYAML returns the resolved CI configuration for this run, and
// whether one is available at all. A false second return means controls
// reading the merged configuration must report not_evaluable.
func (r *RunContext) MergedYAML() (string, bool) {
	// Joining here is what collects the early-fired resolve request: the
	// first consumer that needs the outcome waits for it, everything before
	// ran concurrently with it.
	if r != nil {
		r.Config.join()
	}
	if r == nil || r.Config == nil || !r.Config.Available() {
		return "", false
	}
	return r.Config.MergedYAML, true
}

// ConfigInvalid reports whether the git host judged the configuration this
// run evaluates to be INVALID - a user error in their own CI file, not a
// resolution failure.
//
// The two must not be collapsed, and the direction matters. An unavailable
// resolution says nothing about the user's config and must never be
// reported as "your CI file is broken". An INVALID one is a real answer
// about it, and reporting it as valid is worse: the merge is partial or
// empty, so the jobs that failed to merge are simply absent and every
// pipeline control passes over what is left. A run whose config does not
// merge would print a clean green verdict.
func (r *RunContext) ConfigInvalid() bool {
	if r == nil {
		return false
	}
	r.Config.join()
	return r.Config != nil && r.Config.Available() && !r.Config.Valid
}

// ConfigAndIncludesAgree reports whether the merged configuration in use and
// the snapshot's include attribution describe the SAME configuration.
//
// They come from two independent lanes and only agree in one case. When the
// checkout's digest equals the anchor, MergedYAML is the snapshot's own
// merged_yaml and the snapshot's includes attribute exactly it
// (SourceSnapshot). When the digests diverge, MergedYAML is the config the
// platform resolved for THIS branch, while SnapshotIncludes still holds
// attribution resolved against the anchor - the default branch. The resolve
// endpoint returns no includes at all (see ResolvedConfig), so on a
// divergent branch there is no branch-accurate attribution to be had.
//
// Pairing them anyway is worse than having neither. A branch that adds,
// removes or re-pins an include gets every job from that include classified
// against the OLD attribution, so upstream jobs read as project-authored and
// vice versa. That is the fabricated-finding mode attribution exists to
// prevent, landing on precisely the divergent branch the digest exists to
// detect. Callers must treat attribution as unavailable when this is false.
func (r *RunContext) ConfigAndIncludesAgree() bool {
	if r == nil {
		return false
	}
	r.Config.join()
	return r.Config != nil && r.Config.Source == SourceSnapshot
}

// UnavailableReason names why no merged configuration is available, or ""
// when one is. It is the reason stamped onto the not_evaluable findings
// this state produces.
func (r *RunContext) UnavailableReason() string {
	if r != nil {
		r.Config.join()
	}
	if r == nil || r.Config == nil || r.Config.Available() {
		return ""
	}
	if r.Config.Reason == "" {
		return ReasonResolutionUnavailable
	}
	return r.Config.Reason
}

// Active reports whether --platform was set for this run.
func (r *RunContext) Active() bool { return r != nil }

// Engaged reports whether platform mode actually took over this run's data
// lanes, which requires a context the CLI genuinely fetched.
//
// The distinction matters when the platform could not be reached at all.
// The lane split is a division of labour agreed with a platform that
// ANSWERED: it says "do not collect this yourself, the platform has it".
// With no answer there is no such agreement, and treating the lanes as
// assigned anyway would blank an entire scan because a third party was
// briefly down. Such a run falls back to collecting locally, and says so —
// see Describe, which reports the fetch failure and its cause on every run,
// verbose or not.
//
// This is not a way to prefer the local lane when it is convenient: once
// the platform answers, its lanes apply even when what it answered with is
// "no configuration available".
func (r *RunContext) Engaged() bool { return r != nil && r.Context != nil }

// SnapshotCollectedAt returns the snapshot's collection time in RFC3339, or
// "" when there is no snapshot. It is carried on the push so the platform
// records which cache read a verdict was computed from.
func (r *RunContext) SnapshotCollectedAt() string {
	snap := r.Snapshot()
	if snap.CollectedAt == nil {
		return ""
	}
	return snap.CollectedAt.UTC().Format(time.RFC3339)
}

// MissingSnapshotFields lists the snapshot lanes that carried no data, in a
// stable order. It feeds the push's collection.missing_fields, which is the
// platform's honest-degradation signal: a lane that was never collected is
// reported as missing rather than silently read as empty.
func (r *RunContext) MissingSnapshotFields() []string {
	if !r.Active() {
		return nil
	}
	snap := r.Snapshot()
	if snap.Data == nil {
		// No snapshot at all: every lane is missing, and saying so is more
		// useful than an empty list that reads as "nothing was missing".
		return []string{"branch_protection", "merged_yaml", "mr_approvals", "variables"}
	}
	var missing []string
	if len(snap.Data.BranchProtection) == 0 {
		missing = append(missing, "branch_protection")
	}
	if snap.Data.MergedYaml == "" {
		missing = append(missing, "merged_yaml")
	}
	if len(snap.Data.MrApprovals) == 0 {
		missing = append(missing, "mr_approvals")
	}
	if len(snap.Data.Variables) == 0 {
		missing = append(missing, "variables")
	}
	sort.Strings(missing)
	return missing
}

// LaneMissing reports whether a named snapshot lane carried no data at all.
//
// It is a different question from LaneDegraded, and for some lanes it is
// the more important one. The platform writes branch_protection and
// mr_approvals on ANY successful collection, empty lists included, so their
// absence is never "this project has none" - it only ever means the
// collection did not complete. A caller reading an absent lane as an empty
// one would certify an unprotected default branch as compliant.
//
// Other lanes are the opposite: variables is omitted when the project
// genuinely has none, which is a real answer both variable controls should
// pass on. Which reading applies is the LANE's property, so it is decided
// by the caller that knows the lane, not here.
func (r *RunContext) LaneMissing(field string) bool {
	if !r.Active() {
		return false
	}
	snap := r.Snapshot()
	if snap.Data == nil {
		return true
	}
	switch field {
	case DegradedFieldBranchProtection:
		return len(snap.Data.BranchProtection) == 0
	case DegradedFieldMrApprovals:
		return len(snap.Data.MrApprovals) == 0
	case DegradedFieldVariables:
		return len(snap.Data.Variables) == 0
	case DegradedFieldMergedYaml:
		return snap.Data.MergedYaml == ""
	case DegradedFieldProjectDetails:
		// No lane carries it, so it is missing from every snapshot ever
		// collected. Saying so plainly beats answering false and leaving a
		// caller to conclude the data was there.
		return true
	}
	return false
}

// SnapshotIncludes returns the snapshot's per-include attribution, and
// whether the platform supplied any. A false second return is the state
// that forces the include-reasoning controls to not_evaluable: without
// attribution a component's job is indistinguishable from one the project
// wrote, which fabricates findings rather than merely hiding them.
func (r *RunContext) SnapshotIncludes() ([]json.RawMessage, bool) {
	snap := r.Snapshot()
	if snap.Data == nil || len(snap.Data.Includes) == 0 {
		return nil, false
	}
	return snap.Data.Includes, true
}

// SnapshotCIConfigPath returns the project's configured CI config path from
// the snapshot, or "" when the platform did not supply one. The caller
// decides the default; this reports only what was served.
func (r *RunContext) SnapshotCIConfigPath() string {
	snap := r.Snapshot()
	if snap.Data == nil {
		return ""
	}
	return strings.TrimSpace(snap.Data.CiConfigPath)
}

// LaneDegraded reports whether a named snapshot lane failed collection on
// the platform side. False when there is no snapshot, or when the payload
// predates the bookkeeping - see SnapshotData.DegradedFieldsTrusted.
func (r *RunContext) LaneDegraded(field string) bool {
	snap := r.Snapshot()
	return snap.Data.IsDegraded(field)
}

// DegradedLanes returns the failed lanes in a stable order, for the
// operator-facing summary and the push metadata. Empty when the snapshot
// cannot tell us (below schema v2), which Describe reports distinctly from
// "nothing degraded".
func (r *RunContext) DegradedLanes() []string {
	snap := r.Snapshot()
	if snap.Data == nil || !snap.Data.DegradedFieldsTrusted() {
		return nil
	}
	out := append([]string(nil), snap.Data.DegradedFields...)
	sort.Strings(out)
	return out
}

// DegradationKnowable reports whether this run can distinguish an honestly
// empty lane from a failed one. False on a pre-v2 snapshot, where absence
// proves nothing.
func (r *RunContext) DegradationKnowable() bool {
	snap := r.Snapshot()
	return snap.Data.DegradedFieldsTrusted()
}

// Describe renders the operator-facing summary of what platform mode
// resolved: the policy set, the snapshot's age, and which configuration
// this run is evaluating against and why. Returned as lines so the caller
// controls prefixing and the whole thing stays testable as data.
//
// Every line states a fact the run actually observed. Nothing here is
// inferred or defaulted into looking healthier than it is.
func (r *RunContext) Describe() []string {
	if !r.Active() {
		return nil
	}
	var out []string
	out = append(out, "platform: "+r.Endpoint)

	if r.Context == nil {
		reason := "unknown error"
		if r.ContextErr != nil {
			reason = r.ContextErr.Error()
		}
		out = append(out, "context: NOT fetched ("+reason+") - running with local collection and no policy set")
		return out
	}

	policies := r.Policies()
	out = append(out, fmt.Sprintf("policies: %d resolved", len(policies)))
	for _, p := range policies {
		id := p.ID
		if !p.IsReal() {
			id = "(derived default, no id)"
		}
		out = append(out, fmt.Sprintf("  - %s [%s] %s", p.Name, p.Enforcement, id))
	}

	if collected := r.SnapshotCollectedAt(); collected != "" {
		out = append(out, "snapshot collected_at: "+collected)
	} else {
		out = append(out, "snapshot: none cached for this project yet")
	}
	if missing := r.MissingSnapshotFields(); len(missing) > 0 {
		out = append(out, "snapshot missing lanes: "+strings.Join(missing, ", "))
	}
	// An absent lane and a FAILED lane look identical in the payload, so say
	// which it was. Below schema v2 the platform cannot tell us either, and
	// reporting that is more honest than printing an empty "degraded: none".
	if !r.DegradationKnowable() {
		out = append(out, "snapshot degradation: unknown (pre-v2 snapshot: an absent lane may be a failed collection)")
	} else if degraded := r.DegradedLanes(); len(degraded) > 0 {
		out = append(out, "snapshot degraded lanes: "+strings.Join(degraded, ", ")+" (collection failed; these report not_evaluable)")
	}

	out = append(out, r.describeConfig()...)
	return out
}

// describeConfig renders the branch-aware config decision.
//
// Digests are printed in FULL, not abbreviated. This output is behind
// --verbose, and a truncated digest is exactly useless for the job someone
// reads it to do: comparing their checkout against what the platform
// stored, quoting it in a bug report, or confirming a fix. Commit shas stay
// abbreviated because a short sha is a complete identifier by convention;
// half a digest is not.
func (r *RunContext) describeConfig() []string {
	c := r.Config
	if c == nil {
		return []string{"ci config: not resolved"}
	}
	var out []string
	switch c.Digest {
	case DigestMatch:
		out = append(out, "ci config digest: matches the snapshot anchor")
		out = append(out, "  digest: "+c.LocalDigest+" (v"+c.DigestVersion+")")
	case DigestDiverged:
		out = append(out, "ci config digest: diverges from the snapshot anchor")
		out = append(out, "  local:  "+c.LocalDigest+" (v"+c.DigestVersion+")")
		out = append(out, "  anchor: "+c.AnchorDigest)
	case DigestNoAnchor:
		out = append(out, "ci config digest: the snapshot carries no anchor to compare against")
		out = append(out, "  local:  "+c.LocalDigest+" (v"+c.DigestVersion+")")
	case DigestNotComputed:
		reason := c.DigestAbortReason
		if reason == "" {
			reason = "unknown"
		}
		out = append(out, "ci config digest: not computed ("+reason+") - treated as divergent")
	}

	if c.ShaFromAnchor && c.Digest.Divergent() {
		out = append(out, "  note: no job commit in the environment; resolving at the snapshot anchor's commit, so this run evaluates the project's remote state, not local uncommitted edits")
	}

	// The early-fired resolve request may still be in flight. Wait briefly so
	// the nominal fast answer (a platform cache hit) still prints its real
	// outcome, and say "in flight" honestly for a slow one rather than block
	// the pre-run output on a third party or print an outcome nothing has
	// established.
	if !c.SettledWithin(200 * time.Millisecond) {
		out = append(out, "ci config source: platform resolve endpoint (request in flight; collected when evaluation needs it)")
		return out
	}

	switch c.Source {
	case SourceSnapshot:
		out = append(out, fmt.Sprintf("ci config source: platform snapshot (resolved at %s on %s)", shortDigest(c.AnchorSha), c.AnchorRef))
	case SourceResolved:
		how := "resolved"
		if c.FromCache {
			how = "served from the platform cache"
		}
		line := fmt.Sprintf("ci config source: platform resolve endpoint, %s at %s", how, shortDigest(c.ResolvedSha))
		if !c.Valid {
			line += " - the git host reports this config as INVALID"
		}
		out = append(out, line)
	case SourceUnavailable:
		out = append(out, "ci config source: UNAVAILABLE ("+r.UnavailableReason()+") - controls reading the merged config report not_evaluable")
	}
	return out
}

// shortDigest abbreviates a commit sha for a human-readable line. Used only
// for shas, never for config digests: a short sha is a complete identifier
// by convention, half a digest is not (see describeConfig).
func shortDigest(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "none"
	}
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "..."
}
