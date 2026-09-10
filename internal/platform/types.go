// Package platform is the CLI's client for the Plumber platform's three
// CI-OIDC endpoints: the project context read, the branch-aware config
// resolve, and (elsewhere) the result push.
//
// The package is deliberately free of every other Plumber package. It
// carries the wire shapes and the transport, nothing else: the settings
// blobs inside a snapshot stay json.RawMessage here and are decoded by
// whichever provider package owns their types. That keeps configuration
// able to hold a *ProjectContext without an import cycle back through
// gitlab.
//
// Decoding is FORWARD TOLERANT everywhere, as the platform's contract
// requires: unknown fields are ignored, and a field the CLI does not
// understand never fails a run.
package platform

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Enforcement is a policy's enforcement dial. The platform's vocabulary is
// closed today ("block" | "report") but is carried as a string so an
// unrecognized future value degrades to "not blocking" rather than failing
// the decode.
type Enforcement string

const (
	// EnforcementBlock means a failing verdict for this policy should block.
	EnforcementBlock Enforcement = "block"
	// EnforcementReport means findings are recorded but never block.
	EnforcementReport Enforcement = "report"
)

// Blocking reports whether this dial blocks a pipeline. Anything other than
// the exact "block" value is treated as report-only: an unknown dial must
// never be guessed into blocking someone's pipeline.
func (e Enforcement) Blocking() bool { return e == EnforcementBlock }

// NilUUID is the all-zero uuid the platform's derived "[Plumber default]"
// fallback policy carries. It is NOT a real policies row, so it must never
// be sent back as a push's policy_id. IsReal is the guard.
const NilUUID = "00000000-0000-0000-0000-000000000000"

// Policy is one entry of the resolved policy set. The set is never empty:
// an unassigned project resolves to the derived "[Plumber default]"
// fallback, report-only, carrying NilUUID.
//
// Requirements is this policy's OWN control tree. Two different policies
// may declare the same control_type with DIFFERENT config, which is the
// whole point of the field: a control's parameters belong to the policy
// that declared them and must never be read from a sibling policy.
//
// It is empty for the derived "[Plumber default]" fallback, which is not a
// real policies row and therefore has no tree to read. An empty tree is an
// honest statement that the policy configures nothing, never an error.
type Policy struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	Enforcement  Enforcement         `json:"enforcement"`
	Requirements []PolicyRequirement `json:"requirements,omitempty"`

	// MinPoints is the policy's enforcement threshold as the platform serves it
	// (Policy.min_points on /context, nullable): a block-mode policy blocks when
	// its recomputed FINAL points fall strictly below it. nil = unset, the
	// platform's any-fail rule applies. Read by the platform-verdict renderer
	// only; never a gate the CLI evaluates itself (the exit code is the
	// platform's verdict).
	MinPoints *int `json:"min_points,omitempty"`
}

// PolicyRequirement is one requirement grouping inside a policy's tree.
// Order is the platform's own stored position and is stable across
// requests; readers should not re-sort it.
type PolicyRequirement struct {
	Name     string          `json:"name"`
	Controls []PolicyControl `json:"controls"`
}

// PolicyControl is one control instance a requirement declares.
//
// Config stays RAW deliberately. The platform serves the bytes its own
// policy_controls.config column stores, and decoding into a generic map and
// re-marshaling was measured on the platform side to corrupt integers above
// 2^53 and to reorder keys. Carrying the bytes through untouched is what
// makes "verbatim" true rather than merely "semantically equivalent".
type PolicyControl struct {
	ControlType string          `json:"control_type"`
	Config      json.RawMessage `json:"config"`
}

// ControlConfig returns the raw config this policy declares for a control
// type, and whether the policy declares it at all. The search is over this
// policy's own tree only - never a sibling's.
func (p Policy) ControlConfig(controlType string) (json.RawMessage, bool) {
	for _, req := range p.Requirements {
		for _, c := range req.Controls {
			if c.ControlType == controlType {
				return c.Config, len(c.Config) > 0
			}
		}
	}
	return nil, false
}

// DeclaresAnyControl reports whether this policy carries a non-empty tree.
// A policy that declares nothing must fall back to the CLI's local config
// rather than evaluate against an empty ruleset.
func (p Policy) DeclaresAnyControl() bool {
	for _, req := range p.Requirements {
		if len(req.Controls) > 0 {
			return true
		}
	}
	return false
}

// IsReal reports whether this policy has a real platform id that a push may
// be keyed on. The derived fallback carries the nil uuid and must be pushed
// name-only instead, so a result is never keyed to a row that does not
// exist.
func (p Policy) IsReal() bool {
	id := strings.TrimSpace(p.ID)
	return id != "" && id != NilUUID
}

// ResolutionAnchor records what a snapshot's merged_yaml was resolved
// against. Ref and Sha are always present together. ConfigDigest and
// DigestVersion are present only when the platform could compute them, and
// are absent TOGETHER - an honest absence, never a fabricated value.
type ResolutionAnchor struct {
	Ref           string `json:"ref"`
	Sha           string `json:"sha"`
	ConfigDigest  string `json:"config_digest,omitempty"`
	DigestVersion string `json:"digest_version,omitempty"`
}

// HasDigest reports whether this anchor carries a usable comparison key.
// An anchor without one is ALWAYS DIVERGENT: there is nothing to compare
// against, so the branch's config must be resolved rather than assumed to
// match.
func (a *ResolutionAnchor) HasDigest() bool {
	return a != nil && strings.TrimSpace(a.ConfigDigest) != "" && strings.TrimSpace(a.DigestVersion) != ""
}

// Matches reports whether a locally computed (digest, version) pair is the
// same resolved config this anchor describes. Both the digest and the
// version must match: digests computed under different versions are not
// comparable even when both are 64 hex characters.
func (a *ResolutionAnchor) Matches(digest, version string) bool {
	if !a.HasDigest() || digest == "" || version == "" {
		return false
	}
	return a.ConfigDigest == digest && a.DigestVersion == version
}

// ProjectDetails is the project's core facts from the same lookup that
// resolves CiConfigPath (2026-08-27, #368 ask 4). Present whenever that
// lookup succeeds, archived projects included: the archived flag is half
// the point.
//
// The eight merge-settings fields below (MergeMethod through
// RemoveSourceBranchAfterMerge) were added a day later (2026-08-28, #368
// tier c) and are pointers ON PURPOSE: they are always present on a fresh
// collection since that date but ABSENT on a snapshot stored before then
// (it self-heals on the next refresh). A non-pointer decode would fabricate
// a false or empty value for that stale blob, which is exactly the
// "degraded stays honestly absent" rule SnapshotData exists to uphold.
type ProjectDetails struct {
	// DefaultBranch is the project's default branch at collection time.
	DefaultBranch string `json:"default_branch"`
	// Archived reports whether the project is archived. An archived
	// project still gets this section; its merged_yaml is honest-empty
	// with no degraded_fields entry.
	Archived bool `json:"archived"`
	// PathWithNamespace is the project's full path (group/project) as
	// GitLab reports it.
	PathWithNamespace string `json:"path_with_namespace"`

	// MergeMethod is GitLab's merge_method setting ("merge", "rebase_merge"
	// or "ff"). Nil on a pre-2026-08-28 snapshot.
	MergeMethod *string `json:"merge_method,omitempty"`
	// SquashOption is GitLab's squash_option setting. Nil on a
	// pre-2026-08-28 snapshot.
	SquashOption *string `json:"squash_option,omitempty"`
	// MergePipelinesEnabled is GitLab's merge_pipelines_enabled setting.
	// Nil on a pre-2026-08-28 snapshot.
	MergePipelinesEnabled *bool `json:"merge_pipelines_enabled,omitempty"`
	// MergeTrainsEnabled is GitLab's merge_trains_enabled setting. Nil on a
	// pre-2026-08-28 snapshot.
	MergeTrainsEnabled *bool `json:"merge_trains_enabled,omitempty"`
	// AllowMergeOnSkippedPipeline is GitLab's
	// allow_merge_on_skipped_pipeline setting. Nil on a pre-2026-08-28
	// snapshot.
	AllowMergeOnSkippedPipeline *bool `json:"allow_merge_on_skipped_pipeline,omitempty"`
	// ResolveOutdatedDiffDiscussions is GitLab's
	// resolve_outdated_diff_discussions setting. Nil on a pre-2026-08-28
	// snapshot.
	ResolveOutdatedDiffDiscussions *bool `json:"resolve_outdated_diff_discussions,omitempty"`
	// PrintingMergeRequestLinkEnabled is GitLab's
	// printing_merge_request_link_enabled setting. Nil on a pre-2026-08-28
	// snapshot.
	PrintingMergeRequestLinkEnabled *bool `json:"printing_merge_request_link_enabled,omitempty"`
	// RemoveSourceBranchAfterMerge is GitLab's
	// remove_source_branch_after_merge setting. Nil on a pre-2026-08-28
	// snapshot.
	RemoveSourceBranchAfterMerge *bool `json:"remove_source_branch_after_merge,omitempty"`
}

// SecurityPolicyProject is the GitLab security-policy-project linkage
// (2026-08-27, #368 ask 6).
//
// Known true with ID and FullPath set means the project is linked. Known
// true ALONE (both pointers nil) means the linkage was read
// authoritatively and genuinely found nothing linked - the real Critical
// for ISSUE-601, not an absence to be confused with "could not check".
// Known false means the read was NOT authoritative (auth failure, a null
// GraphQL project, or the field being unavailable on this instance),
// always paired with the "security_policy_project" degraded_fields entry;
// callers must treat that as not_evaluable, never as a pass or a fail.
//
// ID and FullPath are pointers because they are omitted, not zeroed, when
// there is nothing to report: ID absent means either not linked or not
// known, never a real id of 0.
type SecurityPolicyProject struct {
	Known    bool    `json:"known"`
	ID       *int    `json:"id,omitempty"`
	FullPath *string `json:"full_path,omitempty"`
}

// SnapshotData is the collected project settings the platform serves from
// its own cache. Every field is optional: a collection that degraded stays
// honestly absent rather than being fabricated as a zero value.
//
// BranchProtection, MrApprovals and Variables stay raw here on purpose -
// their shapes are the GitLab provider's, and decoding them in this package
// would drag that dependency in. See gitlab.ProtectionFromSnapshot.
type SnapshotData struct {
	// SchemaVersion tags this payload's shape. Absent on snapshots
	// collected before the field existed - an honest absence, not a "1".
	SchemaVersion string `json:"schema_version,omitempty"`

	// BranchProtection is {"protections": [...]} in the platform's current
	// shape. Raw: see the type doc.
	BranchProtection json.RawMessage `json:"branch_protection,omitempty"`

	// MergedYaml is the resolved CI configuration at ResolutionAnchor's sha.
	MergedYaml string `json:"merged_yaml,omitempty"`

	// MrApprovals is {"rules": [...], "settings": {...}}. Raw: see the type doc.
	MrApprovals json.RawMessage `json:"mr_approvals,omitempty"`

	// ResolutionAnchor is present only alongside a successfully resolved
	// MergedYaml.
	ResolutionAnchor *ResolutionAnchor `json:"resolution_anchor,omitempty"`

	// Variables is CI/CD variable METADATA - names, types, scopes and the
	// protected/masked/hidden flags. The platform never serves variable
	// VALUES here, by design. Raw: see the type doc.
	Variables json.RawMessage `json:"variables,omitempty"`

	// Includes is the git host's own per-include attribution for MergedYaml,
	// carried AS-IS in the CLI's MergedCIConfResponseInclude shape. It is the
	// difference between knowing a job came from an upstream component and
	// guessing the project wrote it; see control.controlsRequiringIncludeAttribution
	// for what depends on it. Present only alongside a resolved MergedYaml,
	// the same presence rule as ResolutionAnchor. Raw: decoded by gitlab.
	Includes []json.RawMessage `json:"includes,omitempty"`

	// CiConfigPath is the project's OWN configured CI config path, defaulting
	// to ".gitlab-ci.yml". The platform computes its anchor digest against
	// this path, so a project with a custom path can only ever cache-hit if
	// the CLI digests against it too.
	CiConfigPath string `json:"ci_config_path,omitempty"`

	// ProjectDetails carries the project's core facts and, when the
	// collection ran on or after 2026-08-28, its eight merge settings - see
	// the ProjectDetails type doc. Nil when the underlying lookup failed
	// (paired with DegradedFieldProjectDetails) or (pre-2026-08-27) the
	// platform had not started serving it yet.
	ProjectDetails *ProjectDetails `json:"project_details,omitempty"`

	// SecurityPolicyProject is the GitLab security-policy-project linkage -
	// see the SecurityPolicyProject type doc for its three meaningful
	// shapes. Nil when the linkage was never read (pre-2026-08-27
	// platform, or the field simply was not served).
	SecurityPolicyProject *SecurityPolicyProject `json:"security_policy_project,omitempty"`

	// RawConfig is the RAW, un-merged root CI config file exactly as
	// fetched, at CiConfigPath on the default branch. Present whenever the
	// file fetch itself succeeded, including when the merge step failed or
	// reported INVALID - so a reader can distinguish "no CI file" from
	// "file exists but the merge is absent/broken". Absent past the
	// platform's own size cap (paired with DegradedFieldRawConfig) or when
	// the fetch genuinely failed.
	RawConfig string `json:"raw_config,omitempty"`

	// MergedYamlStatus is GitLab's own merge status for MergedYaml,
	// verbatim ("VALID" or "INVALID"). Absent when the merge response
	// itself is absent: an archived project (see ProjectDetails.Archived)
	// or the merge fetch failed (then DegradedFieldMergedYaml is set).
	// Deliberately not named "Status" bare (INVARIANTS rule A).
	MergedYamlStatus string `json:"merged_yaml_status,omitempty"`

	// CiErrors is GitLab's CI lint/merge errors for MergedYaml, verbatim.
	// Omitted when empty; typically non-empty exactly when
	// MergedYamlStatus is "INVALID".
	CiErrors []string `json:"ci_errors,omitempty"`

	// DegradedFields names the collection lanes that FAILED for this
	// snapshot, from the closed set in DegradedField*. It is the distinction
	// the CLI could not previously make: a lane that is absent AND unlisted
	// is honestly empty and a control may FAIL against it, while a listed
	// lane could not be read and must report not_evaluable instead.
	//
	// Trust it only at SchemaVersion "2" or later - see DegradedFieldsTrusted.
	DegradedFields []string `json:"degraded_fields,omitempty"`
}

// The closed set of lane identifiers DegradedFields may carry. Anything
// else is a platform documentation bug; the CLI carries unknown values
// through to the operator rather than dropping them silently.
const (
	DegradedFieldBranchProtection = "branch_protection"
	DegradedFieldMrApprovals      = "mr_approvals"
	DegradedFieldVariables        = "variables"
	DegradedFieldMergedYaml       = "merged_yaml"
	DegradedFieldProjectDetails   = "project_details"

	// DegradedFieldRawConfig means the raw CI config fetch itself
	// succeeded but exceeded the platform's size cap (maxRawConfigBytes,
	// 1 MiB) at collection time - a genuine could-not-serve-faithfully,
	// distinct from "could not be fetched" but the same not_evaluable
	// treatment applies.
	DegradedFieldRawConfig = "raw_config"
	// DegradedFieldSourceCatalog means at least one component include's
	// catalogue lookup genuinely failed. Never set when a lookup merely
	// determined the target is not a catalogue resource - that is a
	// present-but-empty answer, not a degradation.
	DegradedFieldSourceCatalog = "source_catalog"
	// DegradedFieldSecurityPolicyProject means the security-policy-project
	// linkage read was not authoritative (SecurityPolicyProject.Known is
	// false).
	DegradedFieldSecurityPolicyProject = "security_policy_project"
	// DegradedFieldIncludesJobs means at least one include's job
	// attribution could not be established, or the derive call was capped
	// or failed.
	DegradedFieldIncludesJobs = "includes_jobs"
)

// SnapshotSchemaV2 is the first schema version whose DegradedFields absence
// is a GUARANTEE rather than merely an absence.
const SnapshotSchemaV2 = "2"

// snapshotSchemaV2Num is SnapshotSchemaV2 as a number, for the numeric
// comparison in DegradedFieldsTrusted.
const snapshotSchemaV2Num = 2

// DegradedFieldsTrusted reports whether this payload's DegradedFields may be
// read as complete. Below v2 the field did not exist, so an empty list is
// indistinguishable from an older collection that never recorded the
// bookkeeping - treating that as "nothing degraded" is exactly the false
// reassurance the version gate exists to prevent.
// The comparison is NUMERIC, not lexical. Comparing the strings would make
// "10" sort below "2" and silently distrust every snapshot from schema 10
// onward - a bug that would lie dormant for years and then quietly disable
// the degradation signal exactly when it is hardest to notice.
//
// A version that is not a number at all is not trusted: an unparseable tag
// is not evidence the bookkeeping exists.
func (d *SnapshotData) DegradedFieldsTrusted() bool {
	if d == nil {
		return false
	}
	n, err := strconv.Atoi(strings.TrimSpace(d.SchemaVersion))
	if err != nil {
		return false
	}
	return n >= snapshotSchemaV2Num
}

// IsDegraded reports whether a named lane failed collection. It answers
// false when the payload predates the bookkeeping (see DegradedFieldsTrusted)
// - callers must not read that false as "this lane is fine", only as "this
// snapshot cannot tell us".
func (d *SnapshotData) IsDegraded(field string) bool {
	if !d.DegradedFieldsTrusted() {
		return false
	}
	for _, f := range d.DegradedFields {
		if f == field {
			return true
		}
	}
	return false
}

// Snapshot is the platform's cached data collection for a project. A cache
// miss serializes as an empty snapshot (both fields nil) on a 200 - never a
// 404 and never fabricated content.
type Snapshot struct {
	CollectedAt *time.Time    `json:"collected_at,omitempty"`
	Data        *SnapshotData `json:"data,omitempty"`
}

// Anchor returns the snapshot's resolution anchor, or nil when the snapshot
// carries no data or was collected without one.
func (s Snapshot) Anchor() *ResolutionAnchor {
	if s.Data == nil {
		return nil
	}
	return s.Data.ResolutionAnchor
}

// DismissedIssue is one entry of ProjectContext.DismissedIssues: the match key for a finding the
// platform has in status Dismissed (#447). IdentityHash is the platform's full sha256 hex over
// the shared recipe's Pairs() (identity.PlatformHash); RecipeVersion is the recipe the hash was
// computed under and versions never mix; ControlType rides along as a cheap pre-filter, never
// part of the key.
type DismissedIssue struct {
	IdentityHash  string `json:"identity_hash"`
	RecipeVersion int    `json:"recipe_version"`
	ControlType   string `json:"control_type"`
}

// ProjectContext is the GET .../context response: the resolved policy set
// plus the cached data snapshot. Fetching it never triggers a collection on
// the platform - it is always a cache read.
type ProjectContext struct {
	SchemaVersion   int              `json:"schema_version"`
	Project         string           `json:"project"`
	Policies        []Policy         `json:"policies"`
	Snapshot        Snapshot         `json:"snapshot"`
	DismissedIssues []DismissedIssue `json:"dismissed_issues"`
}

// ResolveRequest asks the platform to resolve the CI config at a specific
// sha. ConfigDigest and DigestVersion are an ALL-OR-NOTHING pair and are
// omitted together when the CLI's own digest computation aborted (a
// traversal over the file cap, or a read failure); the platform then treats
// the config as uncacheable and resolves fresh.
type ResolveRequest struct {
	Sha           string `json:"sha"`
	ConfigDigest  string `json:"config_digest,omitempty"`
	DigestVersion string `json:"digest_version,omitempty"`
}

// ResolvedConfig is the 200 response of the resolve endpoint.
type ResolvedConfig struct {
	// MergedYaml is the resolved configuration. It may be EMPTY when Valid
	// is false.
	MergedYaml string `json:"merged_yaml"`

	// ResolvedSha is the sha this merged_yaml was resolved at. On a cache
	// hit it is the CACHED resolution's sha, which may differ from the sha
	// that was requested: identical config content shares one resolution.
	// Never assert it equals the requested sha.
	ResolvedSha string `json:"resolved_sha"`

	// Valid is false when the git host reported the CI config merge as
	// INVALID - a user error in the pushed config, not a resolution
	// failure. Still a 200.
	Valid bool `json:"valid"`

	// Source is "cache" or "resolved".
	Source string `json:"source"`

	// ConfigDigest / DigestVersion are the PLATFORM's own computation and
	// are authoritative for its cache key. A mismatch against what the CLI
	// sent is a diagnostic, never an error.
	ConfigDigest  string `json:"config_digest,omitempty"`
	DigestVersion string `json:"digest_version,omitempty"`
}
