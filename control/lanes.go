package control

import (
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/internal/platform"
)

// Machine-readable reasons a control's data lane supplied nothing. They
// travel to the platform on the finding, so an operator can tell "we could
// not check this" apart from "this passed" without reading prose.
const (
	// ReasonResolutionUnavailable: no merged CI configuration could be
	// obtained for this run, so nothing that reads the merged pipeline can
	// be evaluated.
	ReasonResolutionUnavailable = "resolution_unavailable"

	// ReasonIncludeAttributionUnavailable: a merged configuration IS
	// available, but not the per-include attribution (which include came
	// from which project, at which ref and blob) that only the git host's
	// config-merge API returns. Controls that reason about includes
	// themselves cannot run on merged YAML alone.
	ReasonIncludeAttributionUnavailable = "include_attribution_unavailable"

	// ReasonSnapshotLaneDegraded: the platform reported this control's
	// snapshot lane as a FAILED collection (degraded_fields), so its absence
	// is not evidence of an honestly-empty setting. Distinct from an absent
	// lane the platform vouches for, which a control may legitimately FAIL
	// against.
	ReasonSnapshotLaneDegraded = "snapshot_lane_degraded"

	// ReasonLaneNotServed: neither lane can feed this control in platform
	// mode - the snapshot contract does not carry its data, and the runner's
	// CI_JOB_TOKEN cannot fetch it either.
	ReasonLaneNotServed = "lane_not_served"

	// ReasonIncludeResolutionFailed: at least one include could not be
	// resolved this run, so both the include list and the per-job
	// attribution built from it are INCOMPLETE rather than merely absent.
	//
	// A dropped include takes its jobs with it: the jobs still appear in the
	// merged pipeline but nothing attributes them to the include that
	// contributed them, so they read as project-authored. That direction
	// fabricates findings, which is why this degrades the same controls a
	// missing attribution lane does rather than being reported as a warning
	// beside them.
	ReasonIncludeResolutionFailed = "include_resolution_failed"

	// ReasonUpstreamProbeFailed: a check against the include's SOURCE
	// project could not be completed, so the control has no evidence either
	// way.
	//
	// These probes are fail-safe: only a confirmed result sets the flag they
	// feed, and a failed probe leaves it at its zero value. That is right for
	// the flag and wrong for the report, because the zero value reads as a
	// clean answer - "this ref is not ambiguous" - that nothing established.
	ReasonUpstreamProbeFailed = "upstream_probe_failed"

	// ReasonRawConfigUnavailable: the project's own UNMERGED CI file could
	// not be read, though the merged pipeline was obtained anyway.
	//
	// The merged document answers almost every rule, so the run is still
	// worth having. Two controls compare the pre-merge file against it, and
	// both fail silently without it rather than loudly: an unread root
	// yields no hardcoded jobs and no local variables, which reads as
	// nothing to report.
	ReasonRawConfigUnavailable = "raw_config_unavailable"

	// ReasonCollectionFailed: a collection this run makes ITSELF could not
	// be completed, so the control that reads it has no data.
	//
	// Distinct from the snapshot reasons above, which describe a lane the
	// PLATFORM could not fill. This one applies in every mode, because a
	// token without the scope for one endpoint is not a platform-mode
	// condition.
	ReasonCollectionFailed = "collection_failed"
)

// controlsRequiringIncludeAttribution lists the GitLab controls whose
// verdict depends on per-include attribution, not merely on the merged
// pipeline. Attribution comes only from the git host's config-merge
// response; a merged YAML document alone does not carry where each job or
// include came from.
//
// It reaches the rules two ways, and BOTH belong here:
//
//   - input.pipeline.includes — the include list itself, for the "is this
//     include pinned / up to date / colliding" checks. Without attribution
//     the list is empty and those controls find nothing: a silent pass.
//   - job.originKind and job.overridden — per-JOB attribution, built from
//     the same include list. Without it every job pulled in by a component
//     or template is indistinguishable from one the project authored, and
//     is classified "hardcoded". That direction produces FALSE POSITIVES,
//     not silent passes: an upstream template job that legitimately ships
//     `when: never` reads as the project having tampered with it. Measured
//     on a real project, dropping attribution turned 1 hardcoded job into
//     9 and invented 7 ISSUE-410 findings that a standalone run of the
//     same commit did not produce.
//
// TestControlsRequiringIncludeAttributionMatchesPolicies derives this same
// set from the policy sources and fails if the two drift.
var controlsRequiringIncludeAttribution = []string{
	"externalRefsMustNotCollide",
	"includesMustBeUpToDate",
	"includesMustNotUseForbiddenVersions",
	"pipelineMustIncludeComponent",
	"pipelineMustIncludeTemplate",
	"pipelineMustNotIncludeHardcodedJobs",
	"securityJobsMustNotBeWeakened",
}

// MarkNotEvaluable records that a control could not be evaluated this run
// and why. The FIRST reason recorded for a control wins: the earliest lane
// to come up empty is the most specific explanation, and a later, broader
// failure should not overwrite it.
func (r *AnalysisResult) MarkNotEvaluable(controlName, reason string) {
	if r == nil || controlName == "" {
		return
	}
	if r.NotEvaluable == nil {
		r.NotEvaluable = map[string]string{}
	}
	if _, exists := r.NotEvaluable[controlName]; exists {
		return
	}
	r.NotEvaluable[controlName] = reason
}

// MarkIncludeAttributionUnavailable flags every control that reasons about
// include attribution as not evaluable. Used when the merged configuration
// came from somewhere that does not carry per-include provenance — today,
// the platform snapshot or its resolve endpoint, both of which return the
// merged document only.
func (r *AnalysisResult) MarkIncludeAttributionUnavailable(entries []ControlEntry) {
	r.markIncludeControls(entries, ReasonIncludeAttributionUnavailable)
}

// markIncludeControls flags the include-reasoning controls with reason.
// Attribution can be missing for more than one cause, and an operator needs
// to know which: a snapshot that served no includes is a platform gap,
// while an include the runner could not resolve is a credential or a
// permission on the upstream project.
func (r *AnalysisResult) markIncludeControls(entries []ControlEntry, reason string) {
	enabled := map[string]bool{}
	for _, e := range entries {
		if !e.Skipped {
			enabled[e.ControlName] = true
		}
	}
	for _, name := range controlsRequiringIncludeAttribution {
		// Skip controls the operator disabled: they were not "unevaluated",
		// they were turned off. Marking them would inflate every
		// not-evaluated count and list a disabled control in the JSON's
		// notEvaluable map as if something had gone wrong.
		if len(entries) > 0 && !enabled[name] {
			continue
		}
		r.MarkNotEvaluable(name, reason)
	}
}

// MarkMergedConfigUnavailable flags every control that reads the merged CI
// pipeline as not evaluable, with reason.
//
// The set is every GitLab control EXCEPT the ones that read a different
// source entirely: branchMustBeProtected evaluates the provider's branch
// protection API, so an unavailable CI configuration says nothing about
// it. Listing the exceptions rather than enumerating the dependents is
// deliberate — a control added later reads the merged pipeline unless it
// says otherwise, and defaulting a new control to not_evaluable when the
// config is missing is the safe direction.
func (r *AnalysisResult) MarkMergedConfigUnavailable(entries []ControlEntry, reason string) {
	for _, e := range entries {
		// A control the operator disabled was not "unevaluated", it was
		// deliberately turned off. Marking it would inflate every
		// not-evaluated count and put a disabled control in a bucket that
		// implies something went wrong.
		if e.Skipped {
			continue
		}
		if controlsIndependentOfMergedConfig[e.ControlName] {
			continue
		}
		r.MarkNotEvaluable(e.ControlName, reason)
	}
}

// markPlatformLaneGaps records which controls platform mode's data lanes
// could not feed for this run. A no-op in standalone mode, which is the
// CLI's default: without --platform nothing here applies and no control's
// status changes.
//
// Two gaps exist, and they are different sizes:
//
//   - No merged configuration at all (the platform's snapshot anchor did
//     not match and its resolve endpoint was unavailable). Every control
//     that reads the pipeline is not_evaluable; settings-based controls are
//     unaffected and still report a real verdict.
//   - A merged configuration but no per-include attribution. The platform
//     now serves includes[] alongside a resolved merged_yaml (snapshot
//     schema v2), so this is no longer unconditional: when attribution IS
//     supplied the include-reasoning controls evaluate normally, and only a
//     snapshot that omits it degrades them.
//
// A third gap is per-lane rather than per-config: MarkDegradedSnapshotLanes
// handles the settings lanes the platform reported as failed collections,
// plus the controls its contract carries no lane for at all.
func markPlatformLaneGaps(result *AnalysisResult, conf *configuration.Configuration) {
	if conf == nil {
		return
	}
	markPlatformLaneGapsFor(result, conf, conf.PlumberConfig)
}

// markPlatformLaneGapsFor is markPlatformLaneGaps against a SPECIFIC
// control configuration rather than the run's own.
//
// Which controls get marked depends on which are enabled, and in platform
// mode that is not one question but one per policy: each policy is
// evaluated under its own control tree, and a control switched off locally
// may be switched on by a policy. Marking only against the local config
// leaves such a control unmarked, so its findings survive the drop and are
// pushed as that policy's verdict - computed over data the lane never
// supplied. That is the fabricated-findings mode this file exists to
// prevent, arriving through the per-policy path instead of the run's.
func markPlatformLaneGapsFor(result *AnalysisResult, conf *configuration.Configuration, pc *configuration.PlumberConfig) {
	if result == nil || conf == nil || !conf.PlatformRun.Engaged() {
		return
	}
	entries := GitLabControls(pc)
	result.MarkDegradedSnapshotLanes(entries, conf.PlatformRun)
	if _, available := conf.PlatformRun.MergedYAML(); !available {
		reason := conf.PlatformRun.UnavailableReason()
		if reason == "" {
			reason = ReasonResolutionUnavailable
		}
		// GitLabControls(nil) returns nothing, so a run with no loaded
		// config would mark nothing and drop nothing — an unavailable
		// resolution would then read as an all-clean pipeline. There is
		// always an effective config by this point in a real run; the
		// fallback keeps the guarantee if that ever stops being true.
		if len(entries) == 0 {
			for _, name := range controlsRequiringIncludeAttribution {
				result.MarkNotEvaluable(name, reason)
			}
		}
		result.MarkMergedConfigUnavailable(entries, reason)
	} else if _, haveIncludes := conf.PlatformRun.SnapshotIncludes(); !haveIncludes || !conf.PlatformRun.ConfigAndIncludesAgree() {
		// A merged configuration with no USABLE attribution alongside it.
		// Two ways that happens, and both must degrade:
		//
		//   - the snapshot carried no includes at all, or
		//   - it carried includes for a DIFFERENT configuration than the one
		//     being evaluated. On a digest-divergent branch MergedYAML is the
		//     branch's freshly resolved config while the includes still
		//     describe the anchor's, and the resolve endpoint serves no
		//     includes of its own (see RunContext.ConfigAndIncludesAgree).
		//
		// Marking here is not merely withholding a verdict: without matching
		// attribution the per-job origin is WRONG, not absent, so these
		// controls would report fabricated violations rather than none.
		result.MarkIncludeAttributionUnavailable(entries)
	} else if includesFailedToResolve(result) {
		// Attribution WAS served and does describe this configuration, but
		// building the per-job half of it still needs each include resolved
		// on its own, and at least one could not be. That is the normal
		// outcome for a runner holding only a job token, which cannot reach
		// the config-merge API the resolution goes through.
		//
		// The consequence is the fabricating one, not the silent one: a
		// dropped include leaves its jobs in the merged pipeline with
		// nothing attributing them upstream, so they read as
		// project-authored and the rules keyed on that distinction fire on
		// them. Degrading here is what stops those findings being pushed.
		result.markIncludeControls(entries, ReasonIncludeResolutionFailed)
	}

	MarkOwnCollectionGaps(result, entries)
}

// MarkOwnCollectionGaps marks the controls whose OWN check could not be
// completed, independent of where the run got its configuration.
//
// Every input here comes from a collection this CLI performs itself in BOTH
// modes: a tag-vs-branch probe against an include's source project, a
// catalogue lookup for its latest version, the project's own unmerged CI
// file. None of it is platform-specific.
//
// It used to live inside the platform-gated marker, which meant a plain
// `plumber analyze` recorded these failures and then read nobody: a rate
// limit or a 403 on the source project left externalRefsMustNotCollide and
// includesMustBeUpToDate reporting a clean pass. The failures degrade ONE
// control each rather than the whole attribution set, and they happen on
// runs where everything else went fine, which is exactly why nothing else
// caught them.
func MarkOwnCollectionGaps(result *AnalysisResult, entries []ControlEntry) {
	if result == nil {
		return
	}
	markOne := func(name, reason string) {
		for _, e := range entries {
			if e.ControlName == name && e.Skipped {
				return
			}
		}
		result.MarkNotEvaluable(name, reason)
	}
	if upstreamProbesFailed(result) {
		markOne("externalRefsMustNotCollide", ReasonUpstreamProbeFailed)
	}
	if versionLookupsFailed(result) {
		markOne("includesMustBeUpToDate", ReasonUpstreamProbeFailed)
	}
	if rawConfigUnavailable(result) {
		markOne("pipelineMustNotOverrideJobVariables", ReasonRawConfigUnavailable)
		markOne("pipelineMustNotIncludeHardcodedJobs", ReasonRawConfigUnavailable)
	}
	result.DropNotEvaluableFindings()
}

// upstreamProbesFailed reports whether this run failed to complete a
// tag-vs-branch lookup against an include's source project.
func upstreamProbesFailed(result *AnalysisResult) bool {
	return result != nil &&
		result.PipelineOriginData != nil &&
		len(result.PipelineOriginData.RefProbesFailed) > 0
}

// rawConfigUnavailable reports whether the project's own unmerged CI file
// went unread while the merged pipeline was obtained anyway.
func rawConfigUnavailable(result *AnalysisResult) bool {
	return result != nil &&
		result.PipelineOriginData != nil &&
		result.PipelineOriginData.RawConfigUnavailable
}

// versionLookupsFailed reports whether this run failed to learn an include's
// latest upstream version - the component catalogue query or the tag listing
// on the include's source project.
func versionLookupsFailed(result *AnalysisResult) bool {
	return result != nil &&
		result.PipelineOriginData != nil &&
		len(result.PipelineOriginData.VersionLookupsFailed) > 0
}

// includesFailedToResolve reports whether this run dropped an include it
// could not fetch. The collector records each one so the run can be flagged
// degraded; the same record is what tells the include-reasoning controls
// their input is incomplete.
func includesFailedToResolve(result *AnalysisResult) bool {
	return result != nil &&
		result.PipelineOriginData != nil &&
		len(result.PipelineOriginData.IncludesFailed) > 0
}

// MarkFailedCollections flags the controls whose own collection could not
// be completed, and drops their findings.
//
// It runs in EVERY mode, unlike the snapshot lane marking. The failure it
// covers is a permission, not a platform: a token that cannot list a
// project's protected branches gets an error where it expected a list, and
// an empty protection list is indistinguishable from a project that
// protects nothing - which is the exact violation branchMustBeProtected
// exists to report. Left unmarked, the loudest possible false positive
// fires on every branch the config names.
//
// The branch NAMES survive such a failure, so this is specifically about
// the protection detail; a control that reads only the branch list would
// still be evaluable.
func (r *AnalysisResult) MarkFailedCollections(entries []ControlEntry) {
	if r == nil || r.ProtectionData == nil || r.ProtectionData.BranchProtectionsKnown {
		return
	}
	enabled := map[string]bool{}
	for _, e := range entries {
		if !e.Skipped {
			enabled[e.ControlName] = true
		}
	}
	if len(entries) > 0 && !enabled[controlBranchMustBeProtected] {
		return
	}
	r.MarkNotEvaluable(controlBranchMustBeProtected, ReasonCollectionFailed)
	r.DropNotEvaluableFindings()
}

// NotEvaluableReason returns the machine-readable reason this control's own
// data lane could not feed it, and whether it was marked at all.
//
// Use this, not the run-level DegradedReasons, when explaining a StatusError
// for ONE control. DegradedReasons describes the RUN, so per-control it
// either says nothing (when empty) or names an unrelated cause: a run
// degraded by a failed variables fetch would explain an unevaluable include
// control with the variables failure.
func (r *AnalysisResult) NotEvaluableReason(controlName string) (string, bool) {
	if r == nil {
		return "", false
	}
	reason, ok := r.NotEvaluable[controlName]
	return reason, ok
}

// DropNotEvaluableFindings removes every finding belonging to a control
// this run marked not evaluable.
//
// A control is marked when its data lane could not feed it, and a lane can
// fail in two ways: by supplying nothing, or by supplying something WRONG.
// The second is why the findings go rather than just the status. Without
// include attribution, jobs a component contributed are indistinguishable
// from ones the project wrote, so rules keyed on that distinction fire on
// upstream jobs behaving normally. Keeping those findings would push
// fabricated violations to the platform and deduct real score points for
// them.
//
// Reporting nothing for a control that could not be evaluated is the
// honest outcome, and the not_evaluable status is what carries the fact
// that it was checked at all.
func (r *AnalysisResult) DropNotEvaluableFindings() {
	if r == nil || len(r.NotEvaluable) == 0 || len(r.Findings) == 0 {
		return
	}
	kept := r.Findings[:0]
	for _, f := range r.Findings {
		info := LookupCode(ErrorCode(f.Code))
		if info != nil {
			if _, marked := r.NotEvaluable[info.ControlName]; marked {
				continue
			}
		}
		kept = append(kept, f)
	}
	r.Findings = kept
}

// controlsIndependentOfMergedConfig names the controls that read a project
// or repository setting rather than the merged CI pipeline, and so still
// evaluate when no merged configuration is available.
//
// A control NOT listed here is treated as pipeline-reading and degrades to
// not_evaluable without a merged configuration. That default is the safe
// direction, so a new pipeline control needs no change here; a new
// SETTINGS control does, or it will wrongly report not_evaluable on a run
// whose CI configuration was unavailable but whose settings were collected
// fine. TestControlsIndependentOfMergedConfigAreRealControls guards the
// names themselves against drift.
var controlsIndependentOfMergedConfig = map[string]bool{
	// Evaluates the provider's branch-protection API, never the pipeline.
	"branchMustBeProtected": true,
	// Read the project's CI/CD settings variables (Settings > CI/CD), not
	// the pipeline's own `variables:` block.
	"cicdVariablesMustBeProtected": true,
	"cicdVariablesMustBeMasked":    true,
	// Read the merge-request approval rules and settings APIs.
	"mergeRequestApprovalRulesMustRequireMinimumApprovals":   true,
	"mergeRequestApprovalRulesMustCoverAllProtectedBranches": true,
	"mergeRequestApprovalSettingsMustBeCompliant":            true,
	// Reads the project payload (Settings > Merge requests).
	"mergeRequestSettingsMustBeCompliant": true,
	// Reads the project's linked security policy project over GraphQL.
	"projectMustHaveSecurityPolicySource": true,
}

// snapshotLaneControls maps each platform snapshot lane identifier to the
// controls that read it. A lane the platform reports as DEGRADED could not
// be collected, so its controls must report not_evaluable rather than FAIL
// against a value that was guessed-empty.
//
// merged_yaml is deliberately absent: an unavailable merged configuration is
// already handled by the config-resolution path (MarkMergedConfigUnavailable),
// which knows the far larger set of pipeline-reading controls.
var snapshotLaneControls = map[string][]string{
	platform.DegradedFieldBranchProtection: {"branchMustBeProtected"},
	platform.DegradedFieldMrApprovals: {
		"mergeRequestApprovalRulesMustRequireMinimumApprovals",
		"mergeRequestApprovalRulesMustCoverAllProtectedBranches",
		"mergeRequestApprovalSettingsMustBeCompliant",
	},
	platform.DegradedFieldVariables: {
		"cicdVariablesMustBeProtected",
		"cicdVariablesMustBeMasked",
	},
	platform.DegradedFieldProjectDetails: {"mergeRequestSettingsMustBeCompliant"},
}

// lanesWhoseAbsenceIsAFailure names the snapshot lanes the platform writes
// on EVERY successful collection, empty lists included. For those, an
// absent lane is never "the project has none": it is the collection not
// having completed, and its controls must abstain rather than score against
// nothing.
//
// This is not the same question degraded_fields answers, and it is not
// redundant with it. degraded_fields is only trustworthy from schema v2
// onward, so an older snapshot can be missing a lane AND report nothing
// degraded — a state that would otherwise read as a clean pass on a
// project whose branch protections were simply never collected.
//
// variables is deliberately NOT here: the platform omits it when the
// project genuinely has no CI/CD variables, which both variable controls
// should pass on. Its absence is an answer, not a gap.
var lanesWhoseAbsenceIsAFailure = map[string]bool{
	platform.DegradedFieldBranchProtection: true,
	platform.DegradedFieldMrApprovals:      true,
}

// controlsWithNoPlatformLane names controls the platform snapshot carries no
// data for at all. They are not degraded and not empty: the lane does not
// exist, so in platform mode there is nothing they could honestly evaluate
// against and they must say so rather than pass.
//
// projectMustHaveSecurityPolicySource reads GitLab's GraphQL
// securityPolicyProject, which the snapshot contract does not serve. A
// CI_JOB_TOKEN cannot reach GraphQL either, so neither lane can feed it.
//
// mergeRequestSettingsMustBeCompliant reads the project payload's merge
// settings (merge_method, squash_option, merge trains, …). The snapshot
// carries no project_details lane, even though the platform's own
// collector already fetches that payload and keeps one field from it, so
// this is a gap in what is SERVED rather than in what is collected.
// Reporting it here rather than letting the control quietly abstain is
// what makes it visible as a platform ask instead of a mystery.
var controlsWithNoPlatformLane = map[string]string{
	"projectMustHaveSecurityPolicySource": ReasonLaneNotServed,
	"mergeRequestSettingsMustBeCompliant": ReasonLaneNotServed,
}

// MarkDegradedSnapshotLanes flags the controls whose platform snapshot lane
// failed collection, plus the controls the snapshot has no lane for at all.
//
// This is the distinction the CLI could not previously make. Before the
// platform served degraded_fields, an absent lane could equally mean "this
// project genuinely has no branch protections" (a real violation a control
// SHOULD fail on) or "the collection blew up". Failing on the first and
// abstaining on the second are both correct; guessing between them is not.
func (r *AnalysisResult) MarkDegradedSnapshotLanes(entries []ControlEntry, run *platform.RunContext) {
	if r == nil || !run.Engaged() {
		return
	}
	enabled := map[string]bool{}
	for _, e := range entries {
		if !e.Skipped {
			enabled[e.ControlName] = true
		}
	}
	mark := func(name, reason string) {
		if len(entries) > 0 && !enabled[name] {
			return
		}
		r.MarkNotEvaluable(name, reason)
	}
	for lane, controls := range snapshotLaneControls {
		// Two ways a lane cannot feed its controls, reported the same way
		// because they mean the same thing to the run: the platform said
		// the collection failed, or the lane is absent from a payload that
		// would carry it on any success. See lanesWhoseAbsenceIsAFailure.
		unusable := run.LaneDegraded(lane) ||
			(lanesWhoseAbsenceIsAFailure[lane] && run.LaneMissing(lane))
		if !unusable {
			continue
		}
		for _, name := range controls {
			mark(name, ReasonSnapshotLaneDegraded)
		}
	}
	for name, reason := range controlsWithNoPlatformLane {
		mark(name, reason)
	}
	if branchListLostOnTheWire(r) {
		mark("branchMustBeProtected", ReasonSnapshotLaneDegraded)
	}
}

// branchListLostOnTheWire reports whether the branch-protection lane
// arrived carrying no branch NAMES.
//
// Every real project has at least one branch, so an empty name list is not
// a fact about the project - it is the lane not having survived. There is a
// known way for that to happen: the platform stores the collector's Go
// slices, a nil slice marshals to JSON `null`, and the context endpoint
// decodes into pointer fields tagged omitempty, so a null list is re-served
// with its key ABSENT. The lane then looks present and well-formed while
// carrying nothing.
//
// It matters which way this fails. With no names, buildBranches produces no
// branches, the rule iterates an empty list and the control passes - a
// project whose protections could not be read is certified compliant. This
// is the only lane where emptiness is impossible rather than merely
// unlikely, which is why the guard is here and not a general rule.
func branchListLostOnTheWire(r *AnalysisResult) bool {
	return r != nil && r.ProtectionData != nil && len(r.ProtectionData.Branches) == 0
}

// ReEvaluateForConfig re-runs the rule engine over the pipeline this run
// already collected, under a DIFFERENT control configuration, and returns
// the findings plus the score they produce.
//
// It exists for platform mode's per-policy evaluation. The platform serves
// each policy its own control parameters, and a policy's verdict has to come
// from its own parameters: reporting a finding computed under policy A's
// config while claiming policy B's effective config is a false positive
// under B, not merely an imprecise label.
//
// Nothing is re-collected. The IR is the one the run already built, so this
// costs a rule evaluation and no git-host traffic. A run with no retained
// pipeline (the GitHub path, or a limited analysis that never built one)
// returns ok=false and the caller keeps the run's own verdict rather than
// inventing an empty one.
func ReEvaluateForConfig(
	result *AnalysisResult,
	conf *configuration.Configuration,
	provider string,
	pc *configuration.PlumberConfig,
) (scoped *AnalysisResult, score PlumberScoreResult, ok bool) {
	if result == nil || conf == nil || pc == nil {
		return nil, PlumberScoreResult{}, false
	}
	// The two providers keep their IR in different fields, so reading
	// result.Pipeline directly made this a silent no-op for every GitHub
	// run: ok=false, and the caller quietly kept the LOCAL config's verdict
	// while still labelling it with this policy's effective_config. Platform
	// mode runs for GitHub too (cmd/analyze_shared.go wires it for both), so
	// that mislabelled every GitHub policy carrying its own control tree.
	pipeline := result.evaluatedPipeline()
	if pipeline == nil {
		return nil, PlumberScoreResult{}, false
	}
	// evaluatePolicies reads the controls off conf.PlumberConfig, so swap in
	// the policy's config for the duration of this evaluation. The copy is
	// shallow and local: the caller's Configuration is never mutated.
	scopedConf := *conf
	scopedConf.PlumberConfig = pc

	found := evaluatePolicies(l.WithField("scope", "per-policy"), &scopedConf, provider, pipeline)

	// The same honesty rules the run applied must apply here, or a policy's
	// verdict would include findings the run itself withheld as unevaluable.
	scopedResult := *result
	scopedResult.Findings = found
	scopedResult.NotEvaluable = nil
	for k, v := range result.NotEvaluable {
		scopedResult.MarkNotEvaluable(k, v)
	}
	// Inheriting the run's marks is not enough. Every marker skips controls
	// the config it was given had DISABLED, and the run's marks were
	// computed against the LOCAL config. A control this policy enables and
	// the local config does not was therefore never marked, so its findings
	// would survive the drop below and be pushed as this policy's verdict -
	// computed over a lane that supplied nothing. Re-marking against the
	// policy's own controls closes that, and MarkNotEvaluable is
	// first-reason-wins so the run's own reasons are never overwritten.
	if provider == configuration.ProviderGitLab {
		markPlatformLaneGapsFor(&scopedResult, &scopedConf, pc)
	}
	scopedResult.DropNotEvaluableFindings()

	counts := map[ErrorCode]int{}
	for _, f := range scopedResult.Findings {
		counts[ErrorCode(f.Code)]++
	}
	// The whole scoped result is returned, not just its findings. The marks
	// computed just above are what StatusFor reads to report a control as
	// not_evaluable, and DropNotEvaluableFindings has already removed the
	// findings they cover. Returning findings alone left the caller holding
	// an empty list and the RUN's marks, so a control this policy enables
	// over a dead lane was pushed as `pass` - the drop making it look clean
	// rather than making it honest.
	return &scopedResult, ComputePlumberScore(counts), true
}

// evaluatedPipeline returns the normalized IR this run built, from whichever
// field the provider that produced it uses. GitLab writes result.Pipeline and
// GitHub writes result.GitHubPipeline; exactly one is ever set.
func (r *AnalysisResult) evaluatedPipeline() *ir.NormalizedPipeline {
	if r == nil {
		return nil
	}
	if r.Pipeline != nil {
		return r.Pipeline
	}
	return r.GitHubPipeline
}
