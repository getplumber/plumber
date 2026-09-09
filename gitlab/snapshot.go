package gitlab

import (
	"encoding/json"
	"strings"

	"github.com/getplumber/plumber/internal/platform"
	glab "gitlab.com/gitlab-org/api/client-go"
)

// This file is the GitLab side of issue #368's lane split: the settings a
// runner cannot read for itself, decoded out of the platform's snapshot
// instead of fetched from GitLab.
//
// The shapes are the platform's collector's, and the platform builds them
// by importing this very package (ADR-0021, "one implementation, two
// hosts"): branch_protection.protections IS []BranchProtection, and
// mr_approvals.rules IS []*glab.ProjectApprovalRule. So these decoders are
// a json.Unmarshal and a mapping of PRESENCE onto the Known flags the
// controls already read, not a translation.
//
// The presence mapping is the part that carries the meaning, and it has
// three states, not two:
//
//   - the lane is in the payload: use it, including an empty list, which is
//     a genuine fact a control may fail on (a project with no branch
//     protections is exactly what branchMustBeProtected exists to catch);
//   - the lane is absent and NOT named in degraded_fields: the collection
//     succeeded and found nothing;
//   - the lane is named in degraded_fields: the collection FAILED, so its
//     absence is evidence of nothing. Known goes false and the control
//     reports not_evaluable rather than failing against a guessed-empty
//     value.
//
// Conflating the last two is the false-pass this whole design exists to
// prevent, in the one direction that matters: telling someone their
// unprotected branch is fine because a fetch broke.

// snapshotBranchProtection is the branch_protection lane's wire shape.
type snapshotBranchProtection struct {
	Branches    []string           `json:"branches"`
	Protections []BranchProtection `json:"protections"`
}

// snapshotMrApprovals is the mr_approvals lane's wire shape.
type snapshotMrApprovals struct {
	Rules    []*glab.ProjectApprovalRule `json:"rules"`
	Settings *glab.ProjectApprovals      `json:"settings"`
}

// snapshotVariables is the variables lane's wire shape. It is metadata
// only: the platform never serves a variable's VALUE, at any scope, so
// there is no Value field to decode into and nothing here can leak one.
type snapshotVariables struct {
	Items []snapshotVariableMeta `json:"items"`
}

// snapshotVariableMeta carries the platform's per-variable metadata.
//
// Scope is why this is not simply CICDVariable: the platform collects
// group-inherited, project-level and instance-level variables into one
// list, while the settings-variable controls are about the project's own
// (Settings > CI/CD > Variables). Flagging a group variable under a
// project's verdict would report a violation the project cannot fix.
//
// The booleans have no omitempty on this side deliberately: the PLATFORM
// omits false ones, so `protected: false` arrives as an absent key and
// decodes to the zero value, which is the right answer. Marking them
// omitempty here would change nothing about decoding but would suggest
// absence meant something other than false.
type snapshotVariableMeta struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Environment string `json:"environment"`
	Protected   bool   `json:"protected"`
	Masked      bool   `json:"masked"`
	Hidden      bool   `json:"hidden"`
	Scope       string `json:"scope"`
}

// snapshotScopeProject is the Scope value the platform tags a project's own
// CI/CD variables with.
const snapshotScopeProject = "project"

// ProtectionFromSnapshot builds the protection collection out of the
// platform's snapshot, for a run whose lanes the platform has taken over.
//
// The second return is false in standalone mode - and whenever the context
// fetch itself failed - so the caller collects from GitLab exactly as it
// always has. It is never false merely because a lane is empty: once the
// platform has answered, its answer is the lane, including "nothing here".
//
// MRSettings comes from the project_details lane, which carries the
// project payload's merge settings (mergeRequestSettingsMustBeCompliant /
// ISSUE-506) since 2026-08-28. It stays nil when that lane is absent,
// degraded, or predates the merge settings - see mrSettingsFromSnapshot for
// why a partial lane is treated as no lane at all.
func ProtectionFromSnapshot(run *platform.RunContext) (*GitlabProtectionAnalysisData, bool) {
	if !run.Engaged() {
		return nil, false
	}
	data := &GitlabProtectionAnalysisData{}
	snap := run.Snapshot()
	if snap.Data == nil {
		// A context with no snapshot: every lane is missing. The controls
		// are marked from the same MissingSnapshotFields the operator sees,
		// and reporting an empty collection here is what makes them abstain
		// rather than pass.
		return data, true
	}

	if raw := snap.Data.BranchProtection; len(raw) > 0 {
		var decoded snapshotBranchProtection
		if err := json.Unmarshal(raw, &decoded); err != nil {
			// A lane the CLI cannot read is not an empty lane. Leaving it
			// zero here pairs with the not_evaluable marking in
			// control/lanes.go, so a contract break degrades rather than
			// inventing a project with no protected branches.
			logger.WithError(err).Warn("platform snapshot carried a branch_protection lane this CLI could not decode; treating it as unavailable")
		} else {
			data.Branches = decoded.Branches
			data.BranchProtections = decoded.Protections
			// The same question the local collection answers, asked of the
			// platform instead: was this listing read authoritatively? A
			// decoded lane the platform did not report as degraded was.
			data.BranchProtectionsKnown = !run.LaneDegraded(platform.DegradedFieldBranchProtection)
		}
	}

	if raw := snap.Data.MrApprovals; len(raw) > 0 {
		var decoded snapshotMrApprovals
		if err := json.Unmarshal(raw, &decoded); err != nil {
			logger.WithError(err).Warn("platform snapshot carried an mr_approvals lane this CLI could not decode; treating it as unavailable")
		} else {
			data.MRApprovalRules = decoded.Rules
			data.MRApprovalSettings = decoded.Settings
		}
	}
	// Known tracks whether the LISTING was read authoritatively, which for
	// a snapshot means the platform's own collection of it succeeded. An
	// empty list from a healthy collection is authoritative and the
	// approval-rule controls should fail on it; the same emptiness from a
	// failed one must not be scored at all.
	data.MRApprovalRulesKnown = !run.LaneDegraded(platform.DegradedFieldMrApprovals)

	// A degraded project_details lane could not be collected, so nothing
	// about the project's merge settings is known and a nil MRSettings is
	// the honest answer: StatusFor already reads it as not_evaluable, the
	// same verdict a failed project fetch produces in standalone mode.
	if !run.LaneDegraded(platform.DegradedFieldProjectDetails) {
		data.MRSettings = mrSettingsFromSnapshot(snap.Data.ProjectDetails)
	}

	return data, true
}

// mrSettingsFromSnapshot projects the project_details lane's eight merge
// settings onto the glab.Project members buildMRSettings reads, or nil when
// the lane cannot supply all eight.
//
// All eight or none, deliberately. The platform's stored blob carries the
// settings as plain booleans and strings written together (2026-08-28), so
// a nil here means the snapshot predates them and self-heals on the next
// refresh - never that one setting is genuinely absent. What makes the
// all-or-nothing rule necessary rather than merely tidy is the shape of
// what they feed: ir.MRSettings has no pointer members and no absence
// marker, so a nil copied through arrives at the ISSUE-506 rule as a real
// `false` or "" and is compared for exact equality against the operator's
// expectation. That fabricates a deviation on a setting nobody read, which
// is a finding the project cannot fix. A nil MRSettings instead makes the
// control report not_evaluable, which is what an unread project payload has
// always produced.
func mrSettingsFromSnapshot(details *platform.ProjectDetails) *glab.Project {
	if details == nil {
		return nil
	}
	if details.MergeMethod == nil ||
		details.SquashOption == nil ||
		details.MergePipelinesEnabled == nil ||
		details.MergeTrainsEnabled == nil ||
		details.AllowMergeOnSkippedPipeline == nil ||
		details.ResolveOutdatedDiffDiscussions == nil ||
		details.PrintingMergeRequestLinkEnabled == nil ||
		details.RemoveSourceBranchAfterMerge == nil {
		logger.Debug("platform snapshot carried a project_details lane without the merge settings; ISSUE-506 stays not evaluable rather than reading an absent setting as false")
		return nil
	}
	// Only the members buildMRSettings reads are set. The rest of
	// glab.Project stays zero on purpose: nothing else reads this value in
	// platform mode, and filling in a plausible id or name would put
	// invented facts one refactor away from being believed.
	return &glab.Project{
		MergeMethod:                     glab.MergeMethodValue(*details.MergeMethod),
		SquashOption:                    glab.SquashOptionValue(*details.SquashOption),
		MergePipelinesEnabled:           *details.MergePipelinesEnabled,
		MergeTrainsEnabled:              *details.MergeTrainsEnabled,
		AllowMergeOnSkippedPipeline:     *details.AllowMergeOnSkippedPipeline,
		ResolveOutdatedDiffDiscussions:  *details.ResolveOutdatedDiffDiscussions,
		PrintingMergeRequestLinkEnabled: *details.PrintingMergeRequestLinkEnabled,
		RemoveSourceBranchAfterMerge:    *details.RemoveSourceBranchAfterMerge,
	}
}

// SecurityPolicyFromSnapshot builds the security-policy-project linkage
// (projectMustHaveSecurityPolicySource / ISSUE-601) out of the platform's
// snapshot, and reports whether the platform served that lane at all.
//
// A false second return means the run has NO linkage data: standalone mode
// and a context that was never fetched (collect it locally, as always), and
// - in platform mode - an absent or degraded lane, where the caller leaves
// the collection nil and the control reports not_evaluable. The runner does
// not fall back to GraphQL for it: a CI job token cannot read that field, so
// the request could only spend a credential to fail.
//
// Known is carried VERBATIM, never upgraded. The platform's three shapes
// each mean something different to the rule, and only one of them is a
// verdict:
//
//   - Known with a linked project: the linkage exists, and the rule checks
//     it against the configured expectation.
//   - Known alone: the linkage was read authoritatively and nothing is
//     linked. That is the real Critical ISSUE-601 exists to report, not an
//     absence.
//   - Known false: the read was not authoritative (an auth failure, a null
//     GraphQL project, or the field being unavailable on this instance).
//     The projection then abstains, so the control reports not_evaluable
//     rather than certifying an unread project as linked or unlinked.
//
// Project is set only when Known AND an id was served. An id alongside
// Known false is not a linkage the run may report on, and an absent id is
// never a real project id of 0.
func SecurityPolicyFromSnapshot(run *platform.RunContext) (*SecurityPolicyData, bool) {
	if !run.Engaged() {
		return nil, false
	}
	snap := run.Snapshot()
	if snap.Data == nil || snap.Data.SecurityPolicyProject == nil {
		return nil, false
	}
	if run.LaneDegraded(platform.DegradedFieldSecurityPolicyProject) {
		// The platform said this collection failed. Serving Known=false
		// would reach the same not_evaluable outcome, but saying the lane
		// supplied nothing is the truthful one and keeps the caller's
		// degraded handling in one place.
		return nil, false
	}
	sp := snap.Data.SecurityPolicyProject
	data := &SecurityPolicyData{Known: sp.Known}
	if sp.Known && sp.ID != nil {
		link := &SecurityPolicyProjectLink{ID: *sp.ID}
		if sp.FullPath != nil {
			link.FullPath = *sp.FullPath
		}
		data.Project = link
	}
	return data, true
}

// snapshotVariableTypeFile is the GraphQL variableType GitLab reports for a
// file-type CI/CD variable.
const snapshotVariableTypeFile = "FILE"

// snapshotEnvironmentScopeAll is the environment_scope value GitLab uses for
// a variable available to every job.
const snapshotEnvironmentScopeAll = "*"

// DeclaredVariableNames returns the names of every CI/CD variable the
// platform collected for this project that can legitimately appear inside an
// image reference.
//
// Scope is deliberately NOT filtered here, unlike VariablesFromSnapshot. The
// settings-variable controls judge the project's own variables and must not
// be handed a group's; expanding a placeholder is the opposite case, because
// a job resolves `$REGISTRY` against everything it inherits and does not care
// which scope defined it.
//
// What IS filtered is every variable whose value the analysing job cannot
// stand in for. The values come from THIS job's environment, and the
// references being expanded belong to every job in the pipeline, so a
// variable is only usable here when its value is the same for all of them
// and is not a secret:
//
//   - FILE type. GitLab exports a file variable as the PATH of a temporary
//     file, not its contents, so substituting would render `$CERT/app` as
//     `/builds/project.tmp/CERT/app` - a reference that looks resolved and
//     is not one.
//   - An environment scope other than `*`. Scope is resolved per job from
//     that job's own `environment:` keyword, so this job's answer is not
//     the other jobs' answer. Substituting it would put a plausible but
//     wrong registry into another job's reference, which is worse than
//     leaving the placeholder: a wrong answer nothing can detect, instead
//     of an abstention.
//   - MASKED or HIDDEN. The value is a declared secret. Expanding it puts
//     it into a finding message, the JSON report and the pushed result,
//     which is exactly what the #370 sensitivity tiers forbid. A reference
//     built out of a secret cannot be judged without disclosing it, so
//     abstaining is the only honest option.
//
// Everything excluded here simply stays a placeholder, gets marked
// unresolved, and makes the image rules abstain on that one job.
//
// Names only: the values come from the job's own environment
// (JobEnvironmentVariables), and the platform serves no values at all.
func DeclaredVariableNames(run *platform.RunContext) []string {
	if !run.Engaged() {
		return nil
	}
	snap := run.Snapshot()
	if snap.Data == nil || len(snap.Data.Variables) == 0 {
		return nil
	}
	var decoded snapshotVariables
	if err := json.Unmarshal(snap.Data.Variables, &decoded); err != nil {
		logger.WithError(err).Warn("platform snapshot carried a variables lane this CLI could not decode; no names to expand image references with")
		return nil
	}
	out := make([]string, 0, len(decoded.Items))
	for _, item := range decoded.Items {
		if item.Name == "" || !expandableFromJobEnvironment(item) {
			continue
		}
		out = append(out, item.Name)
	}
	return out
}

// VariablesFromSnapshot builds the settings-variable collection out of the
// platform's snapshot, filtered to the project's OWN variables.
//
// The second return follows ProtectionFromSnapshot: false only in
// standalone mode.
//
// Known is false when the platform reports the variables lane as a failed
// collection, so cicdVariablesMustBeProtected / ...MustBeMasked report
// not-evaluable instead of certifying an unprotected variable as fine. It
// is TRUE for a healthy collection that found nothing, which is a real
// answer: a project with no CI/CD variables passes both controls.
func VariablesFromSnapshot(run *platform.RunContext) (*GitlabVariablesAnalysisData, bool) {
	if !run.Engaged() {
		return nil, false
	}
	known := !run.LaneDegraded(platform.DegradedFieldVariables)
	data := &GitlabVariablesAnalysisData{Known: known}

	snap := run.Snapshot()
	if snap.Data == nil {
		// A cache miss: the platform has never collected this project, so
		// nothing here is an answer about its variables. An absent lane on an
		// EXISTING snapshot is a real "this project has none" (the platform
		// omits the lane then, and the controls rightly pass); an absent
		// snapshot proves only that nothing was collected, and Known=true
		// here made both variable controls pass vacuously while the
		// branch-protection and approvals lanes abstain on the same state.
		data.Known = false
		return data, true
	}
	if len(snap.Data.Variables) == 0 {
		return data, true
	}

	var decoded snapshotVariables
	if err := json.Unmarshal(snap.Data.Variables, &decoded); err != nil {
		logger.WithError(err).Warn("platform snapshot carried a variables lane this CLI could not decode; treating it as unavailable")
		data.Known = false
		return data, true
	}

	for _, item := range decoded.Items {
		// Group-inherited and instance-level variables are in the payload
		// because other consumers need them; these two controls are about
		// the project's own settings, and a group variable is not the
		// project's to protect or mask.
		if item.Scope != snapshotScopeProject {
			continue
		}
		data.Variables = append(data.Variables, CICDVariable{
			Name:        item.Name,
			Type:        item.Type,
			Environment: item.Environment,
			Protected:   item.Protected,
			Masked:      item.Masked,
			Hidden:      item.Hidden,
			// Value stays empty: the platform serves none, and the IR
			// carries none either (#370 sensitivity tiers).
		})
	}
	return data, true
}

// expandableFromJobEnvironment reports whether this variable's value, as
// seen by the analysing job, is a sound substitute for the value any job in
// the pipeline would see. See DeclaredVariableNames for why each exclusion
// is there.
func expandableFromJobEnvironment(item snapshotVariableMeta) bool {
	if strings.EqualFold(item.Type, snapshotVariableTypeFile) {
		return false
	}
	if item.Masked || item.Hidden {
		return false
	}
	// GitLab withholds a protected variable unless the ref is protected, so
	// on an unprotected ref this job never received it. A value present
	// under that name came from somewhere else - an ENV line in Plumber's
	// own container image is the likely source, where names like VERSION or
	// LANG are ordinary - and using it would judge a job against a value it
	// is specifically not entitled to see.
	if item.Protected && !ciRefIsProtected() {
		return false
	}
	// An absent scope is the default, which is every environment.
	if scope := strings.TrimSpace(item.Environment); scope != "" && scope != snapshotEnvironmentScopeAll {
		return false
	}
	return true
}
