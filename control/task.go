package control

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
	"github.com/getplumber/plumber/utils"
	"github.com/sirupsen/logrus"
)

// maxLocalCIConfigBytes bounds a local .gitlab-ci.yml read from the analyzed
// repository, whose size is not trusted.
const maxLocalCIConfigBytes = 2 << 20 // 2 MiB

// opaEvaluateTimeout bounds a single Rego/OPA evaluation. Policy evaluation
// over a normal pipeline is sub-second; this ceiling only exists so a
// pathologically large attacker-supplied pipeline/config cannot pin the scan
// process on CPU indefinitely. On timeout the evaluation errors and the
// provider's controls abstain, exactly like any other engine failure.
const opaEvaluateTimeout = 2 * time.Minute

// controlBranchMustBeProtected is the sole .plumber.yaml control key
// the task flow still references directly — to decide whether to fetch
// branch-protection metadata from the GitLab API before invoking the
// Rego engine. Every other control is config-driven end-to-end through
// the catalog in catalog.go.
const controlBranchMustBeProtected = "branchMustBeProtected"
const controlMutableRemoteExec = "actionsMustNotExecuteMutableRemoteCode"
const controlMRApprovalRulesMinApprovals = "mergeRequestApprovalRulesMustRequireMinimumApprovals"
const controlMRApprovalRulesCoverAllBranches = "mergeRequestApprovalRulesMustCoverAllProtectedBranches"
const controlMRApprovalSettings = "mergeRequestApprovalSettingsMustBeCompliant"
const controlMRSettings = "mergeRequestSettingsMustBeCompliant"

// mrApprovalRuleControlEnabled reports whether either merge-request
// approval-rule control (ISSUE-502/504) is active for this run. Both read the
// approval rules the GitLab protection collection fetches, so that collection
// must run when either is enabled even if branchMustBeProtected is not.
func mrApprovalRuleControlEnabled(conf *configuration.Configuration) bool {
	if c := conf.PlumberConfig.GetMergeRequestApprovalRulesMustRequireMinimumApprovalsConfig(); c != nil && c.IsEnabled() && shouldRunControl(controlMRApprovalRulesMinApprovals, conf) {
		return true
	}
	if c := conf.PlumberConfig.GetMergeRequestApprovalRulesMustCoverAllProtectedBranchesConfig(); c != nil && c.IsEnabled() && shouldRunControl(controlMRApprovalRulesCoverAllBranches, conf) {
		return true
	}
	return false
}

// approvalRulesReturnedNone reports whether the protection collection ran and
// the GitLab approvals API returned zero rules — the ambiguous case where the
// project is either on GitLab Free (feature unavailable, the API 200-empties)
// or on Premium/Ultimate with no rules configured. The renderers surface a
// Premium/Ultimate caveat for it via AnalysisResult.ApprovalRulesTierCaveat.
func approvalRulesReturnedNone(protectionData *gitlab.GitlabProtectionAnalysisData) bool {
	return protectionData != nil && protectionData.MRApprovalRulesKnown &&
		len(protectionData.MRApprovalRules) == 0
}

// approvalRulesTierCaveatApplies reports whether to surface the Premium/Ultimate
// caveat: an approval-rule control ran (mrApprovalRuleControlEnabled) AND the
// approvals API returned zero rules (approvalRulesReturnedNone). The enabled
// guard is load-bearing — a branch-protection-only run on a zero-rules project
// satisfies approvalRulesReturnedNone but must NOT show the caveat.
func approvalRulesTierCaveatApplies(conf *configuration.Configuration, protectionData *gitlab.GitlabProtectionAnalysisData) bool {
	return mrApprovalRuleControlEnabled(conf) && approvalRulesReturnedNone(protectionData)
}

// mrApprovalSettingsHasNoProtections reports whether the protection collection
// read the project's approval settings and NONE of them are locked down — the
// fully-unlocked state a GitLab Free project returns, where the feature does not
// exist and the approvals API 200-defaults every protection off. Unlike the
// approval RULES case (a 200-empty list), the settings API gives no other tier
// signal, so "no protection in effect" is the only heuristic available.
//
// The author field has INVERTED polarity: MergeRequestsAuthorApproval == true
// means authors CAN approve (no protection), so unlocked wants it true while the
// other five flags must be false. The check is deliberately conservative: any
// single protection active proves the project CAN lock a setting down (so it is
// on a paid tier) and suppresses the caveat.
func mrApprovalSettingsHasNoProtections(protectionData *gitlab.GitlabProtectionAnalysisData) bool {
	if protectionData == nil || protectionData.MRApprovalSettings == nil {
		return false
	}
	s := protectionData.MRApprovalSettings
	return s.MergeRequestsAuthorApproval && // authors CAN approve == not locked down
		!s.MergeRequestsDisableCommittersApproval &&
		!s.DisableOverridingApproversPerMergeRequest &&
		!s.RequirePasswordToApprove &&
		!s.ResetApprovalsOnPush &&
		!s.SelectiveCodeOwnerRemovals
}

// mrApprovalSettingsTierCaveatApplies reports whether to surface the
// Premium/Ultimate caveat for the approval-settings control (ISSUE-503): the
// control ran (mrApprovalSettingsControlEnabled) AND the project has no approval
// protection in effect (mrApprovalSettingsHasNoProtections), the tell-tale
// GitLab-Free signature. The enabled guard is load-bearing the same way it is
// for the rules caveat — a run that never turned this control on must not show
// the caveat.
func mrApprovalSettingsTierCaveatApplies(conf *configuration.Configuration, protectionData *gitlab.GitlabProtectionAnalysisData) bool {
	return mrApprovalSettingsControlEnabled(conf) && mrApprovalSettingsHasNoProtections(protectionData)
}

// mrApprovalSettingsControlEnabled reports whether the merge-request
// approval-settings control (ISSUE-503) is active for this run. It reads the
// approval settings the GitLab protection collection fetches, so that
// collection must run when it is enabled even if no other protection control
// is.
func mrApprovalSettingsControlEnabled(conf *configuration.Configuration) bool {
	c := conf.PlumberConfig.GetMergeRequestApprovalSettingsMustBeCompliantConfig()
	return c != nil && c.IsEnabled() && shouldRunControl(controlMRApprovalSettings, conf)
}

// mrSettingsControlEnabled reports whether the merge-request settings control
// (ISSUE-506) is active for this run. It reads the project MR settings the
// GitLab protection collection fetches, so that collection must run when it is
// enabled even if no other protection control is.
func mrSettingsControlEnabled(conf *configuration.Configuration) bool {
	c := conf.PlumberConfig.GetMergeRequestSettingsMustBeCompliantConfig()
	return c != nil && c.IsEnabled() && shouldRunControl(controlMRSettings, conf)
}

// mrSettingsPremiumFieldsNeedingUpgrade returns the Premium/Ultimate MR-setting
// expectations that read as OFF while the config expects them ON (merge trains,
// merged-results pipelines). These features require a paid tier and the project
// payload carries no tier signal, so an OFF read is ambiguous: a Free project
// that cannot enable them, or a paid project that simply left them off. An
// expectation of false is satisfiable on any tier and never appears here. The
// renderers turn this into a CONDITIONAL caveat next to ISSUE-506 (disable the
// expectation on Free; enable the feature on a paid tier) rather than asserting
// which tier the project is on, since the API cannot tell us.
func mrSettingsPremiumFieldsNeedingUpgrade(conf *configuration.Configuration, protectionData *gitlab.GitlabProtectionAnalysisData) []string {
	if !mrSettingsControlEnabled(conf) || protectionData == nil || protectionData.MRSettings == nil {
		return nil
	}
	c := conf.PlumberConfig.GetMergeRequestSettingsMustBeCompliantConfig()
	s := protectionData.MRSettings
	var fields []string
	if c.MergePipelinesEnabled != nil && *c.MergePipelinesEnabled && !s.MergePipelinesEnabled {
		fields = append(fields, "mergePipelinesEnabled")
	}
	if c.MergeTrainsEnabled != nil && *c.MergeTrainsEnabled && !s.MergeTrainsEnabled {
		fields = append(fields, "mergeTrainsEnabled")
	}
	return fields
}

const controlSecurityPolicy = "projectMustHaveSecurityPolicySource"

// securityPolicyControlEnabled reports whether the security-policy-project
// linkage control (ISSUE-601) is active for this run. It reads the linkage the
// GitLab protection collection fetches, so that collection must run when it is
// enabled even if branchMustBeProtected is not.
func securityPolicyControlEnabled(conf *configuration.Configuration) bool {
	if conf == nil || conf.PlumberConfig == nil {
		return false
	}
	c := conf.PlumberConfig.GetProjectMustHaveSecurityPolicySourceConfig()
	return c != nil && c.IsEnabled() && shouldRunControl(controlSecurityPolicy, conf)
}

// protectionDataNeeded reports whether any control needs the GitLab protection
// collection this run: branchMustBeProtected, either approval-rule control, the
// approval-settings control, the MR-settings control, or the security-policy
// control (they all read the one GitlabProtectionAnalysisData).
func protectionDataNeeded(conf *configuration.Configuration) bool {
	if shouldRunControl(controlBranchMustBeProtected, conf) {
		if cfg := conf.PlumberConfig.GetBranchMustBeProtectedConfig(); cfg != nil && cfg.IsEnabled() {
			return true
		}
	}
	return mrApprovalRuleControlEnabled(conf) || mrApprovalSettingsControlEnabled(conf) ||
		mrSettingsControlEnabled(conf) || securityPolicyControlEnabled(conf)
}

// controlCicdVariablesMustBeProtected / ...Masked are the two .plumber.yaml
// control keys the task flow references directly, to decide whether to fetch
// the project's settings-variable listing (an extra API call) before invoking
// the Rego engine. Both share one collector (CollectGitlabVariables).
const controlCicdVariablesMustBeProtected = "cicdVariablesMustBeProtected"
const controlCicdVariablesMustBeMasked = "cicdVariablesMustBeMasked"

// cicdVariableControlEnabled reports whether either settings-variable control
// is active for this run, so the variable listing is fetched only when a
// control needs it.
func cicdVariableControlEnabled(conf *configuration.Configuration) bool {
	if p := conf.PlumberConfig.GetCicdVariablesMustBeProtectedConfig(); p != nil && p.IsEnabled() && shouldRunControl(controlCicdVariablesMustBeProtected, conf) {
		return true
	}
	if m := conf.PlumberConfig.GetCicdVariablesMustBeMaskedConfig(); m != nil && m.IsEnabled() && shouldRunControl(controlCicdVariablesMustBeMasked, conf) {
		return true
	}
	return false
}

// securityPolicyTierCaveatApplies reports whether to surface the conditional
// Ultimate caveat for ISSUE-601: the control ran, the linkage was read
// authoritatively, and NO policy project is linked — the tier-ambiguous case
// (a non-Ultimate project cannot link one, but an Ultimate project may simply
// have left it unset). A wrong-project-linked read is a real misconfiguration
// on a paid tier, not a tier caveat, and a non-authoritative read is
// not-evaluable, so neither triggers it.
func securityPolicyTierCaveatApplies(conf *configuration.Configuration, protectionData *gitlab.GitlabProtectionAnalysisData) bool {
	if !securityPolicyControlEnabled(conf) || protectionData == nil || !protectionData.SecurityPolicyKnown {
		return false
	}
	return protectionData.SecurityPolicyProject == nil
}

// shouldScanMutableExec reports whether the collector should fetch and
// scan action source for actionsMustNotExecuteMutableRemoteCode
// (ISSUE-714/715). The scan is expensive (up to ~7 sequential HTTP
// requests per unique action), so it runs only when the control is
// actually active: not benched in code, enabled in .plumber.yaml, and
// not excluded by --controls / --skip-controls. When false the collector
// skips the fetch entirely, so disabling the control removes its
// scan-time and rate-limit cost — not just its findings.
func shouldScanMutableExec(conf *configuration.Configuration) bool {
	if conf == nil || conf.PlumberConfig == nil {
		return false
	}
	if configuration.IsBenched("github", controlMutableRemoteExec) {
		return false
	}
	cfg := conf.PlumberConfig.ControlsFor("github").ActionsMustNotExecuteMutableRemoteCode
	if cfg == nil || !cfg.IsEnabled() {
		return false
	}
	return shouldRunControl(controlMutableRemoteExec, conf)
}

// shouldRunControl applies --controls / --skip-controls filtering for a control.
// If --controls is set, only listed controls are eligible.
// Then --skip-controls removes controls from that eligible set.
// Normally the CLI will not allow setting both --controls and --skip-controls together
func shouldRunControl(controlName string, conf *configuration.Configuration) bool {
	if conf == nil {
		return true
	}

	// If --controls is set, only listed controls should run
	if len(conf.ControlsFilter) > 0 {
		found := false
		for _, name := range conf.ControlsFilter {
			if name == controlName {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// If --skip-controls is set, listed controls should not run
	for _, name := range conf.SkipControlsFilter {
		if name == controlName {
			return false
		}
	}

	return true
}

// reportProgress calls the optional progress callback if configured.
func reportProgress(conf *configuration.Configuration, step, total int, message string) {
	if conf.ProgressFunc != nil {
		conf.ProgressFunc(step, total, message)
	}
}

// clearProgressLine clears the spinner line before writing direct stderr output.
func clearProgressLine(conf *configuration.Configuration) {
	if conf.ProgressFunc != nil {
		fmt.Fprint(os.Stderr, "\r\033[K")
	}
}

// analysisStepCount is the total number of progress steps reported during analysis.
const analysisStepCount = 18

// runRegoEngine invokes the experimental Rego/OPA rule engine on the
// GitLab collector outputs and returns the aggregated findings. The
// legacy Go controls always run and remain authoritative until parity
// is reached (see phases 2+). On any failure the returned slice is nil
// and the error is logged at Warn level so the overall analysis still
// completes.
func runRegoEngine(
	l *logrus.Entry,
	conf *configuration.Configuration,
	project *gitlab.Project,
	originData *gitlab.GitlabPipelineOriginData,
	imageData *gitlab.GitlabPipelineImageData,
	protectionData *gitlab.GitlabProtectionAnalysisData,
	variablesData *gitlab.GitlabVariablesAnalysisData,
) []opaengine.Finding {
	pipeline := gitlab.ToNormalizedPipeline(
		conf.ProjectPath,
		project.DefaultBranch,
		project.CiConfPath,
		originData,
		imageData,
		protectionData,
		variablesData,
	)
	return evaluatePolicies(l, conf, "gitlab", pipeline)
}

// evaluatePolicies loads the embedded Rego policies and evaluates them
// against pipeline. The provider argument selects which per-provider
// ControlsConfig under conf.PlumberConfig is fed to the policies (and
// used to filter findings via the provider's enabledControls
// allowlist). conf.ControlsFilter / conf.SkipControlsFilter further
// restrict which controls' findings reach the caller. Callers pass
// "gitlab" or "github". Anything else returns no findings.
func evaluatePolicies(l *logrus.Entry, conf *configuration.Configuration, provider string, pipeline *ir.NormalizedPipeline) []opaengine.Finding {
	l.WithField("provider", provider).Info("Running Rego/OPA rule engine")
	// Empty (non-nil) so the eventual JSON output marshals an empty
	// findings array as `[]`, not `null` — `null` makes downstream
	// jq pipelines like `.findings[]` blow up on a clean run.
	empty := []opaengine.Finding{}
	engine := opaengine.New()
	skip := func(filename string, content []byte) bool {
		return IsRegoFileBenchedForProvider(content, provider)
	}
	if err := engine.LoadFromFSFiltered(policies.FS, skip); err != nil {
		l.WithError(err).Warn("Failed to load embedded Rego policies")
		return empty
	}
	controls := conf.PlumberConfig.ControlsFor(provider)
	ctx, cancel := context.WithTimeout(context.Background(), opaEvaluateTimeout)
	defer cancel()
	findings, err := engine.Evaluate(ctx, pipeline, buildEngineConfig(controls))
	if err != nil {
		l.WithError(err).Warn("Rego/OPA engine evaluation failed")
		return empty
	}
	findings = FilterFindingsByEnabledControls(findings, provider, controls, conf.ControlsFilter, conf.SkipControlsFilter)
	if findings == nil {
		findings = empty
	}
	l.WithField("findingCount", len(findings)).Info("Rego/OPA engine evaluation completed")
	return findings
}

// buildEngineConfig projects the relevant bits of the user's .plumber.yaml
// onto a Rego-friendly map. Policies read it as `input.config.<rule>.<key>`.
// Only the sections consumed by already-ported policies are included;
// additional entries land with each new policy.
func buildEngineConfig(controls *configuration.ControlsConfig) map[string]any {
	if controls == nil {
		return nil
	}
	cfg := map[string]any{}

	if c := controls.ProjectMustHaveSecurityPolicySource; c != nil {
		// expectedProjectId / expectedProjectPath reach the engine only when set:
		// the Rego rule treats their absence as "require any linkage", the id as
		// the authoritative match, and the path as a case-insensitive fallback.
		entry := map[string]any{}
		if c.ExpectedProjectId != nil {
			entry["expectedProjectId"] = *c.ExpectedProjectId
		}
		if c.ExpectedProjectPath != nil {
			entry["expectedProjectPath"] = *c.ExpectedProjectPath
		}
		cfg["projectMustHaveSecurityPolicySource"] = entry
	}

	if c := controls.ContainerImageMustNotUseForbiddenTags; c != nil {
		if len(c.Tags) > 0 {
			cfg["imageMutableTag"] = map[string]any{
				"forbiddenTags": c.Tags,
			}
		}
		if c.IsPinnedByDigestRequired() {
			cfg["containerImageMustNotUseForbiddenTags"] = map[string]any{
				"mustBePinnedByDigest": true,
			}
		}
	}

	if c := controls.PipelineMustNotEnableDebugTrace; c != nil && len(c.ForbiddenVariables) > 0 {
		cfg["debugTrace"] = map[string]any{
			"forbiddenVariables": c.ForbiddenVariables,
		}
	}

	if c := controls.ReleaseWorkflowsMustNotRestoreUntrustedCache; c != nil {
		entry := map[string]any{}
		if len(c.PublishActions) > 0 {
			entry["publishActions"] = c.PublishActions
		}
		if len(c.CacheActions) > 0 {
			specs := make([]map[string]any, 0, len(c.CacheActions))
			for _, s := range c.CacheActions {
				m := map[string]any{"action": s.Action, "mode": s.Mode}
				if s.DisableInput != "" {
					m["disableInput"] = s.DisableInput
				}
				if s.DisableValue != nil {
					m["disableValue"] = *s.DisableValue
				}
				if s.EnableInput != "" {
					m["enableInput"] = s.EnableInput
				}
				if s.EnableContains != "" {
					m["enableContains"] = s.EnableContains
				}
				specs = append(specs, m)
			}
			entry["cacheActions"] = specs
		}
		if len(c.PublishScriptPatterns) > 0 {
			entry["publishScriptPatterns"] = c.PublishScriptPatterns
		}
		if len(c.PublishScriptExcludePatterns) > 0 {
			entry["publishScriptExcludePatterns"] = c.PublishScriptExcludePatterns
		}
		if len(c.AllowedJobs) > 0 {
			entry["allowedJobs"] = c.AllowedJobs
		}
		if len(entry) > 0 {
			cfg["cachePoisoning"] = entry
		}
	}

	if c := controls.PipelineMustNotOverrideJobVariables; c != nil && len(c.Variables) > 0 {
		cfg["jobVariablesOverride"] = map[string]any{
			"protectedVariables": c.Variables,
		}
	}

	if c := controls.SecurityJobsMustNotBeWeakened; c != nil && len(c.SecurityJobPatterns) > 0 {
		cfg["securityJobsWeakened"] = map[string]any{
			"securityJobPatterns":     c.SecurityJobPatterns,
			"allowFailureMustBeFalse": c.AllowFailureMustBeFalse.IsEnabled(true),
			"whenMustNotBeManual":     c.WhenMustNotBeManual.IsEnabled(true),
			"rulesMustNotBeRedefined": c.RulesMustNotBeRedefined.IsEnabled(true),
		}
	}

	if c := controls.PipelineMustNotUseUnsafeVariableExpansion; c != nil && len(c.DangerousVariables) > 0 {
		cfg["unsafeVariableExpansion"] = map[string]any{
			"dangerousVariables": c.DangerousVariables,
			"allowedPatterns":    c.AllowedPatterns,
		}
	}

	if c := controls.BranchMustBeProtected; c != nil {
		entry := map[string]any{
			"namePatterns": c.NamePatterns,
		}
		if c.DefaultMustBeProtected != nil {
			entry["defaultMustBeProtected"] = *c.DefaultMustBeProtected
		}
		if c.AllowForcePush != nil {
			entry["allowForcePush"] = *c.AllowForcePush
		}
		if c.CodeOwnerApprovalRequired != nil {
			entry["codeOwnerApprovalRequired"] = *c.CodeOwnerApprovalRequired
		}
		if c.MinPushAccessLevel != nil {
			entry["minPushAccessLevel"] = *c.MinPushAccessLevel
		}
		if c.MinMergeAccessLevel != nil {
			entry["minMergeAccessLevel"] = *c.MinMergeAccessLevel
		}
		cfg["branchMustBeProtected"] = entry
	}

	if c := controls.MergeRequestApprovalRulesMustRequireMinimumApprovals; c != nil {
		entry := map[string]any{}
		if c.MinimumRequiredApprovals != nil {
			entry["minimumRequiredApprovals"] = *c.MinimumRequiredApprovals
		}
		cfg["mergeRequestApprovalRulesMustRequireMinimumApprovals"] = entry
	}

	if c := controls.MergeRequestApprovalSettingsMustBeCompliant; c != nil {
		// Only SET expectations reach the engine: the Rego rule treats an
		// absent key as "not checked", which is what makes every expectation
		// optional.
		entry := map[string]any{}
		if c.PreventApprovalByAuthor != nil {
			entry["preventApprovalByAuthor"] = *c.PreventApprovalByAuthor
		}
		if c.PreventApprovalsByCommitters != nil {
			entry["preventApprovalsByCommitters"] = *c.PreventApprovalsByCommitters
		}
		if c.PreventEditingApprovalRulesInMR != nil {
			entry["preventEditingApprovalRulesInMR"] = *c.PreventEditingApprovalRulesInMR
		}
		if c.RequireReAuthToApprove != nil {
			entry["requireReAuthToApprove"] = *c.RequireReAuthToApprove
		}
		if c.BehaviorWhenCommitIsAdded != nil {
			entry["behaviorWhenCommitIsAdded"] = *c.BehaviorWhenCommitIsAdded
		}
		cfg["mergeRequestApprovalSettingsMustBeCompliant"] = entry
	}

	if c := controls.MergeRequestSettingsMustBeCompliant; c != nil {
		// Only SET expectations reach the engine: the Rego rule treats an
		// absent key as "not checked", which is what makes every expectation
		// optional (unlike the legacy platform's unconditional equality).
		entry := map[string]any{}
		if c.MergeMethod != nil {
			entry["mergeMethod"] = *c.MergeMethod
		}
		if c.SquashOption != nil {
			entry["squashOption"] = *c.SquashOption
		}
		if c.MergePipelinesEnabled != nil {
			entry["mergePipelinesEnabled"] = *c.MergePipelinesEnabled
		}
		if c.MergeTrainsEnabled != nil {
			entry["mergeTrainsEnabled"] = *c.MergeTrainsEnabled
		}
		if c.AllowMergeOnSkippedPipeline != nil {
			entry["allowMergeOnSkippedPipeline"] = *c.AllowMergeOnSkippedPipeline
		}
		if c.ResolveOutdatedDiffDiscussions != nil {
			entry["resolveOutdatedDiffDiscussions"] = *c.ResolveOutdatedDiffDiscussions
		}
		if c.PrintingMergeRequestLinkEnabled != nil {
			entry["printingMergeRequestLinkEnabled"] = *c.PrintingMergeRequestLinkEnabled
		}
		if c.RemoveSourceBranchAfterMerge != nil {
			entry["removeSourceBranchAfterMerge"] = *c.RemoveSourceBranchAfterMerge
		}
		cfg["mergeRequestSettingsMustBeCompliant"] = entry
	}

	if c := controls.IncludesMustNotUseForbiddenVersions; c != nil {
		defaultForbidden := false
		if c.DefaultBranchIsForbiddenVersion != nil {
			defaultForbidden = *c.DefaultBranchIsForbiddenVersion
		}
		cfg["includesForbiddenVersions"] = map[string]any{
			"forbiddenVersions":               c.ForbiddenVersions,
			"defaultBranchIsForbiddenVersion": defaultForbidden,
		}
	}

	if c := controls.ContainerImageMustComeFromAuthorizedSources; c != nil {
		trustOfficial := false
		if c.TrustDockerHubOfficialImages != nil {
			trustOfficial = *c.TrustDockerHubOfficialImages
		}
		cfg["imageAuthorizedSources"] = map[string]any{
			"trustedUrls":            c.TrustedUrls,
			"trustDockerHubOfficial": trustOfficial,
		}
	}

	if c := controls.PipelineMustNotExecuteUnverifiedScripts; c != nil && len(c.TrustedUrls) > 0 {
		cfg["unverifiedScripts"] = map[string]any{
			"trustedUrls": c.TrustedUrls,
		}
	}

	if c := controls.PipelineMustIncludeComponent; c != nil && c.IsEnabled() {
		if groups, err := c.GetResolvedRequiredGroups(); err == nil && len(groups) > 0 {
			cfg["pipelineMustIncludeComponent"] = map[string]any{
				"requiredGroups": toAnyGroups(groups),
			}
		}
	}

	if c := controls.PipelineMustIncludeTemplate; c != nil && c.IsEnabled() {
		if groups, err := c.GetResolvedRequiredGroups(); err == nil && len(groups) > 0 {
			cfg["pipelineMustIncludeTemplate"] = map[string]any{
				"requiredGroups": toAnyGroups(groups),
			}
		}
	}

	if c := controls.ActionsMustBePinnedByCommitSha; c != nil && c.IsEnabled() {
		entry := map[string]any{}
		if len(c.TrustedOwners) > 0 {
			entry["trustedOwners"] = c.TrustedOwners
		}
		cfg["actionsMustBePinnedByCommitSha"] = entry
	}

	if c := controls.GithubActionMustComeFromAuthorizedSources; c != nil && c.IsEnabled() {
		// trustGithubOfficialActions defaults to true: the first-party
		// actions/* and github/* owners are inside any workflow's
		// implicit trust boundary, so trust them unless explicitly
		// opted out.
		trustOfficial := true
		if c.TrustGithubOfficialActions != nil {
			trustOfficial = *c.TrustGithubOfficialActions
		}
		// trustSameOrgActions also defaults to true: an org's own actions
		// (same owner as the scanned repo) are inside its trust boundary.
		trustSameOrg := true
		if c.TrustSameOrgActions != nil {
			trustSameOrg = *c.TrustSameOrgActions
		}
		entry := map[string]any{
			"trustGithubOfficialActions": trustOfficial,
			"trustSameOrgActions":        trustSameOrg,
			"minimumStars":               c.MinimumStars,
		}
		if len(c.TrustedGithubActions) > 0 {
			entry["trustedGithubActions"] = c.TrustedGithubActions
		}
		cfg["githubActionMustComeFromAuthorizedSources"] = entry
	}

	if c := controls.WorkflowMustIncludeRequiredActions; c != nil && c.IsEnabled() {
		if groups, err := c.GetResolvedRequiredGroups(); err == nil && len(groups) > 0 {
			cfg["workflowMustIncludeRequiredActions"] = map[string]any{
				"requiredGroups": toAnyGroups(groups),
			}
		}
	}

	if len(cfg) == 0 {
		return nil
	}
	return cfg
}

// toAnyGroups converts a [][]string (DNF requiredGroups) into a nested
// []any slice so OPA sees it as a plain JSON array of arrays.
func toAnyGroups(groups [][]string) []any {
	out := make([]any, len(groups))
	for i, g := range groups {
		inner := make([]any, len(g))
		for j, p := range g {
			inner[j] = p
		}
		out[i] = inner
	}
	return out
}

// RunAnalysis executes the complete pipeline analysis for a GitLab project
func RunAnalysis(conf *configuration.Configuration) (*AnalysisResult, error) {
	l := l.WithFields(logrus.Fields{
		"action":      "RunAnalysis",
		"projectPath": conf.ProjectPath,
		"gitlabURL":   conf.GitlabURL,
	})
	l.Info("Starting pipeline analysis")

	result := &AnalysisResult{
		ProjectPath: conf.ProjectPath,
	}

	///////////////////////
	// Fetch Project Info from GitLab
	///////////////////////
	reportProgress(conf, 1, analysisStepCount, "Fetching project information")
	l.Info("Fetching project information from GitLab")
	project, err := gitlab.FetchProjectDetails(conf.ProjectPath, conf.GitlabToken, conf.GitlabURL, conf)
	if err != nil {
		// A network/timeout failure here is incomplete data, not a bad
		// project: degrade (exit 3, honest) instead of hard-failing (exit 2).
		// A definitive answer (404 not-found, auth) still hard-fails (#220).
		if isNetworkError(err) {
			l.WithError(err).Warn("Project information fetch failed (network); reporting incomplete data")
			markDegraded(result, "project information could not be fetched (network or timeout)")
			result.CiValid = false
			return result, nil
		}
		l.WithError(err).Error("Failed to fetch project from GitLab")
		result.CiValid = false
		result.CiMissing = true
		return result, err
	}

	// Update result with project info
	result.ProjectID = project.IdOnPlatform
	result.DefaultBranch = project.DefaultBranch
	result.HeadCommitSha = project.LatestHeadCommitSha

	l.WithFields(logrus.Fields{
		"projectID":     project.IdOnPlatform,
		"projectName":   project.Name,
		"defaultBranch": project.DefaultBranch,
		"ciConfigPath":  project.CiConfPath,
		"archived":      project.Archived,
	}).Info("Project information fetched")

	// Apply --ci-config-path override before converting to ProjectInfo so that
	// all downstream code (local file resolution, remote fetch) uses the custom path.
	if conf.CIConfigPathOverride != "" {
		project.CiConfPath = conf.CIConfigPathOverride
		clearProgressLine(conf)
		fmt.Fprintf(os.Stderr, "Using custom CI config path: %s\n", conf.CIConfigPathOverride)
		l.WithField("ciConfigPathOverride", conf.CIConfigPathOverride).Info("CI config path overridden by --ci-config-path flag")
	}

	// Convert to ProjectInfo for collectors
	projectInfo := project.ToProjectInfo()

	// The --branch flag specifies which branch's CI config to analyze,
	// NOT the project's default branch. Keep them separate.
	// projectInfo.DefaultBranch = actual default branch from GitLab API (e.g., "main")
	// projectInfo.AnalyzeBranch = branch to analyze from CLI (e.g., "testing-branch" or defaults to DefaultBranch)
	if conf.Branch != "" {
		projectInfo.AnalyzeBranch = conf.Branch

		// When analyzing a non-default branch, fetch the correct SHA so that
		// GitLab's ciConfig GraphQL query resolves include:local files from
		// the target branch's file tree, not the default branch's.
		if conf.Branch != projectInfo.DefaultBranch {
			branchSha, err := gitlab.FetchLatestCommitSha(
				conf.GitlabToken, conf.GitlabURL, conf.ProjectPath, conf.Branch, conf,
			)
			if err != nil {
				l.WithError(err).Warn("Unable to fetch commit SHA for analyze branch, using default branch SHA")
			} else {
				projectInfo.LatestHeadCommitSha = branchSha
			}
		}
	}
	result.AnalyzeBranch = projectInfo.AnalyzeBranch
	if projectInfo.LatestHeadCommitSha != "" {
		result.HeadCommitSha = projectInfo.LatestHeadCommitSha
	}

	///////////////////////
	// Resolve CI config source (local file vs remote)
	///////////////////////

	// Priority:
	// 1. If --branch is defined: use remote file on that branch
	// 2. If in a git repo, the local repo IS the analyzed project, and the CI config
	//    file exists locally: use local file (+ resolve include:local from filesystem)
	// 3. Otherwise: use remote file (current default behavior)
	if conf.Branch == "" && conf.IsLocalProject {
		localCIPath, cErr := gitlab.ResolveWithinRepo(conf.GitRepoRoot, project.CiConfPath)
		if cErr != nil {
			l.WithFields(logrus.Fields{
				"ciConfPath": project.CiConfPath,
				"error":      cErr,
			}).Warn("Local CI config path escapes the repository; using remote")
		} else if content, err := utils.ReadFileLimit(localCIPath, maxLocalCIConfigBytes); err == nil {
			conf.LocalCIConfigContent = content
			conf.UsingLocalCIConfig = true
			// The run header reports "CI config: local file"; the path and the
			// --branch hint stay in the verbose log to keep normal output clean.
			l.WithField("localCIPath", localCIPath).Info("Using local CI configuration file (pass --branch to fetch the CI config from GitLab instead)")
		} else if os.IsNotExist(err) {
			l.WithField("localCIPath", localCIPath).Debug("Local CI config file not found, will use remote")
		} else {
			// The file is present but could not be read (e.g. it exceeds the
			// size limit). Surface it instead of silently scoring against the
			// remote CI as though no local file existed.
			clearProgressLine(conf)
			fmt.Fprintf(os.Stderr, "Local CI configuration at %s could not be read (%v); using remote CI configuration instead\n", localCIPath, err)
			l.WithFields(logrus.Fields{
				"localCIPath": localCIPath,
				"error":       err,
			}).Warn("Local CI config file present but unreadable; using remote")
		}
	} else if conf.Branch != "" {
		clearProgressLine(conf)
		fmt.Fprintf(os.Stderr, "Using remote CI configuration from branch: %s\n", projectInfo.AnalyzeBranch)
	}

	result.CIConfigSource = "remote"
	if conf.UsingLocalCIConfig {
		result.CIConfigSource = "local"
	}

	///////////////////////
	// Run Data Collections
	///////////////////////

	// 1. Run Pipeline Origin data collection
	reportProgress(conf, 2, analysisStepCount, "Collecting pipeline origins")
	l.Info("Running Pipeline Origin data collection")
	originDC := &gitlab.GitlabPipelineOriginDataCollection{}
	pipelineOriginData, pipelineOriginMetrics, err := originDC.Run(projectInfo, conf.GitlabToken, conf)
	if err != nil {
		// Network/timeout → degrade (exit 3); a definitive error still hard-
		// fails (exit 2). Same gate as project resolution above (#220).
		if isNetworkError(err) {
			l.WithError(err).Warn("Pipeline Origin data collection failed (network); reporting incomplete data")
			markDegraded(result, "pipeline configuration could not be fetched (network or timeout)")
			result.CiValid = false
			return result, nil
		}
		l.WithError(err).Error("Pipeline Origin data collection failed")
		result.CiValid = false
		result.CiMissing = true
		return result, err
	}

	result.CiValid = pipelineOriginData.CiValid
	result.CiMissing = pipelineOriginData.CiMissing

	// An include that failed to resolve drops its jobs from the merged
	// pipeline, so the analysis ran on a partial config. Flag degraded (the
	// run still evaluates what it has, like a GitHub partial) so the score is
	// withheld rather than scored against an incomplete pipeline (#220).
	if n := len(pipelineOriginData.IncludesFailed); n > 0 {
		markDegraded(result, fmt.Sprintf("%d include(s) could not be resolved; their jobs were not analysed", n))
	}

	// Capture CI config errors for output
	if len(pipelineOriginData.CiErrors) > 0 {
		result.CiErrors = pipelineOriginData.CiErrors
		// A fetch-level error (GraphQL timeout, rate-limit, lost network)
		// leaves us with no pipeline data, so every control would score a
		// vacuous 100%. Flag the run degraded so the renderer withholds the
		// letter score and marks the controls "not evaluated" (#220). A
		// syntactically invalid but successfully fetched config (the
		// MergedResponse branch below) is a real user-fixable finding, not a
		// degraded collection, so it does not set the flag.
		result.DataCollectionDegraded = true
		result.DegradedReasons = append(result.DegradedReasons, pipelineOriginData.CiErrors...)
	} else if pipelineOriginData.MergedResponse != nil && len(pipelineOriginData.MergedResponse.CiConfig.Errors) > 0 {
		result.CiErrors = pipelineOriginData.MergedResponse.CiConfig.Errors
	}

	// Store origin metrics
	if pipelineOriginMetrics != nil {
		result.PipelineOriginMetrics = &PipelineOriginMetricsSummary{
			JobTotal:            pipelineOriginMetrics.JobTotal,
			JobHardcoded:        pipelineOriginMetrics.JobHardcoded,
			OriginTotal:         pipelineOriginMetrics.OriginTotal,
			OriginComponent:     pipelineOriginMetrics.OriginComponent,
			OriginLocal:         pipelineOriginMetrics.OriginLocal,
			OriginProject:       pipelineOriginMetrics.OriginProject,
			OriginRemote:        pipelineOriginMetrics.OriginRemote,
			OriginTemplate:      pipelineOriginMetrics.OriginTemplate,
			OriginGitLabCatalog: pipelineOriginMetrics.OriginGitLabCatalog,
			OriginOutdated:      pipelineOriginMetrics.OriginOutdated,
		}
	}

	// If limited analysis (CI invalid or missing), return early
	// Note: when using local CI config, errors are returned directly by the
	// collector (hard fail) and won't reach this point.
	if pipelineOriginData.LimitedAnalysis {
		l.Info("Limited analysis due to CI configuration issues")
		return result, nil
	}

	// 2. Run Pipeline Image data collection
	reportProgress(conf, 3, analysisStepCount, "Collecting pipeline images")
	l.Info("Running Pipeline Image data collection")
	imageDC := &gitlab.GitlabPipelineImageDataCollection{}
	pipelineImageData, pipelineImageMetrics, err := imageDC.Run(projectInfo, conf.GitlabToken, conf, pipelineOriginData)
	if err != nil {
		// Network/timeout during image/variable collection → degrade (exit 3)
		// instead of the raw exit-2 hard fail this used to produce, matching
		// the origin path. A definitive error still hard-fails (#220).
		if isNetworkError(err) {
			l.WithError(err).Warn("Pipeline Image data collection failed (network); reporting incomplete data")
			markDegraded(result, "pipeline image/variable data could not be fetched (network or timeout)")
			result.CiValid = false
			return result, nil
		}
		l.WithError(err).Error("Pipeline Image data collection failed")
		return result, err
	}

	// Store image metrics
	if pipelineImageMetrics != nil {
		result.PipelineImageMetrics = &PipelineImageMetricsSummary{
			Total: pipelineImageMetrics.Total,
		}
	}

	// Store raw collected data for PBOM generation
	result.PipelineImageData = pipelineImageData
	result.PipelineOriginData = pipelineOriginData

	// Fetch branch-protection metadata when the user configured the
	// corresponding control — the Rego policy needs the protection
	// settings to check every branch against the declared bar.
	var protectionData *gitlab.GitlabProtectionAnalysisData
	if protectionDataNeeded(conf) {
		reportProgress(conf, 9, analysisStepCount, "Checking branch protection")
		protectionDC := &gitlab.GitlabProtectionDataCollection{}
		pData, _, pErr := protectionDC.Run(projectInfo, conf.GitlabToken, conf)
		if pErr != nil {
			// A network failure here leaves branchMustBeProtected with zero
			// branches → a vacuous 100% green. Flag degraded so that control's
			// pass is not trusted (mirrors the GitHub branch path, #220). A
			// non-network failure stays a soft warn as before. The approval-rule
			// controls need no degraded flag here: a nil protectionData makes
			// them report not-evaluable via StatusFor.
			if isNetworkError(pErr) {
				markDegraded(result, degradedReasonBranchProtectionPrefix+" (network or timeout)")
			}
			l.WithError(pErr).Warn("Protection data collection failed; branch and approval-rule policies will see no data")
		} else {
			protectionData = pData
		}
	}

	// Fetch settings-variable metadata when either variable control is
	// enabled — the Rego policies need the protected/masked flags, and the
	// (extra API call) listing is fetched only when a control needs it. The
	// variable values never reach the IR (per the #370 sensitivity tiers).
	var variablesData *gitlab.GitlabVariablesAnalysisData
	if cicdVariableControlEnabled(conf) {
		reportProgress(conf, 10, analysisStepCount, "Checking CI/CD variables")
		var vErr error
		variablesData, vErr = gitlab.CollectGitlabVariables(conf.ProjectPath, conf.GitlabToken, conf)
		if vErr != nil && isNetworkError(vErr) {
			// A transient network failure fetching variables degrades the run
			// (exit 3), matching the branch/image collectors (#220). A
			// permission failure (401/403 or a null project) is NOT network, so
			// it stays a plain not-evaluable — variablesData.Known is false and
			// StatusFor reports it without failing an otherwise-complete run.
			markDegraded(result, degradedReasonVariablesPrefix+" (network or timeout)")
		}
	}

	// Rego/OPA rule engine evaluation — the single authoritative
	// compliance path (the legacy Go controls were retired in
	// docs/REFACTOR_MULTI_PROVIDER.md §8 Phase A).
	result.Findings = runRegoEngine(l, conf, project, pipelineOriginData, pipelineImageData, protectionData, variablesData)
	result.ProtectionData = protectionData
	// An approval-rule control that ran but saw zero rules is the ambiguous
	// GitLab-Free-vs-premium-with-no-rules case (the approvals API 200-empties
	// on Free). Flag it so the renderers can surface a Premium/Ultimate caveat.
	result.ApprovalRulesTierCaveat = approvalRulesTierCaveatApplies(conf, protectionData)
	result.VariablesData = variablesData
	// The approval-settings API gives no tier signal at all (Free 200-defaults
	// every protection off), so "no protection in effect" is the only heuristic;
	// surface the same Premium/Ultimate caveat next to ISSUE-503.
	result.MRApprovalSettingsTierCaveat = mrApprovalSettingsTierCaveatApplies(conf, protectionData)
	// ISSUE-506 can require Premium/Ultimate MR settings (merge trains, merged-
	// results pipelines) the project cannot turn on without a paid tier; flag
	// those so the renderers advise disabling the specific expectation rather
	// than presenting an unfixable failure.
	result.MRSettingsPremiumCaveatFields = mrSettingsPremiumFieldsNeedingUpgrade(conf, protectionData)
	// ISSUE-601 is not-evaluable when the linkage could not be read (auth error /
	// field unavailable): the collector leaves SecurityPolicyKnown false, so
	// StatusFor reports error rather than a false pass. When it WAS read but
	// nothing is linked, surface the conditional Ultimate tier caveat.
	result.SecurityPolicyEvaluable = protectionData != nil && protectionData.SecurityPolicyKnown
	result.SecurityPolicyTierCaveat = securityPolicyTierCaveatApplies(conf, protectionData)

	reportProgress(conf, analysisStepCount, analysisStepCount, "Analysis complete")

	l.WithFields(logrus.Fields{
		"ciValid":   result.CiValid,
		"ciMissing": result.CiMissing,
	}).Info("Pipeline analysis completed")

	return result, nil
}
