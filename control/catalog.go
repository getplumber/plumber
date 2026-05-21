package control

import (
	"github.com/getplumber/plumber/configuration"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// ControlEntry is the canonical per-control view consumed by the
// analyze renderer, the MR comment builder and any future output path.
// Compliance is derived from the Rego Findings list (binary: 100 when
// no finding matches the ControlName, 0 when at least one does);
// Skipped reflects whether the user disabled the control in
// .plumber.yaml. DisplayName is the user-facing title.
type ControlEntry struct {
	DisplayName string
	ControlName string
	Skipped     bool
	Compliance  float64
}

// GitLabControls returns the catalog of GitLab compliance controls
// in their canonical display order. Every known GitLab control is
// returned so the compliance table and the legacy JSON `*Result`
// blocks render every row a v0.2.x user expects:
//
//   - Absent from `gitlab.controls.*` → `Skipped: true`. v0.2.x's
//     legacy control wrappers (`control/controlGitlab*.go` at tag
//     v0.2.22) uniformly set `p.Enabled = false` and short-circuit
//     `Run()` with `result.Skipped = true` when the per-control
//     section is missing from `.plumber.yaml`. The Rego port follows
//     the same contract: findings for absent controls are dropped by
//     FilterFindingsByEnabledControls so the row stays at 100% and
//     the score ignores them.
//   - Present with `enabled: true` → `Skipped: false`, runs.
//   - Present with `enabled: false` (or an empty entry — IsEnabled
//     returns false when the toggle is unset on a non-nil cfg) →
//     `Skipped: true`.
//
// The caller typically fills in the findings-derived compliance by
// looking up FindingsByControl.
func GitLabControls(pc *configuration.PlumberConfig) []ControlEntry {
	if pc == nil {
		return nil
	}
	c := pc.ControlsFor("gitlab")
	entries := make([]ControlEntry, 0, 14)

	// Container images must not use forbidden tags
	cfgForbiddenTags := c.ContainerImageMustNotUseForbiddenTags
	name := "Container images must not use forbidden tags"
	if cfgForbiddenTags != nil && cfgForbiddenTags.IsPinnedByDigestRequired() {
		name = "Container images must not use forbidden tags (pinned by digest)"
	}
	entries = append(entries, ControlEntry{
		DisplayName: name,
		ControlName: "containerImageMustNotUseForbiddenTags",
		Skipped:     cfgForbiddenTags == nil || !cfgForbiddenTags.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Container images must come from authorized sources",
		ControlName: "containerImageMustComeFromAuthorizedSources",
		Skipped:     c.ContainerImageMustComeFromAuthorizedSources == nil || !c.ContainerImageMustComeFromAuthorizedSources.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Branch must be protected",
		ControlName: "branchMustBeProtected",
		Skipped:     c.BranchMustBeProtected == nil || !c.BranchMustBeProtected.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Pipeline must not include hardcoded jobs",
		ControlName: "pipelineMustNotIncludeHardcodedJobs",
		Skipped:     c.PipelineMustNotIncludeHardcodedJobs == nil || !c.PipelineMustNotIncludeHardcodedJobs.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Includes must be up to date",
		ControlName: "includesMustBeUpToDate",
		Skipped:     c.IncludesMustBeUpToDate == nil || !c.IncludesMustBeUpToDate.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Includes must not use forbidden versions",
		ControlName: "includesMustNotUseForbiddenVersions",
		Skipped:     c.IncludesMustNotUseForbiddenVersions == nil || !c.IncludesMustNotUseForbiddenVersions.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Pipeline must include required components",
		ControlName: "pipelineMustIncludeComponent",
		Skipped:     c.PipelineMustIncludeComponent == nil || !c.PipelineMustIncludeComponent.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Pipeline must include required templates",
		ControlName: "pipelineMustIncludeTemplate",
		Skipped:     c.PipelineMustIncludeTemplate == nil || !c.PipelineMustIncludeTemplate.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Pipeline must not enable debug trace",
		ControlName: "pipelineMustNotEnableDebugTrace",
		Skipped:     c.PipelineMustNotEnableDebugTrace == nil || !c.PipelineMustNotEnableDebugTrace.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Pipeline must not use unsafe variable expansion",
		ControlName: "pipelineMustNotUseUnsafeVariableExpansion",
		Skipped:     c.PipelineMustNotUseUnsafeVariableExpansion == nil || !c.PipelineMustNotUseUnsafeVariableExpansion.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Security jobs must not be weakened",
		ControlName: "securityJobsMustNotBeWeakened",
		Skipped:     isSecurityJobsWeakenedSkipped(c.SecurityJobsMustNotBeWeakened),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Pipeline must not execute unverified scripts",
		ControlName: "pipelineMustNotExecuteUnverifiedScripts",
		Skipped:     c.PipelineMustNotExecuteUnverifiedScripts == nil || !c.PipelineMustNotExecuteUnverifiedScripts.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Pipeline must not override job variables",
		ControlName: "pipelineMustNotOverrideJobVariables",
		Skipped:     c.PipelineMustNotOverrideJobVariables == nil || !c.PipelineMustNotOverrideJobVariables.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Pipeline must not use Docker-in-Docker",
		ControlName: "pipelineMustNotUseDockerInDocker",
		Skipped:     c.PipelineMustNotUseDockerInDocker == nil || !c.PipelineMustNotUseDockerInDocker.IsEnabled(),
	})
	return entries
}

// GitHubControls returns the catalog of GitHub Actions controls in
// their canonical display order — the same shape GitLabControls
// uses. Every non-benched GitHub control is returned. Skip semantics
// mirror GitLabControls and v0.2.x's GitLab legacy code: absent from
// `github.controls.*` OR `enabled: false` (or empty entry) →
// Skipped=true. Benched controls remain invisible because their
// findings never reach the catalog.
func GitHubControls(pc *configuration.PlumberConfig) []ControlEntry {
	if pc == nil {
		return nil
	}
	c := pc.ControlsFor("github")
	entries := make([]ControlEntry, 0, 9)

	cfgForbiddenTags := c.ContainerImageMustNotUseForbiddenTags
	name := "Container images must not use forbidden tags"
	if cfgForbiddenTags != nil && cfgForbiddenTags.IsPinnedByDigestRequired() {
		name = "Container images must not use forbidden tags (pinned by digest)"
	}
	entries = append(entries, ControlEntry{
		DisplayName: name,
		ControlName: "containerImageMustNotUseForbiddenTags",
		Skipped:     cfgForbiddenTags == nil || !cfgForbiddenTags.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Third-party actions must be pinned by commit SHA",
		ControlName: "actionsMustBePinnedByCommitSha",
		Skipped:     c.ActionsMustBePinnedByCommitSha == nil || !c.ActionsMustBePinnedByCommitSha.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Branch must be protected",
		ControlName: "branchMustBeProtected",
		Skipped:     c.BranchMustBeProtected == nil || !c.BranchMustBeProtected.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Security jobs must not be weakened",
		ControlName: "securityJobsMustNotBeWeakened",
		Skipped:     isSecurityJobsWeakenedSkipped(c.SecurityJobsMustNotBeWeakened),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Workflows must not use Docker-in-Docker",
		ControlName: "pipelineMustNotUseDockerInDocker",
		Skipped:     c.PipelineMustNotUseDockerInDocker == nil || !c.PipelineMustNotUseDockerInDocker.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Reusable workflows must not inherit secrets",
		ControlName: "reusableWorkflowsMustNotInheritSecrets",
		Skipped:     c.ReusableWorkflowsMustNotInheritSecrets == nil || !c.ReusableWorkflowsMustNotInheritSecrets.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Workflows must not inject user input in scripts",
		ControlName: "workflowMustNotInjectUserInputInScripts",
		Skipped:     c.WorkflowMustNotInjectUserInputInScripts == nil || !c.WorkflowMustNotInjectUserInputInScripts.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Workflows must not use dangerous triggers",
		ControlName: "workflowMustNotUseDangerousTriggers",
		Skipped:     c.WorkflowMustNotUseDangerousTriggers == nil || !c.WorkflowMustNotUseDangerousTriggers.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Workflows must declare permissions",
		ControlName: "workflowsMustDeclarePermissions",
		Skipped:     c.WorkflowsMustDeclarePermissions == nil || !c.WorkflowsMustDeclarePermissions.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Workflows must include required actions",
		ControlName: "workflowMustIncludeRequiredActions",
		Skipped:     c.WorkflowMustIncludeRequiredActions == nil || !c.WorkflowMustIncludeRequiredActions.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Workflow must not grant write-all permissions",
		ControlName: "workflowMustNotGrantPermissionsWriteAll",
		Skipped:     c.WorkflowMustNotGrantPermissionsWriteAll == nil || !c.WorkflowMustNotGrantPermissionsWriteAll.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Actions must not reference archived repositories",
		ControlName: "actionsMustNotBeArchived",
		Skipped:     c.ActionsMustNotBeArchived == nil || !c.ActionsMustNotBeArchived.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Actions must not carry known CVEs",
		ControlName: "actionsMustNotCarryKnownCVEs",
		Skipped:     c.ActionsMustNotCarryKnownCVEs == nil || !c.ActionsMustNotCarryKnownCVEs.IsEnabled(),
	})
	entries = append(entries, ControlEntry{
		DisplayName: "Pipeline must not enable debug trace",
		ControlName: "pipelineMustNotEnableDebugTrace",
		Skipped:     c.PipelineMustNotEnableDebugTrace == nil || !c.PipelineMustNotEnableDebugTrace.IsEnabled(),
	})
	return entries
}

// isSecurityJobsWeakenedSkipped collapses the parent + sub-check
// state of securityJobsMustNotBeWeakened into a single skip flag.
// Absent (cfg == nil) or explicit `enabled: false`: skipped —
// matching v0.2.22 (control/controlGitlabSecurityJobsWeakened.go),
// which short-circuits Run() with `result.Skipped = true` in both
// cases. Parent enabled but every sub-check
// (allowFailureMustBeFalse, rulesMustNotBeRedefined,
// whenMustNotBeManual) is explicitly off → also skipped: there is
// literally nothing to check, and v0.2.22's runner emits
// `skipped: true` in that state too. Sub-check defaults are `true`
// when the toggle is absent, so omitting all three blocks does NOT
// trigger the skip.
func isSecurityJobsWeakenedSkipped(cfg *configuration.SecurityJobsWeakenedControlConfig) bool {
	if cfg == nil || !cfg.IsEnabled() {
		return true
	}
	const subDefault = true
	return !cfg.AllowFailureMustBeFalse.IsEnabled(subDefault) &&
		!cfg.RulesMustNotBeRedefined.IsEnabled(subDefault) &&
		!cfg.WhenMustNotBeManual.IsEnabled(subDefault)
}

// DisabledControlNames returns the set of control names treated as
// skipped for the supplied ControlsConfig — both explicit disables
// (cfg present with IsEnabled() == false) and absent entries (cfg
// == nil). Matching v0.2.x exactly: at tag v0.2.22, every legacy
// control wrapper in `control/controlGitlab*.go` sets
// `p.Enabled = false` when its section is missing from .plumber.yaml,
// so the Rego port drops those findings via
// FilterFindingsByEnabledControls. Issue #158 was specifically about
// v0.3.0-beta.2 keeping absent-control Rego findings in the score;
// this function feeds the filter to close that path. For
// securityJobsMustNotBeWeakened the "skipped" call also covers the
// case where every sub-check is explicitly off — see
// isSecurityJobsWeakenedSkipped. Pass the right provider's
// ControlsConfig (use pc.ControlsFor("gitlab") or
// pc.ControlsFor("github")).
func DisabledControlNames(c *configuration.ControlsConfig) map[string]bool {
	out := map[string]bool{}
	if c == nil {
		return out
	}
	if cfg := c.ContainerImageMustNotUseForbiddenTags; cfg == nil || !cfg.IsEnabled() {
		out["containerImageMustNotUseForbiddenTags"] = true
	}
	if cfg := c.ContainerImageMustComeFromAuthorizedSources; cfg == nil || !cfg.IsEnabled() {
		out["containerImageMustComeFromAuthorizedSources"] = true
	}
	if cfg := c.BranchMustBeProtected; cfg == nil || !cfg.IsEnabled() {
		out["branchMustBeProtected"] = true
	}
	if cfg := c.PipelineMustNotIncludeHardcodedJobs; cfg == nil || !cfg.IsEnabled() {
		out["pipelineMustNotIncludeHardcodedJobs"] = true
	}
	if cfg := c.IncludesMustBeUpToDate; cfg == nil || !cfg.IsEnabled() {
		out["includesMustBeUpToDate"] = true
	}
	if cfg := c.IncludesMustNotUseForbiddenVersions; cfg == nil || !cfg.IsEnabled() {
		out["includesMustNotUseForbiddenVersions"] = true
	}
	if cfg := c.PipelineMustIncludeComponent; cfg == nil || !cfg.IsEnabled() {
		out["pipelineMustIncludeComponent"] = true
	}
	if cfg := c.PipelineMustIncludeTemplate; cfg == nil || !cfg.IsEnabled() {
		out["pipelineMustIncludeTemplate"] = true
	}
	if cfg := c.PipelineMustNotEnableDebugTrace; cfg == nil || !cfg.IsEnabled() {
		out["pipelineMustNotEnableDebugTrace"] = true
	}
	if cfg := c.PipelineMustNotUseUnsafeVariableExpansion; cfg == nil || !cfg.IsEnabled() {
		out["pipelineMustNotUseUnsafeVariableExpansion"] = true
	}
	if isSecurityJobsWeakenedSkipped(c.SecurityJobsMustNotBeWeakened) {
		out["securityJobsMustNotBeWeakened"] = true
	}
	if cfg := c.PipelineMustNotExecuteUnverifiedScripts; cfg == nil || !cfg.IsEnabled() {
		out["pipelineMustNotExecuteUnverifiedScripts"] = true
	}
	if cfg := c.PipelineMustNotOverrideJobVariables; cfg == nil || !cfg.IsEnabled() {
		out["pipelineMustNotOverrideJobVariables"] = true
	}
	if cfg := c.PipelineMustNotUseDockerInDocker; cfg == nil || !cfg.IsEnabled() {
		out["pipelineMustNotUseDockerInDocker"] = true
	}
	if cfg := c.ActionsMustBePinnedByCommitSha; cfg == nil || !cfg.IsEnabled() {
		out["actionsMustBePinnedByCommitSha"] = true
	}
	if cfg := c.WorkflowMustNotInjectUserInputInScripts; cfg == nil || !cfg.IsEnabled() {
		out["workflowMustNotInjectUserInputInScripts"] = true
	}
	if cfg := c.WorkflowMustNotUseDangerousTriggers; cfg == nil || !cfg.IsEnabled() {
		out["workflowMustNotUseDangerousTriggers"] = true
	}
	if cfg := c.WorkflowsMustDeclarePermissions; cfg == nil || !cfg.IsEnabled() {
		out["workflowsMustDeclarePermissions"] = true
	}
	if cfg := c.ReusableWorkflowsMustNotInheritSecrets; cfg == nil || !cfg.IsEnabled() {
		out["reusableWorkflowsMustNotInheritSecrets"] = true
	}
	if cfg := c.WorkflowMustIncludeRequiredActions; cfg == nil || !cfg.IsEnabled() {
		out["workflowMustIncludeRequiredActions"] = true
	}
	if cfg := c.WorkflowMustNotGrantPermissionsWriteAll; cfg == nil || !cfg.IsEnabled() {
		out["workflowMustNotGrantPermissionsWriteAll"] = true
	}
	if cfg := c.ActionsMustNotBeArchived; cfg == nil || !cfg.IsEnabled() {
		out["actionsMustNotBeArchived"] = true
	}
	if cfg := c.ActionsMustNotCarryKnownCVEs; cfg == nil || !cfg.IsEnabled() {
		out["actionsMustNotCarryKnownCVEs"] = true
	}
	return out
}

// FilterFindingsByEnabledControls drops findings whose ControlName
// is either (a) currently benched for the given provider — see
// IsBenched in registry.go — or (b) treated as skipped for the
// supplied ControlsConfig (explicitly disabled OR absent from the
// user's config; see DisabledControlNames). Findings whose code is
// unknown or has no ControlName are kept (defensive: better surfaced
// than silently swallowed). When the supplied ControlsConfig is nil
// no skipped-controls claim is made and all findings pass through;
// callers that want strict skipping must pass a non-nil config. Pass
// the provider name ("gitlab" or "github") and the matching
// ControlsConfig (use pc.ControlsFor(provider)).
func FilterFindingsByEnabledControls(findings []opaengine.Finding, provider string, c *configuration.ControlsConfig, includeOnly, skip []string) []opaengine.Finding {
	disabled := DisabledControlNames(c)
	out := make([]opaengine.Finding, 0, len(findings))
	for _, f := range findings {
		info := LookupCode(ErrorCode(f.Code))
		if info == nil || info.ControlName == "" {
			out = append(out, f)
			continue
		}
		if configuration.IsBenched(provider, info.ControlName) {
			continue
		}
		if disabled[info.ControlName] {
			continue
		}
		if !ControlPassesFilter(info.ControlName, includeOnly, skip) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// ControlPassesFilter applies the --controls / --skip-controls semantics
// for one control name. When includeOnly is non-empty, only listed
// controls pass; skip removes controls from the survivor set. The two
// flags are mutually exclusive at the CLI level (cmd/analyze.go), but
// this helper handles either or both for callers that don't enforce
// that.
func ControlPassesFilter(name string, includeOnly, skip []string) bool {
	if len(includeOnly) > 0 {
		found := false
		for _, n := range includeOnly {
			if n == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, n := range skip {
		if n == name {
			return false
		}
	}
	return true
}

// MarkSkippedByFilter mutates entries in place, setting Skipped=true
// for any control filtered out by --controls / --skip-controls. Called
// from the renderer so the compliance table shows filtered controls as
// "skipped" instead of pretending they ran with 100 % compliance.
// Already-skipped entries (disabled in .plumber.yaml) stay skipped.
func MarkSkippedByFilter(entries []ControlEntry, includeOnly, skip []string) {
	if len(includeOnly) == 0 && len(skip) == 0 {
		return
	}
	for i := range entries {
		if entries[i].Skipped {
			continue
		}
		if !ControlPassesFilter(entries[i].ControlName, includeOnly, skip) {
			entries[i].Skipped = true
		}
	}
}

// ApplyFindings fills in Compliance for each catalog entry based on
// whether any finding matches its ControlName. The rule is binary: 100
// when the control fires no finding (or is skipped), 0 otherwise.
func ApplyFindings(entries []ControlEntry, findingsByControl map[string]int) []ControlEntry {
	out := make([]ControlEntry, len(entries))
	for i, e := range entries {
		e.Compliance = 100.0
		if !e.Skipped && findingsByControl[e.ControlName] > 0 {
			e.Compliance = 0.0
		}
		out[i] = e
	}
	return out
}
