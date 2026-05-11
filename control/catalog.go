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
// in their canonical display order. Each entry is emitted regardless
// of whether the user defined the section in .plumber.yaml — absent
// config is treated as "disabled". The caller typically fills in the
// findings-derived compliance by looking up FindingsByControl.
func GitLabControls(pc *configuration.PlumberConfig) []ControlEntry {
	if pc == nil {
		return nil
	}
	c := pc.ControlsFor("gitlab")
	entries := make([]ControlEntry, 0, 14)

	// Container images must not use forbidden tags
	if cfg := c.ContainerImageMustNotUseForbiddenTags; cfg != nil {
		name := "Container images must not use forbidden tags"
		if cfg.IsPinnedByDigestRequired() {
			name = "Container images must not use forbidden tags (pinned by digest)"
		}
		entries = append(entries, ControlEntry{
			DisplayName: name,
			ControlName: "containerImageMustNotUseForbiddenTags",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.ContainerImageMustComeFromAuthorizedSources; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Container images must come from authorized sources",
			ControlName: "containerImageMustComeFromAuthorizedSources",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.BranchMustBeProtected; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Branch must be protected",
			ControlName: "branchMustBeProtected",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.PipelineMustNotIncludeHardcodedJobs; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Pipeline must not include hardcoded jobs",
			ControlName: "pipelineMustNotIncludeHardcodedJobs",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.IncludesMustBeUpToDate; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Includes must be up to date",
			ControlName: "includesMustBeUpToDate",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.IncludesMustNotUseForbiddenVersions; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Includes must not use forbidden versions",
			ControlName: "includesMustNotUseForbiddenVersions",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.PipelineMustIncludeComponent; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Pipeline must include required components",
			ControlName: "pipelineMustIncludeComponent",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.PipelineMustIncludeTemplate; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Pipeline must include required templates",
			ControlName: "pipelineMustIncludeTemplate",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.PipelineMustNotEnableDebugTrace; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Pipeline must not enable debug trace",
			ControlName: "pipelineMustNotEnableDebugTrace",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.PipelineMustNotUseUnsafeVariableExpansion; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Pipeline must not use unsafe variable expansion",
			ControlName: "pipelineMustNotUseUnsafeVariableExpansion",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.SecurityJobsMustNotBeWeakened; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Security jobs must not be weakened",
			ControlName: "securityJobsMustNotBeWeakened",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.PipelineMustNotExecuteUnverifiedScripts; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Pipeline must not execute unverified scripts",
			ControlName: "pipelineMustNotExecuteUnverifiedScripts",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.PipelineMustNotOverrideJobVariables; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Pipeline must not override job variables",
			ControlName: "pipelineMustNotOverrideJobVariables",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.PipelineMustNotUseDockerInDocker; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Pipeline must not use Docker-in-Docker",
			ControlName: "pipelineMustNotUseDockerInDocker",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	return entries
}

// GitHubControls returns the catalog of GitHub Actions controls in
// their canonical display order — the same shape GitLabControls uses
// so the renderer can emit per-control sections, an Issues table,
// and a Compliance table just like the GitLab path. Currently lists
// the eight default-shipping controls (every non-benched GitHub
// control with a known display name); benched controls remain
// invisible because their findings never reach the catalog.
func GitHubControls(pc *configuration.PlumberConfig) []ControlEntry {
	if pc == nil {
		return nil
	}
	c := pc.ControlsFor("github")
	entries := make([]ControlEntry, 0, 8)

	if cfg := c.ContainerImageMustNotUseForbiddenTags; cfg != nil {
		name := "Container images must not use forbidden tags"
		if cfg.IsPinnedByDigestRequired() {
			name = "Container images must not use forbidden tags (pinned by digest)"
		}
		entries = append(entries, ControlEntry{
			DisplayName: name,
			ControlName: "containerImageMustNotUseForbiddenTags",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.ActionsMustBePinnedByCommitSha; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Third-party actions must be pinned by commit SHA",
			ControlName: "actionsMustBePinnedByCommitSha",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.BranchMustBeProtected; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Branch must be protected",
			ControlName: "branchMustBeProtected",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.SecurityJobsMustNotBeWeakened; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Security jobs must not be weakened",
			ControlName: "securityJobsMustNotBeWeakened",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.PipelineMustNotUseDockerInDocker; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Workflows must not use Docker-in-Docker",
			ControlName: "pipelineMustNotUseDockerInDocker",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.ReusableWorkflowsMustNotInheritSecrets; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Reusable workflows must not inherit secrets",
			ControlName: "reusableWorkflowsMustNotInheritSecrets",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.WorkflowMustNotInjectUserInputInScripts; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Workflows must not inject user input in scripts",
			ControlName: "workflowMustNotInjectUserInputInScripts",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.WorkflowMustNotUseDangerousTriggers; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Workflows must not use dangerous triggers",
			ControlName: "workflowMustNotUseDangerousTriggers",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	if cfg := c.WorkflowsMustDeclarePermissions; cfg != nil {
		entries = append(entries, ControlEntry{
			DisplayName: "Workflows must declare permissions",
			ControlName: "workflowsMustDeclarePermissions",
			Skipped:     !cfg.IsEnabled(),
		})
	}
	return entries
}

// DisabledControlNames returns the set of control names the user has
// explicitly disabled (controls present in the provider's controls
// config with `enabled: false`). Controls absent from the config are
// NOT included — they fall back to the embedded default which has
// them enabled. Pass the right provider's ControlsConfig (use
// pc.ControlsFor("gitlab") or pc.ControlsFor("github")).
func DisabledControlNames(c *configuration.ControlsConfig) map[string]bool {
	out := map[string]bool{}
	if c == nil {
		return out
	}
	if cfg := c.ContainerImageMustNotUseForbiddenTags; cfg != nil && !cfg.IsEnabled() {
		out["containerImageMustNotUseForbiddenTags"] = true
	}
	if cfg := c.ContainerImageMustComeFromAuthorizedSources; cfg != nil && !cfg.IsEnabled() {
		out["containerImageMustComeFromAuthorizedSources"] = true
	}
	if cfg := c.BranchMustBeProtected; cfg != nil && !cfg.IsEnabled() {
		out["branchMustBeProtected"] = true
	}
	if cfg := c.PipelineMustNotIncludeHardcodedJobs; cfg != nil && !cfg.IsEnabled() {
		out["pipelineMustNotIncludeHardcodedJobs"] = true
	}
	if cfg := c.IncludesMustBeUpToDate; cfg != nil && !cfg.IsEnabled() {
		out["includesMustBeUpToDate"] = true
	}
	if cfg := c.IncludesMustNotUseForbiddenVersions; cfg != nil && !cfg.IsEnabled() {
		out["includesMustNotUseForbiddenVersions"] = true
	}
	if cfg := c.PipelineMustIncludeComponent; cfg != nil && !cfg.IsEnabled() {
		out["pipelineMustIncludeComponent"] = true
	}
	if cfg := c.PipelineMustIncludeTemplate; cfg != nil && !cfg.IsEnabled() {
		out["pipelineMustIncludeTemplate"] = true
	}
	if cfg := c.PipelineMustNotEnableDebugTrace; cfg != nil && !cfg.IsEnabled() {
		out["pipelineMustNotEnableDebugTrace"] = true
	}
	if cfg := c.PipelineMustNotUseUnsafeVariableExpansion; cfg != nil && !cfg.IsEnabled() {
		out["pipelineMustNotUseUnsafeVariableExpansion"] = true
	}
	if cfg := c.SecurityJobsMustNotBeWeakened; cfg != nil && !cfg.IsEnabled() {
		out["securityJobsMustNotBeWeakened"] = true
	}
	if cfg := c.PipelineMustNotExecuteUnverifiedScripts; cfg != nil && !cfg.IsEnabled() {
		out["pipelineMustNotExecuteUnverifiedScripts"] = true
	}
	if cfg := c.PipelineMustNotOverrideJobVariables; cfg != nil && !cfg.IsEnabled() {
		out["pipelineMustNotOverrideJobVariables"] = true
	}
	if cfg := c.PipelineMustNotUseDockerInDocker; cfg != nil && !cfg.IsEnabled() {
		out["pipelineMustNotUseDockerInDocker"] = true
	}
	if cfg := c.ActionsMustBePinnedByCommitSha; cfg != nil && !cfg.IsEnabled() {
		out["actionsMustBePinnedByCommitSha"] = true
	}
	if cfg := c.WorkflowMustNotInjectUserInputInScripts; cfg != nil && !cfg.IsEnabled() {
		out["workflowMustNotInjectUserInputInScripts"] = true
	}
	if cfg := c.WorkflowMustNotUseDangerousTriggers; cfg != nil && !cfg.IsEnabled() {
		out["workflowMustNotUseDangerousTriggers"] = true
	}
	if cfg := c.WorkflowsMustDeclarePermissions; cfg != nil && !cfg.IsEnabled() {
		out["workflowsMustDeclarePermissions"] = true
	}
	if cfg := c.ReusableWorkflowsMustNotInheritSecrets; cfg != nil && !cfg.IsEnabled() {
		out["reusableWorkflowsMustNotInheritSecrets"] = true
	}
	return out
}

// FilterFindingsByEnabledControls drops findings whose ControlName
// is either (a) currently benched for the given provider — see
// IsBenched in registry.go — or (b) explicitly disabled in the
// supplied ControlsConfig. Findings whose code is unknown or has no
// ControlName are kept (defensive: better surfaced than silently
// swallowed). Pass the provider name ("gitlab" or "github") and the
// matching ControlsConfig (use pc.ControlsFor(provider)).
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
