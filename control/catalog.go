package control

import "github.com/getplumber/plumber/configuration"

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
	c := &pc.Controls
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
