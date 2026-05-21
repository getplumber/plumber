package configuration

// convertV1ToV2 mutates pc in-place from the legacy v1 schema (top-level
// `controls:` and `engine:`) to the v2 schema (`gitlab.controls:` and
// `github.controls:`). The conversion rule is:
//
//   - All v1 top-level controls move under pc.GitLab.Controls. The
//     legacy schema was historically GitLab-only, so GitLab is the
//     correct destination.
//   - pc.GitHub stays nil (or untouched if already populated). Per-
//     control GitHub config did not exist in v1, so there is nothing
//     to migrate there.
//   - The deprecated `engine:` block is dropped; a warning is returned
//     so the caller can surface it to the user.
//   - Pre-existing pc.GitLab and pc.GitHub are left alone if present
//     (someone hand-mixing v1 + v2 keys gets v2 priority — they
//     explicitly opted in to the new shape).
//   - pc.Controls and pc.Engine are cleared on the way out so
//     downstream code that incorrectly reads them sees nil rather
//     than stale data.
//
// Returns warnings (zero or more) describing anything user-visible
// that happened during conversion. Never returns an error: conversion
// is purely structural and has no failure mode.
func convertV1ToV2(pc *PlumberConfig) []string {
	if pc == nil {
		return nil
	}

	var warnings []string

	// Structural change: top-level controls moved under gitlab.controls.
	// This is the only case where we emit the loud deprecation warning —
	// a stale `version: "1.0"` field on an otherwise-nested file is bumped
	// silently below.
	if !controlsConfigIsZero(pc.Controls) {
		if pc.GitLab == nil {
			pc.GitLab = &ProviderConfig{}
		}
		hadDestination := !controlsConfigIsZero(pc.GitLab.Controls)
		if !hadDestination {
			pc.GitLab.Controls = pc.Controls
		}
		if hadDestination && !controlsConfigEqual(pc.GitLab.Controls, pc.Controls) {
			warnings = append(warnings,
				"both top-level 'controls' (v1) and 'gitlab.controls' (v2) are set; "+
					"v2 (gitlab.controls) wins. Remove the top-level 'controls' block.")
		}
		pc.Controls = ControlsConfig{}
		warnings = append(warnings,
			"legacy config schema detected (top-level 'controls:'). "+
				"Run 'plumber config migrate' to upgrade to schema v2.0. "+
				"v1 support will be removed in the future.")
	}

	// Always normalise the version field. A bare bump from "1.0" to "2.0"
	// without any structural change (the user already nested manually but
	// forgot to update the version) is silent — their intent is clear.
	if pc.Version == "" || pc.Version == "1.0" {
		pc.Version = "2.0"
	}

	return warnings
}

// controlsConfigIsZero reports whether c has no non-nil control entries.
// Used to decide whether the v1→v2 converter should overwrite the
// destination GitLab.Controls map (it should only do so when the
// destination is empty).
func controlsConfigIsZero(c ControlsConfig) bool {
	return c.ContainerImageMustNotUseForbiddenTags == nil &&
		c.ContainerImageMustComeFromAuthorizedSources == nil &&
		c.BranchMustBeProtected == nil &&
		c.PipelineMustNotIncludeHardcodedJobs == nil &&
		c.IncludesMustBeUpToDate == nil &&
		c.IncludesMustNotUseForbiddenVersions == nil &&
		c.PipelineMustIncludeComponent == nil &&
		c.PipelineMustIncludeTemplate == nil &&
		c.PipelineMustNotEnableDebugTrace == nil &&
		c.PipelineMustNotUseUnsafeVariableExpansion == nil &&
		c.SecurityJobsMustNotBeWeakened == nil &&
		c.PipelineMustNotExecuteUnverifiedScripts == nil &&
		c.PipelineMustNotOverrideJobVariables == nil &&
		c.PipelineMustNotUseDockerInDocker == nil &&
		c.ActionsMustBePinnedByCommitSha == nil &&
		c.WorkflowMustIncludeRequiredActions == nil
}

// controlsConfigEqual is a shallow pointer-identity comparison used
// only by the v1→v2 converter to detect "same values nested twice".
// Not a deep equal — two equal-by-value configs with different
// pointers report not-equal. That's fine: we only want to suppress
// the warning when the user literally wrote the same map under both
// keys (rare; mostly a guard for future alias-based YAML).
func controlsConfigEqual(a, b ControlsConfig) bool {
	return a.ContainerImageMustNotUseForbiddenTags == b.ContainerImageMustNotUseForbiddenTags &&
		a.ContainerImageMustComeFromAuthorizedSources == b.ContainerImageMustComeFromAuthorizedSources &&
		a.BranchMustBeProtected == b.BranchMustBeProtected &&
		a.PipelineMustNotIncludeHardcodedJobs == b.PipelineMustNotIncludeHardcodedJobs &&
		a.IncludesMustBeUpToDate == b.IncludesMustBeUpToDate &&
		a.IncludesMustNotUseForbiddenVersions == b.IncludesMustNotUseForbiddenVersions &&
		a.PipelineMustIncludeComponent == b.PipelineMustIncludeComponent &&
		a.PipelineMustIncludeTemplate == b.PipelineMustIncludeTemplate &&
		a.PipelineMustNotEnableDebugTrace == b.PipelineMustNotEnableDebugTrace &&
		a.PipelineMustNotUseUnsafeVariableExpansion == b.PipelineMustNotUseUnsafeVariableExpansion &&
		a.SecurityJobsMustNotBeWeakened == b.SecurityJobsMustNotBeWeakened &&
		a.PipelineMustNotExecuteUnverifiedScripts == b.PipelineMustNotExecuteUnverifiedScripts &&
		a.PipelineMustNotOverrideJobVariables == b.PipelineMustNotOverrideJobVariables &&
		a.PipelineMustNotUseDockerInDocker == b.PipelineMustNotUseDockerInDocker &&
		a.ActionsMustBePinnedByCommitSha == b.ActionsMustBePinnedByCommitSha &&
		a.WorkflowMustIncludeRequiredActions == b.WorkflowMustIncludeRequiredActions
}

// ProviderConfig returns the named provider's config, or nil if absent.
// Accepted names: "gitlab", "github" (case-sensitive). Any other name
// returns nil. Safe to call on a nil receiver.
func (c *PlumberConfig) ProviderConfig(name string) *ProviderConfig {
	if c == nil {
		return nil
	}
	switch name {
	case "gitlab":
		return c.GitLab
	case "github":
		return c.GitHub
	}
	return nil
}

// ControlsFor returns a non-nil pointer to the named provider's
// ControlsConfig. If the provider is absent, returns a pointer to a
// zero-value ControlsConfig so callers can dereference fields without
// nil-checking. The returned pointer is read-only — mutations are
// discarded if the provider was absent.
func (c *PlumberConfig) ControlsFor(provider string) *ControlsConfig {
	pc := c.ProviderConfig(provider)
	if pc == nil {
		return &ControlsConfig{}
	}
	return &pc.Controls
}
