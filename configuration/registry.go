package configuration

import "sort"

// ControlMeta describes a control's static properties: which providers
// it applies to and whether it is currently considered production-
// ready (i.e. NOT benched). Toggle semantics for individual users
// live in .plumber.yaml — this registry only describes the universe
// of controls the engine knows about.
type ControlMeta struct {
	// Providers lists the providers this control is applicable to.
	// "gitlab", "github", or both. Used by ValidateKnownKeys to warn
	// when a control is placed under the wrong provider section.
	Providers []string

	// DisplayName is the human-readable control name, the docs catalog
	// wording (#440). Display only: the technical control name stays the
	// stable key everywhere.
	DisplayName string

	// Category is the docs catalog grouping this control belongs to, one
	// of the Category* constants below. It follows the control's issue-code
	// block (1xx container images, 2xx variables, ... 9xx repository
	// hygiene), which TestControlCategoriesFollowTheCodeBlocks pins.
	Category string
}

// providerGitLab and providerGitHub are exported as constants so call
// sites can reference them by name instead of stringly-typed literals.
const (
	ProviderGitLab = "gitlab"
	ProviderGitHub = "github"
)

// The docs catalog categories (https://getplumber.io/docs/cli/controls),
// verbatim, plus one heading for the benched 9xx repository-hygiene block
// the site does not document yet. Every control belongs to exactly one.
const (
	CategoryContainerImages                = "CI/CD Container Images"
	CategoryCICDVariables                  = "CI/CD Variables"
	CategoryCICDSecrets                    = "CI/CD Secrets"
	CategoryPipelineComposition            = "Pipeline Composition"
	CategoryAccessAndAuthorization         = "Access and Authorization"
	CategorySecuritySource                 = "Security Source"
	CategoryThirdPartyActions              = "Third-party Actions"
	CategoryWorkflowTriggersAndPermissions = "Workflow Triggers and Permissions"
	CategoryRepositoryHygiene              = "Repository Hygiene"
)

// controlsMeta is the canonical registry of every control name the
// engine knows about, with the providers each applies to. Adding a new
// control means adding an entry here so the validator and the bench
// gate both see it.
//
// Single source of truth: when you add a new ControlName in codes.go,
// add a matching entry here. Controls applicable to both providers
// list both. A new GitLab-only control gets {ProviderGitLab}; a new
// GitHub-only control gets {ProviderGitHub}.
var controlsMeta = map[string]ControlMeta{
	// Cross-provider (same control name + rego logic, provider-specific values).
	"branchMustBeProtected": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Branch must be protected",
		Category:    CategoryAccessAndAuthorization,
	},
	"mergeRequestApprovalRulesMustRequireMinimumApprovals": {
		Providers:   []string{ProviderGitLab},
		DisplayName: "MR approval rules must require a minimum number of approvals",
		Category:    CategoryAccessAndAuthorization,
	},
	"mergeRequestApprovalRulesMustCoverAllProtectedBranches": {
		Providers:   []string{ProviderGitLab},
		DisplayName: "MR approval rules must cover all protected branches",
		Category:    CategoryAccessAndAuthorization,
	},
	"mergeRequestApprovalSettingsMustBeCompliant": {
		Providers:   []string{ProviderGitLab},
		DisplayName: "MR approval settings must be compliant",
		Category:    CategoryAccessAndAuthorization,
	},
	"mergeRequestSettingsMustBeCompliant": {
		Providers:   []string{ProviderGitLab},
		DisplayName: "MR settings must be compliant",
		Category:    CategoryAccessAndAuthorization,
	},
	"cicdVariablesMustBeProtected": {
		Providers:   []string{ProviderGitLab},
		DisplayName: "CI/CD variables must be protected",
		Category:    CategoryCICDVariables,
	},
	"cicdVariablesMustBeMasked": {
		Providers:   []string{ProviderGitLab},
		DisplayName: "CI/CD variables must be masked",
		Category:    CategoryCICDVariables,
	},
	"projectMustHaveSecurityPolicySource": {
		Providers:   []string{ProviderGitLab},
		DisplayName: "Project must have a security policy source",
		Category:    CategorySecuritySource,
	},
	"containerImageMustComeFromAuthorizedSources": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Container images must come from authorized sources",
		Category:    CategoryContainerImages,
	},
	"containerImageMustNotUseForbiddenTags": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Container images must not use forbidden tags",
		Category:    CategoryContainerImages,
	},
	"externalRefsMustNotCollide": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Includes must not use ambiguous tag/branch refs",
		Category:    CategoryPipelineComposition,
	},
	"includesMustBeUpToDate": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Includes must be up to date",
		Category:    CategoryPipelineComposition,
	},
	"includesMustNotUseForbiddenVersions": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Includes must not use forbidden versions",
		Category:    CategoryPipelineComposition,
	},
	"pipelineMustIncludeComponent": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Pipeline must include required components",
		Category:    CategoryPipelineComposition,
	},
	"pipelineMustIncludeTemplate": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Pipeline must include required templates",
		Category:    CategoryPipelineComposition,
	},
	"pipelineMustNotEnableDebugTrace": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Pipeline must not enable debug trace",
		Category:    CategoryCICDVariables,
	},
	"pipelineMustNotExecuteUnverifiedScripts": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Pipeline must not execute unverified scripts",
		Category:    CategoryPipelineComposition,
	},
	"pipelineMustNotIncludeHardcodedJobs": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Pipeline must not include hardcoded jobs",
		Category:    CategoryPipelineComposition,
	},
	"pipelineMustNotOverrideJobVariables": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Pipeline must not override job variables",
		Category:    CategoryCICDVariables,
	},
	"pipelineMustNotUseDockerInDocker": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Pipeline must not use Docker-in-Docker",
		Category:    CategoryPipelineComposition,
	},
	"pipelineMustNotUseUnsafeVariableExpansion": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Pipeline must not use unsafe variable expansion",
		Category:    CategoryCICDVariables,
	},
	"securityJobsMustNotBeWeakened": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Security jobs must not be weakened",
		Category:    CategoryPipelineComposition,
	},

	// GitHub-only.
	"actionPinCommentsMustMatchSha": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Action pin comments must match the pinned SHA",
		Category:    CategoryThirdPartyActions,
	},
	"actionPinsMustNotBeStale": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Action pins must not be stale",
		Category:    CategoryThirdPartyActions,
	},
	"actionRefsMustExistUpstream": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Actions must pin commits that exist upstream",
		Category:    CategoryThirdPartyActions,
	},
	"actionsMustBePinnedByCommitSha": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Third-party actions must be pinned by commit SHA",
		Category:    CategoryThirdPartyActions,
	},
	"actionsMustNotBeArchived": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Actions must not reference archived repositories",
		Category:    CategoryThirdPartyActions,
	},
	"actionsMustNotCarryKnownCVEs": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Actions must not carry known CVEs",
		Category:    CategoryThirdPartyActions,
	},
	"actionsMustNotDuplicateRunnerBuiltins": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Actions must not duplicate runner builtins",
		Category:    CategoryThirdPartyActions,
	},
	"actionsMustNotExecuteMutableRemoteCode": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Actions must not execute mutable remote code",
		Category:    CategoryThirdPartyActions,
	},
	"checkoutMustNotPersistCredentials": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Checkout must not persist credentials",
		Category:    CategoryCICDSecrets,
	},
	"containerCredentialsMustComeFromSecrets": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Container credentials must come from secrets",
		Category:    CategoryThirdPartyActions,
	},
	"dependabotEcosystemsMustHaveCooldown": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Dependabot ecosystems must have a cooldown",
		Category:    CategoryRepositoryHygiene,
	},
	"dependabotMustNotAllowInsecureExternalCodeExecution": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Dependabot must not allow insecure external code execution",
		Category:    CategoryRepositoryHygiene,
	},
	"deployJobsMustUseEnvironmentGate": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Deploy jobs must use an environment gate",
		Category:    CategoryCICDSecrets,
	},
	"dockerfilesMustPinBaseImageByDigest": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Dockerfiles must pin base images by digest",
		Category:    CategoryThirdPartyActions,
	},
	"githubActionMustComeFromAuthorizedSources": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Actions must come from authorized sources",
		Category:    CategoryThirdPartyActions,
	},
	"githubAppTokensMustBeRevokedOnExit": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "GitHub App tokens must be revoked on exit",
		Category:    CategoryCICDSecrets,
	},
	"publishWorkflowsMustUseOidcTrustedPublishing": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Publish workflows must use OIDC trusted publishing",
		Category:    CategoryPipelineComposition,
	},
	"pullRequestTargetMustNotCheckoutHead": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "pull_request_target workflows must not check out the PR head",
		Category:    CategoryWorkflowTriggersAndPermissions,
	},
	"releaseWorkflowsMustNotRestoreUntrustedCache": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Release workflows must not restore an untrusted cache",
		Category:    CategoryThirdPartyActions,
	},
	"releaseWorkflowsMustSignArtefacts": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Release workflows must sign artefacts",
		Category:    CategoryThirdPartyActions,
	},
	"repositoriesMustConfigureDependencyUpdates": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Repositories must configure dependency updates",
		Category:    CategoryRepositoryHygiene,
	},
	"repositoriesMustPublishSecurityPolicy": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Repositories must publish a security policy",
		Category:    CategoryRepositoryHygiene,
	},
	"repositoriesMustRunSAST": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Repositories must run SAST",
		Category:    CategoryRepositoryHygiene,
	},
	"reusableWorkflowsMustNotInheritSecrets": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Reusable workflows must not inherit secrets",
		Category:    CategoryCICDSecrets,
	},
	"workflowConditionsMustBeSound": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflow conditions must be sound",
		Category:    CategoryCICDVariables,
	},
	"workflowContainsCallsMustBeSound": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflow contains() calls must be sound",
		Category:    CategoryCICDVariables,
	},
	"workflowMustNotContainObfuscation": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not contain obfuscation",
		Category:    CategoryPipelineComposition,
	},
	"workflowMustNotExportEntireGitHubContext": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not export the entire GitHub context",
		Category:    CategoryCICDVariables,
	},
	"workflowMustNotExportEntireSecretsContext": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not expose all secrets at once",
		Category:    CategoryCICDSecrets,
	},
	"workflowMustNotGrantPermissionsWriteAll": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflow must not grant write-all permissions",
		Category:    CategoryWorkflowTriggersAndPermissions,
	},
	"workflowMustNotIndexSecretsDynamically": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not index secrets dynamically",
		Category:    CategoryCICDSecrets,
	},
	"workflowMustNotInjectUserInputInScripts": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not inject user input in scripts",
		Category:    CategoryCICDVariables,
	},
	"workflowMustNotInjectVarsInScripts": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not inject vars in scripts",
		Category:    CategoryCICDVariables,
	},
	"workflowMustNotReEnableInsecureCommands": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not re-enable insecure commands",
		Category:    CategoryCICDVariables,
	},
	"workflowMustNotTrustSpoofableActorChecks": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not trust spoofable actor checks",
		Category:    CategoryCICDVariables,
	},
	"workflowMustNotUnredactSecretsViaFromJSON": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not unredact secrets via fromJSON",
		Category:    CategoryCICDSecrets,
	},
	"workflowMustNotUseDangerousTriggers": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not use dangerous triggers",
		Category:    CategoryWorkflowTriggersAndPermissions,
	},
	"workflowMustNotUseKnownMisfeatures": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not use known misfeatures",
		Category:    CategoryPipelineComposition,
	},
	"workflowMustNotWriteUntrustedContentToGitHubEnv": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not write untrusted content to $GITHUB_ENV",
		Category:    CategoryCICDVariables,
	},
	"workflowMustIncludeRequiredActions": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must include required actions",
		Category:    CategoryPipelineComposition,
	},
	"workflowMustPinPackageInstalls": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must pin package installs",
		Category:    CategoryCICDVariables,
	},
	"workflowsMustDeclareConcurrency": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must declare concurrency",
		Category:    CategoryPipelineComposition,
	},
	"workflowsMustDeclarePermissions": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must declare permissions",
		Category:    CategoryWorkflowTriggersAndPermissions,
	},
	"workflowsMustHaveExplicitName": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must have an explicit name",
		Category:    CategoryPipelineComposition,
	},
}

// removedControls maps control names that shipped in earlier releases
// but have since been removed from the product to a short explanation.
// A config that still carries one of these keys gets a clear
// "removed and ignored" warning instead of the generic unknown-key
// path (whose Levenshtein suggestion would be misleading), and the
// key never fails a --fail-warnings run into the unknown-key lane by
// accident of history.
var removedControls = map[string]string{
	// The gitleaks-based secret scanning integration was removed in
	// https://github.com/getplumber/plumber/issues/310 — Plumber no
	// longer shells out to external binaries and secret detection is
	// out of scope for the product. Its ISSUE-301 slot is retired and
	// must never be reused (the downstream jobs platform has mapped
	// "secret leak in pipeline configuration" to 301 since before the
	// CLI rule existed).
	"pipelineMustNotLeakSecretsInConfig": "secret detection is no longer part of Plumber; remove this block from .plumber.yaml",
}

// benchedControls is the dev-side gate for controls that are NOT yet
// production-ready, keyed by provider. Findings for any (provider,
// control) pair listed here are dropped before reaching scoring,
// output, or any other downstream consumer — regardless of what the
// user's .plumber.yaml says about them.
//
// Why this exists: GitHub Actions support has dozens of policies in
// the engine at varying maturity levels. Some have only one test
// case, some have no test case at all. Until a control clears the
// "ship-ready" bar (substantive rule + ≥3 tests + docs), keeping it
// on the bench prevents noisy findings from reaching users.
//
// The bench is keyed by provider because cross-provider controls
// (e.g. branchMustBeProtected) often ship on one provider while the
// other side waits on collector or test work.
//
// To promote a benched (provider, control) pair: remove the entry
// from this map. If the control needs configurable behaviour beyond
// on/off, also add a typed struct in configuration/plumberconfig.go
// and wire it through buildEngineConfig.
//
// As of 2026-08-05 (v0.4.28), counted from this file and control/catalog.go:
//   - controlsMeta declares 59 controls: 15 cross-provider, 44
//     GitHub-only, 0 GitLab-only.
//   - GitLab: zero benched. All 15 GitLab-applicable controls ship, and
//     GitLabControls returns exactly those 15.
//   - GitHub: 36 benched, so only 23 of the 59 GitHub-applicable controls
//     reach users, and GitHubControls returns exactly those 23. Eight of
//     the 36 are cross-provider controls benched on the GitHub side only,
//     i.e. they still fire on GitLab.
//
// Keep these numbers honest when you bench or unbench something; they are
// the fastest way to see how much of the GitHub catalog is actually live.
var benchedControls = map[string]map[string]struct{}{
	ProviderGitLab: {},
	ProviderGitHub: {
		// API-backed action checks (need integration tests).
		"actionPinCommentsMustMatchSha":         {},
		"actionPinsMustNotBeStale":              {},
		"actionsMustNotDuplicateRunnerBuiltins": {},

		// Repo-artifact / setup-side controls (need fixture coverage).
		"containerCredentialsMustComeFromSecrets":             {},
		"dependabotEcosystemsMustHaveCooldown":                {},
		"dependabotMustNotAllowInsecureExternalCodeExecution": {},
		"deployJobsMustUseEnvironmentGate":                    {},
		"dockerfilesMustPinBaseImageByDigest":                 {},
		"githubAppTokensMustBeRevokedOnExit":                  {},
		"publishWorkflowsMustUseOidcTrustedPublishing":        {},
		"releaseWorkflowsMustSignArtefacts":                   {},
		"repositoriesMustConfigureDependencyUpdates":          {},
		"repositoriesMustPublishSecurityPolicy":               {},
		"repositoriesMustRunSAST":                             {},

		// Workflow-content controls (varying maturity).
		"workflowConditionsMustBeSound":             {},
		"workflowContainsCallsMustBeSound":          {},
		"workflowMustNotContainObfuscation":         {},
		"workflowMustNotExportEntireGitHubContext":  {},
		"workflowMustNotIndexSecretsDynamically":    {},
		"workflowMustNotInjectVarsInScripts":        {},
		"workflowMustNotReEnableInsecureCommands":   {},
		"workflowMustNotTrustSpoofableActorChecks":  {},
		"workflowMustNotUnredactSecretsViaFromJSON": {},
		"workflowMustNotUseKnownMisfeatures":        {},
		"workflowMustPinPackageInstalls":            {},
		"workflowsMustDeclareConcurrency":           {},
		"workflowsMustHaveExplicitName":             {},

		// Cross-provider controls whose GitHub side needs collector
		// or test work before it ships. They continue to fire
		// findings on GitLab — they're only benched on GitHub.
		"includesMustBeUpToDate":                      {},
		"includesMustNotUseForbiddenVersions":         {},
		"pipelineMustIncludeComponent":                {},
		"pipelineMustIncludeTemplate":                 {},
		"pipelineMustNotIncludeHardcodedJobs":         {},
		"pipelineMustNotOverrideJobVariables":         {},
		"pipelineMustNotUseUnsafeVariableExpansion":   {},
		"containerImageMustComeFromAuthorizedSources": {},
	},
}

// actionMetadataConsumers lists control names whose Rego rules
// depend on the per-`uses:` metadata populated by the GitHub API
// enrichment phase (archived state, latest tag, ref existence,
// advisory database). When EVERY entry in this list is benched for
// a given provider, the collector skips the API round-trips
// entirely — turning a 30-60s scan into a sub-second one on a
// large workflow set.
//
// Add to this list when introducing a new rule that reads from
// `input.pipeline.jobs[*].uses[*].metadata`.
var actionMetadataConsumers = []string{
	"actionPinCommentsMustMatchSha",
	"actionPinsMustNotBeStale",
	"actionRefsMustExistUpstream",
	"externalRefsMustNotCollide",
	"actionsMustNotBeArchived",
	"actionsMustNotCarryKnownCVEs",
	"actionsMustNotDuplicateRunnerBuiltins",
	"actionsMustNotExecuteMutableRemoteCode",
	"githubActionMustComeFromAuthorizedSources",
}

// ProviderNeedsActionMetadata reports whether at least one control
// that depends on action-ref API metadata is currently shipping for
// the given provider. Returns false when every consumer is benched,
// letting the collector skip the GitHub API enrichment loop.
func ProviderNeedsActionMetadata(provider string) bool {
	for _, name := range actionMetadataConsumers {
		if !IsBenched(provider, name) {
			return true
		}
	}
	return false
}

// IsBenched reports whether the given (provider, control) pair is
// currently on the dev-side bench. Findings matching are dropped
// before reaching any user-visible consumer, regardless of YAML
// state.
func IsBenched(provider, controlName string) bool {
	if m, ok := benchedControls[provider]; ok {
		_, b := m[controlName]
		return b
	}
	return false
}

// IsControlApplicableTo reports whether the named control applies to
// the given provider. Returns false for unknown control names.
func IsControlApplicableTo(controlName, provider string) bool {
	meta, ok := controlsMeta[controlName]
	if !ok {
		return false
	}
	for _, p := range meta.Providers {
		if p == provider {
			return true
		}
	}
	return false
}

// ControlCatalogEntry is one row of the exported control catalog: the
// stable technical name plus its display metadata (#440).
type ControlCatalogEntry struct {
	// Name is the technical control name, the stable key used in
	// .plumber.yaml, reports and the score push.
	Name string
	ControlMeta
}

// ControlsCatalog returns every control the engine knows about with its
// display metadata, sorted by technical name. The slice and its entries are
// copies: mutating them cannot corrupt the registry.
func ControlsCatalog() []ControlCatalogEntry {
	out := make([]ControlCatalogEntry, 0, len(controlsMeta))
	for name, meta := range controlsMeta {
		m := meta
		m.Providers = append([]string(nil), meta.Providers...)
		out = append(out, ControlCatalogEntry{Name: name, ControlMeta: m})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ControlMetaFor returns the display metadata for one technical control
// name, and whether the control is known at all.
func ControlMetaFor(name string) (ControlMeta, bool) {
	meta, ok := controlsMeta[name]
	if !ok {
		return ControlMeta{}, false
	}
	meta.Providers = append([]string(nil), meta.Providers...)
	return meta, true
}
