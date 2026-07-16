package configuration

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
}

// providerGitLab and providerGitHub are exported as constants so call
// sites can reference them by name instead of stringly-typed literals.
const (
	ProviderGitLab = "gitlab"
	ProviderGitHub = "github"
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
	"branchMustBeProtected":                       {Providers: []string{ProviderGitLab, ProviderGitHub}},
	"containerImageMustComeFromAuthorizedSources": {Providers: []string{ProviderGitLab, ProviderGitHub}},
	"containerImageMustNotUseForbiddenTags":       {Providers: []string{ProviderGitLab, ProviderGitHub}},
	"externalRefsMustNotCollide":                  {Providers: []string{ProviderGitLab, ProviderGitHub}},
	"includesMustBeUpToDate":                      {Providers: []string{ProviderGitLab, ProviderGitHub}},
	"includesMustNotUseForbiddenVersions":         {Providers: []string{ProviderGitLab, ProviderGitHub}},
	"pipelineMustIncludeComponent":                {Providers: []string{ProviderGitLab, ProviderGitHub}},
	"pipelineMustIncludeTemplate":                 {Providers: []string{ProviderGitLab, ProviderGitHub}},
	"pipelineMustNotEnableDebugTrace":             {Providers: []string{ProviderGitLab, ProviderGitHub}},
	"pipelineMustNotExecuteUnverifiedScripts":     {Providers: []string{ProviderGitLab, ProviderGitHub}},
	"pipelineMustNotIncludeHardcodedJobs":         {Providers: []string{ProviderGitLab, ProviderGitHub}},
	"pipelineMustNotOverrideJobVariables":         {Providers: []string{ProviderGitLab, ProviderGitHub}},
	"pipelineMustNotUseDockerInDocker":            {Providers: []string{ProviderGitLab, ProviderGitHub}},
	"pipelineMustNotUseUnsafeVariableExpansion":   {Providers: []string{ProviderGitLab, ProviderGitHub}},
	"securityJobsMustNotBeWeakened":               {Providers: []string{ProviderGitLab, ProviderGitHub}},

	// GitHub-only.
	"actionPinCommentsMustMatchSha":                       {Providers: []string{ProviderGitHub}},
	"actionPinsMustNotBeStale":                            {Providers: []string{ProviderGitHub}},
	"actionRefsMustExistUpstream":                         {Providers: []string{ProviderGitHub}},
	"actionsMustBePinnedByCommitSha":                      {Providers: []string{ProviderGitHub}},
	"actionsMustNotBeArchived":                            {Providers: []string{ProviderGitHub}},
	"actionsMustNotCarryKnownCVEs":                        {Providers: []string{ProviderGitHub}},
	"actionsMustNotDuplicateRunnerBuiltins":               {Providers: []string{ProviderGitHub}},
	"checkoutMustNotPersistCredentials":                   {Providers: []string{ProviderGitHub}},
	"containerCredentialsMustComeFromSecrets":             {Providers: []string{ProviderGitHub}},
	"dependabotEcosystemsMustHaveCooldown":                {Providers: []string{ProviderGitHub}},
	"dependabotMustNotAllowInsecureExternalCodeExecution": {Providers: []string{ProviderGitHub}},
	"deployJobsMustUseEnvironmentGate":                    {Providers: []string{ProviderGitHub}},
	"dockerfilesMustPinBaseImageByDigest":                 {Providers: []string{ProviderGitHub}},
	"githubActionMustComeFromAuthorizedSources":           {Providers: []string{ProviderGitHub}},
	"githubAppTokensMustBeRevokedOnExit":                  {Providers: []string{ProviderGitHub}},
	"publishWorkflowsMustUseOidcTrustedPublishing":        {Providers: []string{ProviderGitHub}},
	"pullRequestTargetMustNotCheckoutHead":                {Providers: []string{ProviderGitHub}},
	"releaseWorkflowsMustNotRestoreUntrustedCache":        {Providers: []string{ProviderGitHub}},
	"releaseWorkflowsMustSignArtefacts":                   {Providers: []string{ProviderGitHub}},
	"repositoriesMustConfigureDependencyUpdates":          {Providers: []string{ProviderGitHub}},
	"repositoriesMustPublishSecurityPolicy":               {Providers: []string{ProviderGitHub}},
	"repositoriesMustRunSAST":                             {Providers: []string{ProviderGitHub}},
	"reusableWorkflowsMustNotInheritSecrets":              {Providers: []string{ProviderGitHub}},
	"workflowConditionsMustBeSound":                       {Providers: []string{ProviderGitHub}},
	"workflowContainsCallsMustBeSound":                    {Providers: []string{ProviderGitHub}},
	"workflowMustNotContainObfuscation":                   {Providers: []string{ProviderGitHub}},
	"workflowMustNotExportEntireGitHubContext":            {Providers: []string{ProviderGitHub}},
	"workflowMustNotExportEntireSecretsContext":           {Providers: []string{ProviderGitHub}},
	"workflowMustNotGrantPermissionsWriteAll":             {Providers: []string{ProviderGitHub}},
	"workflowMustNotIndexSecretsDynamically":              {Providers: []string{ProviderGitHub}},
	"workflowMustNotInjectUserInputInScripts":             {Providers: []string{ProviderGitHub}},
	"workflowMustNotInjectVarsInScripts":                  {Providers: []string{ProviderGitHub}},
	"workflowMustNotReEnableInsecureCommands":             {Providers: []string{ProviderGitHub}},
	"workflowMustNotTrustSpoofableActorChecks":            {Providers: []string{ProviderGitHub}},
	"workflowMustNotUnredactSecretsViaFromJSON":           {Providers: []string{ProviderGitHub}},
	"workflowMustNotUseDangerousTriggers":                 {Providers: []string{ProviderGitHub}},
	"workflowMustNotUseKnownMisfeatures":                  {Providers: []string{ProviderGitHub}},
	"workflowMustNotWriteUntrustedContentToGitHubEnv":     {Providers: []string{ProviderGitHub}},
	"workflowMustIncludeRequiredActions":                  {Providers: []string{ProviderGitHub}},
	"workflowMustPinPackageInstalls":                      {Providers: []string{ProviderGitHub}},
	"workflowsMustDeclareConcurrency":                     {Providers: []string{ProviderGitHub}},
	"workflowsMustDeclarePermissions":                     {Providers: []string{ProviderGitHub}},
	"workflowsMustHaveExplicitName":                       {Providers: []string{ProviderGitHub}},
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
	"pipelineMustNotLeakSecretsInConfig": "secret detection (gitleaks) is no longer part of Plumber — delete this block from .plumber.yaml; see the security advisory https://github.com/getplumber/plumber/security/advisories/GHSA-w2xj-4v44-6rqr and issue https://github.com/getplumber/plumber/issues/310",
}

// IsRemovedControl reports whether the named control existed in an
// earlier release and has been removed, with the user-facing
// explanation as the second return.
func IsRemovedControl(controlName string) (string, bool) {
	msg, ok := removedControls[controlName]
	return msg, ok
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
// As of 2026-05-06 (commit 7f05d81 + Phase 1 follow-up):
//   - GitLab: zero benched controls. All 14 GitLab controls ship.
//   - GitHub: a lot of benched WIP
var benchedControls = map[string]map[string]struct{}{
	ProviderGitLab: {},
	ProviderGitHub: {
		// API-backed action checks (need integration tests).
		"actionPinCommentsMustMatchSha":         {},
		"actionPinsMustNotBeStale":              {},
		"actionsMustNotDuplicateRunnerBuiltins": {},

		// Repo-artifact / setup-side controls (need fixture coverage).
		"checkoutMustNotPersistCredentials":                   {},
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

// ControlMetaFor returns the registered metadata for a control name,
// or the zero value (empty Providers slice) if the name is unknown.
func ControlMetaFor(controlName string) ControlMeta {
	return controlsMeta[controlName]
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

// AllRegisteredControlNames returns every name in the registry. Used
// by tests and by the configuration validator's misplacement check.
func AllRegisteredControlNames() []string {
	out := make([]string, 0, len(controlsMeta))
	for n := range controlsMeta {
		out = append(out, n)
	}
	return out
}
