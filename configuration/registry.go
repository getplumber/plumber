package configuration

import "sort"

// ControlMeta describes a control's static properties: which providers
// it applies to and whether it is currently considered production-
// ready (i.e. NOT benched). Toggle semantics for individual users
// live in .plumber.yaml: this registry only describes the universe
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

	// ID is the control's immutable identifier (CTRL-XXX), the rename-stable
	// key the platform hangs durable state on (#458). Assigned once from the
	// control's lowest registered issue code so ids follow the same numeric
	// blocks as the issues (1xx container images, 2xx variables, ...); frozen
	// afterwards by TestControlIDsMatchGolden. Never renumber an existing
	// control: rename the NAME if wording must change, the id stays.
	ID string

	// Description is the one-sentence, user-facing explanation of what the
	// control verifies: the CLI's own wording, served to the platform and
	// docs so no consumer authors a divergent copy (#458).
	Description string

	// RequiresConfig is authored truth: true if and only if enabling this
	// control with NO further configuration asserts nothing, i.e. the
	// control is inert (the getplumber/plumber#459 shape): a bare
	// `enabled: true` block produces zero findings until the operator also
	// sets its substantive config fields. It is false both for controls
	// that have no configurable surface beyond `enabled` (their logic is
	// self-contained once enabled) and for controls whose substantive
	// fields merely TUNE a check that already asserts something
	// meaningful unconfigured (e.g. a built-in behavioral default, or an
	// exemption/allowlist narrowing an otherwise-active rule).
	//
	// This is a semantic judgment call, not something reflection can
	// derive: it is decided per control by reading the config struct's
	// doc comment in plumberconfig.go and, where that is ambiguous or
	// stale, the control's Rego evaluation code (#458 requiresConfig
	// amendment). TestRequiresConfigImpliesConfigSchema guards that a
	// RequiresConfig control actually has a config schema with a field
	// beyond `enabled` to require.
	//
	// This flag is authoring-time signal only: the runtime scoring of an
	// unconfigured control (not_evaluable vs. a vacuous pass) remains
	// #459's own decision, not this field's.
	RequiresConfig bool
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
		Providers:      []string{ProviderGitLab, ProviderGitHub},
		DisplayName:    "Branch must be protected",
		Category:       CategoryAccessAndAuthorization,
		ID:             "CTRL-501",
		Description:    "Verifies that the analyzed branch is protected and that the protection settings are compliant: direct pushes and force pushes blocked, access levels tight enough, and code owner approval enforced where required.",
		RequiresConfig: true,
	},
	"mergeRequestApprovalRulesMustRequireMinimumApprovals": {
		Providers:      []string{ProviderGitLab},
		DisplayName:    "MR approval rules must require a minimum number of approvals",
		Category:       CategoryAccessAndAuthorization,
		ID:             "CTRL-502",
		Description:    "Verifies that every merge request approval rule covering all protected branches requires at least the configured minimum number of approvals.",
		RequiresConfig: true,
	},
	"mergeRequestApprovalRulesMustCoverAllProtectedBranches": {
		Providers:   []string{ProviderGitLab},
		DisplayName: "MR approval rules must cover all protected branches",
		Category:    CategoryAccessAndAuthorization,
		ID:          "CTRL-504",
		Description: "Verifies that at least one merge request approval rule applies to every protected branch, so none can be merged without a required approval.",
	},
	"mergeRequestApprovalSettingsMustBeCompliant": {
		Providers:      []string{ProviderGitLab},
		DisplayName:    "MR approval settings must be compliant",
		Category:       CategoryAccessAndAuthorization,
		ID:             "CTRL-503",
		Description:    "Verifies that the project's merge request approval settings (author and committer approval, rule overrides, re-authentication, approval reset on new commits) meet the configured policy.",
		RequiresConfig: true,
	},
	"mergeRequestSettingsMustBeCompliant": {
		Providers:      []string{ProviderGitLab},
		DisplayName:    "MR settings must be compliant",
		Category:       CategoryAccessAndAuthorization,
		ID:             "CTRL-506",
		Description:    "Verifies that the project's merge request and merge settings (merge method, squash policy, merge trains, source-branch removal) match the configured policy.",
		RequiresConfig: true,
	},
	"cicdVariablesMustBeProtected": {
		Providers:   []string{ProviderGitLab},
		DisplayName: "CI/CD variables must be protected",
		Category:    CategoryCICDVariables,
		ID:          "CTRL-201",
		Description: "Verifies that CI/CD settings variables are marked protected so they are not exposed to pipelines running on unprotected branches.",
	},
	"cicdVariablesMustBeMasked": {
		Providers:   []string{ProviderGitLab},
		DisplayName: "CI/CD variables must be masked",
		Category:    CategoryCICDVariables,
		ID:          "CTRL-202",
		Description: "Verifies that CI/CD settings variables are masked so their values do not print in job logs.",
	},
	"projectMustHaveSecurityPolicySource": {
		Providers:   []string{ProviderGitLab},
		DisplayName: "Project must have a security policy source",
		Category:    CategorySecuritySource,
		ID:          "CTRL-601",
		Description: "Verifies that the project directly links the expected GitLab security policy project.",
	},
	"containerImageMustComeFromAuthorizedSources": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Container images must come from authorized sources",
		Category:    CategoryContainerImages,
		ID:          "CTRL-101",
		Description: "Verifies that container images referenced in the pipeline are pulled only from an authorized registry.",
	},
	"containerImageMustNotUseForbiddenTags": {
		Providers:      []string{ProviderGitLab, ProviderGitHub},
		DisplayName:    "Container images must not use forbidden tags",
		Category:       CategoryContainerImages,
		ID:             "CTRL-102",
		Description:    "Flags container images referenced by mutable or forbidden tags (such as latest) and, when configured, requires images to be pinned by digest.",
		RequiresConfig: true,
	},
	"externalRefsMustNotCollide": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Includes must not use ambiguous tag/branch refs",
		Category:    CategoryPipelineComposition,
		ID:          "CTRL-402",
		Description: "Flags external CI references pinned to a name that exists upstream as both a tag and a branch, since the ambiguity can silently switch which revision runs.",
	},
	"includesMustBeUpToDate": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Includes must be up to date",
		Category:    CategoryPipelineComposition,
		ID:          "CTRL-403",
		Description: "Verifies that included CI/CD components and templates use the latest available version.",
	},
	"includesMustNotUseForbiddenVersions": {
		Providers:      []string{ProviderGitLab, ProviderGitHub},
		DisplayName:    "Includes must not use forbidden versions",
		Category:       CategoryPipelineComposition,
		ID:             "CTRL-404",
		Description:    "Flags included CI/CD components and templates that use a version forbidden by the configuration, such as a mutable branch reference.",
		RequiresConfig: true,
	},
	"pipelineMustIncludeComponent": {
		Providers:      []string{ProviderGitLab, ProviderGitHub},
		DisplayName:    "Pipeline must include required components",
		Category:       CategoryPipelineComposition,
		ID:             "CTRL-408",
		Description:    "Verifies that every CI/CD component required by the configuration is included in the pipeline and that its job keys are not overridden.",
		RequiresConfig: true,
	},
	"pipelineMustIncludeTemplate": {
		Providers:      []string{ProviderGitLab, ProviderGitHub},
		DisplayName:    "Pipeline must include required templates",
		Category:       CategoryPipelineComposition,
		ID:             "CTRL-405",
		Description:    "Verifies that every CI/CD template required by the configuration is included in the pipeline and that its job keys are not overridden.",
		RequiresConfig: true,
	},
	"pipelineMustNotEnableDebugTrace": {
		Providers:      []string{ProviderGitLab, ProviderGitHub},
		DisplayName:    "Pipeline must not enable debug trace",
		Category:       CategoryCICDVariables,
		ID:             "CTRL-203",
		Description:    "Detects pipelines that enable CI debug tracing, which prints masked variable values into job logs.",
		RequiresConfig: true,
	},
	"pipelineMustNotExecuteUnverifiedScripts": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Pipeline must not execute unverified scripts",
		Category:    CategoryPipelineComposition,
		ID:          "CTRL-411",
		Description: "Detects pipeline jobs that execute a script without integrity verification, such as piping a remote download directly into a shell.",
	},
	"pipelineMustNotIncludeHardcodedJobs": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Pipeline must not include hardcoded jobs",
		Category:    CategoryPipelineComposition,
		ID:          "CTRL-401",
		Description: "Flags pipeline jobs defined directly in the CI configuration instead of sourced from an approved CI/CD component or include.",
	},
	"pipelineMustNotOverrideJobVariables": {
		Providers:      []string{ProviderGitLab, ProviderGitHub},
		DisplayName:    "Pipeline must not override job variables",
		Category:       CategoryCICDVariables,
		ID:             "CTRL-205",
		Description:    "Detects pipeline configuration that redefines a CI/CD variable that should only be set in CI/CD Settings.",
		RequiresConfig: true,
	},
	"pipelineMustNotUseDockerInDocker": {
		Providers:   []string{ProviderGitLab, ProviderGitHub},
		DisplayName: "Pipeline must not use Docker-in-Docker",
		Category:    CategoryPipelineComposition,
		ID:          "CTRL-412",
		Description: "Flags CI/CD jobs that use a Docker-in-Docker service, or that configure it with an insecure, TLS-disabled daemon.",
	},
	"pipelineMustNotUseUnsafeVariableExpansion": {
		Providers:      []string{ProviderGitLab, ProviderGitHub},
		DisplayName:    "Pipeline must not use unsafe variable expansion",
		Category:       CategoryCICDVariables,
		ID:             "CTRL-204",
		Description:    "Detects CI variables expanded in a shell re-interpretation context such as eval or sh -c, where an attacker-controlled value could execute as code.",
		RequiresConfig: true,
	},
	"securityJobsMustNotBeWeakened": {
		Providers:      []string{ProviderGitLab, ProviderGitHub},
		DisplayName:    "Security jobs must not be weakened",
		Category:       CategoryPipelineComposition,
		ID:             "CTRL-410",
		Description:    "Detects security jobs weakened by allow_failure, a rules override, or when: manual, any of which can let a critical scan be skipped.",
		RequiresConfig: true,
	},

	// GitHub-only.
	"actionPinCommentsMustMatchSha": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Action pin comments must match the pinned SHA",
		Category:    CategoryThirdPartyActions,
		ID:          "CTRL-708",
		Description: "Verifies that a `# vX.Y.Z` version comment on a pinned action matches the tag the pinned commit SHA actually corresponds to.",
	},
	"actionPinsMustNotBeStale": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Action pins must not be stale",
		Category:    CategoryThirdPartyActions,
		ID:          "CTRL-709",
		Description: "Flags actions pinned to a commit SHA that predates the repository's most recent upstream release.",
	},
	"actionRefsMustExistUpstream": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Actions must pin commits that exist upstream",
		Category:    CategoryThirdPartyActions,
		ID:          "CTRL-707",
		Description: "Verifies that a pinned action commit SHA actually exists in the action's upstream repository.",
	},
	"actionsMustBePinnedByCommitSha": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Third-party actions must be pinned by commit SHA",
		Category:    CategoryThirdPartyActions,
		ID:          "CTRL-701",
		Description: "Requires third-party GitHub Actions to be pinned to a full commit SHA instead of a mutable tag or branch reference.",
	},
	"actionsMustNotBeArchived": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Actions must not reference archived repositories",
		Category:    CategoryThirdPartyActions,
		ID:          "CTRL-702",
		Description: "Flags actions hosted in a GitHub repository that has been archived, since it no longer receives maintenance or security fixes.",
	},
	"actionsMustNotCarryKnownCVEs": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Actions must not carry known CVEs",
		Category:    CategoryThirdPartyActions,
		ID:          "CTRL-703",
		Description: "Verifies that the pinned version of every third-party action is free of published security advisories in the GitHub Advisory Database.",
	},
	"actionsMustNotDuplicateRunnerBuiltins": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Actions must not duplicate runner builtins",
		Category:    CategoryThirdPartyActions,
		ID:          "CTRL-711",
		Description: "Flags third-party actions that duplicate functionality the GitHub-hosted runner already provides, an unnecessary supply-chain dependency.",
	},
	"actionsMustNotExecuteMutableRemoteCode": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Actions must not execute mutable remote code",
		Category:    CategoryThirdPartyActions,
		ID:          "CTRL-714",
		Description: "Detects third-party actions whose own source fetches and executes code from a mutable ref without verifying it against a checksum, including obfuscated fetch-then-execute patterns.",
	},
	"checkoutMustNotPersistCredentials": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Checkout must not persist credentials",
		Category:    CategoryCICDSecrets,
		ID:          "CTRL-307",
		Description: "Detects checkout steps that persist credentials in .git/config, especially when a later step uploads that path into an artifact.",
	},
	"containerCredentialsMustComeFromSecrets": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Container credentials must come from secrets",
		Category:    CategoryThirdPartyActions,
		ID:          "CTRL-704",
		Description: "Verifies that container registry credentials are referenced from secrets instead of hardcoded as literal values in the workflow.",
	},
	"dependabotEcosystemsMustHaveCooldown": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Dependabot ecosystems must have a cooldown",
		Category:    CategoryRepositoryHygiene,
		ID:          "CTRL-902",
		Description: "Verifies that every Dependabot update ecosystem declares a cooldown window before opening pull requests for newly published versions.",
	},
	"dependabotMustNotAllowInsecureExternalCodeExecution": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Dependabot must not allow insecure external code execution",
		Category:    CategoryRepositoryHygiene,
		ID:          "CTRL-901",
		Description: "Detects Dependabot configuration that re-enables insecure external code execution for an update ecosystem.",
	},
	"deployJobsMustUseEnvironmentGate": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Deploy jobs must use an environment gate",
		Category:    CategoryCICDSecrets,
		ID:          "CTRL-305",
		Description: "Verifies that deploy and release jobs consuming production secrets declare an environment gate.",
	},
	"dockerfilesMustPinBaseImageByDigest": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Dockerfiles must pin base images by digest",
		Category:    CategoryThirdPartyActions,
		ID:          "CTRL-706",
		Description: "Verifies that Dockerfile FROM references pin the base image by SHA256 digest instead of a mutable tag.",
	},
	"githubActionMustComeFromAuthorizedSources": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Actions must come from authorized sources",
		Category:    CategoryThirdPartyActions,
		ID:          "CTRL-713",
		Description: "Verifies that third-party GitHub Actions referenced in workflows come from an authorized owner, org allowlist, or minimum-popularity source.",
	},
	"githubAppTokensMustBeRevokedOnExit": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "GitHub App tokens must be revoked on exit",
		Category:    CategoryCICDSecrets,
		ID:          "CTRL-306",
		Description: "Detects GitHub App installation tokens minted with revocation disabled, which keeps the token alive after the workflow finishes.",
	},
	"publishWorkflowsMustUseOidcTrustedPublishing": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Publish workflows must use OIDC trusted publishing",
		Category:    CategoryPipelineComposition,
		ID:          "CTRL-421",
		Description: "Verifies that publish workflows to PyPI, npm, or Maven Central use OIDC trusted publishing instead of a long-lived static token.",
	},
	"pullRequestTargetMustNotCheckoutHead": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "pull_request_target workflows must not check out the PR head",
		Category:    CategoryWorkflowTriggersAndPermissions,
		ID:          "CTRL-804",
		Description: "Detects pull_request_target workflows that explicitly check out the pull request head, combining access to base-repo secrets with PR-author-controlled code.",
	},
	"releaseWorkflowsMustNotRestoreUntrustedCache": {
		Providers:      []string{ProviderGitHub},
		DisplayName:    "Release workflows must not restore an untrusted cache",
		Category:       CategoryThirdPartyActions,
		ID:             "CTRL-705",
		Description:    "Flags release and publish jobs that restore a build cache whose key is not scoped to the release ref, closing the cross-branch cache poisoning vector.",
		RequiresConfig: true,
	},
	"releaseWorkflowsMustSignArtefacts": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Release workflows must sign artefacts",
		Category:    CategoryThirdPartyActions,
		ID:          "CTRL-712",
		Description: "Verifies that release and publish workflows sign the artefacts they produce.",
	},
	"repositoriesMustConfigureDependencyUpdates": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Repositories must configure dependency updates",
		Category:    CategoryRepositoryHygiene,
		ID:          "CTRL-903",
		Description: "Verifies that repositories with CI/CD workflows configure a dependency update tool such as Dependabot or Renovate.",
	},
	"repositoriesMustPublishSecurityPolicy": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Repositories must publish a security policy",
		Category:    CategoryRepositoryHygiene,
		ID:          "CTRL-905",
		Description: "Verifies that repositories with CI/CD workflows publish a SECURITY.md vulnerability disclosure policy.",
	},
	"repositoriesMustRunSAST": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Repositories must run SAST",
		Category:    CategoryRepositoryHygiene,
		ID:          "CTRL-904",
		Description: "Verifies that repositories with CI/CD workflows run a recognized static analysis (SAST) scanner.",
	},
	"reusableWorkflowsMustNotInheritSecrets": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Reusable workflows must not inherit secrets",
		Category:    CategoryCICDSecrets,
		ID:          "CTRL-302",
		Description: "Detects reusable workflow calls made with secrets: inherit, which forwards every secret visible to the caller regardless of what the reusable workflow needs.",
	},
	"workflowConditionsMustBeSound": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflow conditions must be sound",
		Category:    CategoryCICDVariables,
		ID:          "CTRL-211",
		Description: "Detects workflow if: conditions that are logically unsound, such as a tautology, a contradiction, or a bare boolean not wrapped in template braces.",
	},
	"workflowContainsCallsMustBeSound": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflow contains() calls must be sound",
		Category:    CategoryCICDVariables,
		ID:          "CTRL-212",
		Description: "Detects contains() expressions called with arguments in the wrong order or of incompatible types, which makes the intended check silently never match.",
	},
	"workflowMustNotContainObfuscation": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not contain obfuscation",
		Category:    CategoryPipelineComposition,
		ID:          "CTRL-420",
		Description: "Detects workflow scripts and expressions that carry invisible or homoglyph characters used to hide what actually executes.",
	},
	"workflowMustNotExportEntireGitHubContext": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not export the entire GitHub context",
		Category:    CategoryCICDVariables,
		ID:          "CTRL-213",
		Description: "Flags workflow steps that serialize the entire github context with toJson, exposing every user-controllable field to whatever consumes the output.",
	},
	"workflowMustNotExportEntireSecretsContext": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not expose all secrets at once",
		Category:    CategoryCICDSecrets,
		ID:          "CTRL-309",
		Description: "Flags workflow steps that serialize the entire secrets context with toJson, exposing every secret the job can access.",
	},
	"workflowMustNotGrantPermissionsWriteAll": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflow must not grant write-all permissions",
		Category:    CategoryWorkflowTriggersAndPermissions,
		ID:          "CTRL-803",
		Description: "Detects workflow permissions blocks that grant write-all, giving the GITHUB_TOKEN write access to every API scope.",
	},
	"workflowMustNotIndexSecretsDynamically": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not index secrets dynamically",
		Category:    CategoryCICDSecrets,
		ID:          "CTRL-308",
		Description: "Detects workflows that read a secret through a dynamic index instead of naming it directly.",
	},
	"workflowMustNotInjectUserInputInScripts": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not inject user input in scripts",
		Category:    CategoryCICDVariables,
		ID:          "CTRL-207",
		Description: "Detects workflow run scripts that inline user-controlled template expressions directly, letting attacker-controlled values break out and execute commands.",
	},
	"workflowMustNotInjectVarsInScripts": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not inject vars in scripts",
		Category:    CategoryCICDVariables,
		ID:          "CTRL-215",
		Description: "Detects workflow run scripts that inline vars or inputs template expressions directly instead of binding them through an env variable first.",
	},
	"workflowMustNotReEnableInsecureCommands": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not re-enable insecure commands",
		Category:    CategoryCICDVariables,
		ID:          "CTRL-208",
		Description: "Detects workflows that re-enable the deprecated set-env and add-path workflow commands via ACTIONS_ALLOW_UNSECURE_COMMANDS.",
	},
	"workflowMustNotTrustSpoofableActorChecks": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not trust spoofable actor checks",
		Category:    CategoryCICDVariables,
		ID:          "CTRL-210",
		Description: "Detects workflows that gate behaviour on a spoofable actor identity check such as github.actor instead of a cryptographically verified signal.",
	},
	"workflowMustNotUnredactSecretsViaFromJSON": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not unredact secrets via fromJSON",
		Category:    CategoryCICDSecrets,
		ID:          "CTRL-303",
		Description: "Detects secrets dereferenced via fromJSON, which bypasses GitHub's log redaction for the resulting sub-fields.",
	},
	"workflowMustNotUseDangerousTriggers": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not use dangerous triggers",
		Category:    CategoryWorkflowTriggersAndPermissions,
		ID:          "CTRL-802",
		Description: "Detects workflows reachable via a trigger that runs with base-repository secrets while being influenceable by an unprivileged caller, combined with checking out fork-controlled code.",
	},
	"workflowMustNotUseKnownMisfeatures": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not use known misfeatures",
		Category:    CategoryPipelineComposition,
		ID:          "CTRL-419",
		Description: "Detects workflows that use a known-harmful pattern such as legacy Windows shells, inline network installs, or uploading the checkout directory as an artifact.",
	},
	"workflowMustNotWriteUntrustedContentToGitHubEnv": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must not write untrusted content to $GITHUB_ENV",
		Category:    CategoryCICDVariables,
		ID:          "CTRL-209",
		Description: "Detects workflows that write user-controlled content to GITHUB_ENV or GITHUB_PATH, letting an attacker override variables or hijack later steps.",
	},
	"workflowMustIncludeRequiredActions": {
		Providers:      []string{ProviderGitHub},
		DisplayName:    "Workflows must include required actions",
		Category:       CategoryPipelineComposition,
		ID:             "CTRL-417",
		Description:    "Verifies that every action or reusable workflow declared as required in the configuration is actually referenced by the project's workflows.",
		RequiresConfig: true,
	},
	"workflowMustPinPackageInstalls": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must pin package installs",
		Category:    CategoryCICDVariables,
		ID:          "CTRL-214",
		Description: "Detects package installs that neither pin a version nor use a lockfile, so every run resolves whatever is latest at execution time.",
	},
	"workflowsMustDeclareConcurrency": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must declare concurrency",
		Category:    CategoryPipelineComposition,
		ID:          "CTRL-418",
		Description: "Verifies that workflows declare a concurrency block so concurrent runs on the same ref do not race on caches, artifacts, and external state.",
	},
	"workflowsMustDeclarePermissions": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must declare permissions",
		Category:    CategoryWorkflowTriggersAndPermissions,
		ID:          "CTRL-801",
		Description: "Verifies that workflows declare an explicit permissions block instead of falling back to the repository's default GITHUB_TOKEN permissions.",
	},
	"workflowsMustHaveExplicitName": {
		Providers:   []string{ProviderGitHub},
		DisplayName: "Workflows must have an explicit name",
		Category:    CategoryPipelineComposition,
		ID:          "CTRL-422",
		Description: "Verifies that every workflow declares a top-level name instead of falling back to its file path in the Actions UI and status checks.",
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
	// https://github.com/getplumber/plumber/issues/310, Plumber no
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
// output, or any other downstream consumer, regardless of what the
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
		// findings on GitLab: they're only benched on GitHub.
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
// entirely, turning a 30-60s scan into a sub-second one on a
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
