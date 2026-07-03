package configuration

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"

	defaultconfig "github.com/getplumber/plumber/defaultConfig"
	"github.com/getplumber/plumber/utils"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// ErrConfigNotFound is returned (wrapped) by LoadPlumberConfig when the config
// file does not exist. Callers that fall back to the embedded default on a
// missing file test for it with errors.Is, rather than substring-matching the
// error text, so a reworded message can never silently break the fallback.
var ErrConfigNotFound = errors.New("config file not found")

// maxConfigFileBytes bounds a .plumber.yaml read. The config is read from the
// analyzed repository, so its size is not trusted.
const maxConfigFileBytes = 2 << 20 // 2 MiB

// validControlSchema maps each known control name to its valid sub-keys.
// When adding a new control, add its entry here to enable validation.
var validControlSchema = map[string][]string{
	"containerImageMustNotUseForbiddenTags": {
		"enabled", "tags", "containerImagesMustBePinnedByDigest",
	},
	"containerImageMustComeFromAuthorizedSources": {
		"enabled", "trustedUrls", "trustDockerHubOfficialImages", "includePlumberDefaults",
	},
	"branchMustBeProtected": {
		"enabled", "namePatterns", "defaultMustBeProtected",
		"allowForcePush", "codeOwnerApprovalRequired",
		"minMergeAccessLevel", "minPushAccessLevel",
	},
	"mergeRequestApprovalRulesMustRequireMinimumApprovals": {
		"enabled", "minimumRequiredApprovals",
	},
	"mergeRequestApprovalRulesMustCoverAllProtectedBranches": {
		"enabled",
	},
	"mergeRequestApprovalSettingsMustBeCompliant": {
		"enabled", "preventApprovalByAuthor", "preventApprovalsByCommitters",
		"preventEditingApprovalRulesInMR", "requireReAuthToApprove",
		"behaviorWhenCommitIsAdded",
	},
	"mergeRequestSettingsMustBeCompliant": {
		"enabled", "mergeMethod", "squashOption", "mergePipelinesEnabled",
		"mergeTrainsEnabled", "allowMergeOnSkippedPipeline",
		"resolveOutdatedDiffDiscussions", "printingMergeRequestLinkEnabled",
		"removeSourceBranchAfterMerge",
	},
	"cicdVariablesMustBeProtected": {
		"enabled",
	},
	"cicdVariablesMustBeMasked": {
		"enabled",
	},
	"projectMustHaveSecurityPolicySource": {
		"enabled", "expectedProjectId", "expectedProjectPath",
	},
	"pipelineMustNotIncludeHardcodedJobs": {
		"enabled",
	},
	"externalRefsMustNotCollide": {
		"enabled",
	},
	"includesMustBeUpToDate": {
		"enabled",
	},
	"includesMustNotUseForbiddenVersions": {
		"enabled", "forbiddenVersions", "defaultBranchIsForbiddenVersion",
	},
	"pipelineMustIncludeComponent": {
		"enabled", "required", "requiredGroups",
	},
	"pipelineMustIncludeTemplate": {
		"enabled", "required", "requiredGroups",
	},
	"pipelineMustNotEnableDebugTrace": {
		"enabled", "forbiddenVariables",
	},
	"pipelineMustNotUseUnsafeVariableExpansion": {
		"enabled", "dangerousVariables", "allowedPatterns",
	},
	"securityJobsMustNotBeWeakened": {
		"enabled", "securityJobPatterns",
		"allowFailureMustBeFalse", "rulesMustNotBeRedefined", "whenMustNotBeManual",
	},
	"pipelineMustNotExecuteUnverifiedScripts": {
		"enabled", "trustedUrls",
	},
	"pipelineMustNotOverrideJobVariables": {
		"enabled", "variables",
	},
	"pipelineMustNotUseDockerInDocker": {
		"enabled", "detectInsecureDaemon",
	},
	"actionsMustBePinnedByCommitSha": {
		"enabled", "trustedOwners",
	},
	"githubActionMustComeFromAuthorizedSources": {
		"enabled", "trustGithubOfficialActions", "trustSameOrgActions", "minimumStars", "trustedGithubActions", "includePlumberDefaults",
	},
	"workflowMustNotInjectUserInputInScripts": {
		"enabled",
	},
	"workflowMustNotWriteUntrustedContentToGitHubEnv": {
		"enabled",
	},
	"workflowMustNotUseDangerousTriggers": {
		"enabled",
	},
	"pullRequestTargetMustNotCheckoutHead": {
		"enabled",
	},
	"checkoutMustNotPersistCredentials": {
		"enabled",
	},
	"workflowsMustDeclarePermissions": {
		"enabled",
	},
	"reusableWorkflowsMustNotInheritSecrets": {
		"enabled",
	},
	"workflowMustNotExportEntireSecretsContext": {
		"enabled",
	},
	"workflowMustNotGrantPermissionsWriteAll": {
		"enabled",
	},
	"actionsMustNotBeArchived": {
		"enabled",
	},
	"actionRefsMustExistUpstream": {
		"enabled",
	},
	"actionsMustNotCarryKnownCVEs": {
		"enabled",
	},
	"actionsMustNotExecuteMutableRemoteCode": {
		"enabled",
	},
	"releaseWorkflowsMustNotRestoreUntrustedCache": {
		"enabled", "publishActions", "cacheActions", "publishScriptPatterns", "publishScriptExcludePatterns", "allowedJobs",
	},
	"workflowMustIncludeRequiredActions": {
		"enabled", "required", "requiredGroups",
	},
}

// validControlKeys returns the list of known control names.
func validControlNames() []string {
	keys := make([]string, 0, len(validControlSchema))
	for k := range validControlSchema {
		keys = append(keys, k)
	}
	return keys
}

// ValidControlNames returns all known control names from the configuration schema.
func ValidControlNames() []string {
	names := validControlNames()
	sort.Strings(names)
	return names
}

// ValidFlatKeys returns every valid flattened key path recognized by the
// schema, e.g. "controls.branchMustBeProtected.enabled". This includes
// keys that may be commented out in the default config file.
func ValidFlatKeys() map[string]struct{} {
	keys := make(map[string]struct{})
	for control, subKeys := range validControlSchema {
		for _, sub := range subKeys {
			keys["controls."+control+"."+sub] = struct{}{}
		}
	}
	return keys
}

// PlumberConfig represents the .plumber.yaml configuration file structure.
//
// Schema versions:
//   - "2.0" — current per-provider schema (gitlab.controls, github.controls).
//   - "1.0" — legacy flat schema (top-level controls). Auto-converted in
//     memory at load time with a deprecation warning. Run
//     `plumber config migrate` to upgrade the file on disk.
//
// The legacy v1 fields (Controls) remain on the struct so the loader can
// detect a v1 file, parse it, and convert it via convertV1ToV2. After a
// v2 load — or after conversion — Controls is the zero value and
// downstream code reads from GitLab.Controls / GitHub.Controls.
type PlumberConfig struct {
	// Version of the config file format.
	// "2.0" = current per-provider schema. "1.0" = legacy flat schema.
	// Missing version is tolerated and treated as legacy.
	Version string `yaml:"version,omitempty"`

	// Extends selects overlay mode. The only supported value is
	// "plumber:default": the file is then a sparse overlay merged onto
	// the embedded baseline. Absent (the default) keeps legacy full
	// replace behavior. See configuration/resolve.go.
	Extends string `yaml:"extends,omitempty"`

	// GitLab provider section (v2 schema). Holds GitLab-specific auth,
	// the enabledControls allowlist, and the per-control configuration map.
	GitLab *ProviderConfig `yaml:"gitlab,omitempty"`

	// GitHub provider section (v2 schema). Same shape as GitLab.
	GitHub *ProviderConfig `yaml:"github,omitempty"`

	// Controls configuration (legacy v1 schema, top-level).
	// After a v2 load this is the zero value; after a v1 load convertV1ToV2
	// moves these into GitLab.Controls and clears this field.
	Controls ControlsConfig `yaml:"controls,omitempty"`

	// Raw is the verbatim text of the config that produced this run, captured
	// at load. The self-describing `plumberConfig` block in the JSON report
	// parses it into a structured object (the verbatim text is never shipped).
	// Not serialized into the config itself.
	Raw string `yaml:"-"`
	// Source is the path the config was loaded from, or "default" when no
	// file was present and the embedded default was used. Not serialized.
	Source string `yaml:"-"`
}

// DefaultScoreEndpoint is the built-in hosted Plumber Score badge service.
// A self-hosted score service is selected with the --score-endpoint flag /
// PLUMBER_ANALYZE_SCORE_ENDPOINT env (surfaced by the CI integration input),
// not from the config file; the OIDC audience the CLI mints then follows that
// value.
const DefaultScoreEndpoint = "https://score.getplumber.io"

// ProviderConfig is the per-provider configuration block introduced in
// schema v2. One instance per provider section in .plumber.yaml.
//
// Toggle semantics mirror the GitLab side: a control absent from
// `controls:` is treated as enabled at the filter level; a control
// present with `enabled: false` is dropped. The dev-side `bench` set
// in control/registry.go suppresses non-production controls
// regardless of YAML state — see that file for how to promote a
// benched control out of bench.
type ProviderConfig struct {
	// Auth holds provider-specific authentication knobs. Optional.
	// Today only GitHub uses this (RequireAuth). Reserved for future
	// per-provider auth options on GitLab if needed.
	Auth *AuthConfig `yaml:"auth,omitempty"`

	// Controls holds per-control configuration. Same struct types as
	// the legacy top-level ControlsConfig — only the YAML location and
	// the values differ between providers.
	Controls ControlsConfig `yaml:"controls,omitempty"`
}

// AuthConfig holds per-provider authentication knobs. Currently only
// GitHub uses this; the type is provider-agnostic so GitLab can adopt
// it later without a schema change.
type AuthConfig struct {
	// RequireAuth, when true, makes the analyze command exit non-zero
	// if no provider credentials are available. Default false on GitHub
	// (soft-degrade with visible banner, matching `gh` CLI ergonomics).
	// Has no effect on GitLab today (GitLab already hard-fails without
	// a token via CLI flag / env).
	RequireAuth *bool `yaml:"requireAuth,omitempty"`
}

// IsRequireAuth returns whether requireAuth is set to true.
// Defaults to false when the section, the field, or the auth block is nil.
func (a *AuthConfig) IsRequireAuth() bool {
	if a == nil || a.RequireAuth == nil {
		return false
	}
	return *a.RequireAuth
}

// ControlsConfig holds configuration for all controls
type ControlsConfig struct {
	// ContainerImageMustNotUseForbiddenTags control configuration
	ContainerImageMustNotUseForbiddenTags *ImageForbiddenTagsControlConfig `yaml:"containerImageMustNotUseForbiddenTags,omitempty"`

	// ContainerImageMustComeFromAuthorizedSources control configuration
	ContainerImageMustComeFromAuthorizedSources *ImageAuthorizedSourcesControlConfig `yaml:"containerImageMustComeFromAuthorizedSources,omitempty"`

	// BranchMustBeProtected control configuration
	BranchMustBeProtected *BranchProtectionControlConfig `yaml:"branchMustBeProtected,omitempty"`

	// MergeRequestApprovalRulesMustRequireMinimumApprovals control
	// configuration (GitLab only). Flags approval rules covering all
	// protected branches that require fewer approvals than the configured
	// minimum (ISSUE-502).
	MergeRequestApprovalRulesMustRequireMinimumApprovals *MRApprovalRulesMinApprovalsControlConfig `yaml:"mergeRequestApprovalRulesMustRequireMinimumApprovals,omitempty"`

	// MergeRequestApprovalRulesMustCoverAllProtectedBranches control
	// configuration (GitLab only). Flags a project where no approval rule
	// applies to all protected branches (ISSUE-504). Config-free beyond
	// `enabled`.
	MergeRequestApprovalRulesMustCoverAllProtectedBranches *EnabledOnlyControlConfig `yaml:"mergeRequestApprovalRulesMustCoverAllProtectedBranches,omitempty"`

	// CicdVariablesMustBeProtected control configuration (GitLab only).
	// Flags project CI/CD settings variables that are not marked
	// protected, so they are exposed to pipelines running on unprotected
	// branches (ISSUE-201). Config-free; toggle via `enabled`.
	CicdVariablesMustBeProtected *EnabledOnlyControlConfig `yaml:"cicdVariablesMustBeProtected,omitempty"`

	// CicdVariablesMustBeMasked control configuration (GitLab only).
	// Flags project CI/CD settings variables that are not masked, so
	// their values print verbatim in every job log a project member can
	// read (ISSUE-202). Config-free; toggle via `enabled`.
	CicdVariablesMustBeMasked *EnabledOnlyControlConfig `yaml:"cicdVariablesMustBeMasked,omitempty"`

	// MergeRequestApprovalSettingsMustBeCompliant control configuration
	// (GitLab only). Checks the project's merge-request approval settings
	// against per-setting optional expectations (ISSUE-503).
	MergeRequestApprovalSettingsMustBeCompliant *MRApprovalSettingsControlConfig `yaml:"mergeRequestApprovalSettingsMustBeCompliant,omitempty"`

	// MergeRequestSettingsMustBeCompliant control configuration (GitLab only).
	// Checks the project's merge-request/merge settings (merge method, squash,
	// merge trains, source-branch removal, etc.) against per-setting optional
	// expectations for exact equality (ISSUE-506).
	MergeRequestSettingsMustBeCompliant *MRSettingsControlConfig `yaml:"mergeRequestSettingsMustBeCompliant,omitempty"`

	// ProjectMustHaveSecurityPolicySource control configuration (GitLab only).
	// Requires the project to link the expected GitLab security policy project
	// (ISSUE-601). Requires GitLab Ultimate.
	ProjectMustHaveSecurityPolicySource *SecurityPolicyControlConfig `yaml:"projectMustHaveSecurityPolicySource,omitempty"`

	// PipelineMustNotIncludeHardcodedJobs control configuration
	PipelineMustNotIncludeHardcodedJobs *HardcodedJobsControlConfig `yaml:"pipelineMustNotIncludeHardcodedJobs,omitempty"`

	// ExternalRefsMustNotCollide control configuration (GitLab + GitHub).
	// Flags external CI references whose symbolic ref resolves upstream as
	// BOTH a tag and a branch (ref-confusion, ISSUE-402): GitHub `uses:`
	// action refs and GitLab `include:` project `ref:` / component
	// `@version` refs. Driven by a per-ref tag+branch API probe.
	// Config-free; toggle via `enabled`.
	ExternalRefsMustNotCollide *EnabledOnlyControlConfig `yaml:"externalRefsMustNotCollide,omitempty"`

	// IncludesMustBeUpToDate control configuration
	IncludesMustBeUpToDate *IncludesUpToDateControlConfig `yaml:"includesMustBeUpToDate,omitempty"`

	// IncludesMustNotUseForbiddenVersions control configuration
	IncludesMustNotUseForbiddenVersions *IncludesForbiddenVersionsControlConfig `yaml:"includesMustNotUseForbiddenVersions,omitempty"`

	// PipelineMustIncludeComponent control configuration
	PipelineMustIncludeComponent *RequiredComponentsControlConfig `yaml:"pipelineMustIncludeComponent,omitempty"`

	// PipelineMustIncludeTemplate control configuration
	PipelineMustIncludeTemplate *RequiredTemplatesControlConfig `yaml:"pipelineMustIncludeTemplate,omitempty"`

	// PipelineMustNotEnableDebugTrace control configuration
	PipelineMustNotEnableDebugTrace *DebugTraceControlConfig `yaml:"pipelineMustNotEnableDebugTrace,omitempty"`

	// PipelineMustNotUseUnsafeVariableExpansion control configuration
	PipelineMustNotUseUnsafeVariableExpansion *VariableInjectionControlConfig `yaml:"pipelineMustNotUseUnsafeVariableExpansion,omitempty"`

	// SecurityJobsMustNotBeWeakened control configuration
	SecurityJobsMustNotBeWeakened *SecurityJobsWeakenedControlConfig `yaml:"securityJobsMustNotBeWeakened,omitempty"`

	// PipelineMustNotExecuteUnverifiedScripts control configuration
	PipelineMustNotExecuteUnverifiedScripts *UnverifiedScriptsControlConfig `yaml:"pipelineMustNotExecuteUnverifiedScripts,omitempty"`

	// PipelineMustNotOverrideJobVariables control configuration
	PipelineMustNotOverrideJobVariables *JobVariablesOverrideControlConfig `yaml:"pipelineMustNotOverrideJobVariables,omitempty"`

	// PipelineMustNotUseDockerInDocker control configuration
	PipelineMustNotUseDockerInDocker *DockerInDockerControlConfig `yaml:"pipelineMustNotUseDockerInDocker,omitempty"`

	// ActionsMustBePinnedByCommitSha control configuration (GitHub Actions only)
	ActionsMustBePinnedByCommitSha *ActionsPinnedByShaControlConfig `yaml:"actionsMustBePinnedByCommitSha,omitempty"`

	// GithubActionMustComeFromAuthorizedSources control configuration
	// (GitHub Actions only). Restricts which `uses:` action sources are
	// allowed: GitHub-official actions, an org allowlist (exact or
	// owner/* wildcard), and an optional minimum-stars trust floor.
	GithubActionMustComeFromAuthorizedSources *ActionAuthorizedSourcesControlConfig `yaml:"githubActionMustComeFromAuthorizedSources,omitempty"`

	// WorkflowMustNotInjectUserInputInScripts control configuration (GitHub Actions only).
	// Config-free; toggle via `enabled`.
	WorkflowMustNotInjectUserInputInScripts *EnabledOnlyControlConfig `yaml:"workflowMustNotInjectUserInputInScripts,omitempty"`

	// WorkflowMustNotWriteUntrustedContentToGitHubEnv control configuration (GitHub Actions only).
	// Config-free; toggle via `enabled`.
	WorkflowMustNotWriteUntrustedContentToGitHubEnv *EnabledOnlyControlConfig `yaml:"workflowMustNotWriteUntrustedContentToGitHubEnv,omitempty"`

	// WorkflowMustNotUseDangerousTriggers control configuration (GitHub Actions only).
	// Config-free; toggle via `enabled`.
	WorkflowMustNotUseDangerousTriggers *EnabledOnlyControlConfig `yaml:"workflowMustNotUseDangerousTriggers,omitempty"`

	// PullRequestTargetMustNotCheckoutHead control configuration (GitHub
	// Actions only). Flags a workflow triggered by `pull_request_target`
	// that checks out the PR head ref, putting base-repo secrets and
	// fork-controlled code in the same run (tj-actions / CVE-2025-30066).
	// Config-free; toggle via `enabled`.
	PullRequestTargetMustNotCheckoutHead *EnabledOnlyControlConfig `yaml:"pullRequestTargetMustNotCheckoutHead,omitempty"`

	// CheckoutMustNotPersistCredentials control configuration (GitHub
	// Actions only). Flags an `actions/checkout` step that omits
	// `persist-credentials: false`, leaving the GITHUB_TOKEN in
	// `.git/config` where a later step can exfiltrate it.
	// Config-free; toggle via `enabled`.
	CheckoutMustNotPersistCredentials *EnabledOnlyControlConfig `yaml:"checkoutMustNotPersistCredentials,omitempty"`

	// WorkflowsMustDeclarePermissions control configuration (GitHub Actions only).
	// Config-free; toggle via `enabled`.
	WorkflowsMustDeclarePermissions *EnabledOnlyControlConfig `yaml:"workflowsMustDeclarePermissions,omitempty"`

	// ReusableWorkflowsMustNotInheritSecrets control configuration (GitHub Actions only).
	// Config-free; toggle via `enabled`.
	ReusableWorkflowsMustNotInheritSecrets *EnabledOnlyControlConfig `yaml:"reusableWorkflowsMustNotInheritSecrets,omitempty"`

	// WorkflowMustNotExportEntireSecretsContext control configuration (GitHub Actions only).
	// Flags a job that serialises the whole `secrets` context via toJson(secrets)
	// into a run script, env binding, or action `with:` input. Config-free; toggle
	// via `enabled`.
	WorkflowMustNotExportEntireSecretsContext *EnabledOnlyControlConfig `yaml:"workflowMustNotExportEntireSecretsContext,omitempty"`

	// WorkflowMustNotGrantPermissionsWriteAll control configuration (GitHub
	// Actions only). Flags workflows or jobs whose effective `permissions:`
	// block is the literal `write-all` shortcut, which grants every scope
	// (contents, packages, deployments, …) write access on GITHUB_TOKEN.
	// Stricter scope-level audits (per-scope write grants) are out of scope
	// here; they get their own rule later. Config-free; toggle via `enabled`.
	WorkflowMustNotGrantPermissionsWriteAll *EnabledOnlyControlConfig `yaml:"workflowMustNotGrantPermissionsWriteAll,omitempty"`

	// ActionsMustNotBeArchived control configuration (GitHub Actions only).
	// Flags `uses: owner/repo@ref` references whose upstream repository is
	// archived on GitHub. Driven by per-action API metadata enriched at
	// collect time. Config-free; toggle via `enabled`.
	ActionsMustNotBeArchived *EnabledOnlyControlConfig `yaml:"actionsMustNotBeArchived,omitempty"`

	// ActionRefsMustExistUpstream control configuration (GitHub Actions
	// only). Flags `uses: owner/repo@<sha>` references pinned to a 40-char
	// commit SHA that the upstream repository confirms does not exist — a
	// typo or an impostor-commit attack. Fires only on a definitive 404
	// from a readable repo; a SHA that could not be verified stays silent.
	// Driven by per-action API metadata enriched at collect time.
	// Config-free; toggle via `enabled`.
	ActionRefsMustExistUpstream *EnabledOnlyControlConfig `yaml:"actionRefsMustExistUpstream,omitempty"`

	// ActionsMustNotCarryKnownCVEs control configuration (GitHub Actions
	// only). Flags `uses: owner/repo@ref` references whose upstream
	// repository carries at least one published advisory in GitHub's
	// Advisory Database under the `actions` ecosystem. Driven by per-
	// action API metadata enriched at collect time. Config-free; toggle
	// via `enabled`.
	ActionsMustNotCarryKnownCVEs *EnabledOnlyControlConfig `yaml:"actionsMustNotCarryKnownCVEs,omitempty"`

	// ActionsMustNotExecuteMutableRemoteCode control configuration (GitHub
	// Actions only). Flags a third-party action whose own source fetches
	// and executes a script from a moving ref at runtime, so a SHA pin on
	// the action does not make its execution immutable. Driven by the
	// collector's per-action source analysis. Config-free; toggle via
	// `enabled`.
	ActionsMustNotExecuteMutableRemoteCode *EnabledOnlyControlConfig `yaml:"actionsMustNotExecuteMutableRemoteCode,omitempty"`

	// ReleaseWorkflowsMustNotRestoreUntrustedCache control configuration (GitHub
	// Actions only). Flags a release/publish job that restores a build cache
	// whose key is not scoped to the release ref, so a PR-populated cache can be
	// injected into the published output. Config-free; toggle via `enabled`.
	ReleaseWorkflowsMustNotRestoreUntrustedCache *CachePoisoningControlConfig `yaml:"releaseWorkflowsMustNotRestoreUntrustedCache,omitempty"`

	// WorkflowMustIncludeRequiredActions control configuration (GitHub
	// Actions only). The GitHub counterpart of
	// PipelineMustIncludeComponent / PipelineMustIncludeTemplate on
	// the GitLab side: assert that workflows reference a configured
	// set of required actions or reusable workflows. Matching is by
	// `owner/repo[/path]` prefix and ref-agnostic, so
	// `org/sast-scan` matches `uses: org/sast-scan@v2`,
	// `uses: org/sast-scan@abc123`, and `uses: org/sast-scan/sub@v1`.
	WorkflowMustIncludeRequiredActions *RequiredActionsControlConfig `yaml:"workflowMustIncludeRequiredActions,omitempty"`
}

// EnabledOnlyControlConfig is the shape used for controls that have no
// configurable behaviour beyond on/off. The Rego rule for these controls
// reads no `input.config.<name>` keys; toggling enabled to false simply
// drops their findings via FilterFindingsByEnabledControls.
type EnabledOnlyControlConfig struct {
	Enabled *bool `yaml:"enabled,omitempty"`
}

// SecurityPolicyControlConfig configures the GitLab security-policy-project
// linkage check (ISSUE-601). GitLab-only, requires Ultimate. When
// ExpectedProjectId is set, the linked policy project must be exactly that
// project. When it is unset, any linked policy project passes and the control
// fails only when none is linked.
type SecurityPolicyControlConfig struct {
	// Enabled controls whether this check runs.
	Enabled *bool `yaml:"enabled,omitempty"`

	// ExpectedProjectId is the numeric GitLab project ID the security policy
	// project must match. Unset => require only that some policy project is
	// linked.
	ExpectedProjectId *int `yaml:"expectedProjectId,omitempty"`

	// ExpectedProjectPath is the full path (namespace/project) the linked
	// security policy project must match — a human-friendly alternative to the
	// numeric ID, compared case-insensitively. Ignored when ExpectedProjectId is
	// also set (the ID is authoritative). Unset (and no ID) => require only that
	// some policy project is linked.
	ExpectedProjectPath *string `yaml:"expectedProjectPath,omitempty"`
}

// IsEnabled reports whether the control is enabled. Returns false when the
// wrapper or the field is nil — same convention as every other IsEnabled().
func (c *SecurityPolicyControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// IsEnabled reports whether the control is enabled. Returns false when
// the wrapper or the field is nil — same convention as every other
// IsEnabled() in this package.
func (c *EnabledOnlyControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// ActionsPinnedByShaControlConfig configures the GitHub Actions supply-
// chain pinning check (ISSUE-701). Only meaningful on GitHub workflows.
type ActionsPinnedByShaControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// TrustedOwners lists action-owner prefixes that are exempt from the
	// pin-by-SHA requirement. Only owners inside the workflow's existing
	// trust boundary should be listed here — "actions" and "github"
	// cover the first-party GitHub-owned actions the runtime trusts
	// implicitly. Adding a third-party owner here re-opens the exact
	// supply-chain risk the check exists to close.
	TrustedOwners []string `yaml:"trustedOwners,omitempty"`
}

// IsEnabled returns whether the control is enabled
func (c *ActionsPinnedByShaControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// CachePoisoningControlConfig configures the release cache-poisoning
// check (ISSUE-705). The action and script INVENTORIES are configurable
// so an org can add its own publish actions, cache actions, or publish
// commands without a plumber release. The built-in cache SEMANTICS
// (which setup-* actions cache by default vs on opt-in, and the
// github.ref* scope tokens) stay in code — that is GitHub behaviour, not
// org policy.
type CachePoisoningControlConfig struct {
	// Enabled controls whether this check runs.
	Enabled *bool `yaml:"enabled,omitempty"`

	// PublishActions are `uses:` owner/repo prefixes that mark a job as
	// release intent (running one restores into a published build).
	PublishActions []string `yaml:"publishActions,omitempty"`

	// CacheActions is the full inventory of cache-restoring actions with
	// their per-action semantics. The rego is a pure engine over this
	// list — nothing about which actions cache (or how) is hardcoded.
	CacheActions []CacheActionSpec `yaml:"cacheActions,omitempty"`

	// PublishScriptPatterns are regexes matched against `run:` scripts to
	// mark a job as release intent (e.g. `cargo publish`).
	PublishScriptPatterns []string `yaml:"publishScriptPatterns,omitempty"`

	// PublishScriptExcludePatterns are regexes that veto a
	// PublishScriptPatterns match on the same `run:` block —
	// verification-only forms that never publish (e.g.
	// `npm publish --dry-run`, gradle `publishToMavenLocal`).
	PublishScriptExcludePatterns []string `yaml:"publishScriptExcludePatterns,omitempty"`

	// AllowedJobs are glob patterns matched against the namespaced job
	// name (`<workflow>/<job>`). A job that matches is exempt from this
	// control — the escape hatch for reviewed/accepted release jobs.
	AllowedJobs []string `yaml:"allowedJobs,omitempty"`
}

// CacheActionSpec describes one cache-restoring action and when it
// actually restores a cache. Mode is "always" (restores whenever
// present), "default" (restores unless DisableInput holds DisableValue),
// or "opt-in" (restores only when EnableInput names a manager).
type CacheActionSpec struct {
	// Action is the `uses:` owner/repo prefix (e.g. "actions/setup-go").
	Action string `yaml:"action"`
	// Mode is "always", "default", or "opt-in".
	Mode string `yaml:"mode"`
	// DisableInput / DisableValue apply to mode "default": the action's
	// `with:` input whose value turns caching off (e.g. cache=false for
	// setup-go, cache-disabled=true for setup-gradle).
	DisableInput string `yaml:"disableInput,omitempty"`
	DisableValue *bool  `yaml:"disableValue,omitempty"`
	// EnableInput applies to mode "opt-in": the `with:` input that, when
	// set to a package manager, turns caching on (e.g. cache=npm).
	EnableInput string `yaml:"enableInput,omitempty"`
	// EnableContains additionally requires EnableInput's value to contain
	// this substring (case-insensitive) for the cache to count as active —
	// e.g. build-push-action restores a GitHub Actions cache only when
	// cache-from contains "type=gha".
	EnableContains string `yaml:"enableContains,omitempty"`
}

// IsEnabled reports whether the control is enabled.
func (c *CachePoisoningControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// ActionAuthorizedSourcesControlConfig configures the GitHub Actions
// authorized-sources supply-chain check (ISSUE-713). Only meaningful on
// GitHub workflows. A `uses:` reference is authorized when its owner is
// GitHub-official (when TrustGithubOfficialActions is on), its
// `owner/repo` matches an entry in TrustedGithubActions, or — when
// MinimumStars > 0 — the action repository has at least that many stars.
type ActionAuthorizedSourcesControlConfig struct {
	// Enabled controls whether this check runs.
	Enabled *bool `yaml:"enabled,omitempty"`

	// TrustGithubOfficialActions trusts the first-party GitHub-owned
	// actions (`actions/*`, `github/*`) that any workflow already
	// executes implicitly. Defaults to true when unset.
	TrustGithubOfficialActions *bool `yaml:"trustGithubOfficialActions,omitempty"`

	// TrustSameOrgActions trusts actions whose owner is the same org/user
	// as the scanned repository — an org's own actions are already inside
	// its trust boundary. Defaults to true when unset.
	TrustSameOrgActions *bool `yaml:"trustSameOrgActions,omitempty"`

	// MinimumStars, when > 0, trusts any action whose upstream
	// repository has at least this many GitHub stars. 0 disables the
	// star check. Requires GitHub API metadata; when the star count
	// cannot be resolved the reference falls back to the allowlist
	// rather than being flagged on missing data.
	MinimumStars int `yaml:"minimumStars,omitempty"`

	// TrustedGithubActions lists action sources that are always allowed.
	// Each entry is either an exact `owner/repo` (e.g. `jdx/mise-action`)
	// or an `owner/*` wildcard trusting a whole org (e.g. `mycompany/*`).
	TrustedGithubActions []string `yaml:"trustedGithubActions,omitempty"`

	// IncludePlumberDefaults, in overlay mode (extends: plumber:default),
	// unions Plumber's curated default trusted list with TrustedGithubActions.
	// Defaults to true. Set false to trust only the entries listed here.
	// Ignored in legacy (no-extends) mode.
	IncludePlumberDefaults *bool `yaml:"includePlumberDefaults,omitempty"`
}

// IsEnabled returns whether the control is enabled
func (c *ActionAuthorizedSourcesControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// IsIncludePlumberDefaults reports whether the curated default trusted
// list is unioned in. Defaults to true when the config or field is nil.
func (c *ActionAuthorizedSourcesControlConfig) IsIncludePlumberDefaults() bool {
	if c == nil || c.IncludePlumberDefaults == nil {
		return true
	}
	return *c.IncludePlumberDefaults
}

// ImageForbiddenTagsControlConfig configuration for the forbidden image tags control
type ImageForbiddenTagsControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// Tags is a list of forbidden tags (e.g., latest, dev)
	Tags []string `yaml:"tags,omitempty"`

	// ContainerImagesMustBePinnedByDigest when true, ALL images must use immutable digest references.
	// Takes precedence over the forbidden tags list — any image not pinned by digest is flagged.
	ContainerImagesMustBePinnedByDigest *bool `yaml:"containerImagesMustBePinnedByDigest,omitempty"`
}

// IsPinnedByDigestRequired returns whether all images must be pinned by digest
func (c *ImageForbiddenTagsControlConfig) IsPinnedByDigestRequired() bool {
	if c == nil || c.ContainerImagesMustBePinnedByDigest == nil {
		return false
	}
	return *c.ContainerImagesMustBePinnedByDigest
}

// ImageAuthorizedSourcesControlConfig configuration for the authorized image sources control
type ImageAuthorizedSourcesControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// TrustedUrls is a list of trusted registry URLs/patterns (supports wildcards)
	TrustedUrls []string `yaml:"trustedUrls,omitempty"`

	// TrustDockerHubOfficialImages trusts official Docker Hub images (e.g., nginx, alpine)
	TrustDockerHubOfficialImages *bool `yaml:"trustDockerHubOfficialImages,omitempty"`

	// IncludePlumberDefaults, in overlay mode (extends: plumber:default),
	// unions Plumber's curated default trusted list with TrustedUrls.
	// Defaults to true. Set false to trust only the entries listed here.
	// Ignored in legacy (no-extends) mode.
	IncludePlumberDefaults *bool `yaml:"includePlumberDefaults,omitempty"`
}

// BranchProtectionControlConfig configuration for the branch protection control
// MRApprovalRulesMinApprovalsControlConfig configures the GitLab
// merge-request approval-rules minimum-approvals check (ISSUE-502).
// GitLab-only.
type MRApprovalRulesMinApprovalsControlConfig struct {
	// Enabled controls whether this check runs.
	Enabled *bool `yaml:"enabled,omitempty"`

	// MinimumRequiredApprovals is the fewest approvals a rule covering all
	// protected branches must require; a covering rule below it is flagged.
	// When unset (nil) the control asserts nothing (treated as 0).
	//
	// Platform migration: this key was named minimumRequiredApprovalAllProtectedBranches
	// on the backend2 platform. It is deliberately shortened to
	// minimumRequiredApprovals in the CLI (the "all protected branches" scope is
	// already implied by the control). A platform-config importer must map the
	// old key to this one.
	MinimumRequiredApprovals *int `yaml:"minimumRequiredApprovals,omitempty"`
}

// IsEnabled reports whether the control is enabled. Returns false when the
// wrapper or the field is nil — same convention as every other IsEnabled().
func (c *MRApprovalRulesMinApprovalsControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// MRApprovalSettingsControlConfig configures the GitLab merge-request
// approval-settings check (ISSUE-503). GitLab-only. Every expectation is
// optional: an unset field is not checked. The booleans check only when set
// true — an explicit false is the same as unset, matching the legacy
// platform's conf semantics (there is no "expect the unsafe setting" mode).
type MRApprovalSettingsControlConfig struct {
	// Enabled controls whether this check runs.
	Enabled *bool `yaml:"enabled,omitempty"`

	// PreventApprovalByAuthor, when true, expects that MR authors cannot
	// approve their own merge requests.
	PreventApprovalByAuthor *bool `yaml:"preventApprovalByAuthor,omitempty"`

	// PreventApprovalsByCommitters, when true, expects that users who
	// committed to an MR cannot approve it.
	PreventApprovalsByCommitters *bool `yaml:"preventApprovalsByCommitters,omitempty"`

	// PreventEditingApprovalRulesInMR, when true, expects that approval
	// rules cannot be overridden per merge request.
	PreventEditingApprovalRulesInMR *bool `yaml:"preventEditingApprovalRulesInMR,omitempty"`

	// RequireReAuthToApprove, when true, expects that approving requires
	// re-authentication.
	RequireReAuthToApprove *bool `yaml:"requireReAuthToApprove,omitempty"`

	// BehaviorWhenCommitIsAdded is the MINIMUM required strictness for what
	// happens to existing approvals when a commit is added to an open MR:
	// "keep_approvals" < "remove_approvals_by_code_owners" <
	// "remove_all_approvals". A project below the configured rung is
	// flagged; any other value fails config validation.
	BehaviorWhenCommitIsAdded *string `yaml:"behaviorWhenCommitIsAdded,omitempty"`
}

// IsEnabled reports whether the control is enabled. Returns false when the
// wrapper or the field is nil — same convention as every other IsEnabled().
func (c *MRApprovalSettingsControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// mrApprovalBehaviorValues are the accepted behaviorWhenCommitIsAdded
// expectations, in strictness order. Kept in the configuration package (the
// validation site) and mirrored by the ir.MRApprovalBehavior* constants the
// projection emits; TestMRApprovalBehaviorValuesMatchIR pins the two lists
// together.
var mrApprovalBehaviorValues = []string{
	"keep_approvals",
	"remove_approvals_by_code_owners",
	"remove_all_approvals",
}

// validateBehaviorWhenCommitIsAdded rejects a behaviorWhenCommitIsAdded
// expectation outside the known ladder AT CONFIG LOAD. Load-bearing: the Rego
// rule looks the value up in its rank map and an unknown string would make
// that lookup undefined, silently disabling the check — a typo like
// "keep-approvals" would read as "not checked" forever.
func (c *MRApprovalSettingsControlConfig) validateBehaviorWhenCommitIsAdded() error {
	if c == nil || c.BehaviorWhenCommitIsAdded == nil {
		return nil
	}
	if slices.Contains(mrApprovalBehaviorValues, *c.BehaviorWhenCommitIsAdded) {
		return nil
	}
	return fmt.Errorf("mergeRequestApprovalSettingsMustBeCompliant.behaviorWhenCommitIsAdded: unknown value %q (expected one of %s)",
		*c.BehaviorWhenCommitIsAdded, strings.Join(mrApprovalBehaviorValues, ", "))
}

// MRSettingsControlConfig configures the GitLab merge-request/merge-settings
// check (ISSUE-506). GitLab-only. Every expectation is optional: an unset field
// is not checked, and each set field is compared against the project's actual
// value for EXACT equality (the legacy platform compared all fields, but always
// with a fully populated policy — optional here keeps a hand-authored YAML from
// flagging on a field the operator never set).
type MRSettingsControlConfig struct {
	// Enabled controls whether this check runs.
	Enabled *bool `yaml:"enabled,omitempty"`

	// MergeMethod is the expected merge method: "merge", "ff", or
	// "rebase_merge". Any other value fails config validation.
	MergeMethod *string `yaml:"mergeMethod,omitempty"`

	// SquashOption is the expected squash policy: "never", "always",
	// "default_on", or "default_off". Any other value fails config validation.
	SquashOption *string `yaml:"squashOption,omitempty"`

	// MergePipelinesEnabled is the expected merged-results-pipelines setting.
	MergePipelinesEnabled *bool `yaml:"mergePipelinesEnabled,omitempty"`

	// MergeTrainsEnabled is the expected merge-trains setting.
	MergeTrainsEnabled *bool `yaml:"mergeTrainsEnabled,omitempty"`

	// AllowMergeOnSkippedPipeline is the expected "allow merge when the
	// pipeline is skipped" setting.
	AllowMergeOnSkippedPipeline *bool `yaml:"allowMergeOnSkippedPipeline,omitempty"`

	// ResolveOutdatedDiffDiscussions is the expected auto-resolve-outdated-
	// discussions setting.
	ResolveOutdatedDiffDiscussions *bool `yaml:"resolveOutdatedDiffDiscussions,omitempty"`

	// PrintingMergeRequestLinkEnabled is the expected print-MR-link-on-push
	// setting.
	PrintingMergeRequestLinkEnabled *bool `yaml:"printingMergeRequestLinkEnabled,omitempty"`

	// RemoveSourceBranchAfterMerge is the expected delete-source-branch-after-
	// merge default.
	RemoveSourceBranchAfterMerge *bool `yaml:"removeSourceBranchAfterMerge,omitempty"`
}

// IsEnabled reports whether the control is enabled. Returns false when the
// wrapper or the field is nil — same convention as every other IsEnabled().
func (c *MRSettingsControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// mrSettingsMergeMethodValues are the accepted mergeMethod expectations, and
// mrSettingsSquashOptionValues the accepted squashOption expectations. Kept at
// the validation site; an unknown value would make the Rego equality check
// compare against a string GitLab never returns (always deviating), so it is
// rejected at config load instead.
var (
	mrSettingsMergeMethodValues  = []string{"merge", "ff", "rebase_merge"}
	mrSettingsSquashOptionValues = []string{"never", "always", "default_on", "default_off"}
)

// validateEnums rejects a mergeMethod or squashOption expectation outside the
// known set AT CONFIG LOAD.
func (c *MRSettingsControlConfig) validateEnums() error {
	if c == nil {
		return nil
	}
	if c.MergeMethod != nil && !slices.Contains(mrSettingsMergeMethodValues, *c.MergeMethod) {
		return fmt.Errorf("mergeRequestSettingsMustBeCompliant.mergeMethod: unknown value %q (expected one of %s)",
			*c.MergeMethod, strings.Join(mrSettingsMergeMethodValues, ", "))
	}
	if c.SquashOption != nil && !slices.Contains(mrSettingsSquashOptionValues, *c.SquashOption) {
		return fmt.Errorf("mergeRequestSettingsMustBeCompliant.squashOption: unknown value %q (expected one of %s)",
			*c.SquashOption, strings.Join(mrSettingsSquashOptionValues, ", "))
	}
	return nil
}

type BranchProtectionControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// NamePatterns is a list of branch name patterns that must be protected (supports wildcards)
	NamePatterns []string `yaml:"namePatterns,omitempty"`

	// DefaultMustBeProtected requires the default branch to be protected
	DefaultMustBeProtected *bool `yaml:"defaultMustBeProtected,omitempty"`

	// AllowForcePush when false, force push must be disabled on protected branches
	AllowForcePush *bool `yaml:"allowForcePush,omitempty"`

	// CodeOwnerApprovalRequired when true, code owner approval is required
	CodeOwnerApprovalRequired *bool `yaml:"codeOwnerApprovalRequired,omitempty"`

	// MinMergeAccessLevel minimum access level required to merge (0=No one, 30=Developer, 40=Maintainer)
	MinMergeAccessLevel *int `yaml:"minMergeAccessLevel,omitempty"`

	// MinPushAccessLevel minimum access level required to push (0=No one, 30=Developer, 40=Maintainer)
	MinPushAccessLevel *int `yaml:"minPushAccessLevel,omitempty"`
}

// HardcodedJobsControlConfig configuration for the hardcoded jobs control
type HardcodedJobsControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`
}

// IncludesUpToDateControlConfig configuration for the includes up-to-date control
type IncludesUpToDateControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`
}

// IncludesForbiddenVersionsControlConfig configuration for the forbidden versions control
type IncludesForbiddenVersionsControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// ForbiddenVersions is a list of version patterns considered forbidden (e.g., latest, main, HEAD)
	ForbiddenVersions []string `yaml:"forbiddenVersions,omitempty"`

	// DefaultBranchIsForbiddenVersion when true, adds the project's default branch to forbidden versions
	DefaultBranchIsForbiddenVersion *bool `yaml:"defaultBranchIsForbiddenVersion,omitempty"`
}

// RequiredComponentsControlConfig configuration for the required components control
type RequiredComponentsControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// Required is a human-readable boolean expression defining required components.
	// Supports AND, OR operators and parentheses for grouping.
	// AND has higher precedence than OR.
	//
	// Examples:
	//   "components/sast/sast AND components/secret-detection/secret-detection"
	//   "(components/sast/sast AND components/secret-detection/secret-detection) OR your-org/full-security/full-security"
	Required string `yaml:"required,omitempty"`

	// RequiredGroups uses DNF (Disjunctive Normal Form) format:
	// Outer array = OR (at least one group must be satisfied)
	// Inner array = AND (all components in group must be present)
	// Example: [["comp-a", "comp-b"], ["comp-c"]] means:
	//   "must have (comp-a AND comp-b) OR (comp-c)"
	//
	// Cannot be used together with 'required'.
	RequiredGroups [][]string `yaml:"requiredGroups,omitempty"`
}

// GetResolvedRequiredGroups returns the effective required groups by resolving
// either the 'required' expression or the 'requiredGroups' field.
// Returns an error if both are set or if the expression is invalid.
func (c *RequiredComponentsControlConfig) GetResolvedRequiredGroups() ([][]string, error) {
	if c == nil {
		return nil, nil
	}
	hasExpression := c.Required != ""
	hasGroups := len(c.RequiredGroups) > 0

	if hasExpression && hasGroups {
		return nil, fmt.Errorf("pipelineMustIncludeComponent: cannot use both 'required' and 'requiredGroups' — use only one")
	}
	if hasExpression {
		groups, err := ParseRequiredExpression(c.Required)
		if err != nil {
			return nil, fmt.Errorf("pipelineMustIncludeComponent: %w", err)
		}
		return groups, nil
	}
	return c.RequiredGroups, nil
}

// RequiredActionsControlConfig configures the GitHub
// workflowMustIncludeRequiredActions control. Mirrors
// RequiredComponentsControlConfig's DNF (Disjunctive Normal Form)
// shape so users running both providers have one mental model:
//   - Required is a boolean expression ("a AND b OR c"), parsed via
//     ParseRequiredExpression into the same OR-of-ANDs groups.
//   - RequiredGroups is the same DNF written directly.
//   - The two fields are mutually exclusive at validate-time.
//
// Each required entry is an owner/repo prefix (or owner/repo/path
// for sub-actions and reusable-workflow paths). Matching is
// ref-agnostic so users can bump pinned SHAs without rewriting the
// policy.
type RequiredActionsControlConfig struct {
	Enabled        *bool      `yaml:"enabled,omitempty"`
	Required       string     `yaml:"required,omitempty"`
	RequiredGroups [][]string `yaml:"requiredGroups,omitempty"`
}

// GetResolvedRequiredGroups returns the effective required groups by
// resolving either the 'required' expression or the 'requiredGroups'
// field. Errors when both are set or when the expression is invalid.
func (c *RequiredActionsControlConfig) GetResolvedRequiredGroups() ([][]string, error) {
	if c == nil {
		return nil, nil
	}
	hasExpression := c.Required != ""
	hasGroups := len(c.RequiredGroups) > 0
	if hasExpression && hasGroups {
		return nil, fmt.Errorf("workflowMustIncludeRequiredActions: cannot use both 'required' and 'requiredGroups'; use only one")
	}
	if hasExpression {
		groups, err := ParseRequiredExpression(c.Required)
		if err != nil {
			return nil, fmt.Errorf("workflowMustIncludeRequiredActions: %w", err)
		}
		return groups, nil
	}
	return c.RequiredGroups, nil
}

// IsEnabled returns whether the control is enabled. Returns false
// when the config block is absent or when `enabled:` is not set.
func (c *RequiredActionsControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// DebugTraceControlConfig configuration for the debug trace detection control
type DebugTraceControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// ForbiddenVariables is a list of CI/CD variable names that must not be set to "true"
	// Defaults: CI_DEBUG_TRACE, CI_DEBUG_SERVICES
	ForbiddenVariables []string `yaml:"forbiddenVariables,omitempty"`
}

// VariableInjectionControlConfig configuration for the unsafe variable expansion control
type VariableInjectionControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// DangerousVariables is a list of CI/CD variable names whose values come from user input
	// and should not appear in script blocks where shell injection is possible
	DangerousVariables []string `yaml:"dangerousVariables,omitempty"`

	// AllowedPatterns is a list of regex patterns. Script lines matching any of these
	// patterns will not be flagged even if they contain a dangerous variable.
	AllowedPatterns []string `yaml:"allowedPatterns,omitempty"`
}

// SecurityJobsWeakenedControlConfig configuration for the security jobs weakening control
type SecurityJobsWeakenedControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// SecurityJobPatterns is a list of job name patterns considered "security jobs" (supports wildcards)
	SecurityJobPatterns []string `yaml:"securityJobPatterns,omitempty"`

	// Sub-control toggles (sit directly under the control, no wrapper)
	AllowFailureMustBeFalse *SecurityJobsSubControlToggle `yaml:"allowFailureMustBeFalse,omitempty"`
	RulesMustNotBeRedefined *SecurityJobsSubControlToggle `yaml:"rulesMustNotBeRedefined,omitempty"`
	WhenMustNotBeManual     *SecurityJobsSubControlToggle `yaml:"whenMustNotBeManual,omitempty"`
}

// SecurityJobsSubControlToggle is a simple enabled/disabled toggle for a sub-control
type SecurityJobsSubControlToggle struct {
	Enabled *bool `yaml:"enabled,omitempty"`
}

// IsEnabled returns whether the sub-control toggle is enabled.
// Returns the provided default if the toggle or its Enabled field is nil.
func (t *SecurityJobsSubControlToggle) IsEnabled(defaultVal bool) bool {
	if t == nil || t.Enabled == nil {
		return defaultVal
	}
	return *t.Enabled
}

// UnverifiedScriptsControlConfig configuration for the unverified script execution control
type UnverifiedScriptsControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// TrustedUrls is a list of URL patterns that should not trigger findings.
	// Supports wildcards (e.g., "https://internal-artifacts.example.com/*").
	TrustedUrls []string `yaml:"trustedUrls,omitempty"`
}

// JobVariablesOverrideControlConfig configuration for the job variable override control
type JobVariablesOverrideControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// Variables is a list of CI/CD variable names that must not be defined
	// in the pipeline configuration file. They should only be set via
	// GitLab CI/CD Settings > Variables.
	Variables []string `yaml:"variables,omitempty"`
}

// DockerInDockerControlConfig configuration for the Docker-in-Docker detection control
type DockerInDockerControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// DetectInsecureDaemon when true, also flags insecure daemon configuration
	// (DOCKER_TLS_CERTDIR="" or DOCKER_HOST pointing to non-TLS port 2375)
	// in jobs that use a DinD service.
	DetectInsecureDaemon *bool `yaml:"detectInsecureDaemon,omitempty"`
}

// RequiredTemplatesControlConfig configuration for the required templates control
type RequiredTemplatesControlConfig struct {
	// Enabled controls whether this check runs
	Enabled *bool `yaml:"enabled,omitempty"`

	// Required is a human-readable boolean expression defining required templates.
	// Supports AND, OR operators and parentheses for grouping.
	// AND has higher precedence than OR.
	//
	// Examples:
	//   "templates/go/go AND templates/trivy/trivy"
	//   "(templates/go/go AND templates/trivy/trivy) OR templates/full-go-pipeline"
	Required string `yaml:"required,omitempty"`

	// RequiredGroups uses DNF (Disjunctive Normal Form) format:
	// Outer array = OR (at least one group must be satisfied)
	// Inner array = AND (all templates in group must be present)
	// Example: [["go", "helm"], ["go_helm_unified"]] means:
	//   "must have (go AND helm) OR (go_helm_unified)"
	//
	// Cannot be used together with 'required'.
	RequiredGroups [][]string `yaml:"requiredGroups,omitempty"`
}

// GetResolvedRequiredGroups returns the effective required groups by resolving
// either the 'required' expression or the 'requiredGroups' field.
// Returns an error if both are set or if the expression is invalid.
func (c *RequiredTemplatesControlConfig) GetResolvedRequiredGroups() ([][]string, error) {
	if c == nil {
		return nil, nil
	}
	hasExpression := c.Required != ""
	hasGroups := len(c.RequiredGroups) > 0

	if hasExpression && hasGroups {
		return nil, fmt.Errorf("pipelineMustIncludeTemplate: cannot use both 'required' and 'requiredGroups' — use only one")
	}
	if hasExpression {
		groups, err := ParseRequiredExpression(c.Required)
		if err != nil {
			return nil, fmt.Errorf("pipelineMustIncludeTemplate: %w", err)
		}
		return groups, nil
	}
	return c.RequiredGroups, nil
}

// LoadPlumberConfig loads configuration from a file path.
// It reads the file once, validates for unknown keys, parses
// the YAML into the config struct, detects whether the file uses
// the legacy v1 schema (top-level `controls:`/`engine:`) or the
// current v2 schema (per-provider `gitlab.controls:` /
// `github.controls:`), and converts v1 in-memory to v2.
// Returns the parsed config, the resolved path, any warnings
// (unknown-key + deprecation), and an error if loading or
// validation failed.
func LoadPlumberConfig(configPath string) (*PlumberConfig, string, []string, error) {
	l := logrus.WithField("action", "LoadPlumberConfig")

	if configPath == "" {
		return nil, "", nil, fmt.Errorf("config file path is required")
	}

	l = l.WithField("configPath", configPath)
	l.Info("Loading configuration from file")

	data, err := utils.ReadFileLimit(configPath, maxConfigFileBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, configPath, nil, fmt.Errorf("%w: %s", ErrConfigNotFound, configPath)
		}
		l.WithError(err).Error("Failed to read config file")
		return nil, configPath, nil, err
	}

	return LoadPlumberConfigFromBytes(data, configPath)
}

// LoadPlumberConfigFromBytes parses configuration from raw bytes, recording
// `source` as its origin — a file path when called via LoadPlumberConfig, or a
// label such as "built-in default" when a caller falls back to the embedded
// config. It runs the same key validation, schema migration (v1 → v2) and
// version normalisation as loading from a file, so a fallback config is held to
// exactly the same contract as a user-supplied one.
func LoadPlumberConfigFromBytes(data []byte, source string) (*PlumberConfig, string, []string, error) {
	l := logrus.WithField("action", "LoadPlumberConfigFromBytes").WithField("source", source)

	warnings := ValidateKnownKeys(data)

	// Resolve overlay mode (extends: plumber:default) before parsing.
	// Legacy files with no extends pass through untouched.
	extendsVal, extErr := detectExtends(data)
	if extErr != nil {
		return nil, source, warnings, extErr
	}
	effectiveData := data
	isOverlay := extendsVal == ExtendsPlumberDefault
	if isOverlay {
		merged, err := resolveOverlayBytes(data)
		if err != nil {
			return nil, source, warnings, err
		}
		effectiveData = merged
	}

	config := &PlumberConfig{}
	if err := yaml.Unmarshal(effectiveData, config); err != nil {
		l.WithError(err).Error("Failed to parse config")
		return nil, source, warnings, err
	}
	// Capture the verbatim config + its source so the JSON report can carry
	// a self-describing `plumberConfig` block (what produced this grade).
	// In overlay mode, Raw holds the resolved (merged) YAML so the report
	// reflects what actually ran, and Extends is cleared since resolution
	// is now complete.
	config.Raw = string(effectiveData)
	config.Source = source
	config.Extends = ""

	// Reject explicitly-set unsupported versions early. Empty version is
	// allowed (legacy default behaviour) and gets a deprecation warning
	// from convertV1ToV2. "1.0" is the legacy schema; "2.0" is current.
	if config.Version != "" && config.Version != "1.0" && config.Version != "2.0" {
		return nil, source, warnings, fmt.Errorf(
			"unsupported config version %q; supported: [\"1.0\" (legacy), \"2.0\" (current)]", config.Version)
	}

	// Detect a top-level `engine:` block in the raw YAML and emit a
	// deprecation warning. The block is no longer parsed into a Go
	// field — yaml.v2 silently ignores it — so this is the only place
	// the user gets feedback that their config has dead bytes.
	if rawHasTopLevelKey(data, "engine") {
		warnings = append(warnings,
			"engine.enabled has been removed in schema v1.0 and is now ignored. "+
				"Delete the 'engine' block from your .plumber.yaml.")
	}

	// Schema detection: presence of any provider section means the file is
	// v2-shaped. Otherwise it's legacy v1 — run the converter to promote
	// top-level controls under gitlab.controls. Mixed files (top-level
	// controls AND a provider section) also go through the converter,
	// where v2 wins for keys present on both sides.
	if config.GitLab == nil && config.GitHub == nil {
		warnings = append(warnings, convertV1ToV2(config)...)
	} else if !controlsConfigIsZero(config.Controls) {
		warnings = append(warnings, convertV1ToV2(config)...)
	}
	// At this point the in-memory config is v2-shaped. If the file did
	// not declare a version, or declared the legacy "1.0", normalise to
	// "2.0" so downstream consumers and re-emitters see the current value.
	if config.Version == "" || config.Version == "1.0" {
		config.Version = "2.0"
	}

	if err := config.validate(); err != nil {
		return nil, source, warnings, fmt.Errorf("configuration validation error: %w", err)
	}

	// Overlay mode: the merge above list-replaces (no per-element merge in
	// deepMergeYAML), so a control's allowlist the overlay mentioned holds
	// only the overlay's own values at this point. Materialize the real
	// includePlumberDefaults semantics (union with the curated base list,
	// or user-only when the toggle is false) now that config is fully
	// built and v2-shaped. Base and overlay are re-parsed independently
	// (not from effectiveData) so each side reflects only its own values.
	if isOverlay {
		baseCfg := &PlumberConfig{}
		_ = yaml.Unmarshal(defaultconfig.Get(), baseCfg)
		overlayCfg := &PlumberConfig{}
		_ = yaml.Unmarshal(data, overlayCfg)
		materializeAuthorizedSources(config, baseCfg, overlayCfg)

		// config.Raw was captured above from effectiveData, i.e. before this
		// materialize step ran. deepMergeYAML list-replaces, so at that
		// point Raw held only the overlay's own (sparse) allowlist entries,
		// not the union with the curated base list. Re-marshal now that the
		// resolved struct carries the real materialized allowlists, so Raw
		// (which feeds the audit report's self-describing `plumberConfig`
		// block and its hash) reflects what actually ran.
		if b, err := yaml.Marshal(config); err == nil {
			config.Raw = string(b)
		} else {
			l.WithError(err).Warn("failed to re-marshal resolved config for Raw; report block may understate materialized allowlists")
		}
	}

	l.WithField("config", config).Debug("Configuration loaded successfully")
	return config, source, warnings, nil
}

// validate checks for configuration errors, including expression syntax
// and mutual exclusivity of 'required' vs 'requiredGroups'.
// In v2 (post-LoadPlumberConfig) the legacy top-level Controls is empty
// and provider sections carry the data; we still walk the legacy field
// defensively to cover code paths that build a PlumberConfig in-process
// without going through the loader.
func (c *PlumberConfig) validate() error {
	if c == nil {
		return nil
	}

	if err := validateControlsConfig(&c.Controls); err != nil {
		return err
	}
	if c.GitLab != nil {
		if err := validateControlsConfig(&c.GitLab.Controls); err != nil {
			return err
		}
	}
	if c.GitHub != nil {
		if err := validateControlsConfig(&c.GitHub.Controls); err != nil {
			return err
		}
	}
	return nil
}

// validateControlsConfig runs structural checks for any control whose
// configuration has cross-field constraints (e.g. mutual exclusivity).
// Provider-agnostic: same rules apply wherever the controls live.
func validateControlsConfig(c *ControlsConfig) error {
	if c == nil {
		return nil
	}
	if comp := c.PipelineMustIncludeComponent; comp != nil {
		if _, err := comp.GetResolvedRequiredGroups(); err != nil {
			return err
		}
	}
	if tmpl := c.PipelineMustIncludeTemplate; tmpl != nil {
		if _, err := tmpl.GetResolvedRequiredGroups(); err != nil {
			return err
		}
	}
	if actions := c.WorkflowMustIncludeRequiredActions; actions != nil {
		if _, err := actions.GetResolvedRequiredGroups(); err != nil {
			return err
		}
	}
	if err := c.MergeRequestApprovalSettingsMustBeCompliant.validateBehaviorWhenCommitIsAdded(); err != nil {
		return err
	}
	if err := c.MergeRequestSettingsMustBeCompliant.validateEnums(); err != nil {
		return err
	}
	return nil
}

// Validate checks structural consistency (required component/template expressions, etc.).
func (c *PlumberConfig) Validate() error {
	return c.validate()
}

// GetContainerImageMustNotUseForbiddenTagsConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetContainerImageMustNotUseForbiddenTagsConfig() *ImageForbiddenTagsControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").ContainerImageMustNotUseForbiddenTags
}

// GetContainerImageMustComeFromAuthorizedSourcesConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetContainerImageMustComeFromAuthorizedSourcesConfig() *ImageAuthorizedSourcesControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").ContainerImageMustComeFromAuthorizedSources
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *ImageForbiddenTagsControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *ImageAuthorizedSourcesControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// IsIncludePlumberDefaults reports whether the curated default trusted
// list is unioned in. Defaults to true when the config or field is nil.
func (c *ImageAuthorizedSourcesControlConfig) IsIncludePlumberDefaults() bool {
	if c == nil || c.IncludePlumberDefaults == nil {
		return true
	}
	return *c.IncludePlumberDefaults
}

// GetBranchMustBeProtectedConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetBranchMustBeProtectedConfig() *BranchProtectionControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").BranchMustBeProtected
}

func (c *PlumberConfig) GetMergeRequestApprovalRulesMustRequireMinimumApprovalsConfig() *MRApprovalRulesMinApprovalsControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").MergeRequestApprovalRulesMustRequireMinimumApprovals
}

func (c *PlumberConfig) GetMergeRequestApprovalRulesMustCoverAllProtectedBranchesConfig() *EnabledOnlyControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").MergeRequestApprovalRulesMustCoverAllProtectedBranches
}

func (c *PlumberConfig) GetCicdVariablesMustBeProtectedConfig() *EnabledOnlyControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").CicdVariablesMustBeProtected
}

func (c *PlumberConfig) GetCicdVariablesMustBeMaskedConfig() *EnabledOnlyControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").CicdVariablesMustBeMasked
}

func (c *PlumberConfig) GetMergeRequestApprovalSettingsMustBeCompliantConfig() *MRApprovalSettingsControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").MergeRequestApprovalSettingsMustBeCompliant
}

func (c *PlumberConfig) GetMergeRequestSettingsMustBeCompliantConfig() *MRSettingsControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").MergeRequestSettingsMustBeCompliant
}

// GetProjectMustHaveSecurityPolicySourceConfig returns the GitLab
// security-policy-project linkage control configuration (ISSUE-601), or nil.
func (c *PlumberConfig) GetProjectMustHaveSecurityPolicySourceConfig() *SecurityPolicyControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").ProjectMustHaveSecurityPolicySource
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *BranchProtectionControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetPipelineMustNotIncludeHardcodedJobsConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetPipelineMustNotIncludeHardcodedJobsConfig() *HardcodedJobsControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").PipelineMustNotIncludeHardcodedJobs
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *HardcodedJobsControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetIncludesMustBeUpToDateConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetIncludesMustBeUpToDateConfig() *IncludesUpToDateControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").IncludesMustBeUpToDate
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *IncludesUpToDateControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetIncludesMustNotUseForbiddenVersionsConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetIncludesMustNotUseForbiddenVersionsConfig() *IncludesForbiddenVersionsControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").IncludesMustNotUseForbiddenVersions
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *IncludesForbiddenVersionsControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetPipelineMustIncludeComponentConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetPipelineMustIncludeComponentConfig() *RequiredComponentsControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").PipelineMustIncludeComponent
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *RequiredComponentsControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetPipelineMustIncludeTemplateConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetPipelineMustIncludeTemplateConfig() *RequiredTemplatesControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").PipelineMustIncludeTemplate
}

// GetPipelineMustNotEnableDebugTraceConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetPipelineMustNotEnableDebugTraceConfig() *DebugTraceControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").PipelineMustNotEnableDebugTrace
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *DebugTraceControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetPipelineMustNotUseUnsafeVariableExpansionConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetPipelineMustNotUseUnsafeVariableExpansionConfig() *VariableInjectionControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").PipelineMustNotUseUnsafeVariableExpansion
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *VariableInjectionControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetSecurityJobsMustNotBeWeakenedConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetSecurityJobsMustNotBeWeakenedConfig() *SecurityJobsWeakenedControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").SecurityJobsMustNotBeWeakened
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *SecurityJobsWeakenedControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetPipelineMustNotExecuteUnverifiedScriptsConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetPipelineMustNotExecuteUnverifiedScriptsConfig() *UnverifiedScriptsControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").PipelineMustNotExecuteUnverifiedScripts
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *UnverifiedScriptsControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetPipelineMustNotOverrideJobVariablesConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetPipelineMustNotOverrideJobVariablesConfig() *JobVariablesOverrideControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").PipelineMustNotOverrideJobVariables
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *JobVariablesOverrideControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// GetPipelineMustNotUseDockerInDockerConfig returns the control configuration
// Returns nil if not configured
func (c *PlumberConfig) GetPipelineMustNotUseDockerInDockerConfig() *DockerInDockerControlConfig {
	if c == nil {
		return nil
	}
	return c.ControlsFor("gitlab").PipelineMustNotUseDockerInDocker
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *DockerInDockerControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// IsDetectInsecureDaemonEnabled returns whether insecure daemon detection is enabled.
// Defaults to true when the field is nil.
func (c *DockerInDockerControlConfig) IsDetectInsecureDaemonEnabled() bool {
	if c == nil || c.DetectInsecureDaemon == nil {
		return true
	}
	return *c.DetectInsecureDaemon
}

// IsEnabled returns whether the control is enabled
// Returns false if not properly configured
func (c *RequiredTemplatesControlConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

// levenshteinDistance calculates the Levenshtein distance between two strings
func levenshteinDistance(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	// Create matrix
	matrix := make([][]int, len(a)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(b)+1)
	}

	// Initialize first column
	for i := 0; i <= len(a); i++ {
		matrix[i][0] = i
	}

	// Initialize first row
	for j := 0; j <= len(b); j++ {
		matrix[0][j] = j
	}

	// Fill in the rest
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(a)][len(b)]
}

func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// FindClosestMatch finds the closest matching valid key using Levenshtein distance.
// Returns an empty string if no reasonable match is found.
func FindClosestMatch(unknownKey string, validKeys []string) string {
	if len(validKeys) == 0 {
		return ""
	}

	type match struct {
		key      string
		distance int
	}

	matches := make([]match, len(validKeys))
	for i, key := range validKeys {
		matches[i] = match{key: key, distance: levenshteinDistance(unknownKey, key)}
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].distance < matches[j].distance
	})

	// Only suggest if distance is reasonable (less than half the key length)
	if matches[0].distance < len(unknownKey)/2+2 {
		return matches[0].key
	}
	return ""
}

// contains checks if a string is in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// rawHasTopLevelKey reports whether the raw YAML data has the named
// key at top level. Used to detect deprecated keys (e.g. "engine") that
// no longer have a Go-side struct field, so they would otherwise be
// silently dropped by yaml.Unmarshal.
func rawHasTopLevelKey(data []byte, name string) bool {
	var raw map[interface{}]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return false
	}
	_, ok := raw[name]
	return ok
}

// ValidateKnownKeys checks for unknown configuration keys in .plumber.yaml
// at both the control level and the sub-key level. It accepts both the
// legacy v1 schema (top-level `controls:`) and the v2 schema (provider-
// nested `gitlab.controls:` / `github.controls:`). Returns a list of
// warning messages for unknown keys, with suggestions where a close
// known key exists.
func ValidateKnownKeys(data []byte) []string {
	var raw map[interface{}]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil
	}

	var warnings []string

	// v1: top-level `controls:`.
	if controlsRaw, ok := raw["controls"]; ok {
		warnings = append(warnings, validateControlsBlock(controlsRaw, "controls")...)
	}

	// v2: per-provider nested `controls:`.
	for _, provider := range []string{"gitlab", "github"} {
		provRaw, ok := raw[provider]
		if !ok {
			continue
		}
		provMap, ok := provRaw.(map[interface{}]interface{})
		if !ok {
			continue
		}
		if controlsRaw, ok := provMap["controls"]; ok {
			prefix := provider + ".controls"
			warnings = append(warnings, validateControlsBlock(controlsRaw, prefix)...)
			warnings = append(warnings, validateControlsBlockProvider(controlsRaw, provider)...)
		}
	}

	return warnings
}

// validateControlsBlockProvider warns when a control listed under
// `gitlab.controls:` or `github.controls:` is not registered for that
// provider in controlsMeta. Catches typos like putting a GitHub-only
// control under gitlab.controls.
func validateControlsBlockProvider(controlsRaw interface{}, provider string) []string {
	controls, ok := controlsRaw.(map[interface{}]interface{})
	if !ok {
		return nil
	}
	var warnings []string
	for keyRaw := range controls {
		controlName, ok := keyRaw.(string)
		if !ok {
			continue
		}
		meta, known := controlsMeta[controlName]
		if !known {
			// validateControlsBlock already covers unknown names.
			continue
		}
		applies := false
		for _, p := range meta.Providers {
			if p == provider {
				applies = true
				break
			}
		}
		if !applies {
			warnings = append(warnings, fmt.Sprintf(
				"Control %q is not applicable to %s; valid providers: %v",
				controlName, provider, meta.Providers))
		}
	}
	return warnings
}

// validateControlsBlock validates an unmarshalled `controls:` block
// (whether at v1 root or under a v2 provider section). The pathPrefix
// is used in warning messages to point the user at the right YAML
// location, e.g. "controls" or "gitlab.controls".
func validateControlsBlock(controlsRaw interface{}, pathPrefix string) []string {
	controls, ok := controlsRaw.(map[interface{}]interface{})
	if !ok {
		return nil
	}

	var warnings []string
	knownNames := validControlNames()

	for keyRaw, valueRaw := range controls {
		controlName, ok := keyRaw.(string)
		if !ok {
			continue
		}

		if msg, removed := removedControls[controlName]; removed {
			warnings = append(warnings,
				fmt.Sprintf("Control %q in %s was removed and is now ignored: %s", controlName, pathPrefix, msg))
			continue
		}

		if !contains(knownNames, controlName) {
			suggestion := FindClosestMatch(controlName, knownNames)
			if suggestion != "" {
				warnings = append(warnings,
					fmt.Sprintf("Unknown control in %s: %q. Did you mean %q?", pathPrefix, controlName, suggestion))
			} else {
				warnings = append(warnings,
					fmt.Sprintf("Unknown control in %s: %q", pathPrefix, controlName))
			}
			continue
		}

		subMap, ok := valueRaw.(map[interface{}]interface{})
		if !ok {
			continue
		}
		validSubKeys := validControlSchema[controlName]

		for subKeyRaw := range subMap {
			subKey, ok := subKeyRaw.(string)
			if !ok {
				continue
			}
			if !contains(validSubKeys, subKey) {
				suggestion := FindClosestMatch(subKey, validSubKeys)
				if suggestion != "" {
					warnings = append(warnings,
						fmt.Sprintf("Unknown key %q in control %q (%s). Did you mean %q?", subKey, controlName, pathPrefix, suggestion))
				} else {
					warnings = append(warnings,
						fmt.Sprintf("Unknown key %q in control %q (%s)", subKey, controlName, pathPrefix))
				}
			}
		}
	}

	return warnings
}
