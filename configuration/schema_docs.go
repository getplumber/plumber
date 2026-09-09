package configuration

// FieldDoc is the authored half of a schema field: the prose and
// constraints reflection cannot know. Structure lives in schema.go;
// TestFieldDocsParity welds the two so neither can drift.
type FieldDoc struct {
	Description string
	Enum        []string
	Default     string
}

// controlFieldDocs is keyed by dotted field path: "control.field",
// "control.parent.child" for nested objects, "control.list[].member" for
// struct-valued array items. Source each Description from the field's own
// doc comment in plumberconfig.go, condensed to one sentence.
var controlFieldDocs = map[string]FieldDoc{
	"cicdVariablesMustBeProtected.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"containerImageMustNotUseForbiddenTags.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"containerImageMustNotUseForbiddenTags.tags": {
		Description: "List of forbidden tags, such as latest or dev.",
	},
	"containerImageMustNotUseForbiddenTags.containerImagesMustBePinnedByDigest": {
		Description: "When true, all images must use immutable digest references, taking precedence over the forbidden tags list.",
	},
	"containerImageMustComeFromAuthorizedSources.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"containerImageMustComeFromAuthorizedSources.trustedUrls": {
		Description: "List of trusted registry URLs or patterns; supports wildcards.",
	},
	"containerImageMustComeFromAuthorizedSources.trustDockerHubOfficialImages": {
		Description: "Trusts official Docker Hub images, such as nginx or alpine.",
	},
	"containerImageMustComeFromAuthorizedSources.includePlumberDefaults": {
		Description: "In overlay mode, unions Plumber's curated default trusted list with trustedUrls; set false to trust only the listed entries; ignored in legacy mode.",
		Default:     "true",
	},
	"branchMustBeProtected.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"branchMustBeProtected.namePatterns": {
		Description: "List of branch name patterns that must be protected; supports wildcards.",
	},
	"branchMustBeProtected.defaultMustBeProtected": {
		Description: "Requires the default branch to be protected.",
	},
	"branchMustBeProtected.allowForcePush": {
		Description: "When false, force push must be disabled on protected branches.",
	},
	"branchMustBeProtected.codeOwnerApprovalRequired": {
		Description: "When true, code owner approval is required.",
	},
	"branchMustBeProtected.minMergeAccessLevel": {
		Description: "Minimum access level required to merge (0 = No one, 30 = Developer, 40 = Maintainer).",
	},
	"branchMustBeProtected.minPushAccessLevel": {
		Description: "Minimum access level required to push (0 = No one, 30 = Developer, 40 = Maintainer).",
	},
	"mergeRequestApprovalRulesMustRequireMinimumApprovals.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"mergeRequestApprovalRulesMustRequireMinimumApprovals.minimumRequiredApprovals": {
		Description: "Fewest approvals a rule covering all protected branches must require; a covering rule below this is flagged. Unset asserts nothing.",
	},
	"mergeRequestApprovalRulesMustCoverAllProtectedBranches.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"cicdVariablesMustBeMasked.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"mergeRequestApprovalSettingsMustBeCompliant.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"mergeRequestApprovalSettingsMustBeCompliant.preventApprovalByAuthor": {
		Description: "When true, expects that merge request authors cannot approve their own merge requests.",
	},
	"mergeRequestApprovalSettingsMustBeCompliant.preventApprovalsByCommitters": {
		Description: "When true, expects that users who committed to a merge request cannot approve it.",
	},
	"mergeRequestApprovalSettingsMustBeCompliant.preventEditingApprovalRulesInMR": {
		Description: "When true, expects that approval rules cannot be overridden per merge request.",
	},
	"mergeRequestApprovalSettingsMustBeCompliant.requireReAuthToApprove": {
		Description: "When true, expects that approving a merge request requires re-authentication.",
	},
	"mergeRequestApprovalSettingsMustBeCompliant.behaviorWhenCommitIsAdded": {
		Description: "Minimum required strictness for what happens to existing approvals when a commit is added to an open merge request; a project below the configured rung is flagged.",
		Enum:        []string{"keep_approvals", "remove_approvals_by_code_owners", "remove_all_approvals"},
	},
	"mergeRequestSettingsMustBeCompliant.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"mergeRequestSettingsMustBeCompliant.mergeMethod": {
		Description: "Expected merge method; any other value fails config validation.",
		Enum:        []string{"merge", "ff", "rebase_merge"},
	},
	"mergeRequestSettingsMustBeCompliant.squashOption": {
		Description: "Expected squash policy; any other value fails config validation.",
		Enum:        []string{"never", "always", "default_on", "default_off"},
	},
	"mergeRequestSettingsMustBeCompliant.mergePipelinesEnabled": {
		Description: "Expected merged-results-pipelines setting.",
	},
	"mergeRequestSettingsMustBeCompliant.mergeTrainsEnabled": {
		Description: "Expected merge-trains setting.",
	},
	"mergeRequestSettingsMustBeCompliant.allowMergeOnSkippedPipeline": {
		Description: "Expected allow-merge-when-pipeline-is-skipped setting.",
	},
	"mergeRequestSettingsMustBeCompliant.resolveOutdatedDiffDiscussions": {
		Description: "Expected auto-resolve-outdated-discussions setting.",
	},
	"mergeRequestSettingsMustBeCompliant.printingMergeRequestLinkEnabled": {
		Description: "Expected print-merge-request-link-on-push setting.",
	},
	"mergeRequestSettingsMustBeCompliant.removeSourceBranchAfterMerge": {
		Description: "Expected delete-source-branch-after-merge default.",
	},
	"projectMustHaveSecurityPolicySource.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"projectMustHaveSecurityPolicySource.expectedProjectId": {
		Description: "Numeric GitLab project ID the linked security policy project must match; unset requires only that some policy project is linked.",
	},
	"projectMustHaveSecurityPolicySource.expectedProjectPath": {
		Description: "Full namespace/project path the linked security policy project must match, compared case-insensitively; ignored when expectedProjectId is also set.",
	},
	"pipelineMustNotIncludeHardcodedJobs.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"externalRefsMustNotCollide.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"includesMustBeUpToDate.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"includesMustNotUseForbiddenVersions.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"includesMustNotUseForbiddenVersions.forbiddenVersions": {
		Description: "List of version patterns considered forbidden, such as latest, main, or HEAD.",
	},
	"includesMustNotUseForbiddenVersions.defaultBranchIsForbiddenVersion": {
		Description: "When true, adds the project's default branch to the forbidden versions list.",
	},
	"pipelineMustIncludeComponent.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"pipelineMustIncludeComponent.required": {
		Description: "Human-readable boolean expression defining required components; supports AND, OR, and parentheses, with AND binding tighter than OR. Mutually exclusive with requiredGroups.",
	},
	"pipelineMustIncludeComponent.requiredGroups": {
		Description: "Required components in DNF form: outer array is OR, inner array is AND. Mutually exclusive with required.",
	},
	"pipelineMustIncludeTemplate.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"pipelineMustIncludeTemplate.required": {
		Description: "Human-readable boolean expression defining required templates; supports AND, OR, and parentheses, with AND binding tighter than OR. Mutually exclusive with requiredGroups.",
	},
	"pipelineMustIncludeTemplate.requiredGroups": {
		Description: "Required templates in DNF form: outer array is OR, inner array is AND. Mutually exclusive with required.",
	},
	"pipelineMustNotEnableDebugTrace.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"pipelineMustNotEnableDebugTrace.forbiddenVariables": {
		Description: "List of CI/CD variable names that must not be set to true; there is no built-in list, so the control asserts nothing until it is set (CI_DEBUG_TRACE and CI_DEBUG_SERVICES are the typical entries).",
	},
	"pipelineMustNotUseUnsafeVariableExpansion.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"pipelineMustNotUseUnsafeVariableExpansion.dangerousVariables": {
		Description: "List of CI/CD variable names whose values come from user input and should not appear in script blocks susceptible to shell injection.",
	},
	"pipelineMustNotUseUnsafeVariableExpansion.allowedPatterns": {
		Description: "List of regex patterns; script lines matching any of them are not flagged even if they contain a dangerous variable.",
	},
	"securityJobsMustNotBeWeakened.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"securityJobsMustNotBeWeakened.securityJobPatterns": {
		Description: "List of job name patterns considered security jobs; supports wildcards.",
	},
	"securityJobsMustNotBeWeakened.allowFailureMustBeFalse": {
		Description: "Sub-control toggle requiring allow_failure to be false on matched security jobs.",
	},
	"securityJobsMustNotBeWeakened.allowFailureMustBeFalse.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"securityJobsMustNotBeWeakened.rulesMustNotBeRedefined": {
		Description: "Sub-control toggle requiring rules to not be redefined on matched security jobs.",
	},
	"securityJobsMustNotBeWeakened.rulesMustNotBeRedefined.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"securityJobsMustNotBeWeakened.whenMustNotBeManual": {
		Description: "Sub-control toggle requiring when to not be set to manual on matched security jobs.",
	},
	"securityJobsMustNotBeWeakened.whenMustNotBeManual.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"pipelineMustNotExecuteUnverifiedScripts.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"pipelineMustNotExecuteUnverifiedScripts.trustedUrls": {
		Description: "List of URL patterns that should not trigger findings; supports wildcards.",
	},
	"pipelineMustNotOverrideJobVariables.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"pipelineMustNotOverrideJobVariables.variables": {
		Description: "List of CI/CD variable names that must not be defined in the pipeline file; they should only be set via GitLab CI/CD Settings > Variables.",
	},
	"pipelineMustNotUseDockerInDocker.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"pipelineMustNotUseDockerInDocker.detectInsecureDaemon": {
		Description: "When true, also flags insecure daemon configuration in jobs that use a Docker-in-Docker service.",
	},
	"actionsMustBePinnedByCommitSha.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"actionsMustBePinnedByCommitSha.trustedOwners": {
		Description: "List of action-owner prefixes exempt from the pin-by-SHA requirement; only owners already inside the workflow's trust boundary should be listed.",
	},
	"githubActionMustComeFromAuthorizedSources.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"githubActionMustComeFromAuthorizedSources.trustGithubOfficialActions": {
		Description: "Trusts first-party GitHub-owned actions (actions/*, github/*); defaults to true when unset.",
		Default:     "true",
	},
	"githubActionMustComeFromAuthorizedSources.trustSameOrgActions": {
		Description: "Trusts actions whose owner is the same org or user as the scanned repository; defaults to true when unset.",
		Default:     "true",
	},
	"githubActionMustComeFromAuthorizedSources.minimumStars": {
		Description: "When greater than 0, trusts any action whose upstream repository has at least this many GitHub stars; 0 disables the star check.",
		Default:     "0",
	},
	"githubActionMustComeFromAuthorizedSources.trustedGithubActions": {
		Description: "Lists action sources that are always allowed; each entry is an exact owner/repo or an owner/* wildcard.",
	},
	"githubActionMustComeFromAuthorizedSources.includePlumberDefaults": {
		Description: "In overlay mode, unions Plumber's curated default trusted list with trustedGithubActions; set false to trust only the listed entries; ignored in legacy mode.",
		Default:     "true",
	},
	"workflowMustNotInjectUserInputInScripts.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"workflowMustNotWriteUntrustedContentToGitHubEnv.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"workflowMustNotUseDangerousTriggers.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"pullRequestTargetMustNotCheckoutHead.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"checkoutMustNotPersistCredentials.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"workflowsMustDeclarePermissions.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"reusableWorkflowsMustNotInheritSecrets.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"workflowMustNotExportEntireSecretsContext.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"workflowMustNotGrantPermissionsWriteAll.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"actionsMustNotBeArchived.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"actionRefsMustExistUpstream.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"actionsMustNotCarryKnownCVEs.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"actionsMustNotExecuteMutableRemoteCode.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"releaseWorkflowsMustNotRestoreUntrustedCache.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"releaseWorkflowsMustNotRestoreUntrustedCache.publishActions": {
		Description: "List of uses: owner/repo prefixes that mark a job as release intent.",
	},
	"releaseWorkflowsMustNotRestoreUntrustedCache.cacheActions": {
		Description: "Full inventory of cache-restoring actions with their per-action caching semantics; nothing about which actions cache is hardcoded.",
	},
	"releaseWorkflowsMustNotRestoreUntrustedCache.cacheActions[].action": {
		Description: "The uses: owner/repo prefix, such as actions/setup-go.",
	},
	"releaseWorkflowsMustNotRestoreUntrustedCache.cacheActions[].mode": {
		Description: "Caching mode for this action.",
		Enum:        []string{"always", "default", "opt-in"},
	},
	"releaseWorkflowsMustNotRestoreUntrustedCache.cacheActions[].disableInput": {
		Description: "For mode default, the action's with: input whose value turns caching off.",
	},
	"releaseWorkflowsMustNotRestoreUntrustedCache.cacheActions[].disableValue": {
		Description: "For mode default, the value of disableInput that turns caching off.",
	},
	"releaseWorkflowsMustNotRestoreUntrustedCache.cacheActions[].enableInput": {
		Description: "For mode opt-in, the with: input that turns caching on when set to a package manager.",
	},
	"releaseWorkflowsMustNotRestoreUntrustedCache.cacheActions[].enableContains": {
		Description: "Additionally requires enableInput's value to contain this substring, case-insensitive, for the cache to count as active.",
	},
	"releaseWorkflowsMustNotRestoreUntrustedCache.publishScriptPatterns": {
		Description: "List of regexes matched against run: scripts to mark a job as release intent.",
	},
	"releaseWorkflowsMustNotRestoreUntrustedCache.publishScriptExcludePatterns": {
		Description: "List of regexes that veto a publishScriptPatterns match on the same run: block, for verification-only forms that never publish.",
	},
	"releaseWorkflowsMustNotRestoreUntrustedCache.allowedJobs": {
		Description: "List of glob patterns matched against the namespaced job name; a matching job is exempt from this control.",
	},
	"workflowMustIncludeRequiredActions.enabled": {
		Description: "Turns the control on; when false or absent the control is skipped.",
	},
	"workflowMustIncludeRequiredActions.required": {
		Description: "Human-readable boolean expression defining required actions or reusable workflows; each entry is an owner/repo[/path] prefix matched ref-agnostically. Mutually exclusive with requiredGroups.",
	},
	"workflowMustIncludeRequiredActions.requiredGroups": {
		Description: "Required actions or reusable workflows in DNF form: outer array is OR, inner array is AND. Mutually exclusive with required.",
	},
}

func applyDocs(prefix string, fields []SchemaField) []SchemaField {
	out := make([]SchemaField, len(fields))
	for i, f := range fields {
		p := prefix + "." + f.Name
		if doc, ok := controlFieldDocs[p]; ok {
			f.Description = doc.Description
			f.Enum = append([]string(nil), doc.Enum...)
			f.Default = doc.Default
		}
		if len(f.Fields) > 0 {
			f.Fields = applyDocs(p, f.Fields)
		}
		if f.Elem != nil && len(f.Elem.Fields) > 0 {
			elem := *f.Elem
			elem.Fields = applyDocs(p+"[]", f.Elem.Fields)
			f.Elem = &elem
		}
		out[i] = f
	}
	return out
}
