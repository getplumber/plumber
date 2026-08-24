package control

// docsBaseURL is the base URL for Plumber issue documentation.
// Each issue code links to its dedicated documentation page.
const docsBaseURL = "https://getplumber.io/docs/cli/issues/"

// ErrorCode represents a unique Plumber issue code (ISSUE-XXX format).
type ErrorCode string

// IssueSeverity is the documented severity for an issue code (aligned with getplumber.io issue docs).
type IssueSeverity string

const (
	SeverityCritical IssueSeverity = "critical"
	SeverityHigh     IssueSeverity = "high"
	SeverityMedium   IssueSeverity = "medium"
	SeverityLow      IssueSeverity = "low"
)

// Issue codes for container image controls (1xx)
const (
	// ISSUE-101: Container image comes from an unauthorized registry
	CodeImageUnauthorizedSource ErrorCode = "ISSUE-101"
	// ISSUE-102: Container image uses a forbidden tag (e.g., latest, dev)
	CodeImageForbiddenTag ErrorCode = "ISSUE-102"
	// ISSUE-103: Container image is not pinned by digest
	CodeImageNotPinnedByDigest ErrorCode = "ISSUE-103"
	// ISSUE-701: Third-party GitHub Action reference is not pinned by commit SHA
	CodeActionUnpinned ErrorCode = "ISSUE-701"
	// ISSUE-704: Container registry password is hard-coded in the workflow
	CodeContainerHardcodedCredentials ErrorCode = "ISSUE-704"
	// ISSUE-705: Release/publish workflow primes a build cache from attacker-controlled artifacts
	CodeCachePoisoning ErrorCode = "ISSUE-705"
	// ISSUE-702: Action is hosted in an archived GitHub repository
	CodeActionArchivedRepo ErrorCode = "ISSUE-702"
	// ISSUE-707: Pinned commit SHA does not exist in the action's upstream repository
	CodeImpostorCommit ErrorCode = "ISSUE-707"
	// ISSUE-708: `# vX.Y.Z` comment does not match the SHA the ref resolves to
	CodeRefVersionMismatch ErrorCode = "ISSUE-708"
	// ISSUE-709: Action pinned by SHA is stale vs the latest upstream release
	CodeStaleActionRef ErrorCode = "ISSUE-709"
	// ISSUE-703: Action version carries a published security advisory
	CodeKnownVulnerableAction ErrorCode = "ISSUE-703"
	// ISSUE-711: Third-party action duplicates a runner built-in (gh CLI, etc.)
	CodeSuperfluousAction ErrorCode = "ISSUE-711"
	// ISSUE-706: Dockerfile FROM reference is not pinned by digest
	CodeDockerfileUnpinnedBase ErrorCode = "ISSUE-706"
	// ISSUE-712: Release / publish workflow produces unsigned artefacts
	CodeReleaseWorkflowUnsigned ErrorCode = "ISSUE-712"
	// ISSUE-713: Third-party GitHub Action comes from an unauthorized source
	CodeActionUnauthorizedSource ErrorCode = "ISSUE-713"
	// ISSUE-714: Action fetches and runs remote code from a mutable ref, in the open (no integrity check)
	CodeActionMutableRemoteExec ErrorCode = "ISSUE-714"
	// ISSUE-715: Action OBFUSCATES a remote code fetch/exec (decode-then-run)
	CodeActionObfuscatedRemoteExec ErrorCode = "ISSUE-715"
	// ISSUE-716: Action source could not be verified (fetch failed) — not a pass
	CodeActionRemoteExecUnverified ErrorCode = "ISSUE-716"
)

// Issue codes for CI/CD variable controls (2xx)
const (
	// ISSUE-203: Pipeline enables CI debug trace (CI_DEBUG_TRACE or CI_DEBUG_SERVICES)
	CodeDebugTraceEnabled ErrorCode = "ISSUE-203"
	// ISSUE-204: Unsafe variable expansion in shell re-interpretation context (eval, sh -c, etc.)
	CodeUnsafeVariableExpansion ErrorCode = "ISSUE-204"
	// ISSUE-205: A variable that should only be set in CI/CD Settings is overridden in the pipeline config
	CodeJobVariableOverridden ErrorCode = "ISSUE-205"
	// ISSUE-207: Workflow inlines user-controlled template expressions into a run: script
	CodeTemplateInjection ErrorCode = "ISSUE-207"
	// ISSUE-208: Workflow re-enables deprecated GitHub Actions workflow commands
	CodeInsecureCommands ErrorCode = "ISSUE-208"
	// ISSUE-209: Workflow writes untrusted content to $GITHUB_ENV or $GITHUB_PATH
	CodeGitHubEnvInjection ErrorCode = "ISSUE-209"
	// ISSUE-210: Workflow gates behaviour on a spoofable actor/bot check
	CodeBotConditions ErrorCode = "ISSUE-210"
	// ISSUE-211: Workflow `if:` condition is logically unsound (always true/false, tautology)
	CodeUnsoundCondition ErrorCode = "ISSUE-211"
	// ISSUE-212: Workflow misuses the `contains()` built-in (argument order, type)
	CodeUnsoundContains ErrorCode = "ISSUE-212"
	// ISSUE-215: Workflow expands a `vars.*` template into a shell script
	CodeTemplateInjectionVars ErrorCode = "ISSUE-215"
	// ISSUE-213: Workflow exports the whole `github` context via toJson(github)
	CodeUnsafeGithubContextDump ErrorCode = "ISSUE-213"
	// ISSUE-214: Workflow installs a package without pinning a version / lockfile
	CodeUnpinnedPackageInstall ErrorCode = "ISSUE-214"
)

// Issue codes for secret and credential handling controls (3xx)
const (
	// ISSUE-301 is RETIRED — do not reuse. It carried the gitleaks-based
	// "secret leak in pipeline configuration" rule until the integration
	// was removed (#310, advisory GHSA-w2xj-4v44-6rqr), and the
	// downstream jobs platform has mapped that meaning to 301 since
	// before the CLI rule existed, so the slot must stay vacant forever.

	// ISSUE-302: Reusable workflow called with `secrets: inherit`
	CodeSecretsInherit ErrorCode = "ISSUE-302"
	// ISSUE-303: Secret dereferenced via fromJSON bypasses log redaction
	CodeUnredactedSecrets ErrorCode = "ISSUE-303"
	// ISSUE-801: Workflow grants no explicit permissions, relying on the repo default
	CodeUndocumentedPermissions ErrorCode = "ISSUE-801"
	// ISSUE-305: Secret used without an environment gate
	CodeSecretsOutsideEnv ErrorCode = "ISSUE-305"
	// ISSUE-306: GitHub App token issued with revocation disabled
	CodeGitHubAppSkipRevoke ErrorCode = "ISSUE-306"
	// ISSUE-307: Checkout persists credentials in .git/config (artipacked)
	CodeArtipacked ErrorCode = "ISSUE-307"
	// ISSUE-308: Workflow reads a secret via a dynamic index (secrets[expr])
	CodeSecretsDynamicIndex ErrorCode = "ISSUE-308"
	// ISSUE-309: Workflow exfiltrates the entire secrets context via toJson(secrets).
	// Moved from ISSUE-301 in the 301/309 swap so the leaked-secrets rule could
	// take the slot already used by the downstream jobs platform.
	CodeOverprovisionedSecrets ErrorCode = "ISSUE-309"
)

// Issue codes for pipeline composition controls (4xx)
const (
	// ISSUE-401: Job is hardcoded (not sourced from include/component)
	CodeJobHardcoded ErrorCode = "ISSUE-401"
	// ISSUE-402: External CI ref collides with both a tag and a branch upstream
	// (GitLab include/component @ref, GitHub action/reusable-workflow @ref)
	CodeRefConfusion ErrorCode = "ISSUE-402"
	// ISSUE-403: Include uses an outdated version
	CodeIncludeOutdated ErrorCode = "ISSUE-403"
	// ISSUE-404: Include uses a forbidden version
	CodeIncludeForbiddenVersion ErrorCode = "ISSUE-404"
	// ISSUE-405: Required template is missing from the pipeline
	CodeTemplateMissing ErrorCode = "ISSUE-405"
	// ISSUE-406: Required template jobs are overridden
	CodeTemplateOverridden ErrorCode = "ISSUE-406"
	// ISSUE-408: Required component is missing from the pipeline
	CodeComponentMissing ErrorCode = "ISSUE-408"
	// ISSUE-409: Required component jobs are overridden
	CodeComponentOverridden ErrorCode = "ISSUE-409"
	// ISSUE-410: Security job is weakened (allow_failure, rules override, when: manual)
	CodeSecurityJobWeakened ErrorCode = "ISSUE-410"
	// ISSUE-411: Pipeline executes unverified scripts (curl|bash, base64|bash, download-then-exec, |sh)
	CodeUnverifiedScriptExecution ErrorCode = "ISSUE-411"
	// ISSUE-412: CI/CD job uses a Docker-in-Docker (dind) service
	CodeDockerInDockerUsage ErrorCode = "ISSUE-412"
	// ISSUE-413: CI/CD job uses Docker-in-Docker with insecure daemon configuration
	CodeDockerInDockerInsecure ErrorCode = "ISSUE-413"
	// ISSUE-802: Job reaches a dangerous trigger (workflow_run, issue_comment,
	// pull_request_review*, discussion*, gollum, fork) AND checks out fork
	// content. pull_request_target is owned by ISSUE-804.
	CodeDangerousTriggers ErrorCode = "ISSUE-802"
	// ISSUE-804: pull_request_target workflow explicitly checks out the PR head (tj-actions pattern)
	CodePullRequestTargetWithHeadCheckout ErrorCode = "ISSUE-804"
	// ISSUE-417: Required action or reusable workflow is not referenced anywhere in the project's workflows
	CodeRequiredActionMissing ErrorCode = "ISSUE-417"
)

// Issue codes for workflow-hygiene controls (6xx)
const (
	// ISSUE-601: Workflow has no explicit `name:` field
	CodeAnonymousDefinition ErrorCode = "ISSUE-601"
	// ISSUE-418: Workflow has no `concurrency:` block at either level
	CodeMissingConcurrency ErrorCode = "ISSUE-418"
	// ISSUE-419: Workflow uses a misfeature pattern (shell: cmd, inline pip install curl|sh, …)
	CodeWorkflowMisfeature ErrorCode = "ISSUE-419"
	// ISSUE-420: Workflow script contains obfuscation (zero-width / non-ASCII unicode, bidi)
	CodeWorkflowObfuscation ErrorCode = "ISSUE-420"
	// ISSUE-421: PyPI / npm publish relies on a static token instead of OIDC trusted publishing
	CodeUseTrustedPublishing ErrorCode = "ISSUE-421"
	// ISSUE-901: dependabot.yml re-enables insecure external code execution
	CodeDependabotInsecureExec ErrorCode = "ISSUE-901"
	// ISSUE-902: dependabot.yml update ecosystem has no cooldown window
	CodeDependabotMissingCooldown ErrorCode = "ISSUE-902"
	// ISSUE-903: Repository has workflows but no dependency update tool configured
	CodeDependencyUpdateToolMissing ErrorCode = "ISSUE-903"
	// ISSUE-904: Repository has workflows but none runs a SAST scanner
	CodeSASTWorkflowMissing ErrorCode = "ISSUE-904"
	// ISSUE-905: Repository has workflows but no SECURITY.md policy file
	CodeSecurityPolicyMissing ErrorCode = "ISSUE-905"
)

// Issue codes for access and authorization controls (5xx)
const (
	// ISSUE-501: Branch is not protected
	CodeBranchUnprotected ErrorCode = "ISSUE-501"
	// ISSUE-502: A merge-request approval rule covering all protected branches requires fewer approvals than the configured minimum
	CodeMRApprovalRulesBelowMinimum ErrorCode = "ISSUE-502"
	// ISSUE-504: No merge-request approval rule applies to all protected branches
	CodeMRApprovalRulesAllBranchesMissing ErrorCode = "ISSUE-504"
	// ISSUE-505: Branch has non-compliant protection settings
	CodeBranchNonCompliant ErrorCode = "ISSUE-505"
	// ISSUE-803: Job runs with overly broad permissions (write-all)
	CodeExcessivePermissions ErrorCode = "ISSUE-803"
)

// ErrorCodeInfo provides metadata about an issue code.
type ErrorCodeInfo struct {
	// Code is the unique issue code (e.g., ISSUE-102).
	Code ErrorCode `json:"code"`
	// Severity reflects potential impact (see documentation); used for Plumber Score.
	Severity IssueSeverity `json:"severity"`
	// Title is a short human-readable title used by SARIF / GLSAST / JSON
	// renderers when no provider-specific override is set. Acts as the
	// default; the catalog DisplayName covers the terminal renderer's
	// per-provider naming separately.
	Title string `json:"title"`
	// Description explains what the issue is. Same fallback semantics as
	// Title: rendered as-is when no provider override is set.
	Description string `json:"description"`
	// Remediation provides guidance on how to fix the issue.
	Remediation string `json:"remediation"`
	// DocURL is a direct link to the documentation for this issue.
	DocURL string `json:"docUrl"`
	// ControlName is the .plumber.yaml control key this code belongs to.
	ControlName string `json:"controlName"`

	// TitleByProvider lets cross-provider controls render different titles
	// in SARIF / JSON / GLSAST depending on which provider produced the
	// finding (mirrors the per-provider DisplayName already supported by
	// the catalog). Keyed by "gitlab" / "github". An empty map (the common
	// case) means TitleFor() falls back to Title for every provider.
	TitleByProvider map[string]string `json:"titleByProvider,omitempty"`
	// DescriptionByProvider works the same way for the longer description.
	DescriptionByProvider map[string]string `json:"descriptionByProvider,omitempty"`
}

// TitleFor returns the title to render for a finding emitted under the
// given provider ("gitlab" / "github"). Falls back to Title if no
// override is registered for the provider, so codes that don't need
// per-provider divergence stay a single Title declaration.
func (i ErrorCodeInfo) TitleFor(provider string) string {
	if override, ok := i.TitleByProvider[provider]; ok && override != "" {
		return override
	}
	return i.Title
}

// DescriptionFor mirrors TitleFor for the description.
func (i ErrorCodeInfo) DescriptionFor(provider string) string {
	if override, ok := i.DescriptionByProvider[provider]; ok && override != "" {
		return override
	}
	return i.Description
}

// errorCodeRegistry maps issue codes to their metadata.
var errorCodeRegistry = map[ErrorCode]ErrorCodeInfo{
	// Container image controls (1xx)
	CodeImageUnauthorizedSource: {
		Code:        CodeImageUnauthorizedSource,
		Severity:    SeverityHigh,
		Title:       "Untrusted image source",
		Description: "A container image is pulled from a registry that is not listed in the authorized sources. Using untrusted registries increases supply chain attack risk.",
		Remediation: "Use images from an authorized registry configured in .plumber.yaml under containerImageMustComeFromAuthorizedSources.authorizedSources, or add the registry to the authorized list.",
		DocURL:      docsBaseURL + string(CodeImageUnauthorizedSource),
		ControlName: "containerImageMustComeFromAuthorizedSources",
	},
	CodeImageForbiddenTag: {
		Code:        CodeImageForbiddenTag,
		Severity:    SeverityMedium,
		Title:       "Forbidden container image tag",
		Description: "A container image in the pipeline uses a tag that is forbidden by the configuration (e.g., 'latest', 'dev'). Mutable tags make builds non-reproducible because the underlying image can change without notice.",
		Remediation: "Pin the image to a specific immutable version tag (e.g., 'python:3.12.1' instead of 'python:latest'). Configure forbidden tags in .plumber.yaml under containerImageMustNotUseForbiddenTags.forbiddenTags.",
		DocURL:      docsBaseURL + string(CodeImageForbiddenTag),
		ControlName: "containerImageMustNotUseForbiddenTags",
	},
	CodeImageNotPinnedByDigest: {
		Code:        CodeImageNotPinnedByDigest,
		Severity:    SeverityHigh,
		Title:       "Container image is not pinned by digest",
		Description: "A container image in the pipeline is not pinned by its SHA256 digest. Without digest pinning, a tag can be reassigned to a different image, introducing supply chain risks.",
		Remediation: "Pin the image using its digest: 'image: registry.example.com/myimage@sha256:abc123...'. You can find the digest with 'docker inspect --format={{.RepoDigests}} <image>'.",
		DocURL:      docsBaseURL + string(CodeImageNotPinnedByDigest),
		ControlName: "containerImageMustNotUseForbiddenTags",
	},
	CodeActionUnpinned: {
		Code:        CodeActionUnpinned,
		Severity:    SeverityHigh,
		Title:       "Third-party action reference is not pinned by commit SHA",
		Description: "A GitHub Actions workflow references a third-party action with a mutable ref (tag or branch) instead of a 40-character commit SHA. Tag and branch refs can be reassigned by the action's maintainer — or by an attacker who compromises the action's repository — to point at arbitrary code, which then runs inside the caller workflow with its secrets. The March 2025 tj-actions/changed-files compromise (CVE-2025-30066) propagated this way to hundreds of repositories, including aquasecurity/trivy.",
		Remediation: "Replace `uses: owner/action@v4` with `uses: owner/action@<40-char-sha>` and add a `# vX.Y.Z` comment to document the version. Tools like Dependabot's `version-update-strategy: sha-and-version` can automate the update flow. Official GitHub-owned actions (actions/*, github/*) can be excluded if they are in the workflow's trusted boundary.",
		DocURL:      docsBaseURL + string(CodeActionUnpinned),
		ControlName: "actionsMustBePinnedByCommitSha",
	},
	CodeCachePoisoning: {
		Code:        CodeCachePoisoning,
		Severity:    SeverityHigh,
		Title:       "Release/publish workflow may consume a poisoned build cache",
		Description: "A release, tag or publish workflow uses `actions/cache@*` (or an equivalent cache action) without scoping the cache key to the ref being released. Caches on GitHub Actions are shared across branches according to the fallback rules: a malicious PR run on a feature branch can populate the same cache key that the release job later restores, silently injecting compiled artefacts, dependencies, or build scripts into the published output. Past supply-chain incidents have abused exactly this fallback to publish compromised packages to PyPI and npm.",
		Remediation: "Either disable the cache entirely on release/publish jobs, or scope the `key:` to the ref being released (e.g. `key: release-${{ github.ref_name }}-${{ hashFiles('**/go.sum') }}`) without a `restore-keys:` fallback that reaches into PR-populated entries. Verify artefacts against a checksum after restoring.",
		DocURL:      docsBaseURL + string(CodeCachePoisoning),
		ControlName: "releaseWorkflowsMustNotRestoreUntrustedCache",
	},
	CodeActionArchivedRepo: {
		Code:        CodeActionArchivedRepo,
		Severity:    SeverityHigh,
		Title:       "Action is hosted in an archived repository",
		Description: "A GitHub Actions workflow references an action whose upstream repository is archived. Archived repos no longer receive maintenance — security fixes, dependency bumps, compatibility patches all stop — and any existing vulnerability stays open forever. A new SHA can still be pushed by the last maintainer, so even pinning by SHA does not make the reference safe against a future takeover.",
		Remediation: "Replace the action with a maintained fork (audit the fork's owner first) or with an equivalent step implemented inline. If the behaviour is trivial, inlining the shell logic avoids the supply-chain dependency entirely.",
		DocURL:      docsBaseURL + string(CodeActionArchivedRepo),
		ControlName: "actionsMustNotBeArchived",
	},
	CodeActionUnauthorizedSource: {
		Code:        CodeActionUnauthorizedSource,
		Severity:    SeverityHigh,
		Title:       "Action comes from an unauthorized source",
		Description: "A GitHub Actions workflow references an action whose source is not authorized. Every third-party action runs with the caller workflow's token and secrets, so an unvetted owner is a direct supply-chain entry point — the vector behind the tj-actions/changed-files compromise (CVE-2025-30066), where an attacker also exploited repository rename/re-creation to squat a once-trusted name. Restricting actions to GitHub-official owners, an explicit org allowlist, and a minimum-popularity floor shrinks that attack surface to vetted sources.",
		Remediation: "Use an action from an authorized source. Configure the allowlist in .plumber.yaml under githubActionMustComeFromAuthorizedSources: keep trustGithubOfficialActions on for actions/* and github/*, add trusted owners or actions to trustedGithubActions (exact `owner/repo` or `owner/*`), and optionally set minimumStars to require a popularity threshold. Vendoring the action into a local `./.github/actions/…` directory removes the external dependency entirely.",
		DocURL:      docsBaseURL + string(CodeActionUnauthorizedSource),
		ControlName: "githubActionMustComeFromAuthorizedSources",
	},
	CodeActionMutableRemoteExec: {
		Code:        CodeActionMutableRemoteExec,
		Severity:    SeverityHigh,
		Title:       "Action fetches and runs remote code from a mutable ref (in the open)",
		Description: "A third-party action's own source fetches and executes a script from a MOVING ref (a branch such as main/master, not a tag or SHA) of another repository at runtime, and does not verify the download against a checksum. Pinning the action by commit SHA does not reach this: the fetched code can change with nothing committed where the pin can see it, so a compromise or retag of that upstream branch runs arbitrary code in the job with its token and secrets. The canonical example is anchore/scan-action, which fetches `raw.githubusercontent.com/anchore/grype/main/install.sh` and runs it. This is a static, text-level match on the action's source: it catches the in-the-open shape, not an author who deliberately hides the fetch (see ISSUE-715), so a clean result asserts 'no known pattern seen', not 'safe'.",
		Remediation: "Prefer an action that pins its downloads to an immutable ref AND verifies a checksum. Otherwise install the tool yourself from a pinned release, verify it against a checksum committed to your repo, and run it directly; or vendor the action and pin its internal fetch. A fetch that already verifies a pinned checksum is content-pinned and is not flagged here.",
		DocURL:      docsBaseURL + string(CodeActionMutableRemoteExec),
		ControlName: "actionsMustNotExecuteMutableRemoteCode",
	},
	CodeActionObfuscatedRemoteExec: {
		Code:        CodeActionObfuscatedRemoteExec,
		Severity:    SeverityCritical,
		Title:       "Action obfuscates a remote code fetch/exec",
		Description: "The action's own source decodes and then executes code: `base64 -d | sh`, `eval \"$(… | base64 -d)\"`, `eval(atob(…))`, `new Function(atob(x))`, a hex/xxd decode piped to a shell, and similar. No legitimate action needs to hide what it runs at runtime, so obfuscation-then-execute is treated as the strongest signal regardless of the host, ref, or encoding used. This deliberately does NOT chase every possible encoding (an unbounded space); it flags the act of hiding itself, which is what makes a clean result meaningful here.",
		Remediation: "Remove the obfuscation. If the action is a dependency, drop or vendor it and replace the hidden fetch with an explicit, pinned, checksum-verified install. An action that must decode data at runtime should not feed that decoded value into a shell or eval.",
		DocURL:      docsBaseURL + string(CodeActionObfuscatedRemoteExec),
		ControlName: "actionsMustNotExecuteMutableRemoteCode",
	},
	CodeActionRemoteExecUnverified: {
		Code:        CodeActionRemoteExecUnverified,
		Severity:    SeverityLow,
		Title:       "Action source could not be verified",
		Description: "Plumber could not fetch the action's own source (a network error, API rate limit, GitHub Enterprise Server host, private repo, or a Docker-image action) so it could not confirm whether the action fetches mutable remote code at runtime. This is surfaced as an explicit could-not-verify finding rather than a silent pass, because a silent pass would let the same repository score differently across CI environments and would over-claim safety on an unchecked dependency.",
		Remediation: "Re-run where the action source is reachable (authenticated token, network access) to get a definitive result, or vendor the action so its source is local and auditable. This finding is informational: it flags an unchecked dependency, not a confirmed problem.",
		DocURL:      docsBaseURL + string(CodeActionRemoteExecUnverified),
		ControlName: "actionsMustNotExecuteMutableRemoteCode",
	},
	CodeImpostorCommit: {
		Code:        CodeImpostorCommit,
		Severity:    SeverityCritical,
		Title:       "Pinned commit SHA does not belong to the action's repository",
		Description: "A workflow pins an action to a commit SHA that does not resolve in the action's upstream repository. That means either the SHA was mistyped (the reference silently runs whatever tag/branch GitHub falls back to, typically the default branch) or — far worse — the author was tricked by a PR comment / stargazer dashboard showing a detached commit that was never merged upstream. The name-and-SHA combination is the precise form of the `impostor commit` attack documented in academic supply-chain literature.",
		Remediation: "Replace the reference with a SHA that actually belongs to the action's repository. Use `gh api repos/<owner>/<repo>/commits/<sha>` to verify before committing the change. That endpoint only accepts commit SHAs, so a pin naming an annotated tag object answers 422 there; check it with `gh api repos/<owner>/<repo>/git/tags/<sha>` instead, which also reports the tag name and the commit it points at.",
		DocURL:      docsBaseURL + string(CodeImpostorCommit),
		ControlName: "actionRefsMustExistUpstream",
	},
	CodeRefVersionMismatch: {
		Code:        CodeRefVersionMismatch,
		Severity:    SeverityMedium,
		Title:       "`# vX.Y.Z` comment does not match the SHA",
		Description: "A workflow pins an action by commit SHA and adds a trailing `# vX.Y.Z` comment to document the intended version, but the SHA does not correspond to the tag named in the comment. Reviewers scanning diffs trust that annotation and miss the discrepancy, so silent downgrades (or upgrades that claim to be a patch) slip through review unnoticed.",
		Remediation: "Either update the SHA to the one the tag points at, or update the comment to the tag that actually corresponds to the SHA. `gh api repos/<owner>/<repo>/git/ref/tags/<tag>` returns the SHA the tag resolves to.",
		DocURL:      docsBaseURL + string(CodeRefVersionMismatch),
		ControlName: "actionPinCommentsMustMatchSha",
	},
	CodeStaleActionRef: {
		Code:        CodeStaleActionRef,
		Severity:    SeverityLow,
		Title:       "Action pin is behind the latest upstream release",
		Description: "A workflow pins an action to a commit SHA that predates the repository's most recent release. The SHA may still work today, but it is missing security fixes, dependency updates, and runtime compatibility changes shipped in later releases. Dependabot's `version-update-strategy: sha-and-version` handles the upgrade loop once configured.",
		Remediation: "Update the pin to the SHA of the latest release, and refresh the trailing `# vX.Y.Z` comment. Enable Dependabot with `package-ecosystem: github-actions` and `version-update-strategy: sha-and-version` to keep the pins fresh automatically.",
		DocURL:      docsBaseURL + string(CodeStaleActionRef),
		ControlName: "actionPinsMustNotBeStale",
	},
	CodeKnownVulnerableAction: {
		Code:        CodeKnownVulnerableAction,
		Severity:    SeverityCritical,
		Title:       "Action version carries a published security advisory",
		Description: "The pinned version of this action appears in the GitHub Advisory Database under the `actions` ecosystem. Running a workflow on a known-vulnerable action version inherits the published vulnerability class (RCE, secret exfiltration, privilege escalation, depending on the advisory). Examples from history: tj-actions/changed-files (CVE-2025-30066), reviewdog/action-setup with the March 2025 compromise, unpatched releases of `actions/artifact`. This check reports every advisory whose affected-version range covers the pinned ref.",
		Remediation: "Upgrade the action to a version outside the advisory's affected range (the advisory page lists a fixed-in version). Pin by SHA once upgraded so future retags cannot silently revert the fix. Configure Dependabot with `package-ecosystem: github-actions` to receive PR alerts when new advisories land.",
		DocURL:      docsBaseURL + string(CodeKnownVulnerableAction),
		ControlName: "actionsMustNotCarryKnownCVEs",
	},
	CodeDockerfileUnpinnedBase: {
		Code:        CodeDockerfileUnpinnedBase,
		Severity:    SeverityMedium,
		Title:       "Dockerfile FROM reference is not pinned by digest",
		Description: "A Dockerfile at the root of the repository (or under a known build directory) uses `FROM image:tag` without a `@sha256:…` digest. Tags are mutable at the registry level: an attacker who compromises the registry — or the image maintainer — can re-push the same tag to point at a different layer, silently injecting code into every later build that pulls the reference. The supply chain of the downstream artefact then inherits that substitution. Pinning by digest is the single control that neutralises this vector.",
		Remediation: "Replace `FROM image:tag` with `FROM image:tag@sha256:…`. `docker inspect --format='{{index .RepoDigests 0}}' image:tag` prints the digest for the tag you just pulled. Automate refresh with Dependabot or Renovate (`package-ecosystem: docker`, `version-update-strategy: sha-and-version`) so the pin stays current.",
		DocURL:      docsBaseURL + string(CodeDockerfileUnpinnedBase),
		ControlName: "dockerfilesMustPinBaseImageByDigest",
	},
	CodeReleaseWorkflowUnsigned: {
		Code:        CodeReleaseWorkflowUnsigned,
		Severity:    SeverityMedium,
		Title:       "Release / publish workflow produces unsigned artefacts",
		Description: "A workflow runs a release or publish action (goreleaser, softprops/action-gh-release, pypa publish, npm-publish, docker build+push) without invoking any signing step. Consumers pulling the released artefact have no cryptographic handle to verify the artefact was built by the expected pipeline rather than tampered with along the way (cache poisoning, compromised runner, repository takeover). Signing (Sigstore cosign, GPG, SLSA provenance) turns 'I trust this came from that repo' into a falsifiable statement.",
		Remediation: "Add a signing step to the release job: `sigstore/cosign-installer` followed by `cosign sign <artefact>` for container images, `sigstore/gh-action-sigstore-python` for Python wheels, `crazy-max/ghaction-import-gpg` + `gpg --detach-sign` for tarballs, or `--snapshot-github-actions` on goreleaser with the signing pipeline configured. Publish the `.sig` / `.asc` alongside the artefact in the release assets.",
		DocURL:      docsBaseURL + string(CodeReleaseWorkflowUnsigned),
		ControlName: "releaseWorkflowsMustSignArtefacts",
	},
	CodeSuperfluousAction: {
		Code:        CodeSuperfluousAction,
		Severity:    SeverityLow,
		Title:       "Third-party action duplicates functionality already on the runner",
		Description: "A workflow uses a third-party action to do something the GitHub-hosted runner already provides out of the box: `gh` CLI operations wrapped by `peter-evans/create-pull-request`, basic cache operations that `actions/cache` already covers, `nick-invision/retry` for a one-line `bash` retry loop. Each extra action is an extra supply-chain dependency for zero capability gain — the sort of reference where an `impostor-commit`, a tag retag, or a compromise of the upstream account buys the attacker a foothold with no functional reason to have taken that risk.",
		Remediation: "Replace the action with the equivalent inline shell step using the runner's built-in tooling (`gh pr create`, `gh release`, simple `bash` retry loops). Keeps the workflow readable AND removes a supply-chain link. When the capability is non-trivial (artifact caching, matrix fan-out), prefer the official `actions/*` action over a third-party duplicate.",
		DocURL:      docsBaseURL + string(CodeSuperfluousAction),
		ControlName: "actionsMustNotDuplicateRunnerBuiltins",
	},
	CodeContainerHardcodedCredentials: {
		Code:        CodeContainerHardcodedCredentials,
		Severity:    SeverityCritical,
		Title:       "Container registry password is hard-coded in the workflow",
		Description: "A GitHub Actions workflow sets `jobs.<name>.container.credentials.password` to a literal string instead of a `${{ secrets.X }}` reference. The password is committed to the repository's history in plain text; anyone with read access — including the entire public on a public repo — can retrieve it, and rotating it requires rewriting history to purge the leak.",
		Remediation: "Store the password in a repository, environment, or organization secret and reference it via `${{ secrets.<NAME> }}`. If the password is already exposed in git history, rotate it immediately and purge the literal with `git filter-repo` or a BFG run before re-publishing.",
		DocURL:      docsBaseURL + string(CodeContainerHardcodedCredentials),
		ControlName: "containerCredentialsMustComeFromSecrets",
	},

	// CI/CD variable controls (2xx)
	CodeDebugTraceEnabled: {
		Code:        CodeDebugTraceEnabled,
		Severity:    SeverityCritical,
		Title:       "Pipeline enables CI debug trace",
		Description: "The pipeline has CI_DEBUG_TRACE or CI_DEBUG_SERVICES enabled, which exposes all secret variables in the job log output. This is a critical security risk in production pipelines.",
		Remediation: "Remove or set CI_DEBUG_TRACE and CI_DEBUG_SERVICES to 'false' in your .gitlab-ci.yml variables section. These should only be used temporarily for debugging and never committed.",
		DocURL:      docsBaseURL + string(CodeDebugTraceEnabled),
		ControlName: "pipelineMustNotEnableDebugTrace",
	},
	CodeUnsafeVariableExpansion: {
		Code:        CodeUnsafeVariableExpansion,
		Severity:    SeverityMedium,
		Title:       "Unsafe variable expansion",
		Description: "A dangerous CI variable is expanded in a shell re-interpretation context (eval, sh -c, bash -c, source, etc.). The expanded value is executed as code, enabling command injection if the variable is user-controlled.",
		Remediation: "Avoid passing variables to commands that re-interpret input as shell code. Use the variable in a safe context (e.g. echo, env) or sanitize/allowlist values. Configure dangerousVariables and allowedPatterns in .plumber.yaml under pipelineMustNotUseUnsafeVariableExpansion.",
		DocURL:      docsBaseURL + string(CodeUnsafeVariableExpansion),
		ControlName: "pipelineMustNotUseUnsafeVariableExpansion",
	},
	CodeJobVariableOverridden: {
		Code:        CodeJobVariableOverridden,
		Severity:    SeverityHigh,
		Title:       "Job variable overrides controlled variable",
		Description: "A CI/CD variable that should only be set in GitLab CI/CD Settings (as a protected or project-level variable) is redefined in the pipeline configuration. This can neutralize security scanners, disable protections, or alter intended behavior.",
		Remediation: "Remove the variable from .gitlab-ci.yml and set it in GitLab CI/CD Settings > Variables instead. Configure the list of controlled variables in .plumber.yaml under pipelineMustNotOverrideJobVariables.variables.",
		DocURL:      docsBaseURL + string(CodeJobVariableOverridden),
		ControlName: "pipelineMustNotOverrideJobVariables",
	},

	// Pipeline composition controls (4xx)
	CodeJobHardcoded: {
		Code:        CodeJobHardcoded,
		Severity:    SeverityMedium,
		Title:       "Hardcoded job",
		Description: "A job in the pipeline is defined directly in the CI configuration instead of being sourced from a CI/CD component or include. Hardcoded jobs bypass governance and standardization.",
		Remediation: "Replace the hardcoded job with a CI/CD component or an include from an approved catalog. Use 'include:' or 'component:' directives in your .gitlab-ci.yml.",
		DocURL:      docsBaseURL + string(CodeJobHardcoded),
		ControlName: "pipelineMustNotIncludeHardcodedJobs",
	},
	CodeRefConfusion: {
		Code:        CodeRefConfusion,
		Severity:    SeverityMedium,
		Title:       "Reference collides with both a tag and a branch",
		Description: "An external CI reference is pinned to a name that exists upstream **as both a tag and a branch** (classic case: a tag `v1` kept in parallel with a branch `v1`). This covers GitHub Actions `uses:` refs and GitLab `include:` project `ref:` / component `@version` refs. The platform resolves the tag first, so today the pinned, tagged revision runs — but a maintainer rename, a typo, or a parameter that drops a character can switch the binding to the branch, which tracks every push. The ambiguity makes the reference fundamentally unreliable: the reviewer cannot tell from the YAML alone which of the two upstream revisions will execute, and the referenced code runs in the pipeline with its secrets and tokens.",
		Remediation: "Pin the reference to a 40-character commit SHA (preferred), which is unambiguous. Alternatively, ask the upstream maintainer to remove one of the two colliding refs; keeping both is a supply-chain landmine for every caller.",
		DocURL:      docsBaseURL + string(CodeRefConfusion),
		ControlName: "externalRefsMustNotCollide",
	},
	CodeIncludeOutdated: {
		Code:        CodeIncludeOutdated,
		Severity:    SeverityLow,
		Title:       "Outdated template",
		Description: "An included CI/CD component or template is not using the latest available version. Outdated versions may miss security patches, bug fixes, or improvements.",
		Remediation: "Update the include to use the latest version. Check the component/template repository for the latest release and update the version reference in your .gitlab-ci.yml.",
		DocURL:      docsBaseURL + string(CodeIncludeOutdated),
		ControlName: "includesMustBeUpToDate",
	},
	CodeIncludeForbiddenVersion: {
		Code:        CodeIncludeForbiddenVersion,
		Severity:    SeverityMedium,
		Title:       "Forbidden include version",
		Description: "An included CI/CD component or template uses a version that is explicitly forbidden (e.g., a mutable branch reference like 'main' instead of a tagged version).",
		Remediation: "Replace the forbidden version with an authorized version format. Use semantic version tags (e.g., '1.2.3' or '~latest') instead of branch names or mutable references as configured in .plumber.yaml.",
		DocURL:      docsBaseURL + string(CodeIncludeForbiddenVersion),
		ControlName: "includesMustNotUseForbiddenVersions",
	},
	CodeTemplateMissing: {
		Code:        CodeTemplateMissing,
		Severity:    SeverityHigh,
		Title:       "Missing required template",
		Description: "A CI/CD template required by the configuration is not included in the pipeline. This means a mandatory workflow step is missing.",
		Remediation: "Add the required template to your .gitlab-ci.yml using 'include:' with the template path specified in your .plumber.yaml under pipelineMustIncludeTemplate.",
		DocURL:      docsBaseURL + string(CodeTemplateMissing),
		ControlName: "pipelineMustIncludeTemplate",
	},
	CodeTemplateOverridden: {
		Code:        CodeTemplateOverridden,
		Severity:    SeverityMedium,
		Title:       "Forbidden override of required template",
		Description: "A required CI/CD template is included but some of its job keys are overridden locally, which may alter the intended behavior.",
		Remediation: "Remove the local overrides on the template's jobs. If customization is needed, check if the template provides variables for configuration instead of overriding job keys directly.",
		DocURL:      docsBaseURL + string(CodeTemplateOverridden),
		ControlName: "pipelineMustIncludeTemplate",
	},
	CodeComponentMissing: {
		Code:        CodeComponentMissing,
		Severity:    SeverityHigh,
		Title:       "Missing required component",
		Description: "A CI/CD component required by the configuration is not included in the pipeline. This means a mandatory compliance check or security scan is missing.",
		Remediation: "Add the required component to your .gitlab-ci.yml using 'include:' with the component path specified in your .plumber.yaml under pipelineMustIncludeComponent.",
		DocURL:      docsBaseURL + string(CodeComponentMissing),
		ControlName: "pipelineMustIncludeComponent",
	},
	CodeComponentOverridden: {
		Code:        CodeComponentOverridden,
		Severity:    SeverityMedium,
		Title:       "Forbidden override of required component",
		Description: "A required CI/CD component is included but some of its job keys are overridden locally, which may alter the intended behavior of the compliance check.",
		Remediation: "Remove the local overrides on the component's jobs. If customization is needed, check if the component provides input variables for configuration instead of overriding job keys directly.",
		DocURL:      docsBaseURL + string(CodeComponentOverridden),
		ControlName: "pipelineMustIncludeComponent",
	},
	CodeSecurityJobWeakened: {
		Code:        CodeSecurityJobWeakened,
		Severity:    SeverityCritical,
		Title:       "Security job weakened",
		Description: "A security job in the pipeline has been weakened by setting allow_failure to true, overriding rules with when: never or when: manual, or setting when to manual. This can cause critical security scans to be skipped or require manual intervention.",
		Remediation: "Ensure security jobs run automatically and block the pipeline on failure. Remove allow_failure: true, do not override rules with when: never or when: manual, and do not set when: manual on security jobs.",
		DocURL:      docsBaseURL + string(CodeSecurityJobWeakened),
		ControlName: "securityJobsMustNotBeWeakened",
	},
	CodeUnverifiedScriptExecution: {
		Code:        CodeUnverifiedScriptExecution,
		Severity:    SeverityHigh,
		Title:       "Unverified script execution",
		Description: "A CI/CD job executes a script without integrity verification: pipe-to-shell (curl | bash), download-then-exec, redirect-then-exec, base64-decode-to-shell (Megalodon-style), or any command piped into bash/sh. An attacker can exfiltrate CI secrets via a compromised URL or obfuscated inline payload.",
		Remediation: "Download scripts to a file, verify checksum or signature on the same line, then execute. Avoid piping remote or encoded content directly into a shell. Vendor scripts in-repo or use trusted package managers.",
		DocURL:      docsBaseURL + string(CodeUnverifiedScriptExecution),
		ControlName: "pipelineMustNotExecuteUnverifiedScripts",
	},

	CodeDockerInDockerUsage: {
		Code:        CodeDockerInDockerUsage,
		Severity:    SeverityHigh,
		Title:       "Docker-in-Docker service detected",
		Description: "A CI/CD job uses a Docker-in-Docker (dind) service. On shared runners running in privileged mode, this enables container escape, lateral movement, and access to secrets from other jobs on the same runner.",
		Remediation: "Replace Docker-in-Docker with a safer alternative such as Kaniko or Buildah for building container images. These tools do not require privileged mode and avoid the security risks of running a Docker daemon inside a CI container.",
		DocURL:      docsBaseURL + string(CodeDockerInDockerUsage),
		ControlName: "pipelineMustNotUseDockerInDocker",
	},
	CodeDockerInDockerInsecure: {
		Code:        CodeDockerInDockerInsecure,
		Severity:    SeverityHigh,
		Title:       "Docker-in-Docker with insecure daemon configuration",
		Description: "A CI/CD job uses Docker-in-Docker with an insecure daemon configuration. Setting DOCKER_TLS_CERTDIR to an empty string or using DOCKER_HOST with tcp://...:2375 disables TLS encryption between the CI job and the Docker daemon, allowing network-level eavesdropping and command injection.",
		Remediation: "If Docker-in-Docker is required, ensure TLS is enabled: do not set DOCKER_TLS_CERTDIR to an empty string, and use tcp://docker:2376 (TLS) instead of tcp://docker:2375 (plaintext). Prefer Kaniko or Buildah to avoid this pattern entirely.",
		DocURL:      docsBaseURL + string(CodeDockerInDockerInsecure),
		ControlName: "pipelineMustNotUseDockerInDocker",
	},

	// Access and authorization controls (5xx)
	CodeBranchUnprotected: {
		Code:        CodeBranchUnprotected,
		Severity:    SeverityCritical,
		Title:       "Branch protection missing",
		Description: "A branch that should be protected according to the configuration has no protection rules. Unprotected branches allow direct pushes and force pushes, bypassing code review.",
		Remediation: "Enable branch protection in GitLab: Settings > Repository > Protected Branches. Add the branch with appropriate access levels for push and merge.",
		DocURL:      docsBaseURL + string(CodeBranchUnprotected),
		ControlName: "branchMustBeProtected",
	},
	CodeMRApprovalRulesBelowMinimum: {
		Code:        CodeMRApprovalRulesBelowMinimum,
		Severity:    SeverityHigh,
		Title:       "Merge request approval rule requires too few approvals",
		Description: "A merge request approval rule that covers all protected branches requires fewer approvals than the configured minimum, so a protected branch can be merged with too little review.",
		Remediation: "Raise the rule's required approvals in Settings > Merge requests > Approval rules to at least your configured minimum, or narrow the rule's scope if it is not meant to cover all protected branches.",
		DocURL:      docsBaseURL + string(CodeMRApprovalRulesBelowMinimum),
		ControlName: "mergeRequestApprovalRulesMustRequireMinimumApprovals",
	},
	CodeMRApprovalRulesAllBranchesMissing: {
		Code:        CodeMRApprovalRulesAllBranchesMissing,
		Severity:    SeverityHigh,
		Title:       "No approval rule covers all protected branches",
		Description: "No merge request approval rule applies to all protected branches, so a protected branch can exist with no required approval and be merged without review.",
		Remediation: "Add a merge request approval rule that applies to all protected branches in Settings > Merge requests > Approval rules.",
		DocURL:      docsBaseURL + string(CodeMRApprovalRulesAllBranchesMissing),
		ControlName: "mergeRequestApprovalRulesMustCoverAllProtectedBranches",
	},
	CodeBranchNonCompliant: {
		Code:        CodeBranchNonCompliant,
		Severity:    SeverityHigh,
		Title:       "Branch protection configuration not compliant",
		Description: "A protected branch does not meet the required protection settings (e.g., force push allowed, access levels too permissive, code owner approval not required).",
		Remediation: "Update branch protection settings in GitLab: Settings > Repository > Protected Branches. Ensure force push is disabled, access levels meet the minimum, and code owner approval is required per your .plumber.yaml configuration.",
		DocURL:      docsBaseURL + string(CodeBranchNonCompliant),
		ControlName: "branchMustBeProtected",
	},
	CodeTemplateInjection: {
		Code:        CodeTemplateInjection,
		Severity:    SeverityCritical,
		Title:       "Template injection in workflow script",
		Description: "A GitHub Actions workflow inlines user-controlled template expressions (github.event.*, github.head_ref, ...) directly into a `run:` shell script. Attacker-controlled values such as PR titles, issue bodies or fork branch names can break out of the intended string and execute arbitrary commands with the job's secrets.",
		Remediation: "Move the template expression into an `env:` binding first, then reference the environment variable from the shell (`\"$TITLE\"`). Shell expansion of a bound variable quotes the value and neutralises injection payloads.",
		DocURL:      docsBaseURL + string(CodeTemplateInjection),
		ControlName: "workflowMustNotInjectUserInputInScripts",
	},
	CodeInsecureCommands: {
		Code:        CodeInsecureCommands,
		Severity:    SeverityHigh,
		Title:       "Deprecated workflow commands re-enabled",
		Description: "A GitHub Actions job re-enables the deprecated `::set-env::` / `::add-path::` workflow commands via ACTIONS_ALLOW_UNSECURE_COMMANDS. Those commands were disabled after CVE-2020-15228 because attacker-controlled log output can rewrite the running job's environment and PATH.",
		Remediation: "Remove the `ACTIONS_ALLOW_UNSECURE_COMMANDS` environment variable. Use the `$GITHUB_ENV` and `$GITHUB_PATH` files explicitly when you need to propagate values, and validate any untrusted content before writing to them.",
		DocURL:      docsBaseURL + string(CodeInsecureCommands),
		ControlName: "workflowMustNotReEnableInsecureCommands",
	},
	CodeBotConditions: {
		Code:        CodeBotConditions,
		Severity:    SeverityHigh,
		Title:       "Workflow gates behaviour on a spoofable actor/bot check",
		Description: "A GitHub Actions workflow gates behaviour on `github.actor`, `github.triggering_actor` or equivalent identity strings (`dependabot[bot]`, `renovate[bot]`, a specific username) without cryptographic backing. Those values are filled from whoever opened or synchronised the PR — an attacker can open a fork PR using a crafted username, or in some trigger types the `actor` field reflects the fork author, not the verified bot. Any step that trusts such a check (`if: github.actor == 'dependabot[bot]'`) can be bypassed by a malicious contributor forging the right login.",
		Remediation: "Never grant elevated behaviour based on `github.actor` / `github.triggering_actor` alone. For Dependabot-specific flows use the `pull_request` event with a separate privileged workflow triggered by `pull_request_target` only after a manual review, or rely on branch protections. For bots, verify the commit signature/author via git rather than the GitHub actor string.",
		DocURL:      docsBaseURL + string(CodeBotConditions),
		ControlName: "workflowMustNotTrustSpoofableActorChecks",
	},
	CodeUnsoundCondition: {
		Code:        CodeUnsoundCondition,
		Severity:    SeverityMedium,
		Title:       "Unsound `if:` condition (tautology, contradiction, or missing ${{ }})",
		Description: "A GitHub Actions `if:` expression contains a pattern that cannot be evaluated as intended: a tautology (`always() || ...`, `true == true`), a contradiction (`false && anything`), or a bare boolean string that is not wrapped in `${{ }}` (GitHub parses it as the literal string \"true\" / \"false\", which is always truthy). The gate the author thought they installed is not actually there — the step/job runs unconditionally (or never), usually silently.",
		Remediation: "Review the condition: remove dead branches (`always()` short-circuits OR), wrap every template expression in `${{ … }}`, and prefer simple comparisons over nested constructs. For debugging, `if: ${{ github.event_name == 'push' }}` is safer than `if: github.event_name == 'push'` which often parses as the literal string.",
		DocURL:      docsBaseURL + string(CodeUnsoundCondition),
		ControlName: "workflowConditionsMustBeSound",
	},
	CodeUnsoundContains: {
		Code:        CodeUnsoundContains,
		Severity:    SeverityMedium,
		Title:       "`contains()` built-in misused (argument order or type)",
		Description: "A GitHub Actions expression calls `contains()` with arguments in the wrong order or of incompatible types. The signature is `contains(haystack, needle)`: passing a single string as the first argument and a whole expression as the second inverts the semantics and the gate never matches the intended case. A common failure mode is `contains('main', github.ref)` — the literal `'main'` does not contain the full ref `refs/heads/main`, so the check always fails even on the `main` branch.",
		Remediation: "Use `contains(github.ref, 'refs/heads/main')` — the ref is the haystack, the branch name is the needle. For filter lists, convert to a set: `contains(fromJSON('[\"main\", \"release\"]'), github.ref_name)` makes the intent explicit.",
		DocURL:      docsBaseURL + string(CodeUnsoundContains),
		ControlName: "workflowContainsCallsMustBeSound",
	},
	CodeUnsafeGithubContextDump: {
		Code:        CodeUnsafeGithubContextDump,
		Severity:    SeverityHigh,
		Title:       "Entire `github` context serialised with toJson(github)",
		Description: "A `run:` step, env binding or action input serialises the whole `github` context (or `github.event`) with `toJson(...)`. The resulting JSON carries every user-controllable field GitHub exposes — PR title, issue body, fork branch name, commit message — bundled with metadata the workflow might otherwise believe is trusted. Any downstream consumer (log line, third-party action, HTTP header) then sees a payload that is trivially shell-injectable under a privileged trigger (`pull_request_target`, `workflow_run`). Same risk class as ISSUE-207 template-injection, but the dump form is worse: a single `echo $JSON` leaks the full attack surface rather than one field.",
		Remediation: "Never pass the `github` context whole. Extract the exact fields you need into named `env:` bindings first (`env: { PR_TITLE: ${{ github.event.pull_request.title }} }`), then reference the environment variable from the shell — expansion quotes the value automatically. If the downstream tool genuinely requires JSON, build it explicitly from the named fields with `jq -n --arg title \"$PR_TITLE\" '{title: $title}'`.",
		DocURL:      docsBaseURL + string(CodeUnsafeGithubContextDump),
		ControlName: "workflowMustNotExportEntireGitHubContext",
	},
	CodeUnpinnedPackageInstall: {
		Code:        CodeUnpinnedPackageInstall,
		Severity:    SeverityMedium,
		Title:       "Package installed without a pinned version or lockfile",
		Description: "A `run:` step invokes `pip install PKG` or `npm install PKG` without a pinned version (`pip install pkg==1.2.3`, `npm install pkg@1.2.3`) and without a lockfile install (`pip install -r requirements.txt`, `npm ci`). Every run then resolves whatever is latest on the registry at execution time — a window exploited repeatedly by typosquat and maintainer-account compromise attacks. Lockfiles (`package-lock.json`, `poetry.lock`, `pdm.lock`, …) combined with `npm ci` / `pip install -r requirements.txt --require-hashes` turn every run into a reproducible, verifiable install.",
		Remediation: "Replace `pip install pkg` with `pip install -r requirements.txt` (with hashes generated via `pip-compile --generate-hashes`) or pin every package explicitly: `pip install 'pkg==1.2.3'`. Replace `npm install pkg` with `npm ci` once the lockfile is committed. Enable Dependabot or Renovate on the locked manifest so upgrades still flow, reviewed, rather than silently.",
		DocURL:      docsBaseURL + string(CodeUnpinnedPackageInstall),
		ControlName: "workflowMustPinPackageInstalls",
	},
	CodeTemplateInjectionVars: {
		Code:        CodeTemplateInjectionVars,
		Severity:    SeverityLow,
		Title:       "Maintainer-adjacent template (`vars.*` or `inputs.*`) expanded into a shell script",
		Description: "A `run:` step inlines a `${{ vars.X }}` or `${{ inputs.X }}` expression directly into the shell command. `vars` values come from repository / organisation / environment variables set by maintainers; `inputs` values come from the caller of a reusable workflow. Neither is PR-author-controlled by default (ISSUE-207 covers that case), but both flip to attacker-controlled under specific conditions: a compromised maintainer account, a misconfigured org-level variable, or a caller workflow that proxies `github.event.*` into a reusable-workflow input. The canonical remediation is identical to ISSUE-207: bind the value through `env:` first, then reference the environment variable from the shell so expansion quotes it automatically.",
		Remediation: "Replace `${{ vars.X }}` / `${{ inputs.X }}` in the `run:` body with an `env:` binding plus `$X` dereference. Example: `env: { REGISTRY: ${{ vars.REGISTRY }} }` at the step, then `docker login \"$REGISTRY\"` in the script.",
		DocURL:      docsBaseURL + string(CodeTemplateInjectionVars),
		ControlName: "workflowMustNotInjectVarsInScripts",
	},
	CodeGitHubEnvInjection: {
		Code:        CodeGitHubEnvInjection,
		Severity:    SeverityHigh,
		Title:       "Untrusted content written to $GITHUB_ENV or $GITHUB_PATH",
		Description: "A GitHub Actions `run:` step appends a user-controlled value (PR title, issue body, fork branch name, ...) to `$GITHUB_ENV` or `$GITHUB_PATH`. The appended value becomes an environment variable or PATH entry for every subsequent step in the job. An attacker who controls the value can override existing variables (for example `NODE_OPTIONS=--require=./exfil.js`) or inject a malicious directory at the front of PATH, hijacking any later `npm`, `bash`, etc. invocation and exfiltrating secrets from privileged triggers.",
		Remediation: "Do not write user-controlled values into `$GITHUB_ENV` or `$GITHUB_PATH`. If you must propagate a value derived from user input, bind it through an `env:` block first (`env: { TITLE: ${{ github.event.issue.title }} }`) and validate/escape it before writing — or pass it as a step output instead. Restrict workflows touching these files to non-PR triggers when possible.",
		DocURL:      docsBaseURL + string(CodeGitHubEnvInjection),
		ControlName: "workflowMustNotWriteUntrustedContentToGitHubEnv",
	},
	CodeArtipacked: {
		Code:        CodeArtipacked,
		Severity:    SeverityHigh,
		Title:       "Checkout persists credentials in .git/config",
		Description: "A GitHub Actions job runs `actions/checkout` without disabling credential persistence. By default the action writes GITHUB_TOKEN into the cloned repository's .git/config. Any subsequent step that uploads `.git` as part of an artifact, or executes fork-controlled code, can exfiltrate the token.",
		Remediation: "Add `with: { persist-credentials: false }` on every `uses: actions/checkout@*` step unless the job legitimately needs to push back. When push is required, scope the token with an explicit `permissions:` block.",
		DocURL:      docsBaseURL + string(CodeArtipacked),
		ControlName: "checkoutMustNotPersistCredentials",
	},
	CodeUnredactedSecrets: {
		Code:        CodeUnredactedSecrets,
		Severity:    SeverityHigh,
		Title:       "Secret dereferenced via fromJSON bypasses log redaction",
		Description: "A GitHub Actions workflow dereferences a secret value with `fromJSON(secrets.X).y` — once fromJSON parses the secret, the inner fields are fresh strings GitHub does not recognise as masked values. Anything that echoes the sub-field (print, log, HTTP header, error message) leaks the plaintext to the job log.",
		Remediation: "Pass structured secrets through `env:` bindings that reference each leaf individually (`env: { API_KEY: ${{ secrets.MY_API_KEY }} }`) so log redaction keeps working. If a JSON blob must be split, do it inside a step that never echoes the result and writes only the necessary parts back to the environment.",
		DocURL:      docsBaseURL + string(CodeUnredactedSecrets),
		ControlName: "workflowMustNotUnredactSecretsViaFromJSON",
	},
	CodeUndocumentedPermissions: {
		Code:        CodeUndocumentedPermissions,
		Severity:    SeverityMedium,
		Title:       "Workflow has no explicit `permissions:` block",
		Description: "A GitHub Actions workflow declares neither a workflow-level nor per-job `permissions:` block. The runner then falls back to the repository-wide default GITHUB_TOKEN permissions — often `contents: write` or `read-all` — giving every step more authority than it needs. Any compromise (unpinned action, template-injection, cache poisoning) inherits the full default scope.",
		Remediation: "Declare the narrowest permissions explicitly: `permissions: { contents: read }` at the workflow level and widen per-job only when a step needs to push, comment on issues, etc. This enforces the principle of least privilege regardless of the repo default setting.",
		DocURL:      docsBaseURL + string(CodeUndocumentedPermissions),
		ControlName: "workflowsMustDeclarePermissions",
	},
	CodeSecretsDynamicIndex: {
		Code:        CodeSecretsDynamicIndex,
		Severity:    SeverityLow,
		Title:       "Secret accessed via a dynamic index `secrets[expr]`",
		Description: "A workflow reads `${{ secrets[expr] }}` where `expr` is not a quoted literal — typically an `env.VAR_NAME`, `inputs.NAME`, or a computed expression. The dynamic form lets the runtime resolve the secret name at execution, which effectively hands read access to every secret the job can see to whatever source controls `expr`. When `expr` comes from a maintainer-controlled env binding the risk is theoretical, but the pattern is brittle: a rename of the named secret, or a later refactor that introduces a template expression at the indexed position, silently promotes the weakness. Prefer naming each secret directly so the grant surface is explicit in the workflow source.",
		Remediation: "Replace `${{ secrets[env.X] }}` with a direct reference `${{ secrets.EXPECTED_NAME }}`. When a matrix really needs to select among N secrets, split the job into N copies with static names rather than indexing; the verbosity is worth the reviewability.",
		DocURL:      docsBaseURL + string(CodeSecretsDynamicIndex),
		ControlName: "workflowMustNotIndexSecretsDynamically",
	},
	CodeGitHubAppSkipRevoke: {
		Code:        CodeGitHubAppSkipRevoke,
		Severity:    SeverityHigh,
		Title:       "GitHub App token issued with revocation disabled",
		Description: "A workflow step that mints a GitHub App installation token (e.g. `actions/create-github-app-token`) sets `skip-token-revoke: true`. That keeps the minted token alive after the workflow finishes, which turns a scoped, short-lived credential into a long-lived one. Any later leak (log fragment, restored cache, exfiltrated artefact) hands the attacker a working token well after the run completes, instead of getting back a revoked one.",
		Remediation: "Remove the `skip-token-revoke: true` input (the default is to revoke). Only keep revocation disabled for workflows that legitimately need to hand the token to a downstream step launched after this workflow — and even then, prefer re-minting it fresh in the downstream workflow.",
		DocURL:      docsBaseURL + string(CodeGitHubAppSkipRevoke),
		ControlName: "githubAppTokensMustBeRevokedOnExit",
	},
	CodeSecretsOutsideEnv: {
		Code:        CodeSecretsOutsideEnv,
		Severity:    SeverityMedium,
		Title:       "Deploy / release job uses secrets without an `environment:` gate",
		Description: "A GitHub Actions job that consumes production secrets (deploy, release, publish) does not declare an `environment:` field. Environments are the gatekeeper GitHub exposes for required reviewers, wait timers, and deployment branch rules — without one, any caller on the configured trigger goes straight to the secret-bearing step, no human-in-the-loop. Combined with a spoofable trigger (ISSUE-802) or an over-broad branch pattern, the secret can be exfiltrated without any review.",
		Remediation: "Put production secrets behind environments. Attach the environment to the deploy job (`environment: production`) and configure required reviewers / wait timers on the environment in the repository settings.",
		DocURL:      docsBaseURL + string(CodeSecretsOutsideEnv),
		ControlName: "deployJobsMustUseEnvironmentGate",
	},
	CodeOverprovisionedSecrets: {
		Code:        CodeOverprovisionedSecrets,
		Severity:    SeverityCritical,
		Title:       "Entire secrets context exported via toJson(secrets)",
		Description: "A GitHub Actions workflow serialises the whole `secrets` context with `toJson(secrets)` or `toJSON(secrets)` and pipes the result into a step's environment, run script, or `with:` input. The resulting string contains every secret the job has access to — repository, organisation and environment — and travels through whatever downstream consumer the step passes it to (a third-party action, a remote server, a log line). Even with GitHub's automatic log redaction, a single `echo` of the JSON payload has been enough to leak tokens in past supply-chain incidents; a compromised reusable action sees them directly regardless of logging.",
		Remediation: "Pass only the specific secrets the step needs, by name: `env: { TOKEN: ${{ secrets.NPM_TOKEN }} }`. If the step forwards credentials to a reusable workflow, name each one in the `secrets:` block of the call rather than using `toJson(secrets)`.",
		DocURL:      docsBaseURL + string(CodeOverprovisionedSecrets),
		ControlName: "workflowMustNotExportEntireSecretsContext",
	},
	CodeSecretsInherit: {
		Code:        CodeSecretsInherit,
		Severity:    SeverityHigh,
		Title:       "Reusable workflow called with `secrets: inherit`",
		Description: "A GitHub Actions job calls a reusable workflow (`jobs.<name>.uses: owner/repo/.github/workflows/x.yml@ref`) with `secrets: inherit`. The call forwards every secret visible to the caller — repo, organisation, environment — to the reusable workflow, regardless of what the reusable workflow actually needs. A compromise of the reusable workflow (upstream maintainer account, malicious PR merged on the reusable side, tag retag) then sees the full secret surface of every caller.",
		Remediation: "Replace `secrets: inherit` with an explicit mapping that names only the secrets the reusable workflow needs: `secrets: { NPM_TOKEN: ${{ secrets.NPM_TOKEN }} }`. For internal reusable workflows hosted in the same repository the risk is lower but the principle stands — narrow the scope so a future incident exposes a minimum.",
		DocURL:      docsBaseURL + string(CodeSecretsInherit),
		ControlName: "reusableWorkflowsMustNotInheritSecrets",
	},
	CodeDangerousTriggers: {
		Code:        CodeDangerousTriggers,
		Severity:    SeverityCritical,
		Title:       "Dangerous workflow trigger",
		Description: "A GitHub Actions job is reachable via a trigger that runs with the base repository's secrets while being influenceable by an unprivileged caller (`workflow_run`, `issue_comment`, `pull_request_review`, `pull_request_review_comment`, `discussion`, `discussion_comment`, `gollum`, `fork`) AND it checks out fork-controlled code. The `pull_request_target` case is owned by ISSUE-804 (pull-request-target-with-head-checkout). This is the same exploit class as the March 2025 tj-actions/changed-files supply-chain compromise (CVE-2025-30066).",
		Remediation: "Prefer the standard `pull_request` trigger unless access to base-repo secrets is strictly required. If a secret-bearing trigger is necessary, never check out fork content and never render github.event.* / github.head_ref into shell commands. For `workflow_run`, keep the job restricted to non-secret-bearing steps.",
		DocURL:      docsBaseURL + string(CodeDangerousTriggers),
		ControlName: "workflowMustNotUseDangerousTriggers",
	},
	CodeAnonymousDefinition: {
		Code:        CodeAnonymousDefinition,
		Severity:    SeverityLow,
		Title:       "Workflow has no explicit name",
		Description: "A GitHub Actions workflow file omits the top-level `name:` field, so GitHub falls back to the file path in the Actions UI, pull-request checks, required-status-check rules, and audit logs. In a repository with many workflows this makes dashboards harder to read and — more importantly — causes the required-status-check settings to bind to file paths that change with renames, silently disabling a compliance gate.",
		Remediation: "Add a human-readable `name: <descriptive-name>` at the top of every workflow. Keep the name stable so branch protections and required status checks continue to match after renames.",
		DocURL:      docsBaseURL + string(CodeAnonymousDefinition),
		ControlName: "workflowsMustHaveExplicitName",
	},
	CodeWorkflowMisfeature: {
		Code:        CodeWorkflowMisfeature,
		Severity:    SeverityMedium,
		Title:       "Workflow uses a known misfeature pattern",
		Description: "A GitHub Actions workflow uses a pattern that is supported but widely considered harmful: `shell: cmd` / `shell: powershell` on Windows runners (legacy shells, weak quoting, historical CVEs), an inline pip/gem/bundler install against a network URL, or an `actions/upload-artifact` of the checkout directory (leaks `.git` including tokens if ISSUE-307 artipacked also fires).",
		Remediation: "Switch Windows jobs to `shell: pwsh`. Vendor dependencies or use a pinned install step with checksums. Never upload the checkout directory as an artefact — upload the build output only.",
		DocURL:      docsBaseURL + string(CodeWorkflowMisfeature),
		ControlName: "workflowMustNotUseKnownMisfeatures",
	},
	CodeWorkflowObfuscation: {
		Code:        CodeWorkflowObfuscation,
		Severity:    SeverityHigh,
		Title:       "Workflow script contains obfuscation (zero-width / bidi / non-ASCII homoglyphs)",
		Description: "A GitHub Actions `run:` script or an expression carries invisible characters — zero-width spaces, bidirectional override codepoints (Trojan Source, CVE-2021-42574), or homoglyph identifiers mixing Cyrillic / Greek letters with Latin. The rendered source reads harmless on GitHub while the runner executes a different instruction. This was seen in the wild in backdoored npm / PyPI packages and has been documented as a supply-chain attack primitive since 2021.",
		Remediation: "Strip non-ASCII characters from workflow scripts and expression references unless strictly necessary (localised strings, user-facing labels). Enable `.gitattributes` pre-commit checks that block zero-width and bidirectional Unicode in source files.",
		DocURL:      docsBaseURL + string(CodeWorkflowObfuscation),
		ControlName: "workflowMustNotContainObfuscation",
	},
	CodeUseTrustedPublishing: {
		Code:        CodeUseTrustedPublishing,
		Severity:    SeverityHigh,
		Title:       "Publish step relies on a static token instead of OIDC trusted publishing",
		Description: "A GitHub Actions workflow publishes to PyPI, npm, or Maven Central using a long-lived `API_TOKEN` / `NPM_TOKEN` / `OSSRH_USERNAME` secret instead of OIDC-backed trusted publishing. Static publish tokens are reusable from anywhere they leak to — logs, build caches, malicious dependencies — whereas OIDC tokens are short-lived and bound to a specific repository / environment / workflow.",
		Remediation: "Migrate to trusted publishing: for PyPI set a publisher in the project settings and drop the token; for npm use the `--provenance` flag with OIDC; for Maven Central use the Sonatype portal's trusted publishing. Delete the static token once OIDC is live.",
		DocURL:      docsBaseURL + string(CodeUseTrustedPublishing),
		ControlName: "publishWorkflowsMustUseOidcTrustedPublishing",
	},
	CodeDependabotMissingCooldown: {
		Code:        CodeDependabotMissingCooldown,
		Severity:    SeverityLow,
		Title:       "Dependabot ecosystem has no cooldown window",
		Description: "An update ecosystem in `.github/dependabot.yml` declares no `cooldown:` block. Dependabot then opens a PR the instant a new upstream version is published — including when that version was uploaded minutes ago by a compromised maintainer account. A cooldown window (48–72 hours is common) gives the security-advisory pipeline time to flag a bad release before the automation merges it.",
		Remediation: "Add a `cooldown:` block to each update ecosystem: for example `cooldown: { default-days: 3, semver-major-days: 7, include: [\"*\"] }`. Adjust the window to fit the project's patching tolerance but never skip it for ecosystems that auto-merge.",
		DocURL:      docsBaseURL + string(CodeDependabotMissingCooldown),
		ControlName: "dependabotEcosystemsMustHaveCooldown",
	},
	CodeDependencyUpdateToolMissing: {
		Code:        CodeDependencyUpdateToolMissing,
		Severity:    SeverityMedium,
		Title:       "Repository has workflows but no dependency update tool",
		Description: "The repository ships CI/CD workflows but neither `.github/dependabot.yml` nor `renovate.json` / `.renovaterc` is configured. Dependencies then drift as upstream security patches land — nothing opens the PRs that would pull them in. On a project with any third-party action pinning (which every sane workflow does), this means SHA pins go stale and every unpatched CVE for the pinned versions stays unreachable until a human remembers to refresh the locks.",
		Remediation: "Add `.github/dependabot.yml` with at minimum `package-ecosystem: github-actions` and your primary language ecosystem (npm, pip, gomod, etc.). For more configurable flows prefer Renovate: `npx -y renovate-config-validator` validates a `renovate.json` before commit.",
		DocURL:      docsBaseURL + string(CodeDependencyUpdateToolMissing),
		ControlName: "repositoriesMustConfigureDependencyUpdates",
	},
	CodeSASTWorkflowMissing: {
		Code:        CodeSASTWorkflowMissing,
		Severity:    SeverityLow,
		Title:       "No static analysis scanner runs in CI",
		Description: "None of the repository's workflows invokes a recognised SAST scanner (CodeQL, Semgrep, SonarQube, Trivy config scan, Snyk, FOSSA, etc.). Static analysis catches whole vulnerability classes — injection, unsafe deserialisation, crypto misuse — before they reach production; leaving it out of CI means the only gate is manual review, which misses regressions exactly when the diff is large.",
		Remediation: "Add a workflow that runs CodeQL (`github/codeql-action/init` + `analyze`, free for public repos), Semgrep, or an equivalent SAST scanner on pushes to the default branch and on pull requests. Enable GitHub's code-scanning alerts so findings open issues rather than sit in log output.",
		DocURL:      docsBaseURL + string(CodeSASTWorkflowMissing),
		ControlName: "repositoriesMustRunSAST",
	},
	CodeSecurityPolicyMissing: {
		Code:        CodeSecurityPolicyMissing,
		Severity:    SeverityLow,
		Title:       "Repository has no SECURITY.md policy file",
		Description: "The repository has no `SECURITY.md` (nor `.github/SECURITY.md`, nor `docs/SECURITY.md`) documenting the vulnerability disclosure process. Researchers who find an issue have no public contact beyond opening a GitHub issue — which defeats coordinated disclosure and teaches them to dump vulnerabilities in the open. The file can be short: two lines naming the contact channel and the expected response window are enough to move reports off the public tracker.",
		Remediation: "Add a `SECURITY.md` at the repo root or under `.github/`. GitHub ships a template (New file → security policy). Include: the supported versions, the reporting channel (email / security@ / private advisory), the expected first-response SLA, and any bounty / safe-harbour terms the project honours.",
		DocURL:      docsBaseURL + string(CodeSecurityPolicyMissing),
		ControlName: "repositoriesMustPublishSecurityPolicy",
	},
	CodeDependabotInsecureExec: {
		Code:        CodeDependabotInsecureExec,
		Severity:    SeverityCritical,
		Title:       "Dependabot re-enables insecure external code execution",
		Description: "The repository's `.github/dependabot.yml` sets `insecure-external-code-execution: allow` for one of its update ecosystems. Dependabot will then execute install / postinstall hooks from every candidate dependency version during its version-resolution passes, giving any compromised upstream package a path to run arbitrary code in the Dependabot runner — which holds privileged access to the repository via a non-auditable push token. This is the option Dependabot itself documents as dangerous and defaults to `deny`.",
		Remediation: "Remove the `insecure-external-code-execution: allow` entry. If a specific ecosystem genuinely requires executing upstream scripts to resolve versions, scope the allowance narrowly with `enable-beta-ecosystems: false` and pair it with a dedicated runner isolation review — do not set it repository-wide.",
		DocURL:      docsBaseURL + string(CodeDependabotInsecureExec),
		ControlName: "dependabotMustNotAllowInsecureExternalCodeExecution",
	},
	CodeMissingConcurrency: {
		Code:        CodeMissingConcurrency,
		Severity:    SeverityMedium,
		Title:       "Workflow has no concurrency block",
		Description: "A GitHub Actions workflow declares no `concurrency:` block at either the workflow or the job level. Without it, concurrent pushes to the same branch (common during rebases and force-pushes) start parallel runs that race on caches, artifact uploads, and external state — and burn runner minutes. When the workflow deploys, it can also land stale state by overtaking a newer run.",
		Remediation: "Add a `concurrency` block that groups runs by ref: `concurrency: { group: ${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: true }`. For deploy workflows, keep `cancel-in-progress: false` so an in-flight deploy finishes cleanly.",
		DocURL:      docsBaseURL + string(CodeMissingConcurrency),
		ControlName: "workflowsMustDeclareConcurrency",
	},
	CodePullRequestTargetWithHeadCheckout: {
		Code:        CodePullRequestTargetWithHeadCheckout,
		Severity:    SeverityCritical,
		Title:       "pull_request_target workflow explicitly checks out the PR head",
		Description: "A workflow triggered by `pull_request_target` calls `actions/checkout` with an explicit `ref:` pointing at the pull request's head (e.g. `github.event.pull_request.head.sha`, `github.head_ref`). This is the exact pattern behind the March 2025 tj-actions/changed-files compromise (CVE-2025-30066): the workflow has access to the base repository's secrets AND it executes code controlled by the PR author. Any shell step that runs after the checkout is a direct path to secret exfiltration. Unlike the broader dangerous-triggers check (ISSUE-802) which flags the trigger itself, this rule flags the actual exploitable combination.",
		Remediation: "Either switch to the standard `pull_request` event (runs in the fork's context, no base-repo secrets), or remove the explicit `ref:` input so `actions/checkout` falls back to the base repository's SHA. If cross-context code must be examined, split the job: a small pull_request_target job gathers metadata, then hands off to a separate pull_request workflow that executes the fork code.",
		DocURL:      docsBaseURL + string(CodePullRequestTargetWithHeadCheckout),
		ControlName: "pullRequestTargetMustNotCheckoutHead",
	},
	CodeRequiredActionMissing: {
		Code:        CodeRequiredActionMissing,
		Severity:    SeverityHigh,
		Title:       "Required action or reusable workflow is missing",
		Description: "A GitHub action or reusable workflow declared as required in `workflowMustIncludeRequiredActions.requiredGroups` is not referenced by any job or step in the project's `.github/workflows/` files. The missing reference means a mandatory security scan, compliance check, or organization-wide workflow is not actually running on this repository.",
		Remediation: "Add a `uses: <owner>/<repo>[@<ref>]` step that references the required action, or a `jobs.<name>.uses: <owner>/<repo>/.github/workflows/<file>.yml@<ref>` job that calls the required reusable workflow. The exact path declared in `.plumber.yaml` under `workflowMustIncludeRequiredActions` is matched ref-agnostically, so any pinned ref works.",
		DocURL:      docsBaseURL + string(CodeRequiredActionMissing),
		ControlName: "workflowMustIncludeRequiredActions",
	},
	CodeExcessivePermissions: {
		Code:        CodeExcessivePermissions,
		Severity:    SeverityHigh,
		Title:       "Excessive workflow permissions",
		Description: "A GitHub Actions job's effective permissions block grants `write-all`, giving its GITHUB_TOKEN write access to every API scope regardless of what the job actually needs. Paired with a compromise through injection, dangerous triggers or a malicious action, this amplifies impact to full repository control.",
		Remediation: "Declare the narrowest permissions block that lets the job do its work. Prefer `permissions: { contents: read }` at the workflow level and grant additional scopes only on the jobs that truly need them.",
		DocURL:      docsBaseURL + string(CodeExcessivePermissions),
		ControlName: "workflowMustNotGrantPermissionsWriteAll",
	},
}

// LookupCode returns the ErrorCodeInfo for a given issue code, or nil if not found.
func LookupCode(code ErrorCode) *ErrorCodeInfo {
	info, ok := errorCodeRegistry[code]
	if !ok {
		return nil
	}
	return &info
}

// SeverityForCode returns the documented severity for a code, or medium if unknown.
func SeverityForCode(code ErrorCode) IssueSeverity {
	info := LookupCode(code)
	if info == nil {
		return SeverityMedium
	}
	return info.Severity
}

// AllCodes returns all registered issue codes sorted by code.
func AllCodes() []ErrorCodeInfo {
	codes := make([]ErrorCodeInfo, 0, len(errorCodeRegistry))
	for _, info := range errorCodeRegistry {
		codes = append(codes, info)
	}
	// Sort by code for deterministic output
	for i := 0; i < len(codes); i++ {
		for j := i + 1; j < len(codes); j++ {
			if codes[i].Code > codes[j].Code {
				codes[i], codes[j] = codes[j], codes[i]
			}
		}
	}
	return codes
}

// DocURL returns the documentation URL for a given issue code.
func (c ErrorCode) DocURL() string {
	info := LookupCode(c)
	if info == nil {
		return docsBaseURL
	}
	return info.DocURL
}

// String returns the string representation of an issue code.
func (c ErrorCode) String() string {
	return string(c)
}
