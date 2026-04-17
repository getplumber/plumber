package control

// docsBaseURL is the base URL for Plumber issue documentation.
// Each issue code links to its dedicated documentation page.
const docsBaseURL = "https://getplumber.io/docs/use-plumber/issues/"

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
)

// Issue codes for CI/CD variable controls (2xx)
const (
	// ISSUE-203: Pipeline enables CI debug trace (CI_DEBUG_TRACE or CI_DEBUG_SERVICES)
	CodeDebugTraceEnabled ErrorCode = "ISSUE-203"
	// ISSUE-204: Unsafe variable expansion in shell re-interpretation context (eval, sh -c, etc.)
	CodeUnsafeVariableExpansion ErrorCode = "ISSUE-204"
	// ISSUE-205: A variable that should only be set in CI/CD Settings is overridden in the pipeline config
	CodeJobVariableOverridden ErrorCode = "ISSUE-205"
)

// Issue codes for pipeline composition controls (4xx)
const (
	// ISSUE-401: Job is hardcoded (not sourced from include/component)
	CodeJobHardcoded ErrorCode = "ISSUE-401"
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
	// ISSUE-411: Pipeline downloads and executes a script without integrity verification (curl|bash, wget|sh)
	CodeUnverifiedScriptExecution ErrorCode = "ISSUE-411"
	// ISSUE-412: CI/CD job uses a Docker-in-Docker (dind) service
	CodeDockerInDockerUsage ErrorCode = "ISSUE-412"
	// ISSUE-413: CI/CD job uses Docker-in-Docker with insecure daemon configuration
	CodeDockerInDockerInsecure ErrorCode = "ISSUE-413"
)

// Issue codes for access and authorization controls (5xx)
const (
	// ISSUE-501: Branch is not protected
	CodeBranchUnprotected ErrorCode = "ISSUE-501"
	// ISSUE-505: Branch has non-compliant protection settings
	CodeBranchNonCompliant ErrorCode = "ISSUE-505"
)

// ErrorCodeInfo provides metadata about an issue code.
type ErrorCodeInfo struct {
	// Code is the unique issue code (e.g., ISSUE-102).
	Code ErrorCode `json:"code"`
	// Severity reflects potential impact (see documentation); used for Plumber Score.
	Severity IssueSeverity `json:"severity"`
	// Title is a short human-readable title.
	Title string `json:"title"`
	// Description explains what the issue is.
	Description string `json:"description"`
	// Remediation provides guidance on how to fix the issue.
	Remediation string `json:"remediation"`
	// DocURL is a direct link to the documentation for this issue.
	DocURL string `json:"docUrl"`
	// ControlName is the .plumber.yaml control key this code belongs to.
	ControlName string `json:"controlName"`
}

// errorCodeRegistry maps issue codes to their metadata.
var errorCodeRegistry = map[ErrorCode]ErrorCodeInfo{
	// Container image controls (1xx)
	CodeImageUnauthorizedSource: {
		Code:        CodeImageUnauthorizedSource,
		Severity:    SeverityCritical,
		Title:       "Untrusted image source",
		Description: "A container image is pulled from a registry that is not listed in the authorized sources. Using untrusted registries increases supply chain attack risk.",
		Remediation: "Use images from an authorized registry configured in .plumber.yaml under containerImageMustComeFromAuthorizedSources.authorizedSources, or add the registry to the authorized list.",
		DocURL:      docsBaseURL + string(CodeImageUnauthorizedSource),
		ControlName: "containerImageMustComeFromAuthorizedSources",
	},
	CodeImageForbiddenTag: {
		Code:        CodeImageForbiddenTag,
		Severity:    SeverityHigh,
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
		Severity:    SeverityHigh,
		Title:       "Unsafe variable expansion",
		Description: "A dangerous CI variable is expanded in a shell re-interpretation context (eval, sh -c, bash -c, source, etc.). The expanded value is executed as code, enabling command injection if the variable is user-controlled.",
		Remediation: "Avoid passing variables to commands that re-interpret input as shell code. Use the variable in a safe context (e.g. echo, env) or sanitize/allowlist values. Configure dangerousVariables and allowedPatterns in .plumber.yaml under pipelineMustNotUseUnsafeVariableExpansion.",
		DocURL:      docsBaseURL + string(CodeUnsafeVariableExpansion),
		ControlName: "pipelineMustNotUseUnsafeVariableExpansion",
	},
	CodeJobVariableOverridden: {
		Code:        CodeJobVariableOverridden,
		Severity:    SeverityCritical,
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
		Severity:    SeverityHigh,
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
		Severity:    SeverityHigh,
		Title:       "Forbidden override of required component",
		Description: "A required CI/CD component is included but some of its job keys are overridden locally, which may alter the intended behavior of the compliance check.",
		Remediation: "Remove the local overrides on the component's jobs. If customization is needed, check if the component provides input variables for configuration instead of overriding job keys directly.",
		DocURL:      docsBaseURL + string(CodeComponentOverridden),
		ControlName: "pipelineMustIncludeComponent",
	},
	CodeSecurityJobWeakened: {
		Code:        CodeSecurityJobWeakened,
		Severity:    SeverityHigh,
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
		Description: "A CI/CD job downloads and immediately executes a script from the internet (e.g., curl | bash, wget | sh) without verifying its integrity. An attacker who compromises the remote URL can serve a modified script that exfiltrates secrets.",
		Remediation: "Download the script to a file first, verify its checksum against a known-good value, then execute it. Alternatively, vendor the script into your repository or use a trusted package manager.",
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
		Severity:    SeverityCritical,
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
	CodeBranchNonCompliant: {
		Code:        CodeBranchNonCompliant,
		Severity:    SeverityHigh,
		Title:       "Branch protection configuration not compliant",
		Description: "A protected branch does not meet the required protection settings (e.g., force push allowed, access levels too permissive, code owner approval not required).",
		Remediation: "Update branch protection settings in GitLab: Settings > Repository > Protected Branches. Ensure force push is disabled, access levels meet the minimum, and code owner approval is required per your .plumber.yaml configuration.",
		DocURL:      docsBaseURL + string(CodeBranchNonCompliant),
		ControlName: "branchMustBeProtected",
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
