package control

// docsBaseURL is the base URL for Plumber error code documentation.
// Each error code has a short URL that redirects to the full documentation page.
const docsBaseURL = "https://getplumber.io/e/"

// ErrorCode represents a unique Plumber error code (PLB-XXXX format).
type ErrorCode string

// Error codes for container image controls (PLB-01xx)
const (
	// PLB-0101: Container image uses a forbidden tag (e.g., latest, dev)
	CodeImageForbiddenTag ErrorCode = "PLB-0101"
	// PLB-0102: Container image is not pinned by digest
	CodeImageNotPinnedByDigest ErrorCode = "PLB-0102"
	// PLB-0103: Container image comes from an unauthorized registry
	CodeImageUnauthorizedSource ErrorCode = "PLB-0103"
)

// Error codes for branch protection controls (PLB-02xx)
const (
	// PLB-0201: Branch is not protected
	CodeBranchUnprotected ErrorCode = "PLB-0201"
	// PLB-0202: Branch has non-compliant protection settings
	CodeBranchNonCompliant ErrorCode = "PLB-0202"
)

// Error codes for pipeline origin controls (PLB-03xx)
const (
	// PLB-0301: Job is hardcoded (not sourced from include/component)
	CodeJobHardcoded ErrorCode = "PLB-0301"
	// PLB-0302: Include uses an outdated version
	CodeIncludeOutdated ErrorCode = "PLB-0302"
	// PLB-0303: Include uses a forbidden version
	CodeIncludeForbiddenVersion ErrorCode = "PLB-0303"
)

// Error codes for required includes controls (PLB-04xx)
const (
	// PLB-0401: Required component is missing from the pipeline
	CodeComponentMissing ErrorCode = "PLB-0401"
	// PLB-0402: Required component jobs are overridden
	CodeComponentOverridden ErrorCode = "PLB-0402"
	// PLB-0403: Required template is missing from the pipeline
	CodeTemplateMissing ErrorCode = "PLB-0403"
	// PLB-0404: Required template jobs are overridden
	CodeTemplateOverridden ErrorCode = "PLB-0404"
)

// Error codes for security controls (PLB-05xx)
const (
	// PLB-0501: Pipeline enables CI debug trace (CI_DEBUG_TRACE or CI_DEBUG_SERVICES)
	CodeDebugTraceEnabled ErrorCode = "PLB-0501"
)

// ErrorCodeInfo provides metadata about an error code.
type ErrorCodeInfo struct {
	// Code is the unique error code (e.g., PLB-0101).
	Code ErrorCode `json:"code"`
	// Title is a short human-readable title.
	Title string `json:"title"`
	// Description explains what the issue is.
	Description string `json:"description"`
	// Remediation provides guidance on how to fix the issue.
	Remediation string `json:"remediation"`
	// DocURL is a direct link to the documentation for this error.
	DocURL string `json:"docUrl"`
	// ControlName is the .plumber.yaml control key this code belongs to.
	ControlName string `json:"controlName"`
}

// errorCodeRegistry maps error codes to their metadata.
var errorCodeRegistry = map[ErrorCode]ErrorCodeInfo{
	// Container image controls
	CodeImageForbiddenTag: {
		Code:        CodeImageForbiddenTag,
		Title:       "Forbidden image tag",
		Description: "A container image in the pipeline uses a tag that is forbidden by the configuration (e.g., 'latest', 'dev'). Mutable tags make builds non-reproducible because the underlying image can change without notice.",
		Remediation: "Pin the image to a specific immutable version tag (e.g., 'python:3.12.1' instead of 'python:latest'). Configure forbidden tags in .plumber.yaml under containerImageMustNotUseForbiddenTags.forbiddenTags.",
		DocURL:      docsBaseURL + string(CodeImageForbiddenTag),
		ControlName: "containerImageMustNotUseForbiddenTags",
	},
	CodeImageNotPinnedByDigest: {
		Code:        CodeImageNotPinnedByDigest,
		Title:       "Image not pinned by digest",
		Description: "A container image in the pipeline is not pinned by its SHA256 digest. Without digest pinning, a tag can be reassigned to a different image, introducing supply chain risks.",
		Remediation: "Pin the image using its digest: 'image: registry.example.com/myimage@sha256:abc123...'. You can find the digest with 'docker inspect --format={{.RepoDigests}} <image>'.",
		DocURL:      docsBaseURL + string(CodeImageNotPinnedByDigest),
		ControlName: "containerImageMustNotUseForbiddenTags",
	},
	CodeImageUnauthorizedSource: {
		Code:        CodeImageUnauthorizedSource,
		Title:       "Unauthorized image source",
		Description: "A container image is pulled from a registry that is not listed in the authorized sources. Using untrusted registries increases supply chain attack risk.",
		Remediation: "Use images from an authorized registry configured in .plumber.yaml under containerImageMustComeFromAuthorizedSources.authorizedSources, or add the registry to the authorized list.",
		DocURL:      docsBaseURL + string(CodeImageUnauthorizedSource),
		ControlName: "containerImageMustComeFromAuthorizedSources",
	},

	// Branch protection controls
	CodeBranchUnprotected: {
		Code:        CodeBranchUnprotected,
		Title:       "Branch not protected",
		Description: "A branch that should be protected according to the configuration has no protection rules. Unprotected branches allow direct pushes and force pushes, bypassing code review.",
		Remediation: "Enable branch protection in GitLab: Settings > Repository > Protected Branches. Add the branch with appropriate access levels for push and merge.",
		DocURL:      docsBaseURL + string(CodeBranchUnprotected),
		ControlName: "branchMustBeProtected",
	},
	CodeBranchNonCompliant: {
		Code:        CodeBranchNonCompliant,
		Title:       "Non-compliant branch protection",
		Description: "A protected branch does not meet the required protection settings (e.g., force push allowed, access levels too permissive, code owner approval not required).",
		Remediation: "Update branch protection settings in GitLab: Settings > Repository > Protected Branches. Ensure force push is disabled, access levels meet the minimum, and code owner approval is required per your .plumber.yaml configuration.",
		DocURL:      docsBaseURL + string(CodeBranchNonCompliant),
		ControlName: "branchMustBeProtected",
	},

	// Pipeline origin controls
	CodeJobHardcoded: {
		Code:        CodeJobHardcoded,
		Title:       "Hardcoded job",
		Description: "A job in the pipeline is defined directly in the CI configuration instead of being sourced from a CI/CD component or include. Hardcoded jobs bypass governance and standardization.",
		Remediation: "Replace the hardcoded job with a CI/CD component or an include from an approved catalog. Use 'include:' or 'component:' directives in your .gitlab-ci.yml.",
		DocURL:      docsBaseURL + string(CodeJobHardcoded),
		ControlName: "pipelineMustNotIncludeHardcodedJobs",
	},
	CodeIncludeOutdated: {
		Code:        CodeIncludeOutdated,
		Title:       "Outdated include version",
		Description: "An included CI/CD component or template is not using the latest available version. Outdated versions may miss security patches, bug fixes, or improvements.",
		Remediation: "Update the include to use the latest version. Check the component/template repository for the latest release and update the version reference in your .gitlab-ci.yml.",
		DocURL:      docsBaseURL + string(CodeIncludeOutdated),
		ControlName: "includesMustBeUpToDate",
	},
	CodeIncludeForbiddenVersion: {
		Code:        CodeIncludeForbiddenVersion,
		Title:       "Forbidden include version",
		Description: "An included CI/CD component or template uses a version that is explicitly forbidden (e.g., a mutable branch reference like 'main' instead of a tagged version).",
		Remediation: "Replace the forbidden version with an authorized version format. Use semantic version tags (e.g., '1.2.3' or '~latest') instead of branch names or mutable references as configured in .plumber.yaml.",
		DocURL:      docsBaseURL + string(CodeIncludeForbiddenVersion),
		ControlName: "includesMustNotUseForbiddenVersions",
	},

	// Required includes controls
	CodeComponentMissing: {
		Code:        CodeComponentMissing,
		Title:       "Required component missing",
		Description: "A CI/CD component required by the configuration is not included in the pipeline. This means a mandatory compliance check or security scan is missing.",
		Remediation: "Add the required component to your .gitlab-ci.yml using 'include:' with the component path specified in your .plumber.yaml under pipelineMustIncludeComponent.",
		DocURL:      docsBaseURL + string(CodeComponentMissing),
		ControlName: "pipelineMustIncludeComponent",
	},
	CodeComponentOverridden: {
		Code:        CodeComponentOverridden,
		Title:       "Required component overridden",
		Description: "A required CI/CD component is included but some of its job keys are overridden locally, which may alter the intended behavior of the compliance check.",
		Remediation: "Remove the local overrides on the component's jobs. If customization is needed, check if the component provides input variables for configuration instead of overriding job keys directly.",
		DocURL:      docsBaseURL + string(CodeComponentOverridden),
		ControlName: "pipelineMustIncludeComponent",
	},
	CodeTemplateMissing: {
		Code:        CodeTemplateMissing,
		Title:       "Required template missing",
		Description: "A CI/CD template required by the configuration is not included in the pipeline. This means a mandatory workflow step is missing.",
		Remediation: "Add the required template to your .gitlab-ci.yml using 'include:' with the template path specified in your .plumber.yaml under pipelineMustIncludeTemplate.",
		DocURL:      docsBaseURL + string(CodeTemplateMissing),
		ControlName: "pipelineMustIncludeTemplate",
	},
	CodeTemplateOverridden: {
		Code:        CodeTemplateOverridden,
		Title:       "Required template overridden",
		Description: "A required CI/CD template is included but some of its job keys are overridden locally, which may alter the intended behavior.",
		Remediation: "Remove the local overrides on the template's jobs. If customization is needed, check if the template provides variables for configuration instead of overriding job keys directly.",
		DocURL:      docsBaseURL + string(CodeTemplateOverridden),
		ControlName: "pipelineMustIncludeTemplate",
	},

	// Security controls
	CodeDebugTraceEnabled: {
		Code:        CodeDebugTraceEnabled,
		Title:       "Debug trace enabled",
		Description: "The pipeline has CI_DEBUG_TRACE or CI_DEBUG_SERVICES enabled, which exposes all secret variables in the job log output. This is a critical security risk in production pipelines.",
		Remediation: "Remove or set CI_DEBUG_TRACE and CI_DEBUG_SERVICES to 'false' in your .gitlab-ci.yml variables section. These should only be used temporarily for debugging and never committed.",
		DocURL:      docsBaseURL + string(CodeDebugTraceEnabled),
		ControlName: "pipelineMustNotEnableDebugTrace",
	},
}

// LookupCode returns the ErrorCodeInfo for a given error code, or nil if not found.
func LookupCode(code ErrorCode) *ErrorCodeInfo {
	info, ok := errorCodeRegistry[code]
	if !ok {
		return nil
	}
	return &info
}

// AllCodes returns all registered error codes sorted by code.
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

// DocURL returns the documentation URL for a given error code.
func (c ErrorCode) DocURL() string {
	info := LookupCode(c)
	if info == nil {
		return docsBaseURL
	}
	return info.DocURL
}

// String returns the string representation of an error code.
func (c ErrorCode) String() string {
	return string(c)
}
