// Package ir defines the provider-agnostic intermediate representation of a
// CI/CD pipeline. Provider collectors produce an *ir.NormalizedPipeline that
// the OPA rule engine consumes regardless of the source.
package ir

// Provider identifies the CI/CD platform that originated a pipeline.
type Provider string

// Supported providers.
const (
	ProviderGitLab Provider = "gitlab"
	ProviderGitHub Provider = "github"
)

// NormalizedPipeline is the provider-agnostic view of a CI/CD pipeline.
// Provider-specific data that does not fit the shared fields lives in Raw.
type NormalizedPipeline struct {
	Provider      Provider          `json:"provider"`
	ProjectPath   string            `json:"projectPath,omitempty"`
	DefaultBranch string            `json:"defaultBranch,omitempty"`
	Jobs          []Job             `json:"jobs,omitempty"`
	Includes      []Include         `json:"includes,omitempty"`
	Branches      []Branch          `json:"branches,omitempty"`
	Dependabot    *DependabotConfig `json:"dependabot,omitempty"`

	// GlobalVariables are pipeline-level variables declared at the top
	// of the source (e.g. `variables:` block at the root of
	// .gitlab-ci.yml). Includes the merge with upstream component /
	// template defaults — convenient for "what will actually be set at
	// runtime" checks (CI_DEBUG_TRACE leaking secrets, insecure
	// DOCKER_TLS_CERTDIR …).
	GlobalVariables map[string]string `json:"globalVariables,omitempty"`

	// LocalGlobalVariables are the pipeline-level variables the user
	// wrote directly at the root of their CI file, before any merge
	// with included templates or components. Empty when the user did
	// not declare a `variables:` block at the root. Used by policies
	// that must distinguish "user-authored override" from "shipped by
	// upstream template" — notably ISSUE-205 (variable-override).
	// Mirrors the raw-conf scan in
	// controlGitlabPipelineJobVariablesOverride.go.
	LocalGlobalVariables map[string]string `json:"localGlobalVariables,omitempty"`

	// RenovateConfigPath is the file path where a Renovate config was
	// discovered (`renovate.json`, `.renovaterc`, `renovate.json5`,
	// …). Empty when no Renovate config is present.
	RenovateConfigPath string `json:"renovateConfigPath,omitempty"`

	// SecurityPolicyPath is the path of the repository's SECURITY.md
	// (root, .github/, or docs/). Empty when the file is absent.
	SecurityPolicyPath string `json:"securityPolicyPath,omitempty"`

	// Dockerfiles lists every Dockerfile the collector scanned at the
	// repo root and under common build directories, with each FROM
	// base-image extracted so policies can check pinning state.
	Dockerfiles []Dockerfile `json:"dockerfiles,omitempty"`

	Raw map[string]any `json:"raw,omitempty"`
}

// Dockerfile captures the result of parsing a single Dockerfile's
// FROM directives for supply-chain auditing.
type Dockerfile struct {
	Path  string           `json:"path"`
	Bases []DockerfileBase `json:"bases,omitempty"`
}

// DockerfileBase is one FROM line. PinnedByDigest is true when the
// base image is referenced via `image@sha256:...` (immutable);
// otherwise the tag (or default-tag) form lets the registry serve a
// different layer for the same name.
type DockerfileBase struct {
	Image          string `json:"image"`
	Line           int    `json:"line"`
	PinnedByDigest bool   `json:"pinnedByDigest,omitempty"`
}

// DependabotConfig captures the bits of .github/dependabot.yml that
// feed the dependabot-* policies. Populated by the GitHub collector
// when the file exists; nil otherwise.
type DependabotConfig struct {
	Path                   string   `json:"path"`
	InsecureExecEcosystems []string `json:"insecureExecEcosystems,omitempty"`
	// MissingCooldownEcosystems lists ecosystems in the config that
	// have no `cooldown:` block. A cooldown window gives security
	// advisory pipelines time to flag a bad release before
	// Dependabot's PR automation picks it up.
	MissingCooldownEcosystems []string `json:"missingCooldownEcosystems,omitempty"`
}

// Job is a single pipeline unit of work.
type Job struct {
	Name         string            `json:"name"`
	Image        *Image            `json:"image,omitempty"`
	Services     []Image           `json:"services,omitempty"`
	Scripts      []string          `json:"scripts,omitempty"`
	// ScriptBlocks names the source block ("before_script", "script",
	// "after_script") for each entry of Scripts, in the same order.
	// Lets script-scanning policies surface where the offending line
	// lives so legacy consumers (the Rego-port issue payload) can
	// echo the v0.2.x scriptBlock attribute. Empty when the collector
	// did not track origins (older fixtures).
	ScriptBlocks []string          `json:"scriptBlocks,omitempty"`
	AllowFailure bool              `json:"allowFailure,omitempty"`
	When         string            `json:"when,omitempty"`
	Variables    map[string]string `json:"variables,omitempty"`
	// LocalVariables is the raw `variables:` map authored by the
	// project itself (root .gitlab-ci.yml or workflow file), before any
	// merge with upstream component/template definitions. Empty when
	// the user did not declare a `variables:` block on this job —
	// distinguishing "user wrote SAST_DISABLED here" from "upstream
	// template ships SAST_DISABLED". Variable-override policies must
	// read this field, never the merged Variables, to avoid punishing
	// projects for variables their upstream catalogs already set.
	LocalVariables map[string]string `json:"localVariables,omitempty"`
	// Rules captures the job's `rules:` block (GitLab CI). Each entry
	// is a {if, when, allow_failure, exists, changes, …} map; rules
	// such as `- when: never` neutralise the job at runtime even when
	// the job is otherwise correctly configured. Policies that care
	// about effective execution (security-job weakening) read this
	// list and reject any rule whose terminal `when` would prevent
	// the job from running.
	Rules []map[string]any `json:"rules,omitempty"`
	OriginFile   string            `json:"originFile,omitempty"`
	OriginLine   int               `json:"originLine,omitempty"`
	OriginKind   string            `json:"originKind,omitempty"`
	// Overridden is true when the job inherits from an upstream
	// component or template but the project locally redefined some of
	// its keys. Lets policies distinguish "user-authored override" from
	// "vanilla upstream definition" — the rules-redefinition guard in
	// security_jobs_weakened depends on this signal.
	Overridden bool `json:"overridden,omitempty"`
	// OverriddenKeys lists the specific job-level keys the project
	// redefined when overriding an upstream definition (`rules`,
	// `image`, `when`, …). Empty when the job was not overridden,
	// which lets policies target a particular kind of override
	// (rules redefinition, image substitution, …) without flagging
	// every override globally.
	OverriddenKeys []string `json:"overriddenKeys,omitempty"`

	// Permissions are the job's effective permissions as declared in the
	// source provider. For GitHub Actions this is the job-level block if
	// present, otherwise the inherited workflow-level block. The value may
	// be a string shortcut ("write-all", "read-all") or a map of scope
	// names to access level — policies are expected to handle both.
	Permissions any `json:"permissions,omitempty"`

	// Triggers are the event names under which the enclosing workflow runs
	// (for GitHub Actions, the `on:` section of the workflow file). The
	// collector propagates them to every job of the workflow. GitLab jobs
	// leave this field empty: the concept maps poorly onto GitLab's
	// `workflow.rules` and `only/except` semantics, and the few rules that
	// care about triggers are GitHub-specific.
	Triggers []string `json:"triggers,omitempty"`

	// Uses lists every third-party action referenced by the job's steps
	// (for GitHub Actions, `jobs.<name>.steps[].uses` with its
	// accompanying `with:` block). Empty for GitLab jobs, which model
	// external code through `include:` instead (already covered by the
	// pipeline Includes list).
	Uses []Action `json:"uses,omitempty"`

	// ReusableWorkflowUses is the `uses:` declared at the job level (not
	// the step level). Populated only for GitHub Actions jobs that are
	// reusable-workflow calls: `jobs.<name>.uses:
	// owner/repo/.github/workflows/x.yml@ref`. Empty for every other
	// job type.
	ReusableWorkflowUses string `json:"reusableWorkflowUses,omitempty"`

	// SecretsInherit is true when a reusable-workflow call forwards
	// every caller-visible secret to the callee via `secrets: inherit`.
	// Only meaningful when ReusableWorkflowUses is set.
	SecretsInherit bool `json:"secretsInherit,omitempty"`

	// Conditions collects every `if:` expression attached to the job
	// (job-level + each step's). Kept as raw YAML strings so Rego
	// policies can match them with regular expressions — no attempt
	// at GitHub-expression-language parsing at the collector level.
	Conditions []string `json:"conditions,omitempty"`

	// WorkflowName is the value of the top-level `name:` field of the
	// enclosing workflow. Empty when the workflow has no explicit
	// name (GitHub falls back to the file path in the UI). Propagated
	// to every job of the workflow by the collector.
	WorkflowName string `json:"workflowName,omitempty"`

	// WorkflowHasConcurrency is true when the enclosing workflow
	// declares a top-level `concurrency:` block. Job-level
	// concurrency is tracked separately via JobHasConcurrency.
	WorkflowHasConcurrency bool `json:"workflowHasConcurrency,omitempty"`

	// JobHasConcurrency is true when the job has its own
	// `concurrency:` block, independent of the workflow-level one.
	JobHasConcurrency bool `json:"jobHasConcurrency,omitempty"`

	// Environment is the `environment:` field declared on the job
	// (GitHub Actions deployment environment gate). Accepts both the
	// `environment: production` shorthand and the long form — the
	// collector keeps only the name. Empty when no environment is set.
	Environment string `json:"environment,omitempty"`
}

// Action is a single invocation of a reusable third-party action.
// Uses is the full ref ("owner/repo@v4" or "owner/repo@<sha>"), With
// is the raw `with:` map (scope values may be strings, bools or
// numbers, hence `any`).
//
// Metadata, when present, carries facts resolved against the
// GitHub API (archived repo, ref kind, tag SHA). Zero-valued
// Metadata — or a nil pointer — means the collector did not look
// it up (no token, offline run, non-GitHub action). Policies that
// key on API evidence should treat absence as "unknown" and stay
// silent to avoid false positives.
//
// Comment holds the trailing `# comment` that workflow authors
// commonly add behind a hash-pinned reference to document the
// human-readable version (e.g. `@abc123… # v4.1.0`). Kept as the
// raw string after stripping leading whitespace + `#`.
type Action struct {
	Uses string         `json:"uses"`
	With map[string]any `json:"with,omitempty"`
	// Line is the 1-based line number of the `uses:` directive in the
	// source workflow file. Populated by the provider collector so
	// action-level findings can point the reviewer at the exact step
	// instead of the surrounding job header. Zero when unknown.
	Line     int             `json:"line,omitempty"`
	Metadata *ActionMetadata `json:"metadata,omitempty"`
	Comment  string          `json:"comment,omitempty"`
}

// ActionMetadata mirrors the collector-side GitHubMetadata shape.
// Kept in internal/ir so policies can consume it via the serialised
// JSON input without internal/ir importing the collector package.
type ActionMetadata struct {
	RepoArchived     bool     `json:"repoArchived,omitempty"`
	RefExists        bool     `json:"refExists,omitempty"`
	RefKind          string   `json:"refKind,omitempty"`
	TagSha           string   `json:"tagSha,omitempty"`
	LatestTag        string   `json:"latestTag,omitempty"`
	LatestReleaseSha string   `json:"latestReleaseSha,omitempty"`
	CommentVersion   string   `json:"commentVersion,omitempty"`
	CommentTagSha    string   `json:"commentTagSha,omitempty"`
	RefIsAmbiguous   bool     `json:"refIsAmbiguous,omitempty"`
	Advisories       []string `json:"advisories,omitempty"`
}

// Image references a container image (job image, service, step base).
// CredentialsPassword carries the literal value of the image's
// `credentials.password` field (GitHub Actions `jobs.*.container` and
// `services.*`). It is the raw YAML string — `${{ secrets.X }}`
// expressions come through as the template itself, so policies can
// distinguish a secret reference from a hard-coded literal.
type Image struct {
	Name                string `json:"name"`
	Tag                 string `json:"tag,omitempty"`
	Digest              string `json:"digest,omitempty"`
	Registry            string `json:"registry,omitempty"`
	CredentialsPassword string `json:"credentialsPassword,omitempty"`
}

// Include models an external pipeline fragment pulled into the current one.
// Path is a normalized form of Source suitable for comparison against a
// user-declared required component/template list (version suffix and
// instance URL prefix stripped). AltPath optionally carries a second
// candidate path — some collectors (Plumber-augmented templates)
// know a template under two equivalent names and both should match.
// OverriddenJobs enumerates the jobs inherited from this include whose
// behaviour was overridden locally with one of the CI/CD keys that
// meaningfully change semantics (script, image, rules, …).
type Include struct {
	Kind           string          `json:"kind"`
	Source         string          `json:"source"`
	Ref            string          `json:"ref,omitempty"`
	Current        string          `json:"current,omitempty"`
	Path           string          `json:"path,omitempty"`
	AltPath        string          `json:"altPath,omitempty"`
	Nested         bool            `json:"nested,omitempty"`
	ComponentName  string          `json:"componentName,omitempty"`
	// OriginHash is a stable identifier for the origin of this
	// include, used by external tooling to deduplicate the same
	// upstream source across pipelines.
	OriginHash     uint64          `json:"originHash,omitempty"`
	OverriddenJobs []OverriddenJob `json:"overriddenJobs,omitempty"`
}

// OverriddenJob captures a single job whose inherited definition was
// locally overridden. Keys is the list of CI/CD fields (script, image,
// rules, …) whose values were redefined in the pipeline configuration.
type OverriddenJob struct {
	Name string   `json:"name"`
	Keys []string `json:"keys,omitempty"`
}

// Branch is a branch of the source repository as seen by the collector.
// Fields beyond Name/Protected are populated from the provider's branch
// protection API (GitLab /api/v4/projects/:id/protected_branches, the
// GitHub equivalent, …). They stay zero-valued when the collector did
// not fetch protection settings.
type Branch struct {
	Name                      string `json:"name"`
	Protected                 bool   `json:"protected"`
	ProtectionPattern         string `json:"protectionPattern,omitempty"`
	AllowForcePush            bool   `json:"allowForcePush,omitempty"`
	CodeOwnerApprovalRequired bool   `json:"codeOwnerApprovalRequired,omitempty"`
	MinPushAccessLevel        int    `json:"minPushAccessLevel,omitempty"`
	MinMergeAccessLevel       int    `json:"minMergeAccessLevel,omitempty"`
}
