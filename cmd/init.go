package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/getplumber/plumber/configuration"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v2"
)

const (
	// Provider selection (the first question — drives every later filter).
	provGitLab = "GitLab (gitlab.com / self-hosted)"
	provGitHub = "GitHub Actions (github.com / GHES)"

	catImages      = "Container image security (tags, trusted registries)"
	catComposition = "Pipeline composition (includes, scripts, security jobs, DinD)"
	catAccess      = "Access control (branch protection)"
	catVariables   = "Variable security (debug trace, unsafe expansion)"

	// GitLab-applicable composition checks (existing).
	compHardcoded = "Disallow hardcoded jobs (use includes/components)"
	compUpToDate  = "Require catalog includes to be up to date"
	compForbidden = "Forbid mutable include refs (latest, main, HEAD, …)"
	compSecurity  = "Detect weakened security scanning jobs"
	compScripts   = "Detect unverified remote script execution (curl|bash, …)"
	compJobVars   = "Detect sensitive variables overridden in pipeline YAML"
	compDinD      = "Detect Docker-in-Docker (dind) usage"

	// GitHub-applicable composition checks (new). The cross-provider ones
	// (security jobs, DinD) reuse compSecurity / compDinD above.
	compActionPin           = "Require third-party actions pinned by commit SHA"
	compDangerousTriggers   = "Flag dangerous workflow triggers (pull_request_target, workflow_run, …)"
	compDeclarePermissions  = "Require workflows to declare an explicit permissions: block"
	compReusableSecrets     = "Forbid reusable-workflow calls using secrets: inherit"
	compTemplateInjection   = "Detect script-injection sinks (${{ github.event.* }} → run:)"
)

var (
	configInitOutput string
	configInitForce  bool
)

// runConfigInit is bound to `plumber config init` (registered from config.go).
func runConfigInit(cmd *cobra.Command, args []string) error {
	if !verbose {
		logrus.SetLevel(logrus.WarnLevel)
	}

	if !isInteractiveInit() {
		return fmt.Errorf(`plumber config init needs an interactive terminal for the wizard.

For the default template with comments (suitable for CI or scripts), run:
  plumber config generate -o .plumber.yaml`)
	}

	state, err := runInitWizard()
	if err != nil {
		return err
	}
	cfg := state.toPlumberConfig()
	if err := writeInitConfig(cfg, configInitOutput, configInitForce, true, "plumber config init"); err != nil {
		return err
	}
	printInitNextSteps(configInitOutput, state.Providers)
	if state.runAnalyzeAfter {
		return maybeRunAnalyze(configInitOutput, state.Providers)
	}
	return nil
}

func isInteractiveInit() bool {
	if os.Getenv("CI") != "" {
		return false
	}
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// initWizardState collects answers from the survey.
type initWizardState struct {
	// Providers carries the selected target platforms ("gitlab",
	// "github", or both). Every per-control prompt and the final
	// `toPlumberConfig` mapping branch on this list — controls only
	// applicable to one provider stay out of the other provider's
	// section even when "both" is selected.
	Providers []string

	Categories []string

	ForbiddenTagsEnabled   bool
	ForbiddenTagsCSV       string
	PinByDigest            bool
	AuthorizedEnabled      bool
	TrustDockerHubOfficial bool
	TrustedURLsText        string

	CompositionChoices []string

	// GitHub-side actionsMustBePinnedByCommitSha trustedOwners list.
	// Only populated when GitHub is selected and compActionPin is in
	// CompositionChoices.
	ActionPinTrustedOwnersMultiline string

	// SecurityJobPatternsGitHubMultiline is the GitHub-side override
	// of the security-job pattern list. GitHub job names are
	// namespaced as `workflow/job`, so the canonical patterns differ
	// from GitLab's bare-name set. Only populated when GitHub is
	// selected and compSecurity is in CompositionChoices.
	SecurityJobPatternsGitHubMultiline string

	BranchEnabled  bool
	BranchPatterns string

	DebugTraceEnabled      bool
	UnsafeExpansionEnabled bool

	RequireComponents      bool
	RequiredComponentsExpr string

	RequireTemplates      bool
	RequiredTemplatesExpr string

	// includesMustNotUseForbiddenVersions (when compForbidden selected)
	ForbiddenVersionsMultiline      string
	DefaultBranchIsForbiddenVersion bool

	// securityJobsMustNotBeWeakened (when compSecurity selected)
	SecurityJobPatternsMultiline string
	SecuritySubAllowFailure      bool
	SecuritySubRules             bool
	SecuritySubWhenNotManual     bool

	// pipelineMustNotExecuteUnverifiedScripts (when compScripts selected)
	ScriptTrustedURLsMultiline string

	// pipelineMustNotOverrideJobVariables (when compJobVars selected)
	JobOverrideVariablesMultiline string

	// pipelineMustNotUseDockerInDocker (when compDinD selected)
	DinDDetectInsecureDaemon bool

	// branchMustBeProtected (when catAccess)
	BranchDefaultMustBeProtected    bool
	BranchAllowForcePush            bool
	BranchCodeOwnerApprovalRequired bool
	BranchMinMergeAccessLevel       string
	BranchMinPushAccessLevel        string

	// pipelineMustNotEnableDebugTrace
	DebugForbiddenVariablesMultiline string

	// pipelineMustNotUseUnsafeVariableExpansion
	DangerousVariablesMultiline string
	AllowedPatternsMultiline    string

	runAnalyzeAfter bool
}

func printInitSection(label string) {
	fmt.Fprintf(os.Stderr, "\n── %s ──\n\n", label)
}

func runInitWizard() (*initWizardState, error) {
	fmt.Fprintln(os.Stderr, "Welcome to Plumber.")
	fmt.Fprintln(os.Stderr, "This wizard creates a .plumber.yaml tailored to your project.")
	fmt.Fprintln(os.Stderr, "Press Enter to accept defaults, Space to toggle, and Ctrl-C to quit.")
	fmt.Fprintln(os.Stderr)

	st := &initWizardState{}

	// Step 0 — provider selection. Drives every downstream filter:
	// which areas are offered, which questions appear inside each
	// area, and which provider section(s) the resulting config gets
	// written under. Auto-detect from the git remote when possible
	// so the default lands on the right provider out of the box;
	// multi-select still lets the user pick "both" for monorepos
	// that ship to both platforms or for shared config repos.
	providerOptions := []string{provGitLab, provGitHub}
	providerDefault := autoDetectProviderForInit()
	if err := survey.AskOne(&survey.MultiSelect{
		Message:  "Which provider(s) do you want to configure?",
		Help:     "Pick one to scope the wizard. Pick both for a config that targets a monorepo or a config file shared across repos. Auto-detection picks the default based on your git remote.",
		Options:  providerOptions,
		PageSize: 4,
		Default:  providerDefault,
	}, &st.Providers, survey.WithValidator(survey.Required)); err != nil {
		return nil, err
	}
	st.Providers = providersFromWizardLabels(st.Providers)

	allCats := wizardCategoriesForProviders(st.Providers)
	err := survey.AskOne(&survey.MultiSelect{
		Message:  "Which areas do you want to enforce?",
		Options:  allCats,
		PageSize: 10,
		Default:  allCats,
	}, &st.Categories, survey.WithValidator(survey.Required))
	if err != nil {
		return nil, err
	}

	has := func(s string) bool {
		for _, c := range st.Categories {
			if c == s {
				return true
			}
		}
		return false
	}

	if has(catImages) {
		printInitSection("Container image security")
		if err := survey.AskOne(&survey.Confirm{Message: "Forbid mutable image tags (e.g. latest, dev, main)?", Default: true}, &st.ForbiddenTagsEnabled); err != nil {
			return nil, err
		}
		if st.ForbiddenTagsEnabled {
			if err := survey.AskOne(&survey.Input{
				Message: "Forbidden tags (comma-separated)",
				Default: "latest, dev, development, staging, main, master",
			}, &st.ForbiddenTagsCSV); err != nil {
				return nil, err
			}
			if err := survey.AskOne(&survey.Confirm{Message: "Require every image to be pinned by digest (@sha256:…)?", Default: false}, &st.PinByDigest); err != nil {
				return nil, err
			}
		}

		// The authorized-sources control (containerImageMustComeFromAuthorizedSources)
		// is GitLab-only today — the GitHub rego rule is on the dev bench.
		// Only surface its prompts when GitLab is in scope; skipping them
		// for a GitHub-only run keeps the wizard from collecting answers
		// that would never reach the written config.
		if hasProvider(st, "gitlab") {
			if err := survey.AskOne(&survey.Confirm{Message: "Restrict images to authorized registries only? (GitLab)", Default: true}, &st.AuthorizedEnabled); err != nil {
				return nil, err
			}
			if st.AuthorizedEnabled {
				if err := survey.AskOne(&survey.Confirm{Message: "Trust official Docker Hub library images (e.g. alpine, python)?", Default: true}, &st.TrustDockerHubOfficial); err != nil {
					return nil, err
				}
				if err := survey.AskOne(&survey.Multiline{
					Message: "Trusted registry URL patterns (one per line)",
					Help:    "Supports wildcards, e.g. registry.example.com/*, $CI_REGISTRY_IMAGE:*. Images not matching any pattern will be flagged.",
					Default: strings.Join(defaultTrustedURLs(), "\n"),
				}, &st.TrustedURLsText); err != nil {
					return nil, err
				}
			}
		}
	}

	if has(catComposition) {
		printInitSection("Pipeline composition")
		allComp := compositionOptionsForProviders(st.Providers)
		if err := survey.AskOne(&survey.MultiSelect{
			Message:  "Which pipeline checks should be enabled?",
			Options:  allComp,
			PageSize: 14,
			Default:  allComp,
		}, &st.CompositionChoices, survey.WithValidator(survey.Required)); err != nil {
			return nil, err
		}

		if compSelected(st, compActionPin) {
			fmt.Fprintf(os.Stderr, "\n  › Action pin trusted owners (GitHub)\n")
			if err := survey.AskOne(&survey.Multiline{
				Message: "Action-owner prefixes exempt from the pin-by-SHA requirement (one per line)",
				Help:    "Only list owners already inside your workflow's trust boundary. \"actions\" and \"github\" cover the first-party GitHub-owned actions.",
				Default: strings.Join(defaultGitHubTrustedActionOwners(), "\n"),
			}, &st.ActionPinTrustedOwnersMultiline); err != nil {
				return nil, err
			}
		}

		if compSelected(st, compForbidden) && hasProvider(st, "gitlab") {
			fmt.Fprintf(os.Stderr, "\n  › Forbidden include refs\n")
			if err := survey.AskOne(&survey.Multiline{
				Message: "Forbidden version refs (one per line)",
				Help:    "Refs like latest, ~latest, main, master, HEAD are mutable and can introduce breaking changes silently.",
				Default: strings.Join(defaultForbiddenVersions(), "\n"),
			}, &st.ForbiddenVersionsMultiline); err != nil {
				return nil, err
			}
			if err := survey.AskOne(&survey.Confirm{
				Message: "Also treat the project's default branch name as a forbidden ref?",
				Default: false,
			}, &st.DefaultBranchIsForbiddenVersion); err != nil {
				return nil, err
			}
		}

		if compSelected(st, compSecurity) {
			fmt.Fprintf(os.Stderr, "\n  › Security jobs\n")
			if hasProvider(st, "gitlab") {
				if err := survey.AskOne(&survey.Multiline{
					Message: "GitLab security-job patterns (one per line)",
					Help:    "Wildcards are supported, e.g. *-sast, gemnasium-*. GitLab job names are bare (no workflow prefix).",
					Default: strings.Join(defaultSecurityJobPatterns(), "\n"),
				}, &st.SecurityJobPatternsMultiline); err != nil {
					return nil, err
				}
			}
			if hasProvider(st, "github") {
				if err := survey.AskOne(&survey.Multiline{
					Message: "GitHub security-job patterns (one per line)",
					Help:    "GitHub job names are namespaced as workflow/job, so patterns use *substring* form. Defaults cover the GitHub-native scanners.",
					Default: strings.Join(defaultGitHubSecurityJobPatterns(), "\n"),
				}, &st.SecurityJobPatternsGitHubMultiline); err != nil {
					return nil, err
				}
			}
			if err := survey.AskOne(&survey.Confirm{
				Message: "Flag jobs that set allow_failure: true (GitLab) / continue-on-error: true (GitHub)?",
				Default: false,
			}, &st.SecuritySubAllowFailure); err != nil {
				return nil, err
			}
			if err := survey.AskOne(&survey.Confirm{
				Message: "Flag jobs that redefine rules?",
				Default: true,
			}, &st.SecuritySubRules); err != nil {
				return nil, err
			}
			if err := survey.AskOne(&survey.Confirm{
				Message: "Flag jobs that set when: manual?",
				Default: true,
			}, &st.SecuritySubWhenNotManual); err != nil {
				return nil, err
			}
		}

		if compSelected(st, compScripts) && hasProvider(st, "gitlab") {
			fmt.Fprintf(os.Stderr, "\n  › Unverified scripts\n")
			if err := survey.AskOne(&survey.Multiline{
				Message: "Script host URL patterns to trust (one per line)",
				Help:    "Leave empty to flag every remote script. Example: https://internal.example.com/*",
			}, &st.ScriptTrustedURLsMultiline); err != nil {
				return nil, err
			}
		}

		if compSelected(st, compJobVars) && hasProvider(st, "gitlab") {
			fmt.Fprintf(os.Stderr, "\n  › Job variable overrides\n")
			if err := survey.AskOne(&survey.Multiline{
				Message: "Variables that pipelines must not override (one per line)",
				Help:    "These are security-critical GitLab CI variables; overriding them can disable scanning.",
				Default: strings.Join(defaultJobOverrideVariables(), "\n"),
			}, &st.JobOverrideVariablesMultiline); err != nil {
				return nil, err
			}
		}

		if compSelected(st, compDinD) {
			fmt.Fprintf(os.Stderr, "\n  › Docker-in-Docker\n")
			if err := survey.AskOne(&survey.Confirm{
				Message: "Also detect insecure daemon socket usage (e.g. tcp:// without TLS)?",
				Default: true,
			}, &st.DinDDetectInsecureDaemon); err != nil {
				return nil, err
			}
		}

		// Required-inclusions prompts are GitLab-only (the component /
		// template concepts have no direct equivalent on GitHub —
		// closest analogues would be required actions or required
		// reusable workflows, but neither is shipping as a control
		// today). Skip the section entirely when only GitHub is in
		// scope.
		if hasProvider(st, "gitlab") {
			fmt.Fprintf(os.Stderr, "\n  › Required inclusions (GitLab)\n")
			if err := survey.AskOne(&survey.Confirm{
				Message: "Require specific catalog components in every pipeline?",
				Default: false,
			}, &st.RequireComponents); err != nil {
				return nil, err
			}
			if st.RequireComponents {
				if err := survey.AskOne(&survey.Input{
					Message: "Required components expression",
					Help:    "Paths with optional AND / OR and parentheses. Examples:\n  components/sast/sast\n  components/sast/sast AND components/secret-detection/secret-detection\n  (components/sast/sast AND components/secret-detection) OR components/full-security",
				}, &st.RequiredComponentsExpr); err != nil {
					return nil, err
				}
			}

			fmt.Fprintln(os.Stderr)
			if err := survey.AskOne(&survey.Confirm{
				Message: "Require specific project file templates in every pipeline?",
				Default: false,
			}, &st.RequireTemplates); err != nil {
				return nil, err
			}
			if st.RequireTemplates {
				if err := survey.AskOne(&survey.Input{
					Message: "Required templates expression",
					Help:    "Paths with optional AND / OR and parentheses. Examples:\n  templates/security/sast\n  templates/security/sast AND templates/security/secret-detection",
				}, &st.RequiredTemplatesExpr); err != nil {
					return nil, err
				}
			}
		}
	}

	if has(catAccess) {
		printInitSection("Access control: branch protection")
		st.BranchEnabled = true
		if err := survey.AskOne(&survey.Input{
			Message: "Branch name patterns to protect (comma-separated; wildcards ok)",
			Default: "main, master, release/*, production, dev",
		}, &st.BranchPatterns); err != nil {
			return nil, err
		}
		if err := survey.AskOne(&survey.Confirm{
			Message: "Require the repository default branch to be covered by a protected pattern?",
			Default: true,
		}, &st.BranchDefaultMustBeProtected); err != nil {
			return nil, err
		}
		if err := survey.AskOne(&survey.Confirm{
			Message: "Allow force push on protected branches?",
			Default: false,
		}, &st.BranchAllowForcePush); err != nil {
			return nil, err
		}
		if err := survey.AskOne(&survey.Confirm{
			Message: "Require code owner approval on protected branches?",
			Default: false,
		}, &st.BranchCodeOwnerApprovalRequired); err != nil {
			return nil, err
		}
		// minMerge/minPushAccessLevel are GitLab-specific numeric
		// permission tiers; GitHub uses a different model (role
		// strings + branch-protection rule shape) and the GitHub
		// rego rule doesn't read these fields. Skip the prompts when
		// GitLab is out of scope.
		if hasProvider(st, "gitlab") {
			if err := survey.AskOne(&survey.Input{
				Message: "Minimum access level to merge (GitLab)",
				Help:    "30 = Developer, 40 = Maintainer, 50 = Owner",
				Default: "30",
			}, &st.BranchMinMergeAccessLevel); err != nil {
				return nil, err
			}
			if err := survey.AskOne(&survey.Input{
				Message: "Minimum access level to push to protected branches (GitLab)",
				Help:    "30 = Developer, 40 = Maintainer, 50 = Owner",
				Default: "40",
			}, &st.BranchMinPushAccessLevel); err != nil {
				return nil, err
			}
		}
	}

	if has(catVariables) {
		printInitSection("Variable security")
		if err := survey.AskOne(&survey.Confirm{Message: "Flag pipelines that enable CI_DEBUG_TRACE or CI_DEBUG_SERVICES?", Default: true}, &st.DebugTraceEnabled); err != nil {
			return nil, err
		}
		if st.DebugTraceEnabled {
			if err := survey.AskOne(&survey.Multiline{
				Message: "Variables whose presence in pipeline YAML is forbidden (one per line)",
				Help:    "Setting CI_DEBUG_TRACE=true exposes all masked variables and secrets in job logs.",
				Default: "CI_DEBUG_TRACE\nCI_DEBUG_SERVICES",
			}, &st.DebugForbiddenVariablesMultiline); err != nil {
				return nil, err
			}
		}
		if err := survey.AskOne(&survey.Confirm{Message: "Flag pipelines that expand user-controlled variables in scripts unsafely?", Default: true}, &st.UnsafeExpansionEnabled); err != nil {
			return nil, err
		}
		if st.UnsafeExpansionEnabled {
			if err := survey.AskOne(&survey.Multiline{
				Message: "User-controlled variables to watch for unsafe expansion (one per line)",
				Help:    "These are variables whose values come from user input (MR title, commit message, branch name, etc.) and should not appear in scripts without sanitization.",
				Default: strings.Join(defaultDangerousVariables(), "\n"),
			}, &st.DangerousVariablesMultiline); err != nil {
				return nil, err
			}
			if err := survey.AskOne(&survey.Multiline{
				Message: "Script line regexes to exclude from findings (one per line, optional)",
				Help:    "Lines matching any of these patterns are ignored. Useful for approved patterns like echo \"$$VAR\" that are safe in your context.",
			}, &st.AllowedPatternsMultiline); err != nil {
				return nil, err
			}
		}
	}

	fmt.Fprintln(os.Stderr)
	var runAnalyze bool
	if err := survey.AskOne(&survey.Confirm{
		Message: "Run 'plumber analyze' after writing? (" + runAnalyzeAuthHint(st.Providers) + ")",
		Default: false,
	}, &runAnalyze); err != nil {
		return nil, err
	}
	st.runAnalyzeAfter = runAnalyze
	return st, nil
}

func boolPtrInit(b bool) *bool { return &b }
func intPtrInit(i int) *int    { return &i }

// hasProvider reports whether the wizard state currently targets the
// given canonical provider name ("gitlab" or "github"). Returns false
// for an empty Providers slice — callers should always set at least
// one provider before invoking the per-control flow.
func hasProvider(st *initWizardState, name string) bool {
	for _, p := range st.Providers {
		if p == name {
			return true
		}
	}
	return false
}

// providersFromWizardLabels translates the human-facing provider
// labels (provGitLab / provGitHub) into the canonical strings used
// throughout the wizard ("gitlab" / "github"). Preserves order.
func providersFromWizardLabels(labels []string) []string {
	out := make([]string, 0, len(labels))
	for _, l := range labels {
		switch l {
		case provGitLab, "gitlab":
			out = append(out, "gitlab")
		case provGitHub, "github":
			out = append(out, "github")
		}
	}
	return out
}

// autoDetectProviderForInit picks the default provider selection
// based on the current git remote so the most common single-provider
// case lands on the right pre-checked option without the user
// having to touch it. Falls back to GitLab when nothing matches —
// preserves historical behaviour for the (still common) GitLab-only
// case.
func autoDetectProviderForInit() []string {
	out, err := exec.Command("git", "config", "--get", "remote.origin.url").Output()
	if err == nil {
		url := strings.ToLower(strings.TrimSpace(string(out)))
		switch {
		case strings.Contains(url, "github.com"):
			return []string{provGitHub}
		case strings.Contains(url, "gitlab"):
			return []string{provGitLab}
		}
	}
	return []string{provGitLab}
}

// wizardCategoriesForProviders returns the list of "Which areas do
// you want to enforce?" options applicable to the chosen provider
// set. catVariables (debug-trace + unsafe-expansion) is GitLab-only
// today — the GitHub-side controls in that bucket are all on the
// bench, so the option is omitted when only GitHub is selected.
func wizardCategoriesForProviders(providers []string) []string {
	hasGitLab := false
	for _, p := range providers {
		if p == "gitlab" {
			hasGitLab = true
		}
	}
	cats := []string{catImages, catComposition, catAccess}
	if hasGitLab {
		cats = append(cats, catVariables)
	}
	return cats
}

// compositionOptionsForProviders returns the per-provider menu items
// for the "Which pipeline checks?" multi-select. Cross-provider
// checks (security jobs, DinD) appear once. Provider-specific checks
// are added only when the relevant provider is in scope.
func compositionOptionsForProviders(providers []string) []string {
	hasGitLab := false
	hasGitHub := false
	for _, p := range providers {
		switch p {
		case "gitlab":
			hasGitLab = true
		case "github":
			hasGitHub = true
		}
	}
	var out []string
	if hasGitLab {
		out = append(out, compHardcoded, compUpToDate, compForbidden)
	}
	out = append(out, compSecurity, compDinD)
	if hasGitLab {
		out = append(out, compScripts, compJobVars)
	}
	if hasGitHub {
		out = append(out,
			compActionPin,
			compDangerousTriggers,
			compDeclarePermissions,
			compReusableSecrets,
			compTemplateInjection,
		)
	}
	return out
}

// defaultGitHubSecurityJobPatterns mirrors the GitHub-side defaults
// shipped in .plumber.yaml's github.controls.securityJobsMustNotBeWeakened
// block. GitHub job identifiers are namespaced as `workflow/job`, so
// every pattern uses leading + trailing wildcards.
func defaultGitHubSecurityJobPatterns() []string {
	return []string{
		"*codeql*",
		"*dependency-review*",
		"*trufflehog*",
		"*gitleaks*",
		"*osv-scanner*",
		"*-sast",
		"*-sast-*",
		"*-scan",
		"*scan*",
		"*-security",
		"*-security-*",
		"*-audit",
		"*-audit-*",
	}
}

// defaultGitHubTrustedActionOwners mirrors the .plumber.yaml default
// for actionsMustBePinnedByCommitSha.trustedOwners — the first-party
// owners whose actions the runtime trusts implicitly.
func defaultGitHubTrustedActionOwners() []string {
	return []string{"actions", "github"}
}

// runAnalyzeAuthHint composes the auth hint shown alongside the
// "Run plumber analyze after writing?" tail prompt so each provider
// gets the right credential guidance up front.
func runAnalyzeAuthHint(providers []string) string {
	switch {
	case len(providers) == 1 && providers[0] == "github":
		return "no token needed for local-clone scan; export GH_TOKEN or run `gh auth login` for full results"
	case len(providers) == 1 && providers[0] == "gitlab":
		return "requires GITLAB_TOKEN in the environment"
	default:
		return "requires GITLAB_TOKEN for GitLab and GH_TOKEN (or `gh auth login`) for GitHub"
	}
}

func defaultTrustedURLs() []string {
	return []string{
		"docker.io/docker:*",
		"gcr.io/kaniko-project/*",
		"$CI_REGISTRY_IMAGE:*",
		"$CI_REGISTRY_IMAGE/*",
		"getplumber/plumber:*",
		"docker.io/getplumber/plumber:*",
		"registry.gitlab.com/security-products/*",
	}
}

func defaultDangerousVariables() []string {
	return []string{
		"CI_MERGE_REQUEST_TITLE",
		"CI_MERGE_REQUEST_DESCRIPTION",
		"CI_COMMIT_MESSAGE",
		"CI_COMMIT_TITLE",
		"CI_COMMIT_TAG_MESSAGE",
		"CI_COMMIT_REF_NAME",
		"CI_COMMIT_REF_SLUG",
		"CI_COMMIT_BRANCH",
		"CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
		"CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME",
	}
}

func defaultJobOverrideVariables() []string {
	return []string{
		"SECURE_ANALYZERS_PREFIX",
		"SAST_DISABLED",
		"SAST_EXCLUDED_PATHS",
		"SAST_EXCLUDED_ANALYZERS",
		"SECRET_DETECTION_DISABLED",
		"SECRET_DETECTION_EXCLUDED_PATHS",
		"CONTAINER_SCANNING_DISABLED",
		"DAST_DISABLED",
		"DEPENDENCY_SCANNING_DISABLED",
		"LICENSE_SCANNING_DISABLED",
	}
}

func defaultSecurityJobPatterns() []string {
	return []string{
		"*-sast",
		"secret_detection",
		"container_scanning",
		"*_dependency_scanning",
		"gemnasium-*",
		"dast",
		"dast_*",
		"license_scanning",
	}
}

func defaultForbiddenVersions() []string {
	return []string{"latest", "~latest", "main", "master", "HEAD"}
}

func parseCSVInit(s string) []string {
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseLinesInit(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func parseIntInit(s string, def int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return i
}

func compSelected(st *initWizardState, label string) bool {
	for _, c := range st.CompositionChoices {
		if c == label {
			return true
		}
	}
	return false
}

func (st *initWizardState) toPlumberConfig() *configuration.PlumberConfig {
	cfg := &configuration.PlumberConfig{Version: "2.0"}

	// Empty Providers slice = backwards-compatible path (existing
	// tests, starter config). Default to GitLab-only so historical
	// callers keep producing the same shape they always did.
	providers := st.Providers
	if len(providers) == 0 {
		providers = []string{"gitlab"}
	}

	// Build target provider sections up front so each per-control
	// block writes to whichever side(s) apply without sprinkling
	// hasProvider checks across the function body. gitlabSection /
	// githubSection are nil when the provider isn't in scope.
	var gitlabSection, githubSection *configuration.ProviderConfig
	for _, p := range providers {
		switch p {
		case "gitlab":
			cfg.GitLab = &configuration.ProviderConfig{}
			gitlabSection = cfg.GitLab
		case "github":
			cfg.GitHub = &configuration.ProviderConfig{}
			githubSection = cfg.GitHub
		}
	}

	has := func(s string) bool {
		for _, c := range st.Categories {
			if c == s {
				return true
			}
		}
		return false
	}

	if has(catImages) {
		if st.ForbiddenTagsEnabled {
			tags := parseCSVInit(st.ForbiddenTagsCSV)
			if len(tags) == 0 {
				tags = parseCSVInit("latest, dev, development, staging, main, master")
			}
			block := &configuration.ImageForbiddenTagsControlConfig{
				Enabled:                             boolPtrInit(true),
				Tags:                                tags,
				ContainerImagesMustBePinnedByDigest: boolPtrInit(st.PinByDigest),
			}
			if gitlabSection != nil {
				gitlabSection.Controls.ContainerImageMustNotUseForbiddenTags = block
			}
			if githubSection != nil {
				githubSection.Controls.ContainerImageMustNotUseForbiddenTags = block
			}
		}
		// containerImageMustComeFromAuthorizedSources is GitLab-only
		// (the GitHub rego rule is on the dev bench).
		if st.AuthorizedEnabled && gitlabSection != nil {
			urls := parseLinesInit(st.TrustedURLsText)
			if len(urls) == 0 {
				urls = defaultTrustedURLs()
			}
			gitlabSection.Controls.ContainerImageMustComeFromAuthorizedSources = &configuration.ImageAuthorizedSourcesControlConfig{
				Enabled:                      boolPtrInit(true),
				TrustedUrls:                  urls,
				TrustDockerHubOfficialImages: boolPtrInit(st.TrustDockerHubOfficial),
			}
		}
	}

	if has(catComposition) {
		// GitLab-only composition checks.
		if gitlabSection != nil {
			if compSelected(st, compHardcoded) {
				gitlabSection.Controls.PipelineMustNotIncludeHardcodedJobs = &configuration.HardcodedJobsControlConfig{
					Enabled: boolPtrInit(true),
				}
			}
			if compSelected(st, compUpToDate) {
				gitlabSection.Controls.IncludesMustBeUpToDate = &configuration.IncludesUpToDateControlConfig{
					Enabled: boolPtrInit(true),
				}
			}
			if compSelected(st, compForbidden) {
				vers := parseLinesInit(st.ForbiddenVersionsMultiline)
				if len(vers) == 0 {
					vers = defaultForbiddenVersions()
				}
				gitlabSection.Controls.IncludesMustNotUseForbiddenVersions = &configuration.IncludesForbiddenVersionsControlConfig{
					Enabled:                         boolPtrInit(true),
					ForbiddenVersions:               vers,
					DefaultBranchIsForbiddenVersion: boolPtrInit(st.DefaultBranchIsForbiddenVersion),
				}
			}
			if compSelected(st, compScripts) {
				gitlabSection.Controls.PipelineMustNotExecuteUnverifiedScripts = &configuration.UnverifiedScriptsControlConfig{
					Enabled:     boolPtrInit(true),
					TrustedUrls: parseLinesInit(st.ScriptTrustedURLsMultiline),
				}
			}
			if compSelected(st, compJobVars) {
				vars := parseLinesInit(st.JobOverrideVariablesMultiline)
				if len(vars) == 0 {
					vars = defaultJobOverrideVariables()
				}
				gitlabSection.Controls.PipelineMustNotOverrideJobVariables = &configuration.JobVariablesOverrideControlConfig{
					Enabled:   boolPtrInit(true),
					Variables: vars,
				}
			}

			if e := strings.TrimSpace(st.RequiredComponentsExpr); e != "" {
				gitlabSection.Controls.PipelineMustIncludeComponent = &configuration.RequiredComponentsControlConfig{
					Enabled:  boolPtrInit(true),
					Required: e,
				}
			} else if st.RequireComponents {
				fmt.Fprintln(os.Stderr, "Note: component requirement skipped (no expression provided).")
			}

			if e := strings.TrimSpace(st.RequiredTemplatesExpr); e != "" {
				gitlabSection.Controls.PipelineMustIncludeTemplate = &configuration.RequiredTemplatesControlConfig{
					Enabled:  boolPtrInit(true),
					Required: e,
				}
			} else if st.RequireTemplates {
				fmt.Fprintln(os.Stderr, "Note: template requirement skipped (no expression provided).")
			}
		}

		// Cross-provider: security-jobs. GitLab and GitHub take their
		// own pattern set (job-name conventions differ) but share the
		// three sub-control toggles.
		if compSelected(st, compSecurity) {
			subs := &configuration.SecurityJobsWeakenedControlConfig{
				Enabled:                 boolPtrInit(true),
				AllowFailureMustBeFalse: &configuration.SecurityJobsSubControlToggle{Enabled: boolPtrInit(st.SecuritySubAllowFailure)},
				RulesMustNotBeRedefined: &configuration.SecurityJobsSubControlToggle{Enabled: boolPtrInit(st.SecuritySubRules)},
				WhenMustNotBeManual:     &configuration.SecurityJobsSubControlToggle{Enabled: boolPtrInit(st.SecuritySubWhenNotManual)},
			}
			if gitlabSection != nil {
				p := parseLinesInit(st.SecurityJobPatternsMultiline)
				if len(p) == 0 {
					p = defaultSecurityJobPatterns()
				}
				cp := *subs
				cp.SecurityJobPatterns = p
				gitlabSection.Controls.SecurityJobsMustNotBeWeakened = &cp
			}
			if githubSection != nil {
				p := parseLinesInit(st.SecurityJobPatternsGitHubMultiline)
				if len(p) == 0 {
					p = defaultGitHubSecurityJobPatterns()
				}
				cp := *subs
				cp.SecurityJobPatterns = p
				githubSection.Controls.SecurityJobsMustNotBeWeakened = &cp
			}
		}

		// Cross-provider: Docker-in-Docker.
		if compSelected(st, compDinD) {
			block := &configuration.DockerInDockerControlConfig{
				Enabled:              boolPtrInit(true),
				DetectInsecureDaemon: boolPtrInit(st.DinDDetectInsecureDaemon),
			}
			if gitlabSection != nil {
				gitlabSection.Controls.PipelineMustNotUseDockerInDocker = block
			}
			if githubSection != nil {
				githubSection.Controls.PipelineMustNotUseDockerInDocker = block
			}
		}

		// GitHub-only composition checks.
		if githubSection != nil {
			if compSelected(st, compActionPin) {
				owners := parseLinesInit(st.ActionPinTrustedOwnersMultiline)
				if len(owners) == 0 {
					owners = defaultGitHubTrustedActionOwners()
				}
				githubSection.Controls.ActionsMustBePinnedByCommitSha = &configuration.ActionsPinnedByShaControlConfig{
					Enabled:       boolPtrInit(true),
					TrustedOwners: owners,
				}
			}
			if compSelected(st, compDangerousTriggers) {
				githubSection.Controls.WorkflowMustNotUseDangerousTriggers = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
			}
			if compSelected(st, compDeclarePermissions) {
				githubSection.Controls.WorkflowsMustDeclarePermissions = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
			}
			if compSelected(st, compReusableSecrets) {
				githubSection.Controls.ReusableWorkflowsMustNotInheritSecrets = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
			}
			if compSelected(st, compTemplateInjection) {
				githubSection.Controls.WorkflowMustNotInjectUserInputInScripts = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
			}
		}
	}

	if has(catAccess) && st.BranchEnabled {
		patterns := parseCSVInit(st.BranchPatterns)
		if len(patterns) == 0 {
			patterns = parseCSVInit("main, master, release/*, production, dev")
		}
		if gitlabSection != nil {
			gitlabSection.Controls.BranchMustBeProtected = &configuration.BranchProtectionControlConfig{
				Enabled:                   boolPtrInit(true),
				DefaultMustBeProtected:    boolPtrInit(st.BranchDefaultMustBeProtected),
				NamePatterns:              patterns,
				AllowForcePush:            boolPtrInit(st.BranchAllowForcePush),
				CodeOwnerApprovalRequired: boolPtrInit(st.BranchCodeOwnerApprovalRequired),
				MinMergeAccessLevel:       intPtrInit(parseIntInit(st.BranchMinMergeAccessLevel, 30)),
				MinPushAccessLevel:        intPtrInit(parseIntInit(st.BranchMinPushAccessLevel, 40)),
			}
		}
		if githubSection != nil {
			// GitHub branch-protection ignores the access-level fields
			// (different permission model), so leave them unset to
			// keep the YAML focused on what the GitHub rule reads.
			githubSection.Controls.BranchMustBeProtected = &configuration.BranchProtectionControlConfig{
				Enabled:                   boolPtrInit(true),
				DefaultMustBeProtected:    boolPtrInit(st.BranchDefaultMustBeProtected),
				NamePatterns:              patterns,
				AllowForcePush:            boolPtrInit(st.BranchAllowForcePush),
				CodeOwnerApprovalRequired: boolPtrInit(st.BranchCodeOwnerApprovalRequired),
			}
		}
	}

	// catVariables (debug-trace + unsafe-expansion) is GitLab-only.
	// The GitHub-side controls in that bucket are all benched, so
	// the option doesn't even appear in the menu when only GitHub
	// is selected — but guard the writer too for defence in depth.
	if has(catVariables) && gitlabSection != nil {
		if st.DebugTraceEnabled {
			fb := parseLinesInit(st.DebugForbiddenVariablesMultiline)
			if len(fb) == 0 {
				fb = []string{"CI_DEBUG_TRACE", "CI_DEBUG_SERVICES"}
			}
			gitlabSection.Controls.PipelineMustNotEnableDebugTrace = &configuration.DebugTraceControlConfig{
				Enabled:            boolPtrInit(true),
				ForbiddenVariables: fb,
			}
		}
		if st.UnsafeExpansionEnabled {
			danger := parseLinesInit(st.DangerousVariablesMultiline)
			if len(danger) == 0 {
				danger = defaultDangerousVariables()
			}
			gitlabSection.Controls.PipelineMustNotUseUnsafeVariableExpansion = &configuration.VariableInjectionControlConfig{
				Enabled:            boolPtrInit(true),
				DangerousVariables: danger,
				AllowedPatterns:    parseLinesInit(st.AllowedPatternsMultiline),
			}
		}
	}

	return cfg
}

func starterPlumberConfig() *configuration.PlumberConfig {
	st := &initWizardState{
		Providers:              []string{"gitlab", "github"},
		Categories:             []string{catImages, catComposition, catAccess, catVariables},
		ForbiddenTagsEnabled:   true,
		ForbiddenTagsCSV:       "latest, dev, development, staging, main, master",
		PinByDigest:            false,
		AuthorizedEnabled:      true,
		TrustDockerHubOfficial: true,
		TrustedURLsText:        strings.Join(defaultTrustedURLs(), "\n"),
		CompositionChoices: []string{
			compHardcoded, compUpToDate, compForbidden, compSecurity, compScripts, compJobVars, compDinD,
			compActionPin, compDangerousTriggers, compDeclarePermissions, compReusableSecrets, compTemplateInjection,
		},
		ActionPinTrustedOwnersMultiline:    strings.Join(defaultGitHubTrustedActionOwners(), "\n"),
		SecurityJobPatternsGitHubMultiline: strings.Join(defaultGitHubSecurityJobPatterns(), "\n"),
		ForbiddenVersionsMultiline:         strings.Join(defaultForbiddenVersions(), "\n"),
		DefaultBranchIsForbiddenVersion:    false,
		SecurityJobPatternsMultiline:       strings.Join(defaultSecurityJobPatterns(), "\n"),
		SecuritySubAllowFailure:            false,
		SecuritySubRules:                   true,
		SecuritySubWhenNotManual:           true,
		JobOverrideVariablesMultiline:      strings.Join(defaultJobOverrideVariables(), "\n"),
		DinDDetectInsecureDaemon:           true,
		BranchEnabled:                      true,
		BranchPatterns:                     "main, master, release/*, production, dev",
		BranchDefaultMustBeProtected:       true,
		BranchAllowForcePush:               false,
		BranchCodeOwnerApprovalRequired:    false,
		BranchMinMergeAccessLevel:          "30",
		BranchMinPushAccessLevel:           "40",
		DebugTraceEnabled:                  true,
		DebugForbiddenVariablesMultiline:   "CI_DEBUG_TRACE\nCI_DEBUG_SERVICES",
		UnsafeExpansionEnabled:             true,
		DangerousVariablesMultiline:        strings.Join(defaultDangerousVariables(), "\n"),
		AllowedPatternsMultiline:           "",
	}
	return st.toPlumberConfig()
}

// writeInitConfig writes validated YAML with a provenance header. If promptIfExists is true
// and the path exists without --force, an interactive overwrite prompt may be shown.
func writeInitConfig(cfg *configuration.PlumberConfig, path string, force, promptIfExists bool, generatedBy string) error {
	if cfg == nil {
		return fmt.Errorf("internal error: nil config")
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("generated configuration failed validation: %w", err)
	}

	if _, err := os.Stat(path); err == nil && !force {
		if promptIfExists && isInteractiveInit() {
			var overwrite bool
			if err := survey.AskOne(&survey.Confirm{
				Message: fmt.Sprintf("%s already exists. Overwrite?", path),
				Default: false,
			}, &overwrite); err != nil {
				return err
			}
			if !overwrite {
				return fmt.Errorf("aborted: file exists")
			}
		} else {
			return fmt.Errorf("file %s already exists (use --force to overwrite)", path)
		}
	}

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	header := "# Plumber configuration (https://github.com/getplumber/plumber)\n" +
		"# Generated by: " + generatedBy + "\n\n"
	content := append([]byte(header), out...)

	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(path, content, 0644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, _, warnings, err := configuration.LoadPlumberConfig(path); err != nil {
		return fmt.Errorf("reload check failed: %w", err)
	} else {
		for _, w := range warnings {
			fmt.Fprintf(os.Stderr, "warning: %s\n", w)
		}
	}
	fmt.Printf("Wrote %s\n", path)
	return nil
}

func printInitNextSteps(path string, providers []string) {
	fmt.Fprintln(os.Stderr, "\nNext steps:")
	fmt.Fprintf(os.Stderr, "  1. Review %s and adjust any values\n", path)
	step := 2
	switch {
	case len(providers) == 1 && providers[0] == "github":
		fmt.Fprintf(os.Stderr, "  %d. (Optional) Authenticate: export GH_TOKEN=<token>  OR  gh auth login\n", step)
		step++
	case len(providers) == 1 && providers[0] == "gitlab":
		fmt.Fprintf(os.Stderr, "  %d. export GITLAB_TOKEN=<token>\n", step)
		step++
	default:
		fmt.Fprintf(os.Stderr, "  %d. Authenticate: export GITLAB_TOKEN for GitLab and/or GH_TOKEN (or `gh auth login`) for GitHub\n", step)
		step++
	}
	fmt.Fprintf(os.Stderr, "  %d. plumber analyze --config %s\n", step, path)
}

func maybeRunAnalyze(configPath string, providers []string) error {
	// On a GitLab-only wizard run, keep the historical contract:
	// fall back to a clean no-op if GITLAB_TOKEN is missing. On a
	// GitHub-only run, the local-clone path soft-degrades without a
	// token, so we always let plumber decide. On a "both" run, only
	// short-circuit when neither credential is present.
	gitlabOnly := len(providers) == 1 && providers[0] == "gitlab"
	if gitlabOnly && os.Getenv("GITLAB_TOKEN") == "" {
		fmt.Fprintln(os.Stderr, "GITLAB_TOKEN is not set; skipping analyze.")
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	c := exec.Command(exe, "analyze", "--config", configPath)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("plumber analyze: %w", err)
	}
	return nil
}
