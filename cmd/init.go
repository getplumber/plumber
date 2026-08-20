package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/AlecAivazis/survey/v2"
	"github.com/getplumber/plumber/configuration"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v2"
)

const (
	// Provider selection (the first question — drives every later filter).
	provGitLab = "GitLab (gitlab.com / self-hosted)"
	provGitHub = "GitHub Actions (github.com / GHES)"
	provBoth   = "Both (GitLab + GitHub Actions)"

	catImages      = "Container image security (tags, trusted registries)"
	catComposition = "Pipeline composition (includes, scripts, security jobs, DinD)"
	catAccess      = "Access control (branch protection, MR approvals)"
	catVariables   = "Variable security (settings variables, debug trace, unsafe expansion)"

	// GitLab-applicable composition checks (existing).
	compHardcoded    = "Disallow hardcoded jobs (use includes/components)"
	compUpToDate     = "Require catalog includes to be up to date"
	compForbidden    = "Forbid mutable include refs (latest, main, HEAD, …)"
	compRefCollision = "Flag include refs that resolve to both a tag and a branch"
	compSecurity     = "Detect weakened security scanning jobs"
	compScripts      = "Detect unverified script execution (curl|bash, base64|bash, |sh, …)"
	compJobVars      = "Detect sensitive variables overridden in pipeline YAML"
	compDinD         = "Detect Docker-in-Docker (dind) usage"

	// GitHub-applicable composition checks (new). The cross-provider ones
	// (security jobs, DinD) reuse compSecurity / compDinD above.
	compActionPin          = "Require third-party actions pinned by commit SHA"
	compAuthorizedActions  = "Restrict third-party actions to authorized sources"
	compDangerousTriggers  = "Flag dangerous workflow triggers (pull_request_target, workflow_run, …)"
	compPRTargetHead       = "Forbid pull_request_target workflows that check out the PR head"
	compDeclarePermissions = "Require workflows to declare an explicit permissions: block"
	compReusableSecrets    = "Forbid reusable-workflow calls using secrets: inherit"
	compOverprovSecrets    = "Forbid exporting the entire secrets context (toJson(secrets))"
	compTemplateInjection  = "Detect script-injection sinks (${{ github.event.* }} → run:)"
	compEnvInjection       = "Detect $GITHUB_ENV / $GITHUB_PATH injection (untrusted content → sticky env/PATH)"
	compWriteAllPerms      = "Forbid permissions: write-all in workflows"
	compRefConfusion       = "Flag third-party actions whose ref is both a tag and a branch"
	compArchivedActions    = "Flag third-party actions from archived repositories"
	compKnownCVEs          = "Flag third-party actions with known CVEs (GitHub Advisory DB)"
	compImpostorCommit     = "Flag third-party actions pinned to a commit SHA absent upstream (impostor commit)"
	compMutableRemoteExec  = "Flag actions that fetch+execute mutable remote code (SHA pin bypassed)"
	compCachePoisoning     = "Flag release/publish jobs restoring an unscoped build cache"
	compDebugTraceGitHub   = "Flag Actions debug logging (ACTIONS_STEP_DEBUG / ACTIONS_RUNNER_DEBUG)"
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

	state, err := runInitWizard(false)
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

	// AuthorizedActionsUsePlumberList decides, when compAuthorizedActions
	// is selected, whether githubActionMustComeFromAuthorizedSources ships
	// Plumber's curated trusted-org allowlist + the 20k-star floor (true,
	// matching the default template) or an empty allowlist the user fills
	// in from scratch (false). Only meaningful when GitHub is selected and
	// compAuthorizedActions is in CompositionChoices.
	AuthorizedActionsUsePlumberList bool

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
	VarsProtectedEnabled   bool
	VarsMaskedEnabled      bool

	RequireComponents      bool
	RequiredComponentsExpr string

	RequireTemplates      bool
	RequiredTemplatesExpr string

	// includesMustNotUseForbiddenVersions (when compForbidden selected)
	ForbiddenVersionsMultiline      string
	DefaultBranchIsForbiddenVersion bool

	// securityJobsMustNotBeWeakened (when compSecurity selected). All
	// three sub-toggles are tracked per provider: GitLab ships them off
	// (its security templates trip allow_failure / rules / when:manual)
	// while GitHub has no such convention and defaults all three on,
	// matching .plumber.yaml.
	SecurityJobPatternsMultiline   string
	SecuritySubAllowFailure        bool
	SecuritySubAllowFailureGitHub  bool
	SecuritySubRules               bool
	SecuritySubRulesGitHub         bool
	SecuritySubWhenNotManual       bool
	SecuritySubWhenNotManualGitHub bool

	// GitHub-only composition controls (when compDebugTraceGitHub /
	// required-actions are selected).
	DebugForbiddenVariablesGitHubMultiline string
	RequireActions                         bool
	RequiredActionsExpr                    string

	// pipelineMustNotExecuteUnverifiedScripts (when compScripts selected)
	ScriptTrustedURLsMultiline string

	// pipelineMustNotOverrideJobVariables (when compJobVars selected)
	JobOverrideVariablesMultiline string

	// pipelineMustNotUseDockerInDocker (when compDinD selected)
	DinDDetectInsecureDaemon bool

	// branchMustBeProtected (when catAccess). Code-owner approval is
	// tracked per provider; the curated default is off for both GitLab
	// and GitHub, matching .plumber.yaml.
	BranchDefaultMustBeProtected          bool
	BranchAllowForcePush                  bool
	BranchCodeOwnerApprovalRequired       bool
	BranchCodeOwnerApprovalRequiredGitHub bool
	BranchMinMergeAccessLevel             string
	BranchMinPushAccessLevel              string

	// mergeRequestApprovalRulesMustRequireMinimumApprovals /
	// ...MustCoverAllProtectedBranches (GitLab-only, catAccess).
	MRApprovalMinEnabled      bool
	MRApprovalMinCount        string
	MRApprovalCoverAllEnabled bool

	// mergeRequestApprovalSettingsMustBeCompliant (GitLab-only, catAccess).
	MRApprovalSettingsEnabled           bool
	MRApprovalSettingsPreventAuthor     bool
	MRApprovalSettingsPreventCommitters bool
	MRApprovalSettingsPreventEditing    bool
	MRApprovalSettingsRequireReAuth     bool
	MRApprovalSettingsBehavior          string

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

func (st *initWizardState) askImageQuestions() error {
	printInitSection("Container image security")
	if err := survey.AskOne(&survey.Confirm{Message: "Forbid mutable image tags (e.g. latest, dev, main)?", Default: true}, &st.ForbiddenTagsEnabled); err != nil {
		return err
	}
	if st.ForbiddenTagsEnabled {
		if err := survey.AskOne(&survey.Input{
			Message: "Forbidden tags (comma-separated)",
			Default: defaultForbiddenTags(),
		}, &st.ForbiddenTagsCSV); err != nil {
			return err
		}
		if err := survey.AskOne(&survey.Confirm{Message: "Require every image to be pinned by digest (@sha256:…)?", Default: true}, &st.PinByDigest); err != nil {
			return err
		}
	}
	if !hasProvider(st, "gitlab") {
		return nil
	}
	if err := survey.AskOne(&survey.Confirm{Message: "Restrict images to authorized registries only? (GitLab)", Default: true}, &st.AuthorizedEnabled); err != nil {
		return err
	}
	if !st.AuthorizedEnabled {
		return nil
	}
	if err := survey.AskOne(&survey.Confirm{Message: "Trust official Docker Hub library images (e.g. alpine, python)?", Default: true}, &st.TrustDockerHubOfficial); err != nil {
		return err
	}
	return survey.AskOne(&survey.Multiline{
		Message: "Trusted registry URL patterns (one per line)",
		Help:    "Supports wildcards, e.g. registry.example.com/*, $CI_REGISTRY_IMAGE:*. Images not matching any pattern will be flagged.",
		Default: strings.Join(defaultTrustedURLs(), "\n"),
	}, &st.TrustedURLsText)
}

func (st *initWizardState) askGitLabSecurityJobQuestions() error {
	if err := survey.AskOne(&survey.Multiline{
		Message: "GitLab security-job patterns (one per line)",
		Help:    "Wildcards are supported, e.g. *-sast, gemnasium-*. GitLab job names are bare (no workflow prefix).",
		Default: strings.Join(defaultSecurityJobPatterns(), "\n"),
	}, &st.SecurityJobPatternsMultiline); err != nil {
		return err
	}
	if err := survey.AskOne(&survey.Confirm{Message: "Flag GitLab jobs that set allow_failure: true?", Default: false}, &st.SecuritySubAllowFailure); err != nil {
		return err
	}
	if err := survey.AskOne(&survey.Confirm{Message: "Flag GitLab jobs that redefine rules?", Default: true}, &st.SecuritySubRules); err != nil {
		return err
	}
	return survey.AskOne(&survey.Confirm{Message: "Flag GitLab jobs that set when: manual?", Default: true}, &st.SecuritySubWhenNotManual)
}

func (st *initWizardState) askGitHubSecurityJobQuestions() error {
	if err := survey.AskOne(&survey.Multiline{
		Message: "GitHub security-job patterns (one per line)",
		Help:    "GitHub job names are namespaced as workflow/job, so patterns use *substring* form. Defaults cover the GitHub-native scanners.",
		Default: strings.Join(defaultGitHubSecurityJobPatterns(), "\n"),
	}, &st.SecurityJobPatternsGitHubMultiline); err != nil {
		return err
	}
	if err := survey.AskOne(&survey.Confirm{Message: "Flag GitHub jobs that set continue-on-error: true?", Default: true}, &st.SecuritySubAllowFailureGitHub); err != nil {
		return err
	}
	if err := survey.AskOne(&survey.Confirm{Message: "Flag GitHub jobs that redefine rules (if:/when overrides)?", Default: true}, &st.SecuritySubRulesGitHub); err != nil {
		return err
	}
	return survey.AskOne(&survey.Confirm{Message: "Flag GitHub jobs that are manual-dispatch only?", Default: true}, &st.SecuritySubWhenNotManualGitHub)
}

func (st *initWizardState) askSecurityJobQuestions() error {
	fmt.Fprintf(os.Stderr, "\n  › Security jobs\n")
	if hasProvider(st, "gitlab") {
		if err := st.askGitLabSecurityJobQuestions(); err != nil {
			return err
		}
	}
	if hasProvider(st, "github") {
		return st.askGitHubSecurityJobQuestions()
	}
	return nil
}

func (st *initWizardState) askRequiredInclusionQuestions() error {
	if hasProvider(st, "github") {
		fmt.Fprintf(os.Stderr, "\n  › Required actions (GitHub)\n")
		if err := survey.AskOne(&survey.Confirm{Message: "Require specific actions or reusable workflows across all workflows?", Default: false}, &st.RequireActions); err != nil {
			return err
		}
		if st.RequireActions {
			if err := survey.AskOne(&survey.Input{
				Message: "Required actions expression",
				Help:    "owner/repo[/path] entries with optional AND / OR and parentheses. Examples:\n  myorg/sast-scan\n  myorg/sast-scan AND myorg/dependency-review\n  (myorg/sast-scan AND myorg/secret-scan) OR myorg/full-security-suite",
			}, &st.RequiredActionsExpr); err != nil {
				return err
			}
		}
	}
	if !hasProvider(st, "gitlab") {
		return nil
	}
	fmt.Fprintf(os.Stderr, "\n  › Required inclusions (GitLab)\n")
	if err := survey.AskOne(&survey.Confirm{Message: "Require specific catalog components in every pipeline?", Default: false}, &st.RequireComponents); err != nil {
		return err
	}
	if st.RequireComponents {
		if err := survey.AskOne(&survey.Input{
			Message: "Required components expression",
			Help:    "Paths with optional AND / OR and parentheses. Examples:\n  components/sast/sast\n  components/sast/sast AND components/secret-detection/secret-detection\n  (components/sast/sast AND components/secret-detection) OR components/full-security",
		}, &st.RequiredComponentsExpr); err != nil {
			return err
		}
	}
	fmt.Fprintln(os.Stderr)
	if err := survey.AskOne(&survey.Confirm{Message: "Require specific project file templates in every pipeline?", Default: false}, &st.RequireTemplates); err != nil {
		return err
	}
	if st.RequireTemplates {
		return survey.AskOne(&survey.Input{
			Message: "Required templates expression",
			Help:    "Paths with optional AND / OR and parentheses. Examples:\n  templates/security/sast\n  templates/security/sast AND templates/security/secret-detection",
		}, &st.RequiredTemplatesExpr)
	}
	return nil
}

// askCompositionFirstHalf covers: action-pin, forbidden refs, security jobs, scripts.
func (st *initWizardState) askCompositionFirstHalf() error {
	if compSelected(st, compActionPin) {
		fmt.Fprintf(os.Stderr, "\n  › Action pin trusted owners (GitHub)\n")
		if err := survey.AskOne(&survey.Multiline{
			Message: "Action-owner prefixes exempt from the pin-by-SHA requirement (one per line)",
			Help:    "Only list owners already inside your workflow's trust boundary. \"actions\" and \"github\" cover the first-party GitHub-owned actions.",
			Default: strings.Join(defaultGitHubTrustedActionOwners(), "\n"),
		}, &st.ActionPinTrustedOwnersMultiline); err != nil {
			return err
		}
	}
	if compSelected(st, compAuthorizedActions) && hasProvider(st, "github") {
		fmt.Fprintf(os.Stderr, "\n  › Authorized action sources (GitHub)\n")
		const (
			curated = "Include Plumber's curated trusted orgs (recommended)"
			scratch = "Start from an empty allowlist (add your own orgs)"
		)
		choice := curated
		if err := survey.AskOne(&survey.Select{
			Message: "Trusted third-party action sources:",
			Help:    "GitHub-official (actions/*, github/*) and your own org are trusted either way. \"Curated\" also ships Plumber's allowlist of well-known publisher orgs plus a 20,000-star trust floor — the same set as the default template. \"From scratch\" leaves the allowlist empty for you to fill in.",
			Options: []string{curated, scratch},
			Default: curated,
		}, &choice); err != nil {
			return err
		}
		st.AuthorizedActionsUsePlumberList = choice == curated
	}
	if compSelected(st, compForbidden) && hasProvider(st, "gitlab") {
		fmt.Fprintf(os.Stderr, "\n  › Forbidden include refs\n")
		if err := survey.AskOne(&survey.Multiline{
			Message: "Forbidden version refs (one per line)",
			Help:    "Refs like latest, ~latest, main, master, HEAD are mutable and can introduce breaking changes silently.",
			Default: strings.Join(defaultForbiddenVersions(), "\n"),
		}, &st.ForbiddenVersionsMultiline); err != nil {
			return err
		}
		if err := survey.AskOne(&survey.Confirm{
			Message: "Also treat the project's default branch name as a forbidden ref?",
			Default: false,
		}, &st.DefaultBranchIsForbiddenVersion); err != nil {
			return err
		}
	}
	if compSelected(st, compSecurity) {
		if err := st.askSecurityJobQuestions(); err != nil {
			return err
		}
	}
	if compSelected(st, compScripts) {
		fmt.Fprintf(os.Stderr, "\n  › Unverified scripts\n")
		if err := survey.AskOne(&survey.Multiline{
			Message: "Script host URL patterns to trust (one per line)",
			Help:    "Leave empty to flag every remote script. Example: https://internal.example.com/*",
		}, &st.ScriptTrustedURLsMultiline); err != nil {
			return err
		}
	}
	return nil
}

// askCompositionSecondHalf covers: job-var overrides, DinD, debug trace, required inclusions.
func (st *initWizardState) askCompositionSecondHalf() error {
	if compSelected(st, compJobVars) && hasProvider(st, "gitlab") {
		fmt.Fprintf(os.Stderr, "\n  › Job variable overrides\n")
		if err := survey.AskOne(&survey.Multiline{
			Message: "Variables that pipelines must not override (one per line)",
			Help:    "These are security-critical GitLab CI variables; overriding them can disable scanning.",
			Default: strings.Join(defaultJobOverrideVariables(), "\n"),
		}, &st.JobOverrideVariablesMultiline); err != nil {
			return err
		}
	}
	if compSelected(st, compDinD) {
		fmt.Fprintf(os.Stderr, "\n  › Docker-in-Docker\n")
		if err := survey.AskOne(&survey.Confirm{
			Message: "Also detect insecure daemon socket usage (e.g. tcp:// without TLS)?",
			Default: true,
		}, &st.DinDDetectInsecureDaemon); err != nil {
			return err
		}
	}
	if compSelected(st, compDebugTraceGitHub) {
		fmt.Fprintf(os.Stderr, "\n  › Actions debug logging\n")
		if err := survey.AskOne(&survey.Multiline{
			Message: "Forbidden debug variables (one per line)",
			Help:    "Setting these to true makes the Actions runner dump every env var (including masked secrets) into the job log.",
			Default: strings.Join(defaultGitHubDebugTraceVariables(), "\n"),
		}, &st.DebugForbiddenVariablesGitHubMultiline); err != nil {
			return err
		}
	}
	return st.askRequiredInclusionQuestions()
}

func (st *initWizardState) askCompositionDetails() error {
	if err := st.askCompositionFirstHalf(); err != nil {
		return err
	}
	return st.askCompositionSecondHalf()
}

func (st *initWizardState) askCompositionQuestions() error {
	printInitSection("Pipeline composition")
	allComp := compositionOptionsForProviders(st.Providers)
	if err := survey.AskOne(&survey.MultiSelect{
		Message:  "Which pipeline checks should be enabled?",
		Options:  allComp,
		PageSize: 14,
		Default:  allComp,
	}, &st.CompositionChoices, survey.WithValidator(survey.Required)); err != nil {
		return err
	}
	return st.askCompositionDetails()
}

func (st *initWizardState) askAccessQuestions() error {
	printInitSection("Access control: branch protection")
	st.BranchEnabled = true
	if err := survey.AskOne(&survey.Input{
		Message: "Branch name patterns to protect (comma-separated; wildcards ok)",
		Default: defaultBranchPatterns(),
	}, &st.BranchPatterns); err != nil {
		return err
	}
	if err := survey.AskOne(&survey.Confirm{
		Message: "Require the repository default branch to be covered by a protected pattern?",
		Default: true,
	}, &st.BranchDefaultMustBeProtected); err != nil {
		return err
	}
	if err := survey.AskOne(&survey.Confirm{Message: "Allow force push on protected branches?", Default: false}, &st.BranchAllowForcePush); err != nil {
		return err
	}
	if hasProvider(st, "gitlab") {
		if err := survey.AskOne(&survey.Confirm{
			Message: "Require code owner approval on protected branches? (GitLab)",
			Default: false,
		}, &st.BranchCodeOwnerApprovalRequired); err != nil {
			return err
		}
		if err := survey.AskOne(&survey.Input{
			Message: "Minimum access level to merge (GitLab)",
			Help:    "30 = Developer, 40 = Maintainer, 50 = Owner",
			Default: "30",
		}, &st.BranchMinMergeAccessLevel); err != nil {
			return err
		}
		if err := survey.AskOne(&survey.Input{
			Message: "Minimum access level to push to protected branches (GitLab)",
			Help:    "30 = Developer, 40 = Maintainer, 50 = Owner",
			Default: "40",
		}, &st.BranchMinPushAccessLevel); err != nil {
			return err
		}
		if err := survey.AskOne(&survey.Confirm{
			Message: "Flag MR approval rules that require fewer than a minimum number of approvals? (GitLab)",
			Help:    "Checks approval rules covering all protected branches against a minimum. Requires a token that can read approval rules (a premium feature). Ships off by default.",
			Default: defaultMRApprovalMinEnabled(),
		}, &st.MRApprovalMinEnabled); err != nil {
			return err
		}
		if st.MRApprovalMinEnabled {
			if err := survey.AskOne(&survey.Input{
				Message: "Minimum approvals a rule covering all protected branches must require (GitLab)",
				Default: fmt.Sprintf("%d", defaultMRApprovalMinCount()),
			}, &st.MRApprovalMinCount); err != nil {
				return err
			}
		}
		if err := survey.AskOne(&survey.Confirm{
			Message: "Flag projects where no MR approval rule covers all protected branches? (GitLab)",
			Help:    "A protected branch with no covering approval rule can be merged with no required approval. Ships off by default.",
			Default: defaultMRApprovalCoverAllEnabled(),
		}, &st.MRApprovalCoverAllEnabled); err != nil {
			return err
		}
		if err := survey.AskOne(&survey.Confirm{
			Message: "Check MR approval settings against expectations? (GitLab)",
			Help:    "Compares the project's approval settings (author/committer approval, per-MR overrides, re-auth, approval reset) to the expectations you pick next. Ships off by default.",
			Default: defaultMRApprovalSettingsEnabled(),
		}, &st.MRApprovalSettingsEnabled); err != nil {
			return err
		}
		if st.MRApprovalSettingsEnabled {
			if err := survey.AskOne(&survey.Confirm{
				Message: "Expect that MR authors cannot approve their own merge requests? (GitLab)",
				Default: defaultMRApprovalSettingsBool(func(c *configuration.MRApprovalSettingsControlConfig) *bool { return c.PreventApprovalByAuthor }),
			}, &st.MRApprovalSettingsPreventAuthor); err != nil {
				return err
			}
			if err := survey.AskOne(&survey.Confirm{
				Message: "Expect that users who committed to an MR cannot approve it? (GitLab)",
				Default: defaultMRApprovalSettingsBool(func(c *configuration.MRApprovalSettingsControlConfig) *bool { return c.PreventApprovalsByCommitters }),
			}, &st.MRApprovalSettingsPreventCommitters); err != nil {
				return err
			}
			if err := survey.AskOne(&survey.Confirm{
				Message: "Expect that approval rules cannot be edited per merge request? (GitLab)",
				Default: defaultMRApprovalSettingsBool(func(c *configuration.MRApprovalSettingsControlConfig) *bool { return c.PreventEditingApprovalRulesInMR }),
			}, &st.MRApprovalSettingsPreventEditing); err != nil {
				return err
			}
			if err := survey.AskOne(&survey.Confirm{
				Message: "Expect re-authentication to approve? (GitLab)",
				Help:    "Strict: every approval re-prompts credentials. Answering no leaves this setting unchecked.",
				Default: defaultMRApprovalSettingsBool(func(c *configuration.MRApprovalSettingsControlConfig) *bool { return c.RequireReAuthToApprove }),
			}, &st.MRApprovalSettingsRequireReAuth); err != nil {
				return err
			}
			if err := survey.AskOne(&survey.Select{
				Message: "Minimum required behavior when a commit is added to an open MR (GitLab)",
				Help:    "A project below the chosen rung is flagged: keep_approvals (weakest, effectively unchecked) < remove_approvals_by_code_owners < remove_all_approvals.",
				Options: mrApprovalBehaviorOptions(),
				Default: defaultMRApprovalSettingsBehavior(),
			}, &st.MRApprovalSettingsBehavior); err != nil {
				return err
			}
		}
	}
	if hasProvider(st, "github") {
		if err := survey.AskOne(&survey.Confirm{
			Message: "Require code owner approval on protected branches? (GitHub)",
			Default: false,
		}, &st.BranchCodeOwnerApprovalRequiredGitHub); err != nil {
			return err
		}
	}
	return nil
}

func (st *initWizardState) askVariableQuestions() error {
	printInitSection("Variable security")
	if err := survey.AskOne(&survey.Confirm{Message: "Flag CI/CD settings variables (Settings > CI/CD > Variables) that are not protected?", Help: "Unprotected variables are exposed to pipelines on unprotected branches. Requires a GitLab token that can read variables. Ships off by default.", Default: defaultCicdVariablesProtectedEnabled()}, &st.VarsProtectedEnabled); err != nil {
		return err
	}
	if err := survey.AskOne(&survey.Confirm{Message: "Flag CI/CD settings variables that are not masked?", Help: "Unmasked variables print verbatim in job logs. Ships off by default.", Default: defaultCicdVariablesMaskedEnabled()}, &st.VarsMaskedEnabled); err != nil {
		return err
	}
	if err := survey.AskOne(&survey.Confirm{Message: "Flag pipelines that enable CI_DEBUG_TRACE or CI_DEBUG_SERVICES?", Default: true}, &st.DebugTraceEnabled); err != nil {
		return err
	}
	if st.DebugTraceEnabled {
		if err := survey.AskOne(&survey.Multiline{
			Message: "Variables whose presence in pipeline YAML is forbidden (one per line)",
			Help:    "Setting CI_DEBUG_TRACE=true exposes all masked variables and secrets in job logs.",
			Default: "CI_DEBUG_TRACE\nCI_DEBUG_SERVICES",
		}, &st.DebugForbiddenVariablesMultiline); err != nil {
			return err
		}
	}
	if err := survey.AskOne(&survey.Confirm{Message: "Flag pipelines that expand user-controlled variables in scripts unsafely?", Default: true}, &st.UnsafeExpansionEnabled); err != nil {
		return err
	}
	if !st.UnsafeExpansionEnabled {
		return nil
	}
	if err := survey.AskOne(&survey.Multiline{
		Message: "User-controlled variables to watch for unsafe expansion (one per line)",
		Help:    "These are variables whose values come from user input (MR title, commit message, branch name, etc.) and should not appear in scripts without sanitization.",
		Default: strings.Join(defaultDangerousVariables(), "\n"),
	}, &st.DangerousVariablesMultiline); err != nil {
		return err
	}
	return survey.AskOne(&survey.Multiline{
		Message: "Script line regexes to exclude from findings (one per line, optional)",
		Help:    "Lines matching any of these patterns are ignored. Useful for approved patterns like echo \"$$VAR\" that are safe in your context.",
	}, &st.AllowedPatternsMultiline)
}

func (st *initWizardState) hasCategory(cat string) bool {
	return slices.Contains(st.Categories, cat)
}

func (st *initWizardState) askCategoryQuestions() error {
	if st.hasCategory(catImages) {
		if err := st.askImageQuestions(); err != nil {
			return err
		}
	}
	if st.hasCategory(catComposition) {
		if err := st.askCompositionQuestions(); err != nil {
			return err
		}
	}
	if st.hasCategory(catAccess) {
		if err := st.askAccessQuestions(); err != nil {
			return err
		}
	}
	if st.hasCategory(catVariables) {
		if err := st.askVariableQuestions(); err != nil {
			return err
		}
	}
	return nil
}

func runInitWizard(skipAnalyzePrompt bool) (*initWizardState, error) {
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
	// an explicit "Both" option still covers monorepos that ship to
	// both platforms or shared config repos.
	providerOptions := []string{provGitLab, provGitHub, provBoth}
	providerDefault := provGitLab
	if d := autoDetectProviderForInit(); len(d) > 0 {
		providerDefault = d[0]
	}
	var providerChoice string
	if err := survey.AskOne(&survey.Select{
		Message:  "Which provider do you want to configure?",
		Help:     "Pick the platform this config targets. Choose Both for a monorepo or a config file shared across repos. The default follows your git remote.",
		Options:  providerOptions,
		PageSize: 4,
		Default:  providerDefault,
	}, &providerChoice); err != nil {
		return nil, err
	}
	st.Providers = providersFromProviderChoice(providerChoice)

	allCats := wizardCategoriesForProviders(st.Providers)
	if err := survey.AskOne(&survey.MultiSelect{
		Message:  "Which areas do you want to enforce?",
		Options:  allCats,
		PageSize: 10,
		Default:  allCats,
	}, &st.Categories, survey.WithValidator(survey.Required)); err != nil {
		return nil, err
	}

	if err := st.askCategoryQuestions(); err != nil {
		return nil, err
	}

	if !skipAnalyzePrompt {
		fmt.Fprintln(os.Stderr)
		var runAnalyze bool
		if err := survey.AskOne(&survey.Confirm{
			Message: "Run 'plumber analyze' after writing? (" + runAnalyzeAuthHint(st.Providers) + ")",
			Default: false,
		}, &runAnalyze); err != nil {
			return nil, err
		}
		st.runAnalyzeAfter = runAnalyze
	}
	return st, nil
}

func boolPtrInit(b bool) *bool { return &b }
func intPtrInit(i int) *int    { return &i }

// hasProvider reports whether the wizard state currently targets the
// given canonical provider name ("gitlab" or "github"). Returns false
// for an empty Providers slice — callers should always set at least
// one provider before invoking the per-control flow.
func hasProvider(st *initWizardState, name string) bool {
	return slices.Contains(st.Providers, name)
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

// providersFromProviderChoice maps the single provider-selection answer
// (provGitLab / provGitHub / provBoth) to the canonical provider list.
// A single-select replaces rather than accumulates, so picking GitHub
// yields GitHub only; "Both" is the explicit multi-provider opt-in
// (issue #256, where a pre-checked multi-select left GitLab in scope).
func providersFromProviderChoice(choice string) []string {
	labels := []string{choice}
	if choice == provBoth {
		labels = []string{provGitLab, provGitHub}
	}
	return providersFromWizardLabels(labels)
}

// autoDetectProviderForInit picks the default provider selection
// based on the current git remote so the most common single-provider
// case lands on the right highlighted default without the user
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
		out = append(out, compHardcoded, compUpToDate, compForbidden, compRefCollision)
	}
	out = append(out, compSecurity, compDinD)
	if hasGitLab {
		out = append(out, compScripts, compJobVars)
	}
	if hasGitHub {
		out = append(out,
			compActionPin,
			compAuthorizedActions,
			compDangerousTriggers,
			compPRTargetHead,
			compDeclarePermissions,
			compReusableSecrets,
			compOverprovSecrets,
			compTemplateInjection,
			compEnvInjection,
			compWriteAllPerms,
			compRefConfusion,
			compArchivedActions,
			compKnownCVEs,
			compImpostorCommit,
			compMutableRemoteExec,
			compCachePoisoning,
			compDebugTraceGitHub,
		)
	}
	return out
}

// defaultGitHubDebugTraceVariables mirrors the .plumber.yaml default for
// github.controls.pipelineMustNotEnableDebugTrace.forbiddenVariables — the
// Actions debug toggles that dump masked secrets into job logs.
// embeddedDefault parses the shipped default config (defaultconfig.Get — the
// same bytes embedded in the binary and written verbatim by `plumber config
// generate`) once. The wizard sources every default value from here instead of
// hand-maintained copies, so `plumber init` and the shipped baseline cannot
// drift. The embed is a compile-time constant covered by
// TestConfigFilesLoadAndValidate, so an unparseable/incomplete embed is a
// build-time bug — hence the panic.
var embeddedDefault = sync.OnceValue(func() *configuration.PlumberConfig {
	var cfg configuration.PlumberConfig
	if err := yaml.Unmarshal(defaultconfig.Get(), &cfg); err != nil {
		panic(fmt.Sprintf("plumber: embedded default config is unparseable: %v", err))
	}
	if cfg.GitLab == nil || cfg.GitHub == nil {
		panic("plumber: embedded default config is missing a provider section")
	}
	return &cfg
})

func defaultGitLabControls() configuration.ControlsConfig { return embeddedDefault().GitLab.Controls }
func defaultGitHubControls() configuration.ControlsConfig { return embeddedDefault().GitHub.Controls }

// defaultMRApproval* source the wizard's Confirm/Input defaults for the
// merge-request approval-rule controls from the shipped default, so the
// prompts and the zero-config baseline cannot drift.
func defaultMRApprovalMinEnabled() bool {
	if c := defaultGitLabControls().MergeRequestApprovalRulesMustRequireMinimumApprovals; c != nil {
		return c.IsEnabled()
	}
	return false
}

func defaultMRApprovalMinCount() int {
	if c := defaultGitLabControls().MergeRequestApprovalRulesMustRequireMinimumApprovals; c != nil && c.MinimumRequiredApprovals != nil {
		return *c.MinimumRequiredApprovals
	}
	return 1
}

func defaultMRApprovalCoverAllEnabled() bool {
	if c := defaultGitLabControls().MergeRequestApprovalRulesMustCoverAllProtectedBranches; c != nil {
		return c.IsEnabled()
	}
	return false
}

// defaultCicdVariablesProtectedEnabled / ...Masked source the wizard's
// Confirm defaults from the shipped default (both ship disabled), so the
// wizard prompt and the zero-config baseline cannot drift.
func defaultCicdVariablesProtectedEnabled() bool {
	if c := defaultGitLabControls().CicdVariablesMustBeProtected; c != nil {
		return c.IsEnabled()
	}
	return false
}

func defaultCicdVariablesMaskedEnabled() bool {
	if c := defaultGitLabControls().CicdVariablesMustBeMasked; c != nil {
		return c.IsEnabled()
	}
	return false
}

// defaultMRApprovalSettings* source the wizard's prompt defaults for the
// merge-request approval-settings control from the shipped default, so the
// prompts and the zero-config baseline cannot drift.
func defaultMRApprovalSettingsEnabled() bool {
	if c := defaultGitLabControls().MergeRequestApprovalSettingsMustBeCompliant; c != nil {
		return c.IsEnabled()
	}
	return false
}

// defaultMRApprovalSettingsBool reads one optional boolean expectation from
// the shipped default via the field selector; an unset field defaults the
// prompt to false ("not checked").
func defaultMRApprovalSettingsBool(field func(*configuration.MRApprovalSettingsControlConfig) *bool) bool {
	if c := defaultGitLabControls().MergeRequestApprovalSettingsMustBeCompliant; c != nil {
		if v := field(c); v != nil {
			return *v
		}
	}
	return false
}

func defaultMRApprovalSettingsBehavior() string {
	if c := defaultGitLabControls().MergeRequestApprovalSettingsMustBeCompliant; c != nil && c.BehaviorWhenCommitIsAdded != nil {
		return *c.BehaviorWhenCommitIsAdded
	}
	return ir.MRApprovalBehaviorKeepApprovals
}

// mrApprovalBehaviorOptions is the behavior ladder in strictness order, from
// the IR constants the projection emits (the same values config validation
// accepts).
func mrApprovalBehaviorOptions() []string {
	return []string{
		ir.MRApprovalBehaviorKeepApprovals,
		ir.MRApprovalBehaviorRemoveCodeOwnerApprovals,
		ir.MRApprovalBehaviorRemoveAllApprovals,
	}
}

// defaultForbiddenTags is the CSV prompt default for forbidden image tags,
// sourced from the GitLab containerImageMustNotUseForbiddenTags default.
func defaultForbiddenTags() string {
	if c := defaultGitLabControls().ContainerImageMustNotUseForbiddenTags; c != nil {
		return strings.Join(c.Tags, ", ")
	}
	return ""
}

// defaultBranchPatterns is the CSV prompt default for protected-branch
// patterns, sourced from the GitLab branchMustBeProtected default.
func defaultBranchPatterns() string {
	if c := defaultGitLabControls().BranchMustBeProtected; c != nil {
		return strings.Join(c.NamePatterns, ", ")
	}
	return ""
}

// defaultTrustedActionsMinimumStars sources the star floor for
// githubActionMustComeFromAuthorizedSources from the embedded default.
func defaultTrustedActionsMinimumStars() int {
	if c := defaultGitHubControls().GithubActionMustComeFromAuthorizedSources; c != nil {
		return c.MinimumStars
	}
	return 0
}

func defaultGitHubDebugTraceVariables() []string {
	if c := defaultGitHubControls().PipelineMustNotEnableDebugTrace; c != nil {
		return c.ForbiddenVariables
	}
	return nil
}

// defaultCachePoisoning* mirror the shipped .plumber.yaml inventories for
// releaseWorkflowsMustNotRestoreUntrustedCache. Kept in sync with the
// embedded default by TestStarterGitHubControlsMatchEmbeddedDefault.
func defaultCachePoisoningPublishActions() []string {
	if c := defaultGitHubControls().ReleaseWorkflowsMustNotRestoreUntrustedCache; c != nil {
		return c.PublishActions
	}
	return nil
}

func defaultCachePoisoningCacheActions() []configuration.CacheActionSpec {
	if c := defaultGitHubControls().ReleaseWorkflowsMustNotRestoreUntrustedCache; c != nil {
		return c.CacheActions
	}
	return nil
}

func defaultCachePoisoningPublishScriptPatterns() []string {
	if c := defaultGitHubControls().ReleaseWorkflowsMustNotRestoreUntrustedCache; c != nil {
		return c.PublishScriptPatterns
	}
	return nil
}

func defaultCachePoisoningPublishScriptExcludePatterns() []string {
	if c := defaultGitHubControls().ReleaseWorkflowsMustNotRestoreUntrustedCache; c != nil {
		return c.PublishScriptExcludePatterns
	}
	return nil
}

// defaultGitHubSecurityJobPatterns mirrors the GitHub-side defaults
// shipped in .plumber.yaml's github.controls.securityJobsMustNotBeWeakened
// block. GitHub job identifiers are namespaced as `workflow/job`, so
// every pattern uses leading + trailing wildcards.
func defaultGitHubSecurityJobPatterns() []string {
	if c := defaultGitHubControls().SecurityJobsMustNotBeWeakened; c != nil {
		return c.SecurityJobPatterns
	}
	return nil
}

// defaultGitHubTrustedActionOwners mirrors the .plumber.yaml default
// for actionsMustBePinnedByCommitSha.trustedOwners — the first-party
// owners whose actions the runtime trusts implicitly.
func defaultGitHubTrustedActionOwners() []string {
	if c := defaultGitHubControls().ActionsMustBePinnedByCommitSha; c != nil {
		return c.TrustedOwners
	}
	return nil
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

// defaultTrustedURLs mirrors the .plumber.yaml default for
// gitlab.controls.containerImageMustComeFromAuthorizedSources.trustedUrls.
// Kept in lockstep with the embedded default by
// TestDefaultTrustedURLsMatchEmbeddedDefault.
func defaultTrustedURLs() []string {
	if c := defaultGitLabControls().ContainerImageMustComeFromAuthorizedSources; c != nil {
		return c.TrustedUrls
	}
	return nil
}

// defaultTrustedGithubActions mirrors the .plumber.yaml default for
// github.controls.githubActionMustComeFromAuthorizedSources.trustedGithubActions
// — Plumber's curated allowlist of well-known publisher orgs. Kept in lockstep
// with the embedded default by TestDefaultTrustedGithubActionsMatchEmbeddedDefault.
func defaultTrustedGithubActions() []string {
	if c := defaultGitHubControls().GithubActionMustComeFromAuthorizedSources; c != nil {
		return c.TrustedGithubActions
	}
	return nil
}

func defaultDangerousVariables() []string {
	if c := defaultGitLabControls().PipelineMustNotUseUnsafeVariableExpansion; c != nil {
		return c.DangerousVariables
	}
	return nil
}

func defaultJobOverrideVariables() []string {
	if c := defaultGitLabControls().PipelineMustNotOverrideJobVariables; c != nil {
		return c.Variables
	}
	return nil
}

func defaultSecurityJobPatterns() []string {
	if c := defaultGitLabControls().SecurityJobsMustNotBeWeakened; c != nil {
		return c.SecurityJobPatterns
	}
	return nil
}

func defaultForbiddenVersions() []string {
	if c := defaultGitLabControls().IncludesMustNotUseForbiddenVersions; c != nil {
		return c.ForbiddenVersions
	}
	return nil
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
	return slices.Contains(st.CompositionChoices, label)
}

func (st *initWizardState) applyImageControls(gl, gh *configuration.ProviderConfig) {
	if st.ForbiddenTagsEnabled {
		tags := parseCSVInit(st.ForbiddenTagsCSV)
		if len(tags) == 0 {
			tags = parseCSVInit(defaultForbiddenTags())
		}
		block := &configuration.ImageForbiddenTagsControlConfig{
			Enabled:                             boolPtrInit(true),
			Tags:                                tags,
			ContainerImagesMustBePinnedByDigest: boolPtrInit(st.PinByDigest),
		}
		if gl != nil {
			gl.Controls.ContainerImageMustNotUseForbiddenTags = block
		}
		if gh != nil {
			gh.Controls.ContainerImageMustNotUseForbiddenTags = block
		}
	}
	// containerImageMustComeFromAuthorizedSources is GitLab-only.
	if st.AuthorizedEnabled && gl != nil {
		urls := parseLinesInit(st.TrustedURLsText)
		if len(urls) == 0 {
			urls = defaultTrustedURLs()
		}
		gl.Controls.ContainerImageMustComeFromAuthorizedSources = &configuration.ImageAuthorizedSourcesControlConfig{
			Enabled:                      boolPtrInit(true),
			TrustedUrls:                  urls,
			TrustDockerHubOfficialImages: boolPtrInit(st.TrustDockerHubOfficial),
		}
	}
}

func (st *initWizardState) applyAccessControls(gl, gh *configuration.ProviderConfig) {
	patterns := parseCSVInit(st.BranchPatterns)
	if len(patterns) == 0 {
		patterns = parseCSVInit(defaultBranchPatterns())
	}
	if gl != nil {
		gl.Controls.BranchMustBeProtected = &configuration.BranchProtectionControlConfig{
			Enabled:                   boolPtrInit(true),
			DefaultMustBeProtected:    boolPtrInit(st.BranchDefaultMustBeProtected),
			NamePatterns:              patterns,
			AllowForcePush:            boolPtrInit(st.BranchAllowForcePush),
			CodeOwnerApprovalRequired: boolPtrInit(st.BranchCodeOwnerApprovalRequired),
			MinMergeAccessLevel:       intPtrInit(parseIntInit(st.BranchMinMergeAccessLevel, 30)),
			MinPushAccessLevel:        intPtrInit(parseIntInit(st.BranchMinPushAccessLevel, 40)),
		}
		if st.MRApprovalMinEnabled {
			gl.Controls.MergeRequestApprovalRulesMustRequireMinimumApprovals = &configuration.MRApprovalRulesMinApprovalsControlConfig{
				Enabled:                  boolPtrInit(true),
				MinimumRequiredApprovals: intPtrInit(parseIntInit(st.MRApprovalMinCount, defaultMRApprovalMinCount())),
			}
		}
		if st.MRApprovalCoverAllEnabled {
			gl.Controls.MergeRequestApprovalRulesMustCoverAllProtectedBranches = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
		}
		if st.MRApprovalSettingsEnabled {
			// Every expectation is emitted, answered value included: a false
			// boolean means "not checked" (same as unset) but keeps the full
			// configuration surface visible in the generated file.
			behavior := st.MRApprovalSettingsBehavior
			if behavior == "" {
				behavior = defaultMRApprovalSettingsBehavior()
			}
			gl.Controls.MergeRequestApprovalSettingsMustBeCompliant = &configuration.MRApprovalSettingsControlConfig{
				Enabled:                         boolPtrInit(true),
				PreventApprovalByAuthor:         boolPtrInit(st.MRApprovalSettingsPreventAuthor),
				PreventApprovalsByCommitters:    boolPtrInit(st.MRApprovalSettingsPreventCommitters),
				PreventEditingApprovalRulesInMR: boolPtrInit(st.MRApprovalSettingsPreventEditing),
				RequireReAuthToApprove:          boolPtrInit(st.MRApprovalSettingsRequireReAuth),
				BehaviorWhenCommitIsAdded:       &behavior,
			}
		}
	}
	if gh != nil {
		// GitHub branch-protection ignores access-level fields.
		gh.Controls.BranchMustBeProtected = &configuration.BranchProtectionControlConfig{
			Enabled:                   boolPtrInit(true),
			DefaultMustBeProtected:    boolPtrInit(st.BranchDefaultMustBeProtected),
			NamePatterns:              patterns,
			AllowForcePush:            boolPtrInit(st.BranchAllowForcePush),
			CodeOwnerApprovalRequired: boolPtrInit(st.BranchCodeOwnerApprovalRequiredGitHub),
		}
	}
}

// applyVariableControls writes the catVariables controls (GitLab-only).
func (st *initWizardState) applyVariableControls(gl *configuration.ProviderConfig) {
	if st.DebugTraceEnabled {
		fb := parseLinesInit(st.DebugForbiddenVariablesMultiline)
		if len(fb) == 0 {
			fb = []string{"CI_DEBUG_TRACE", "CI_DEBUG_SERVICES"}
		}
		gl.Controls.PipelineMustNotEnableDebugTrace = &configuration.DebugTraceControlConfig{
			Enabled:            boolPtrInit(true),
			ForbiddenVariables: fb,
		}
	}
	if st.UnsafeExpansionEnabled {
		danger := parseLinesInit(st.DangerousVariablesMultiline)
		if len(danger) == 0 {
			danger = defaultDangerousVariables()
		}
		gl.Controls.PipelineMustNotUseUnsafeVariableExpansion = &configuration.VariableInjectionControlConfig{
			Enabled:            boolPtrInit(true),
			DangerousVariables: danger,
			AllowedPatterns:    parseLinesInit(st.AllowedPatternsMultiline),
		}
	}
	if st.VarsProtectedEnabled {
		gl.Controls.CicdVariablesMustBeProtected = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
	}
	if st.VarsMaskedEnabled {
		gl.Controls.CicdVariablesMustBeMasked = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
	}
}

func (st *initWizardState) toPlumberConfig() *configuration.PlumberConfig {
	cfg := &configuration.PlumberConfig{Version: "2.0"}

	providers := st.Providers
	if len(providers) == 0 {
		providers = []string{"gitlab"}
	}

	var gl, gh *configuration.ProviderConfig
	for _, p := range providers {
		switch p {
		case "gitlab":
			cfg.GitLab = &configuration.ProviderConfig{}
			gl = cfg.GitLab
		case "github":
			cfg.GitHub = &configuration.ProviderConfig{}
			gh = cfg.GitHub
		}
	}

	has := func(cat string) bool {
		for _, c := range st.Categories {
			if c == cat {
				return true
			}
		}
		return false
	}

	if has(catImages) {
		st.applyImageControls(gl, gh)
	}
	if has(catComposition) {
		// GitLab-only composition checks.
		if gl != nil {
			if compSelected(st, compHardcoded) {
				gl.Controls.PipelineMustNotIncludeHardcodedJobs = &configuration.HardcodedJobsControlConfig{
					Enabled: boolPtrInit(true),
				}
			}
			if compSelected(st, compUpToDate) {
				gl.Controls.IncludesMustBeUpToDate = &configuration.IncludesUpToDateControlConfig{
					Enabled: boolPtrInit(true),
				}
			}
			if compSelected(st, compRefCollision) {
				gl.Controls.ExternalRefsMustNotCollide = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
			}
			if compSelected(st, compForbidden) {
				vers := parseLinesInit(st.ForbiddenVersionsMultiline)
				if len(vers) == 0 {
					vers = defaultForbiddenVersions()
				}
				gl.Controls.IncludesMustNotUseForbiddenVersions = &configuration.IncludesForbiddenVersionsControlConfig{
					Enabled:                         boolPtrInit(true),
					ForbiddenVersions:               vers,
					DefaultBranchIsForbiddenVersion: boolPtrInit(st.DefaultBranchIsForbiddenVersion),
				}
			}
			if compSelected(st, compJobVars) {
				vars := parseLinesInit(st.JobOverrideVariablesMultiline)
				if len(vars) == 0 {
					vars = defaultJobOverrideVariables()
				}
				gl.Controls.PipelineMustNotOverrideJobVariables = &configuration.JobVariablesOverrideControlConfig{
					Enabled:   boolPtrInit(true),
					Variables: vars,
				}
			}

			if e := strings.TrimSpace(st.RequiredComponentsExpr); e != "" {
				gl.Controls.PipelineMustIncludeComponent = &configuration.RequiredComponentsControlConfig{
					Enabled:  boolPtrInit(true),
					Required: e,
				}
			} else if st.RequireComponents {
				fmt.Fprintln(os.Stderr, "Note: component requirement skipped (no expression provided).")
			}

			if e := strings.TrimSpace(st.RequiredTemplatesExpr); e != "" {
				gl.Controls.PipelineMustIncludeTemplate = &configuration.RequiredTemplatesControlConfig{
					Enabled:  boolPtrInit(true),
					Required: e,
				}
			} else if st.RequireTemplates {
				fmt.Fprintln(os.Stderr, "Note: template requirement skipped (no expression provided).")
			}
		}

		// Cross-provider: security-jobs. GitLab and GitHub take their
		// own pattern set (job-name conventions differ) and their own
		// allow-failure default (GitLab off, GitHub on); the other two
		// sub-toggles are shared. Each section gets fresh toggle structs
		// so the two providers never alias the same pointer.
		if compSelected(st, compSecurity) {
			if gl != nil {
				p := parseLinesInit(st.SecurityJobPatternsMultiline)
				if len(p) == 0 {
					p = defaultSecurityJobPatterns()
				}
				gl.Controls.SecurityJobsMustNotBeWeakened = &configuration.SecurityJobsWeakenedControlConfig{
					Enabled:                 boolPtrInit(true),
					SecurityJobPatterns:     p,
					AllowFailureMustBeFalse: &configuration.SecurityJobsSubControlToggle{Enabled: boolPtrInit(st.SecuritySubAllowFailure)},
					RulesMustNotBeRedefined: &configuration.SecurityJobsSubControlToggle{Enabled: boolPtrInit(st.SecuritySubRules)},
					WhenMustNotBeManual:     &configuration.SecurityJobsSubControlToggle{Enabled: boolPtrInit(st.SecuritySubWhenNotManual)},
				}
			}
			if gh != nil {
				p := parseLinesInit(st.SecurityJobPatternsGitHubMultiline)
				if len(p) == 0 {
					p = defaultGitHubSecurityJobPatterns()
				}
				gh.Controls.SecurityJobsMustNotBeWeakened = &configuration.SecurityJobsWeakenedControlConfig{
					Enabled:                 boolPtrInit(true),
					SecurityJobPatterns:     p,
					AllowFailureMustBeFalse: &configuration.SecurityJobsSubControlToggle{Enabled: boolPtrInit(st.SecuritySubAllowFailureGitHub)},
					RulesMustNotBeRedefined: &configuration.SecurityJobsSubControlToggle{Enabled: boolPtrInit(st.SecuritySubRulesGitHub)},
					WhenMustNotBeManual:     &configuration.SecurityJobsSubControlToggle{Enabled: boolPtrInit(st.SecuritySubWhenNotManualGitHub)},
				}
			}
		}

		// Cross-provider: unverified scripts.
		if compSelected(st, compScripts) {
			block := &configuration.UnverifiedScriptsControlConfig{
				Enabled:     boolPtrInit(true),
				TrustedUrls: parseLinesInit(st.ScriptTrustedURLsMultiline),
			}
			if gl != nil {
				gl.Controls.PipelineMustNotExecuteUnverifiedScripts = block
			}
			if gh != nil {
				gh.Controls.PipelineMustNotExecuteUnverifiedScripts = block
			}
		}

		// Cross-provider: Docker-in-Docker.
		if compSelected(st, compDinD) {
			block := &configuration.DockerInDockerControlConfig{
				Enabled:              boolPtrInit(true),
				DetectInsecureDaemon: boolPtrInit(st.DinDDetectInsecureDaemon),
			}
			if gl != nil {
				gl.Controls.PipelineMustNotUseDockerInDocker = block
			}
			if gh != nil {
				gh.Controls.PipelineMustNotUseDockerInDocker = block
			}
		}

		// GitHub-only composition checks.
		if gh != nil {
			if compSelected(st, compActionPin) {
				owners := parseLinesInit(st.ActionPinTrustedOwnersMultiline)
				if len(owners) == 0 {
					owners = defaultGitHubTrustedActionOwners()
				}
				gh.Controls.ActionsMustBePinnedByCommitSha = &configuration.ActionsPinnedByShaControlConfig{
					Enabled:       boolPtrInit(true),
					TrustedOwners: owners,
				}
			}
			if compSelected(st, compAuthorizedActions) {
				// Always trust GitHub-official owners and the repo's own
				// org. Depending on the wizard choice, either ship Plumber's
				// curated allowlist + 20k-star floor (matching the default
				// template) or leave the allowlist empty for the user to fill.
				block := &configuration.ActionAuthorizedSourcesControlConfig{
					Enabled:                    boolPtrInit(true),
					TrustGithubOfficialActions: boolPtrInit(true),
					TrustSameOrgActions:        boolPtrInit(true),
				}
				if st.AuthorizedActionsUsePlumberList {
					block.MinimumStars = defaultTrustedActionsMinimumStars()
					block.TrustedGithubActions = defaultTrustedGithubActions()
				}
				gh.Controls.GithubActionMustComeFromAuthorizedSources = block
			}
			if compSelected(st, compDangerousTriggers) {
				gh.Controls.WorkflowMustNotUseDangerousTriggers = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
			}
			if compSelected(st, compPRTargetHead) {
				gh.Controls.PullRequestTargetMustNotCheckoutHead = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
			}
			if compSelected(st, compDeclarePermissions) {
				gh.Controls.WorkflowsMustDeclarePermissions = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
			}
			if compSelected(st, compReusableSecrets) {
				gh.Controls.ReusableWorkflowsMustNotInheritSecrets = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
			}
			if compSelected(st, compOverprovSecrets) {
				gh.Controls.WorkflowMustNotExportEntireSecretsContext = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
			}
			if compSelected(st, compTemplateInjection) {
				gh.Controls.WorkflowMustNotInjectUserInputInScripts = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
			}
			if compSelected(st, compEnvInjection) {
				gh.Controls.WorkflowMustNotWriteUntrustedContentToGitHubEnv = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
			}
			if compSelected(st, compWriteAllPerms) {
				gh.Controls.WorkflowMustNotGrantPermissionsWriteAll = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
			}
			if compSelected(st, compRefConfusion) {
				gh.Controls.ExternalRefsMustNotCollide = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
			}
			if compSelected(st, compArchivedActions) {
				gh.Controls.ActionsMustNotBeArchived = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
			}
			if compSelected(st, compKnownCVEs) {
				gh.Controls.ActionsMustNotCarryKnownCVEs = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
			}
			if compSelected(st, compImpostorCommit) {
				gh.Controls.ActionRefsMustExistUpstream = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
			}
			if compSelected(st, compMutableRemoteExec) {
				gh.Controls.ActionsMustNotExecuteMutableRemoteCode = &configuration.EnabledOnlyControlConfig{Enabled: boolPtrInit(true)}
			}
			if compSelected(st, compCachePoisoning) {
				gh.Controls.ReleaseWorkflowsMustNotRestoreUntrustedCache = &configuration.CachePoisoningControlConfig{
					Enabled:                      boolPtrInit(true),
					PublishActions:               defaultCachePoisoningPublishActions(),
					CacheActions:                 defaultCachePoisoningCacheActions(),
					PublishScriptPatterns:        defaultCachePoisoningPublishScriptPatterns(),
					PublishScriptExcludePatterns: defaultCachePoisoningPublishScriptExcludePatterns(),
				}
			}
			if compSelected(st, compDebugTraceGitHub) {
				fb := parseLinesInit(st.DebugForbiddenVariablesGitHubMultiline)
				if len(fb) == 0 {
					fb = defaultGitHubDebugTraceVariables()
				}
				gh.Controls.PipelineMustNotEnableDebugTrace = &configuration.DebugTraceControlConfig{
					Enabled:            boolPtrInit(true),
					ForbiddenVariables: fb,
				}
			}

			// Required-actions is opt-in: written only when an expression
			// is supplied, mirroring pipelineMustIncludeComponent on the
			// GitLab side.
			if e := strings.TrimSpace(st.RequiredActionsExpr); e != "" {
				gh.Controls.WorkflowMustIncludeRequiredActions = &configuration.RequiredActionsControlConfig{
					Enabled:  boolPtrInit(true),
					Required: e,
				}
			} else if st.RequireActions {
				fmt.Fprintln(os.Stderr, "Note: required-actions requirement skipped (no expression provided).")
			}
		}
	}
	if has(catAccess) && st.BranchEnabled {
		st.applyAccessControls(gl, gh)
	}
	// catVariables is GitLab-only.
	if has(catVariables) && gl != nil {
		st.applyVariableControls(gl)
	}

	return cfg
}

// writeInitConfig writes validated YAML with a provenance header. If promptIfExists is true
// and the path exists without --force, an interactive overwrite prompt may be shown.
// checkInitOverwrite returns an error when the target file exists and the user
// does not consent to overwriting it.
func checkInitOverwrite(path string, force, promptIfExists bool) error {
	if _, err := os.Stat(path); err != nil {
		return nil // file does not exist — nothing to check
	}
	if force {
		return nil
	}
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
		return nil
	}
	return fmt.Errorf("file %s already exists (use --force to overwrite)", path)
}

// marshalAndWriteConfig encodes cfg to YAML, prepends the provenance header,
// ensures the parent directory exists, writes the file, and prints any
// post-write validation warnings.
func marshalAndWriteConfig(cfg *configuration.PlumberConfig, path, generatedBy string) error {
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
	_, _, warnings, err := configuration.LoadPlumberConfig(path)
	if err != nil {
		return fmt.Errorf("reload check failed: %w", err)
	}
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	return nil
}

func writeInitConfig(cfg *configuration.PlumberConfig, path string, force, promptIfExists bool, generatedBy string) error {
	if cfg == nil {
		return fmt.Errorf("internal error: nil config")
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("generated configuration failed validation: %w", err)
	}
	if err := checkInitOverwrite(path, force, promptIfExists); err != nil {
		return err
	}
	if err := marshalAndWriteConfig(cfg, path, generatedBy); err != nil {
		return err
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
