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
	catImages      = "Container image security (tags, trusted registries)"
	catComposition = "Pipeline composition (includes, scripts, security jobs, DinD)"
	catAccess      = "Access control (branch protection)"
	catVariables   = "Variable security (debug trace, unsafe expansion)"
	compHardcoded  = "Disallow hardcoded jobs (use includes/components)"
	compUpToDate   = "Require catalog includes to be up to date"
	compForbidden  = "Forbid mutable include refs (latest, main, HEAD, …)"
	compSecurity   = "Detect weakened security scanning jobs"
	compScripts    = "Detect unverified remote script execution (curl|bash, …)"
	compJobVars    = "Detect sensitive variables overridden in pipeline YAML"
	compDinD       = "Detect Docker-in-Docker (dind) usage"
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
	printInitNextSteps(configInitOutput)
	if state.runAnalyzeAfter {
		return maybeRunAnalyze(configInitOutput)
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
	Categories []string

	ForbiddenTagsEnabled   bool
	ForbiddenTagsCSV       string
	PinByDigest            bool
	AuthorizedEnabled      bool
	TrustDockerHubOfficial bool
	TrustedURLsText        string

	CompositionChoices []string

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
	allCats := []string{catImages, catComposition, catAccess, catVariables}
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

		if err := survey.AskOne(&survey.Confirm{Message: "Restrict images to authorized registries only?", Default: true}, &st.AuthorizedEnabled); err != nil {
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

	if has(catComposition) {
		printInitSection("Pipeline composition")
		allComp := []string{compHardcoded, compUpToDate, compForbidden, compSecurity, compScripts, compJobVars, compDinD}
		if err := survey.AskOne(&survey.MultiSelect{
			Message:  "Which pipeline checks should be enabled?",
			Options:  allComp,
			PageSize: 12,
			Default:  allComp,
		}, &st.CompositionChoices, survey.WithValidator(survey.Required)); err != nil {
			return nil, err
		}

		if compSelected(st, compForbidden) {
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
			if err := survey.AskOne(&survey.Multiline{
				Message: "Job name patterns that count as security jobs (one per line)",
				Help:    "Wildcards are supported, e.g. *-sast, gemnasium-*.",
				Default: strings.Join(defaultSecurityJobPatterns(), "\n"),
			}, &st.SecurityJobPatternsMultiline); err != nil {
				return nil, err
			}
			if err := survey.AskOne(&survey.Confirm{
				Message: "Flag jobs that set allow_failure: true?",
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

		if compSelected(st, compScripts) {
			fmt.Fprintf(os.Stderr, "\n  › Unverified scripts\n")
			if err := survey.AskOne(&survey.Multiline{
				Message: "Script host URL patterns to trust (one per line)",
				Help:    "Leave empty to flag every remote script. Example: https://internal.example.com/*",
			}, &st.ScriptTrustedURLsMultiline); err != nil {
				return nil, err
			}
		}

		if compSelected(st, compJobVars) {
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

		fmt.Fprintf(os.Stderr, "\n  › Required inclusions\n")
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
		if err := survey.AskOne(&survey.Input{
			Message: "Minimum access level to merge",
			Help:    "30 = Developer, 40 = Maintainer, 50 = Owner",
			Default: "30",
		}, &st.BranchMinMergeAccessLevel); err != nil {
			return nil, err
		}
		if err := survey.AskOne(&survey.Input{
			Message: "Minimum access level to push to protected branches",
			Help:    "30 = Developer, 40 = Maintainer, 50 = Owner",
			Default: "40",
		}, &st.BranchMinPushAccessLevel); err != nil {
			return nil, err
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
		Message: "Run 'plumber analyze' after writing? (requires GITLAB_TOKEN in the environment)",
		Default: false,
	}, &runAnalyze); err != nil {
		return nil, err
	}
	st.runAnalyzeAfter = runAnalyze
	return st, nil
}

func boolPtrInit(b bool) *bool { return &b }
func intPtrInit(i int) *int    { return &i }

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
	cfg := &configuration.PlumberConfig{
		Version: "2.0",
		GitLab:  &configuration.ProviderConfig{},
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
			cfg.GitLab.Controls.ContainerImageMustNotUseForbiddenTags = &configuration.ImageForbiddenTagsControlConfig{
				Enabled:                             boolPtrInit(true),
				Tags:                                tags,
				ContainerImagesMustBePinnedByDigest: boolPtrInit(st.PinByDigest),
			}
		}
		if st.AuthorizedEnabled {
			urls := parseLinesInit(st.TrustedURLsText)
			if len(urls) == 0 {
				urls = defaultTrustedURLs()
			}
			cfg.GitLab.Controls.ContainerImageMustComeFromAuthorizedSources = &configuration.ImageAuthorizedSourcesControlConfig{
				Enabled:                      boolPtrInit(true),
				TrustedUrls:                  urls,
				TrustDockerHubOfficialImages: boolPtrInit(st.TrustDockerHubOfficial),
			}
		}
	}

	if has(catComposition) {
		if compSelected(st, compHardcoded) {
			cfg.GitLab.Controls.PipelineMustNotIncludeHardcodedJobs = &configuration.HardcodedJobsControlConfig{
				Enabled: boolPtrInit(true),
			}
		}
		if compSelected(st, compUpToDate) {
			cfg.GitLab.Controls.IncludesMustBeUpToDate = &configuration.IncludesUpToDateControlConfig{
				Enabled: boolPtrInit(true),
			}
		}
		if compSelected(st, compForbidden) {
			vers := parseLinesInit(st.ForbiddenVersionsMultiline)
			if len(vers) == 0 {
				vers = defaultForbiddenVersions()
			}
			cfg.GitLab.Controls.IncludesMustNotUseForbiddenVersions = &configuration.IncludesForbiddenVersionsControlConfig{
				Enabled:                         boolPtrInit(true),
				ForbiddenVersions:               vers,
				DefaultBranchIsForbiddenVersion: boolPtrInit(st.DefaultBranchIsForbiddenVersion),
			}
		}
		if compSelected(st, compSecurity) {
			patterns := parseLinesInit(st.SecurityJobPatternsMultiline)
			if len(patterns) == 0 {
				patterns = defaultSecurityJobPatterns()
			}
			cfg.GitLab.Controls.SecurityJobsMustNotBeWeakened = &configuration.SecurityJobsWeakenedControlConfig{
				Enabled:                 boolPtrInit(true),
				SecurityJobPatterns:     patterns,
				AllowFailureMustBeFalse: &configuration.SecurityJobsSubControlToggle{Enabled: boolPtrInit(st.SecuritySubAllowFailure)},
				RulesMustNotBeRedefined: &configuration.SecurityJobsSubControlToggle{Enabled: boolPtrInit(st.SecuritySubRules)},
				WhenMustNotBeManual:     &configuration.SecurityJobsSubControlToggle{Enabled: boolPtrInit(st.SecuritySubWhenNotManual)},
			}
		}
		if compSelected(st, compScripts) {
			cfg.GitLab.Controls.PipelineMustNotExecuteUnverifiedScripts = &configuration.UnverifiedScriptsControlConfig{
				Enabled:     boolPtrInit(true),
				TrustedUrls: parseLinesInit(st.ScriptTrustedURLsMultiline),
			}
		}
		if compSelected(st, compJobVars) {
			vars := parseLinesInit(st.JobOverrideVariablesMultiline)
			if len(vars) == 0 {
				vars = defaultJobOverrideVariables()
			}
			cfg.GitLab.Controls.PipelineMustNotOverrideJobVariables = &configuration.JobVariablesOverrideControlConfig{
				Enabled:   boolPtrInit(true),
				Variables: vars,
			}
		}
		if compSelected(st, compDinD) {
			cfg.GitLab.Controls.PipelineMustNotUseDockerInDocker = &configuration.DockerInDockerControlConfig{
				Enabled:              boolPtrInit(true),
				DetectInsecureDaemon: boolPtrInit(st.DinDDetectInsecureDaemon),
			}
		}

		if e := strings.TrimSpace(st.RequiredComponentsExpr); e != "" {
			cfg.GitLab.Controls.PipelineMustIncludeComponent = &configuration.RequiredComponentsControlConfig{
				Enabled:  boolPtrInit(true),
				Required: e,
			}
		} else if st.RequireComponents {
			fmt.Fprintln(os.Stderr, "Note: component requirement skipped (no expression provided).")
		}

		if e := strings.TrimSpace(st.RequiredTemplatesExpr); e != "" {
			cfg.GitLab.Controls.PipelineMustIncludeTemplate = &configuration.RequiredTemplatesControlConfig{
				Enabled:  boolPtrInit(true),
				Required: e,
			}
		} else if st.RequireTemplates {
			fmt.Fprintln(os.Stderr, "Note: template requirement skipped (no expression provided).")
		}
	}

	if has(catAccess) && st.BranchEnabled {
		patterns := parseCSVInit(st.BranchPatterns)
		if len(patterns) == 0 {
			patterns = parseCSVInit("main, master, release/*, production, dev")
		}
		cfg.GitLab.Controls.BranchMustBeProtected = &configuration.BranchProtectionControlConfig{
			Enabled:                   boolPtrInit(true),
			DefaultMustBeProtected:    boolPtrInit(st.BranchDefaultMustBeProtected),
			NamePatterns:              patterns,
			AllowForcePush:            boolPtrInit(st.BranchAllowForcePush),
			CodeOwnerApprovalRequired: boolPtrInit(st.BranchCodeOwnerApprovalRequired),
			MinMergeAccessLevel:       intPtrInit(parseIntInit(st.BranchMinMergeAccessLevel, 30)),
			MinPushAccessLevel:        intPtrInit(parseIntInit(st.BranchMinPushAccessLevel, 40)),
		}
	}

	if has(catVariables) {
		if st.DebugTraceEnabled {
			fb := parseLinesInit(st.DebugForbiddenVariablesMultiline)
			if len(fb) == 0 {
				fb = []string{"CI_DEBUG_TRACE", "CI_DEBUG_SERVICES"}
			}
			cfg.GitLab.Controls.PipelineMustNotEnableDebugTrace = &configuration.DebugTraceControlConfig{
				Enabled:            boolPtrInit(true),
				ForbiddenVariables: fb,
			}
		}
		if st.UnsafeExpansionEnabled {
			danger := parseLinesInit(st.DangerousVariablesMultiline)
			if len(danger) == 0 {
				danger = defaultDangerousVariables()
			}
			cfg.GitLab.Controls.PipelineMustNotUseUnsafeVariableExpansion = &configuration.VariableInjectionControlConfig{
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
		Categories:             []string{catImages, catComposition, catAccess, catVariables},
		ForbiddenTagsEnabled:   true,
		ForbiddenTagsCSV:       "latest, dev, development, staging, main, master",
		PinByDigest:            false,
		AuthorizedEnabled:      true,
		TrustDockerHubOfficial: true,
		TrustedURLsText:        strings.Join(defaultTrustedURLs(), "\n"),
		CompositionChoices: []string{
			compHardcoded, compUpToDate, compForbidden, compSecurity, compScripts, compJobVars, compDinD,
		},
		ForbiddenVersionsMultiline:       strings.Join(defaultForbiddenVersions(), "\n"),
		DefaultBranchIsForbiddenVersion:  false,
		SecurityJobPatternsMultiline:     strings.Join(defaultSecurityJobPatterns(), "\n"),
		SecuritySubAllowFailure:          false,
		SecuritySubRules:                 true,
		SecuritySubWhenNotManual:         true,
		JobOverrideVariablesMultiline:    strings.Join(defaultJobOverrideVariables(), "\n"),
		DinDDetectInsecureDaemon:         true,
		BranchEnabled:                    true,
		BranchPatterns:                   "main, master, release/*, production, dev",
		BranchDefaultMustBeProtected:     true,
		BranchAllowForcePush:             false,
		BranchCodeOwnerApprovalRequired:  false,
		BranchMinMergeAccessLevel:        "30",
		BranchMinPushAccessLevel:         "40",
		DebugTraceEnabled:                true,
		DebugForbiddenVariablesMultiline: "CI_DEBUG_TRACE\nCI_DEBUG_SERVICES",
		UnsafeExpansionEnabled:           true,
		DangerousVariablesMultiline:      strings.Join(defaultDangerousVariables(), "\n"),
		AllowedPatternsMultiline:         "",
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

func printInitNextSteps(path string) {
	fmt.Fprintln(os.Stderr, "\nNext steps:")
	fmt.Fprintf(os.Stderr, "  1. Review %s and adjust any values\n", path)
	fmt.Fprintf(os.Stderr, "  2. export GITLAB_TOKEN=<token>\n")
	fmt.Fprintf(os.Stderr, "  3. plumber analyze --config %s\n", path)
}

func maybeRunAnalyze(configPath string) error {
	if os.Getenv("GITLAB_TOKEN") == "" {
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
