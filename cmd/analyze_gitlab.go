package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/AlecAivazis/survey/v2"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/internal/defaultconfig"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	plumberprovider "github.com/getplumber/plumber/provider"
	"github.com/getplumber/plumber/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

var (
	// Flags for analyze command
	gitlabURL         string
	githubURL         string
	providerFlag      string
	projectPath       string
	defaultBranch     string
	outputFile        string
	printOutput       bool
	configFile        string
	threshold         float64
	// thresholdSet is true when the deprecated --threshold was supplied
	// explicitly (flag or PLUMBER_ANALYZE_THRESHOLD); it switches the gate
	// back to the legacy passing-controls percentage.
	thresholdSet bool
	minScore     string
	minPoints    float64
	// minPointsSet distinguishes an explicit --min-points from its default:
	// when only --min-score is given, the points gate is off.
	minPointsSet bool
	pbomFile     string
	pbomCycloneDXFile string
	sarifFile         string
	glsastFile        string
	mrComment         bool
	badge             bool
	showScore         bool
	showScorePoint    bool
	pushScore         bool
	scoreEndpoint     string
	controlsFilter    string
	skipControls      string
	ciConfigPath      string
)

const (
	errConfigFileNotFound = "configuration file not found: %w. Create one with `plumber config generate` or `plumber config init`"
	fmtIndentLine         = "  %s\n"
	fmtIndentPara         = "  %s\n\n"
	fmtIndentColored      = "  %s%s%s\n"
	fmtColored            = "%s%s%s\n"
)

var analyzeCmd = &cobra.Command{
	Use:          "analyze",
	Short:        "Analyze CI/CD configuration (GitLab via API, or local GitHub Actions when origin is GitHub)",
	SilenceUsage: true, // Don't print usage on errors (e.g., threshold failures)
	Long: `Analyze CI/CD configuration for security issues.

GitLab path (when the git remote is GitLab, or when you pass --gitlab-url and --project):
  Connects to GitLab, retrieves CI/CD configuration and project settings, and runs
  checks including pipeline origins, images, tags, and branch protection.
  Required environment variable: GITLAB_TOKEN

GitHub path (when origin is GitHub and --gitlab-url / --project are not set):
  Scans local .github/workflows only (Rego). No GitLab token. Some flags apply only
  to the GitLab API path (see README).

Flags (auto-detected from git remote if not specified):
  --gitlab-url    GitLab instance URL (auto-detected from git remote)
  --project       Full path of the project (auto-detected from git remote)

Optional flags:
  --config           Path to .plumber.yaml config file (default: .plumber.yaml)
  --min-points       Minimum Plumber Score points to pass, 0-100 (default: 100 — any finding fails)
  --min-score        Minimum Plumber Score letter to pass, A-E (e.g. B fails on C, D, E)
  --threshold        Deprecated: minimum percentage of passing controls, 0-100; use --min-points / --min-score
  --branch           Branch to analyze (defaults to project's default branch)
  --print            Print text output to stdout (default: true)
  --output           Write JSON results to file (optional)
  --pbom             Write PBOM (Pipeline Bill of Materials) to file (optional)
  --pbom-cyclonedx   Write PBOM in CycloneDX format for integration with security tools
  --mr-comment       Post/update a Plumber comment on the merge request (requires api scope, merge request pipeline only)
  --badge            Create/update a Plumber letter-score badge on the project (requires api scope; only runs on default branch)
  --score            Letter score, points, bar, and counts in stdout (banner only); points + score in JSON/PBOM/CycloneDX; badge/MR use letter when set (optional)
  --score-point      Same as --score plus full points breakdown in stdout and MR comment (optional; wins if both set)
  --score-push       Publish this repo's Plumber Score to the hosted badge service (CI only; a local run is a no-op) (optional)
  --score-endpoint   Score service base URL (default https://score.getplumber.io); override only for a self-hosted score service (optional)
  --controls         Run only listed controls (comma-separated)
  --skip-controls    Skip listed controls (comma-separated)
  --fail-warnings    Treat configuration warnings as errors (exit 2)
  --ci-config-path   Override the CI configuration file path (default: auto-detected from GitLab project settings, usually .gitlab-ci.yml)

Exit codes:
  0  Analysis passed (score gate met)
  1  Gate failure (Plumber Score below --min-points / --min-score, or deprecated --threshold not met)
  2  Runtime error (configuration error, network failure, missing token, etc.)

Examples:
  # Set token via environment variable
  export GITLAB_TOKEN=glpat-xxxx

  # Analyze current repo (auto-detects GitLab URL and project from git remote)
  plumber analyze

  # Analyze a specific project
  plumber analyze --gitlab-url https://gitlab.com --project mygroup/myproject

  # Analyze with custom config and a relaxed score gate
  plumber analyze --gitlab-url https://gitlab.com --project mygroup/myproject --config custom.yaml --min-points 80

  # Analyze and save JSON to file (no stdout)
  plumber analyze --gitlab-url https://gitlab.com --project mygroup/myproject --print=false --output results.json

  # Analyze a project that uses a custom CI configuration file path
  plumber analyze --ci-config-path my-custom-ci.yml
`,
	RunE: runAnalyze,
}

func init() {
	rootCmd.AddCommand(analyzeCmd)

	// GitLab connection flags (auto-detected from git remote if not specified)
	analyzeCmd.Flags().StringVar(&gitlabURL, "gitlab-url", "", "GitLab instance URL (auto-detected from git remote, required otherwise)")
	analyzeCmd.Flags().StringVar(&projectPath, "project", "", "Project path (auto-detected from git remote, required otherwise)")

	// GitHub Enterprise Server: override the GitHub API host. Default
	// (empty) targets api.github.com. Set to your GHES API host (e.g.
	// "ghes.example.com" or "ghes.example.com/api/v3") to scan a
	// self-hosted instance. Auth via GH_TOKEN / GH_ENTERPRISE_TOKEN.
	analyzeCmd.Flags().StringVar(&githubURL, "github-url", "", "GitHub Enterprise Server API host (empty = api.github.com)")

	// Provider override. Forces GitHub or GitLab without pinning a host —
	// the host is still auto-detected from the git remote (or defaults to
	// the SaaS host). Use it when auto-detection cannot tell a corporate
	// GitHub Enterprise Server host apart from self-hosted GitLab. For
	// pinning a specific host/remote, use --github-url / --gitlab-url.
	analyzeCmd.Flags().StringVar(&providerFlag, "provider", "", "Force provider: 'github' or 'gitlab' (overrides auto-detection; host still auto-detected)")

	// Optional flags with defaults
	analyzeCmd.Flags().StringVar(&configFile, "config", ".plumber.yaml", "Path to .plumber.yaml config file")
	analyzeCmd.Flags().Float64Var(&threshold, "threshold", 100, "Deprecated: minimum percentage of passing controls, 0-100; use --min-points / --min-score instead")
	analyzeCmd.Flags().StringVar(&minScore, "min-score", "", "Minimum Plumber Score letter to pass, A-E (e.g. B fails on C, D, E)")
	analyzeCmd.Flags().Float64Var(&minPoints, "min-points", 100, "Minimum Plumber Score points to pass, 0-100 (default 100: any finding fails)")
	analyzeCmd.Flags().StringVar(&defaultBranch, "branch", "", "Branch to analyze (defaults to project's default branch)")
	analyzeCmd.Flags().BoolVar(&printOutput, "print", true, "Print text output to stdout")
	analyzeCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write JSON results to file")
	analyzeCmd.Flags().StringVar(&pbomFile, "pbom", "", "Write PBOM (Pipeline Bill of Materials) to file")
	analyzeCmd.Flags().StringVar(&pbomCycloneDXFile, "pbom-cyclonedx", "", "Write PBOM in CycloneDX format (for security tool integration)")
	analyzeCmd.Flags().StringVar(&sarifFile, "sarif", "", "Write SARIF 2.1.0 results to file (for GitHub Code Scanning / GitLab Security Dashboard)")
	analyzeCmd.Flags().StringVar(&glsastFile, "glsast", "", "Write a GitLab SAST report (gl-sast-report.json) to file (for the GitLab Security Dashboard / MR widget)")
	analyzeCmd.Flags().BoolVar(&mrComment, "mr-comment", false, "Post/update a compliance comment on the merge request (requires api scope token; only works in merge request pipelines)")
	analyzeCmd.Flags().BoolVar(&badge, "badge", false, "Create/update a Plumber compliance badge on the project (requires api scope; only runs on default branch)")
	analyzeCmd.Flags().BoolVar(&showScore, "score", false, "Banner: letter score, points, bar, severity counts on stdout; points + score in JSON, PBOM, CycloneDX; badge shows letter when set")
	analyzeCmd.Flags().BoolVar(&showScorePoint, "score-point", false, "Like --score plus full points breakdown in stdout and MR comment; overrides --score when both are set")
	analyzeCmd.Flags().BoolVar(&pushScore, "score-push", false, "Publish this repo's Plumber Score to the hosted badge service (CI only; needs a CI OIDC id-token, so a local run is a no-op)")
	analyzeCmd.Flags().StringVar(&scoreEndpoint, "score-endpoint", "", "Score service base URL (default https://score.getplumber.io); override only for a self-hosted score service")
	analyzeCmd.Flags().StringVar(&controlsFilter, "controls", "", "Run only listed controls (comma-separated)")
	analyzeCmd.Flags().StringVar(&skipControls, "skip-controls", "", "Skip listed controls (comma-separated)")
	analyzeCmd.Flags().BoolVar(&failWarnings, "fail-warnings", false, "Treat configuration warnings as errors (exit 2)")
	analyzeCmd.Flags().StringVar(&ciConfigPath, "ci-config-path", "", "Override the CI configuration file path (default: auto-detected from GitLab project settings, usually .gitlab-ci.yml)")

	for flag, envKey := range envKeys {
		if f := analyzeCmd.Flags().Lookup(flag); f != nil {
			f.Usage += " (env: " + envKey + ")"
		}
	}
}

// resolveProvider applies the provider-selection precedence and returns the
// chosen provider ("github"/"gitlab") plus a short, user-facing reason for
// the detection banner. Returns ("", "") when neither a flag nor a git remote
// can determine it (not in a repo, no provider flag).
func resolveProvider(provider string, gitlabURLFromFlag, githubURLFromFlag bool, remoteInfo *utils.GitRemoteInfo) (string, string) {
	switch {
	case githubURLFromFlag:
		return "github", "set by --github-url"
	case gitlabURLFromFlag:
		return "gitlab", "set by --gitlab-url"
	case provider == "github":
		return "github", "set by --provider github"
	case provider == "gitlab":
		return "gitlab", "set by --provider gitlab"
	case remoteInfo != nil:
		return remoteInfo.Provider, remoteInfo.ProviderReason
	default:
		return "", ""
	}
}

// printProviderDetection tells the user which provider was selected and why,
// then always shows how to change it — so a wrong guess (e.g. a GitHub
// Enterprise Server host mistaken for self-hosted GitLab) is both visible and
// trivially correctable.
func printProviderDetection(provider, reason string) {
	name := "GitLab"
	if provider == "github" {
		name = "GitHub"
	}
	fmt.Fprintf(os.Stderr, "Provider: %s (%s)\n", name, reason)
	fmt.Fprintf(os.Stderr, "  To change: --provider github|gitlab, or --github-url <host> / --gitlab-url <url> to also target a specific host/remote.\n")
}

// loadConfigOrOffer loads the Plumber config file. When the file is missing and
// the terminal is interactive, it prompts the user to generate a config on the
// spot (via the wizard or the default template) and then reloads it so the
// calling analyze command can continue uninterrupted.
func loadConfigOrOffer(cfgFile string) (*configuration.PlumberConfig, string, []string, error) {
	pc, path, warnings, err := configuration.LoadPlumberConfig(cfgFile)
	if err == nil {
		return pc, path, warnings, nil
	}

	if !strings.Contains(err.Error(), "config file not found") {
		return nil, "", nil, fmt.Errorf("configuration error: %w", err)
	}

	// Config file not found — in non-interactive mode just show the hint.
	if !isInteractiveInit() {
		return nil, "", nil, fmt.Errorf(errConfigFileNotFound, err)
	}

	fmt.Fprintf(os.Stderr, "\nNo configuration file found at %q.\n\n", cfgFile)

	const (
		choiceWizard   = "Interactive wizard  (plumber config init)"
		choiceGenerate = "Default template    (plumber config generate)"
		choiceNo       = "No, exit"
	)

	var choice string
	if surveyErr := survey.AskOne(&survey.Select{
		Message: "Would you like to generate a configuration file now?",
		Options: []string{choiceWizard, choiceGenerate, choiceNo},
		Default: choiceWizard,
	}, &choice); surveyErr != nil || choice == choiceNo {
		return nil, "", nil, fmt.Errorf(errConfigFileNotFound, err)
	}

	if genErr := handleConfigGeneration(choice, cfgFile, choiceWizard, choiceGenerate); genErr != nil {
		return nil, "", nil, genErr
	}

	// Reload after generation.
	pc, path, warnings, err = configuration.LoadPlumberConfig(cfgFile)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to reload config after generation: %w", err)
	}
	return pc, path, warnings, nil
}

// handleConfigGeneration runs the wizard or default-template generation path
// chosen by the user in loadConfigOrOffer.
func handleConfigGeneration(choice, cfgFile, choiceWizard, choiceGenerate string) error {
	switch choice {
	case choiceWizard:
		state, wizErr := runInitWizard(true) // skip "run analyze after?" — we're already in analyze
		if wizErr != nil {
			return fmt.Errorf("config init failed: %w", wizErr)
		}
		cfg := state.toPlumberConfig()
		if writeErr := writeInitConfig(cfg, cfgFile, false, true, "plumber analyze"); writeErr != nil {
			return fmt.Errorf("config init failed: %w", writeErr)
		}
		printInitNextSteps(cfgFile, state.Providers)
	case choiceGenerate:
		if writeErr := os.WriteFile(cfgFile, defaultconfig.Get(), 0644); writeErr != nil {
			return fmt.Errorf("failed to write config file: %w", writeErr)
		}
		fmt.Fprintf(os.Stderr, "Generated %s\n", cfgFile)
	default:
		return fmt.Errorf("unexpected choice: %s", choice)
	}
	return nil
}

// analyzeFlags bundles the parsed flag-changed booleans so they don't have to
// be re-queried throughout the call chain.
type analyzeFlags struct {
	gitlabURLFromFlag bool
	githubURLFromFlag bool
	projectFromFlag   bool
	branchFromFlag    bool
}

func readAnalyzeFlags(cmd *cobra.Command) analyzeFlags {
	return analyzeFlags{
		gitlabURLFromFlag: cmd.Flags().Changed("gitlab-url"),
		githubURLFromFlag: cmd.Flags().Changed("github-url"),
		projectFromFlag:   cmd.Flags().Changed("project"),
		branchFromFlag:    cmd.Flags().Changed("branch"),
	}
}

// validateProviderFlags returns an error for mutually exclusive or contradictory
// provider flag combinations.
func validateProviderFlags(flags analyzeFlags) error {
	if flags.gitlabURLFromFlag && flags.githubURLFromFlag {
		return fmt.Errorf("--gitlab-url and --github-url are mutually exclusive; pass one to select the provider explicitly")
	}
	switch providerFlag {
	case "", "github", "gitlab":
	default:
		return fmt.Errorf("--provider must be 'github' or 'gitlab' (got %q)", providerFlag)
	}
	if providerFlag == "gitlab" && flags.githubURLFromFlag {
		return fmt.Errorf("--provider gitlab conflicts with --github-url; use --gitlab-url to pin a GitLab host")
	}
	if providerFlag == "github" && flags.gitlabURLFromFlag {
		return fmt.Errorf("--provider github conflicts with --gitlab-url; use --github-url to pin a GitHub host")
	}
	return nil
}

// parseControlsFilters validates and parses the --controls / --skip-controls flags.
func parseControlsFilters() (includeOnly, skip []string, err error) {
	if controlsFilter != "" && skipControls != "" {
		return nil, nil, fmt.Errorf("--controls and --skip-controls cannot be used together")
	}
	includeOnly, err = parseControlsFilter(controlsFilter)
	if err != nil {
		return nil, nil, err
	}
	skip, err = parseControlsFilter(skipControls)
	if err != nil {
		return nil, nil, err
	}
	return includeOnly, skip, nil
}

// dispatchGitHub runs the GitHub analysis path and returns its result.
// It is called after provider resolution confirms provider == "github".
func dispatchGitHub(cmd *cobra.Command, flags analyzeFlags, remoteInfo *utils.GitRemoteInfo, controlsFilterList, skipControlsList []string) error {
	if flags.projectFromFlag {
		ref := ""
		if flags.branchFromFlag {
			ref = defaultBranch
		}
		return runGitHubAnalyzeRemote(githubURL, projectPath, ref, controlsFilterList, skipControlsList)
	}
	if remoteInfo == nil {
		return fmt.Errorf("GitHub local scan needs a git repository (run inside a clone), or pass --project owner/repo for a remote scan")
	}
	return runGitHubAnalyze(remoteInfo, controlsFilterList, skipControlsList)
}

// gitLabRemoteInfo holds the three fields extracted from a GitRemoteInfo that
// the GitLab path needs; avoids passing the full struct deep into helpers.
type gitLabRemoteInfo struct {
	repoRoot    string
	remoteURL   string
	projectPath string
}

// resolveGitLabTarget fills in gitlabURL and projectPath from flags / git remote
// and returns the per-repo git metadata needed for local-project detection.
func resolveGitLabTarget(flags analyzeFlags, remoteInfo *utils.GitRemoteInfo) (gitLabRemoteInfo, error) {
	var info gitLabRemoteInfo
	if remoteInfo != nil {
		info.repoRoot = remoteInfo.RepoRoot
		info.remoteURL = remoteInfo.URL
		info.projectPath = remoteInfo.ProjectPath
	}

	if !flags.gitlabURLFromFlag {
		if remoteInfo != nil {
			gitlabURL = remoteInfo.URL
		} else {
			gitlabURL = "https://gitlab.com"
		}
		fmt.Fprintf(os.Stderr, "GitLab URL: %s\n", gitlabURL)
	}
	if !flags.projectFromFlag && remoteInfo != nil {
		projectPath = remoteInfo.ProjectPath
		fmt.Fprintf(os.Stderr, "Project: %s\n", projectPath)
	}

	if gitlabURL == "" {
		return info, fmt.Errorf("GitLab URL is required: pass --gitlab-url <url> or run inside a git clone so it can be auto-detected")
	}
	if projectPath == "" {
		return info, fmt.Errorf("--project is required (could not auto-detect from git remote)")
	}
	return info, nil
}

// resolveGitLabToken returns the GITLAB_TOKEN or an informative error.
func resolveGitLabToken(flags analyzeFlags) (string, error) {
	token := os.Getenv("GITLAB_TOKEN")
	if token != "" {
		return token, nil
	}
	// Only nudge toward GitHub when GitLab was auto-detected — if the user
	// picked GitLab explicitly, the GHES hint is just noise.
	if providerFlag == "" && !flags.gitlabURLFromFlag {
		host := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSuffix(gitlabURL, "/"), "https://"), "http://")
		return "", fmt.Errorf("GITLAB_TOKEN environment variable is required for GitLab analysis. "+
			"If %s is actually a GitHub Enterprise Server instance, scan it as GitHub instead with: plumber analyze --provider github (or --github-url %s)", host, host)
	}
	return "", fmt.Errorf("GITLAB_TOKEN environment variable is required for GitLab analysis")
}

// applyConfigWarnings prints validation warnings and returns an error when
// --fail-warnings is set.
func applyConfigWarnings(warnings []string) error {
	if len(warnings) == 0 {
		return nil
	}
	fmt.Fprintf(os.Stderr, "Configuration validation warnings:\n")
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "  - %s\n", w)
	}
	if failWarnings {
		return fmt.Errorf("configuration has %d warning(s) and --fail-warnings is set", len(warnings))
	}
	fmt.Fprintf(os.Stderr, "Please fix the warnings above for best results.\n\n")
	return nil
}

// buildGitLabConf constructs the analysis Configuration from the already-resolved inputs.
func buildGitLabConf(
	cleanGitlabURL, gitlabToken string,
	flags analyzeFlags,
	remote gitLabRemoteInfo,
	plumberConfig *configuration.PlumberConfig,
	controlsFilterList, skipControlsList []string,
) *configuration.Configuration {
	conf := configuration.NewDefaultConfiguration()
	conf.GitlabURL = cleanGitlabURL
	conf.GitlabToken = gitlabToken
	conf.ProjectPath = projectPath
	conf.Branch = defaultBranch
	conf.PlumberConfig = plumberConfig
	conf.GitRepoRoot = remote.repoRoot
	conf.ControlsFilter = controlsFilterList
	conf.SkipControlsFilter = skipControlsList
	conf.CIConfigPathOverride = ciConfigPath

	// Local CI file support only applies when the local repo IS the analyzed
	// project AND the user did not explicitly name a project on the CLI.
	// Explicit project name = analyse exactly that project, ignore pwd.
	// (Symmetric CLI semantics with the GitHub path.)
	explicitProject := flags.gitlabURLFromFlag || flags.projectFromFlag
	if !explicitProject && remote.repoRoot != "" && remote.remoteURL != "" {
		conf.IsLocalProject = strings.TrimSuffix(remote.remoteURL, "/") == cleanGitlabURL &&
			remote.projectPath == projectPath
	}

	if verbose {
		conf.LogLevel = logrus.DebugLevel
	}
	return conf
}

// computeGitLabCompliance returns the overall compliance percentage and the
// number of non-skipped controls that were evaluated.
//
// When the CI config is missing or invalid no findings were produced because
// nothing could be analysed — not because the project is compliant. Those
// cases short-circuit to 0 so an absent or broken .gitlab-ci.yml never scores
// 100% and cannot be used to bypass the gate.
func computeGitLabCompliance(result *control.AnalysisResult, conf *configuration.Configuration) (compliance float64, controlCount int) {
	if result.CiMissing || !result.CiValid {
		return 0.0, 0
	}
	findingCountsByControl := map[string]int{}
	for _, f := range result.Findings {
		if info := control.LookupCode(control.ErrorCode(f.Code)); info != nil {
			findingCountsByControl[info.ControlName]++
		}
	}
	passed := 0
	entries := control.GitLabControls(conf.PlumberConfig)
	control.MarkSkippedByFilter(entries, conf.ControlsFilter, conf.SkipControlsFilter)
	for _, e := range entries {
		if e.Skipped {
			continue
		}
		controlCount++
		if findingCountsByControl[e.ControlName] == 0 {
			passed++
		}
	}
	if controlCount > 0 {
		compliance = float64(passed) * 100.0 / float64(controlCount)
	}
	return compliance, controlCount
}

// envKeys maps each analyze flag to the environment variable that overrides it
// when the flag is not set explicitly on the command line (flags always win).
var envKeys = map[string]string{
	"gitlab-url":     "PLUMBER_ANALYZE_GITLAB_URL",
	"github-url":     "PLUMBER_ANALYZE_GITHUB_URL",
	"project":        "PLUMBER_ANALYZE_PROJECT",
	"provider":       "PLUMBER_ANALYZE_PROVIDER",
	"branch":         "PLUMBER_ANALYZE_BRANCH",
	"config":         "PLUMBER_ANALYZE_CONFIG",
	"threshold":      "PLUMBER_ANALYZE_THRESHOLD",
	"min-score":      "PLUMBER_ANALYZE_MIN_SCORE",
	"min-points":     "PLUMBER_ANALYZE_MIN_POINTS",
	"print":          "PLUMBER_ANALYZE_PRINT",
	"output":         "PLUMBER_ANALYZE_OUTPUT",
	"pbom":           "PLUMBER_ANALYZE_PBOM",
	"pbom-cyclonedx": "PLUMBER_ANALYZE_PBOM_CYCLONEDX",
	"sarif":          "PLUMBER_ANALYZE_SARIF",
	"glsast":         "PLUMBER_ANALYZE_GLSAST",
	"mr-comment":     "PLUMBER_ANALYZE_MR_COMMENT",
	"badge":          "PLUMBER_ANALYZE_BADGE",
	"score":          "PLUMBER_ANALYZE_SCORE",
	"score-point":    "PLUMBER_ANALYZE_SCORE_POINT",
	"score-push":     "PLUMBER_ANALYZE_SCORE_PUSH",
	"score-endpoint": "PLUMBER_ANALYZE_SCORE_ENDPOINT",
	"controls":       "PLUMBER_ANALYZE_CONTROLS",
	"skip-controls":  "PLUMBER_ANALYZE_SKIP_CONTROLS",
	"fail-warnings":  "PLUMBER_ANALYZE_FAIL_WARNINGS",
	"ci-config-path": "PLUMBER_ANALYZE_CI_CONFIG_PATH",
	"verbose":        "PLUMBER_ANALYZE_VERBOSE",
}

func envStringFallback(cmd *cobra.Command, flag, envKey string, dest *string) error {
	if !cmd.Flags().Changed(flag) {
		if v := os.Getenv(envKey); v != "" {
			*dest = v
			// Mark the flag as set so a value provided via a PLUMBER_ANALYZE_*
			// env var drives provider/host/project selection exactly like the
			// equivalent flag. The GitLab CI component passes coordinates as env
			// vars, not flags; without this the provider stays undetermined and
			// the host gets overwritten with the gitlab.com default.
			if err := cmd.Flags().Set(flag, v); err != nil {
				return fmt.Errorf("apply %s: %w", envKey, err)
			}
		}
	}
	return nil
}

func envBoolFallback(cmd *cobra.Command, flag, envKey string, dest *bool) error {
	if !cmd.Flags().Changed(flag) {
		if v := os.Getenv(envKey); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return fmt.Errorf("invalid value for %s: %q: %w", envKey, v, err)
			}
			*dest = b
		}
	}
	return nil
}

// resolveGateFlags validates the pass/fail gate flags after the env fallbacks
// ran and records which gate is active. The default gate is the Plumber Score
// (--min-points 100: any finding fails, exactly the behavior the old default
// --threshold 100 had). Supplying the deprecated --threshold switches back to
// the legacy passing-controls percentage and warns; combining it with the
// score gate flags is an error.
func resolveGateFlags(cmd *cobra.Command) error {
	thresholdSet = cmd.Flags().Changed("threshold") || os.Getenv(envKeys["threshold"]) != ""
	minPointsSet = cmd.Flags().Changed("min-points") || os.Getenv(envKeys["min-points"]) != ""

	if thresholdSet && (minPointsSet || minScore != "") {
		return fmt.Errorf("the deprecated --threshold cannot be combined with --min-points / --min-score; drop --threshold")
	}
	if thresholdSet {
		fmt.Fprintf(os.Stderr, "Warning: --threshold is deprecated and will be removed in a future release; gate on the Plumber Score with --min-points (0-100) or --min-score (A-E) instead. See https://getplumber.io/docs/plumber-score\n")
		// Inverted comparison so NaN fails closed: ParseFloat accepts "nan",
		// which every ordered comparison answers false — `< 0 || > 100` would
		// let it through and the gate could then never fail.
		if !(threshold >= 0 && threshold <= 100) {
			return fmt.Errorf("threshold must be between 0 and 100")
		}
		return nil
	}
	if !(minPoints >= 0 && minPoints <= 100) {
		return fmt.Errorf("min-points must be between 0 and 100")
	}
	if minScore != "" {
		minScore = strings.ToUpper(strings.TrimSpace(minScore))
		if control.ScoreLetterRank(minScore) == 0 {
			return fmt.Errorf("min-score must be one of A, B, C, D, E")
		}
	}
	return nil
}

func envFloat64Fallback(cmd *cobra.Command, flag, envKey string, dest *float64) error {
	if !cmd.Flags().Changed(flag) {
		if v := os.Getenv(envKey); v != "" {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return fmt.Errorf("invalid value for %s: %q: %w", envKey, v, err)
			}
			*dest = f
		}
	}
	return nil
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	if err := envBoolFallback(cmd, "verbose", envKeys["verbose"], &verbose); err != nil {
		return err
	} else if verbose {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.WarnLevel)
	}

	// Apply environment variable fallbacks; CLI flags always take precedence.
	// The string fallbacks mark the flag as set, so env-provided coordinates
	// select the provider/host/project exactly like flags (the GitLab CI
	// component passes them as PLUMBER_ANALYZE_* env vars, not flags).
	for _, apply := range []func() error{
		func() error { return envStringFallback(cmd, "gitlab-url", envKeys["gitlab-url"], &gitlabURL) },
		func() error { return envStringFallback(cmd, "github-url", envKeys["github-url"], &githubURL) },
		func() error { return envStringFallback(cmd, "project", envKeys["project"], &projectPath) },
		func() error { return envStringFallback(cmd, "provider", envKeys["provider"], &providerFlag) },
		func() error { return envStringFallback(cmd, "branch", envKeys["branch"], &defaultBranch) },
		func() error { return envStringFallback(cmd, "config", envKeys["config"], &configFile) },
		func() error { return envStringFallback(cmd, "output", envKeys["output"], &outputFile) },
		func() error { return envStringFallback(cmd, "pbom", envKeys["pbom"], &pbomFile) },
		func() error { return envStringFallback(cmd, "pbom-cyclonedx", envKeys["pbom-cyclonedx"], &pbomCycloneDXFile) },
		func() error { return envStringFallback(cmd, "sarif", envKeys["sarif"], &sarifFile) },
		func() error { return envStringFallback(cmd, "glsast", envKeys["glsast"], &glsastFile) },
		func() error { return envStringFallback(cmd, "score-endpoint", envKeys["score-endpoint"], &scoreEndpoint) },
		func() error { return envStringFallback(cmd, "controls", envKeys["controls"], &controlsFilter) },
		func() error { return envStringFallback(cmd, "skip-controls", envKeys["skip-controls"], &skipControls) },
		func() error { return envStringFallback(cmd, "ci-config-path", envKeys["ci-config-path"], &ciConfigPath) },
		func() error { return envFloat64Fallback(cmd, "threshold", envKeys["threshold"], &threshold) },
		func() error { return envStringFallback(cmd, "min-score", envKeys["min-score"], &minScore) },
		func() error { return envFloat64Fallback(cmd, "min-points", envKeys["min-points"], &minPoints) },
		func() error { return envBoolFallback(cmd, "print", envKeys["print"], &printOutput) },
		func() error { return envBoolFallback(cmd, "mr-comment", envKeys["mr-comment"], &mrComment) },
		func() error { return envBoolFallback(cmd, "badge", envKeys["badge"], &badge) },
		func() error { return envBoolFallback(cmd, "score", envKeys["score"], &showScore) },
		func() error { return envBoolFallback(cmd, "score-point", envKeys["score-point"], &showScorePoint) },
		func() error { return envBoolFallback(cmd, "score-push", envKeys["score-push"], &pushScore) },
		func() error { return envBoolFallback(cmd, "fail-warnings", envKeys["fail-warnings"], &failWarnings) },
	} {
		if err := apply(); err != nil {
			return err
		}
	}

	flags := readAnalyzeFlags(cmd)

	if err := validateProviderFlags(flags); err != nil {
		return err
	}

	if err := resolveGateFlags(cmd); err != nil {
		return err
	}

	controlsFilterList, skipControlsList, err := parseControlsFilters()
	if err != nil {
		return err
	}

	remoteInfo := utils.DetectGitRemote()

	providerName, reason := resolveProvider(providerFlag, flags.gitlabURLFromFlag, flags.githubURLFromFlag, remoteInfo)
	if providerName == "" {
		return fmt.Errorf("could not determine the provider: not in a git repository and no provider flag set. " +
			"Pass --provider github|gitlab, or --github-url <host> / --gitlab-url <url> to target a specific instance")
	}
	printProviderDetection(providerName, reason)

	if providerName == "github" {
		return dispatchGitHub(cmd, flags, remoteInfo, controlsFilterList, skipControlsList)
	}

	remote, err := resolveGitLabTarget(flags, remoteInfo)
	if err != nil {
		return err
	}

	gitlabToken, err := resolveGitLabToken(flags)
	if err != nil {
		return err
	}

	cleanGitlabURL := strings.TrimSuffix(gitlabURL, "/")

	plumberConfig, configPath, configWarnings, err := loadConfigOrOffer(configFile)
	if err != nil {
		return err
	}
	if err := applyConfigWarnings(configWarnings); err != nil {
		return err
	}

	if printOutput {
		printBanner()
	}
	fmt.Fprintf(os.Stderr, "Using configuration: %s\n", configPath)
	fmt.Fprintf(os.Stderr, "Analyzing project: %s on %s\n", projectPath, cleanGitlabURL)

	conf := buildGitLabConf(cleanGitlabURL, gitlabToken, flags, remote, plumberConfig, controlsFilterList, skipControlsList)

	p, ok := plumberprovider.Get("gitlab")
	if !ok {
		return fmt.Errorf("gitlab provider not registered")
	}
	return runWithProvider(p, cmd, conf, controlsFilterList, skipControlsList)
}

// parseControlsFilter parses and validates a comma separated control list.
func parseControlsFilter(raw string) ([]string, error) {
	// Empty flag means that no filter,
	// so keep current behavior (all controls run).
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	// Resolve valid names from the same schema used by .plumber.yaml validation.
	validControls := configuration.ValidControlNames()
	validSet := make(map[string]struct{}, len(validControls))
	for _, control := range validControls {
		validSet[control] = struct{}{}
	}

	controls := make([]string, 0)
	controlsSet := make(map[string]struct{})
	unknown := make([]string, 0)
	unknownSet := make(map[string]struct{})

	for _, part := range strings.Split(raw, ",") {
		control := strings.TrimSpace(part)
		if control == "" {
			continue
		}

		// Collecting unknown names so it can return one actionable error.
		if _, ok := validSet[control]; !ok {
			if _, seen := unknownSet[control]; !seen {
				unknownSet[control] = struct{}{}
				unknown = append(unknown, control)
			}
			continue
		}

		// Keeps the first occurrence only,
		// it will avoid duplicate work downstream.
		if _, seen := controlsSet[control]; seen {
			continue
		}
		controlsSet[control] = struct{}{}
		controls = append(controls, control)
	}

	if len(unknown) > 0 {
		sort.Strings(unknown)
		sort.Strings(validControls)
		var b strings.Builder
		b.WriteString("unknown control names: ")
		b.WriteString(strings.Join(unknown, ", "))
		b.WriteString("\n\nValid controls:\n")
		for _, name := range validControls {
			b.WriteString("  - ")
			b.WriteString(name)
			b.WriteString("\n")
		}
		return nil, fmt.Errorf("%s", b.String())
	}

	return controls, nil
}

// buildAnalysisJSONReport assembles the ordered analysis JSON payload. The
// same bytes are written to --output and pushed to the score service, so the
// stored badge record and the file on disk can never diverge.
func buildAnalysisJSONReport(result *control.AnalysisResult, pc *configuration.PlumberConfig, s complianceSummary, p jsonOutputParams) ([]byte, error) {
	score, scoreMode, provider, includeOnly, skip :=
		s.score, s.scoreMode, p.provider, p.includeOnly, p.skip
	// Marshal AnalysisResult into a generic map so the per-control
	// `*Result` legacy blocks can sit alongside its existing fields
	// without forcing every consumer to follow the dev's flat-findings
	// shape. The legacy keys (imageForbiddenTagsResult, …) carry the
	// same issues + metrics pair v0.2.x emitted, so downstream tooling
	// parses the dev output unchanged.
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal result: %w", err)
	}
	output := map[string]any{}
	if err := json.Unmarshal(raw, &output); err != nil {
		return nil, fmt.Errorf("unmarshal result: %w", err)
	}
	// The gate that produced `passed` is spelled out next to it: the score
	// gate emits minPoints / minScore; the deprecated --threshold gate emits
	// threshold for the pipelines still supplying it. The compliance
	// percentage itself is gone (#320) — plumberScore is the grade.
	if s.thresholdSet {
		output["threshold"] = s.threshold
	} else {
		if s.pointsGateActive() {
			output["minPoints"] = s.minPoints
		}
		if s.minScore != "" {
			output["minScore"] = s.minScore
		}
	}
	output["passed"] = s.passed()
	if scoreMode && score != nil {
		output["plumberScore"] = score
	}
	// `partialControls` surfaces the postflight-skipped story so CI
	// consumers can detect "we couldn't fully evaluate X" without
	// scraping the rendered terminal output. Today the only entry
	// is `branchMustBeProtected` when GitHub /branches/{name}/
	// protection 403'd; future controls with similar partial-data
	// modes can append here.
	if partial := partialControlEntries(result); len(partial) > 0 {
		output["partialControls"] = partial
	}
	// plumberConfig makes the report self-describing: the policy that produced
	// this grade, parsed into a structured object (not the verbatim file, so
	// comments and formatting never leave the repo) plus a content hash. The
	// CLI does NOT classify standard-vs-custom (it's the untrusted client); the
	// score service classifies server-side from this object and its hash.
	output["plumberConfig"] = buildPlumberConfigBlock(pc)
	for k, v := range legacyResultsByName(result, pc, provider, includeOnly, skip) {
		output[k] = v
	}

	// Top-level aggregate blocks (pipelineOriginMetrics +
	// pipelineImageMetrics) are populated by the GitLab task path
	// and serialised straight from AnalysisResult. The GitHub path
	// doesn't fill those fields, so inject GitHub-shaped equivalents
	// here from result.GitHubStats — same top-level key slots, GitHub-
	// native counters ("originAction" / "originReusableWorkflow"
	// instead of "originComponent" / "originTemplate"). Keeps the
	// "scroll to the top of analysis.json" experience symmetric
	// across providers.
	if provider == "github" && result.GitHubStats != nil {
		s := result.GitHubStats
		output["pipelineOriginMetrics"] = map[string]any{
			"jobTotal":                             s.JobsTotal,
			"workflowsTotal":                       s.WorkflowsTotal,
			"originAction":                         s.ActionRefsTotal,
			"originActionUnpinned":                 s.ActionRefsUnpinned,
			"originActionTrustedExempt":            s.ActionRefsExempt,
			"originReusableWorkflow":               s.ReusableCalls,
			"originReusableWorkflowSecretsInherit": s.ReusableCallsSecretsInherit,
			"originTotal":                          s.ActionRefsTotal + s.ReusableCalls,
		}
		output["pipelineImageMetrics"] = map[string]any{
			"total": s.ImagesTotal,
		}
	}

	// Drop the flat Rego findings list from the file on both
	// providers. Legacy GitLab consumers parse the per-control
	// *Result blocks (issues/metrics/compliance) and never read
	// `findings`. The GitHub side now ships per-control *Result
	// blocks for every shipping control (the 4 cross-provider ones
	// + 5 GitHub-only added in this session), so the flat array is
	// no longer needed as an escape hatch — keeping it would just
	// duplicate every issue between the top level and the *Result
	// blocks. Cross-provider structural parity > flat-jq convenience.
	delete(output, "findings")

	// Encode with intentional key order so readers see project/context first,
	// scoring next, then per-control *Result blocks (not Go map lexical order).
	return marshalLegacyAnalysisJSONObject(output)
}

// buildPlumberConfigBlock returns the self-describing `plumberConfig` block:
// the policy that produced the run parsed into a structured object (NOT the
// verbatim file — comments and formatting are dropped), its source, and a
// sha256 content hash of that object. Falls back to the embedded default
// (source "default") when no config file was loaded.
func buildPlumberConfigBlock(pc *configuration.PlumberConfig) map[string]any {
	source, rawCfg := "default", ""
	if pc != nil && pc.Raw != "" {
		source, rawCfg = pc.Source, pc.Raw
	}
	if rawCfg == "" {
		rawCfg = string(defaultconfig.Get())
		source = "default"
	}
	policy := parsePolicyObject(rawCfg)
	// Hash the canonical JSON of the parsed policy: encoding/json sorts map
	// keys, so the digest depends only on the policy's content, never on the
	// file's comments, whitespace, or key order.
	canonical, _ := json.Marshal(policy)
	sum := sha256.Sum256(canonical)
	return map[string]any{
		"source":          source,
		"effectivePolicy": policy,
		"hash":            "sha256:" + hex.EncodeToString(sum[:]),
	}
}

// parsePolicyObject parses YAML config text into a JSON-friendly object,
// dropping comments and formatting. yaml.v2 decodes maps as map[any]any, which
// json.Marshal cannot encode, so nested maps are rewritten to string keys.
// Returns an empty object when the text is blank or cannot be parsed.
func parsePolicyObject(rawCfg string) map[string]any {
	if strings.TrimSpace(rawCfg) == "" {
		return map[string]any{}
	}
	var parsed any
	if err := yaml.Unmarshal([]byte(rawCfg), &parsed); err != nil {
		return map[string]any{}
	}
	obj, ok := normalizeYAMLValue(parsed).(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return obj
}

// normalizeYAMLValue rewrites yaml.v2's map[any]any into JSON-encodable
// map[string]any, recursively, leaving scalars and slices intact.
func normalizeYAMLValue(v any) any {
	switch t := v.(type) {
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, val := range t {
			m[fmt.Sprint(k)] = normalizeYAMLValue(val)
		}
		return m
	case []any:
		for i := range t {
			t[i] = normalizeYAMLValue(t[i])
		}
		return t
	default:
		return v
	}
}

// writeJSONToFile builds the analysis JSON report and writes it to p.filePath.
func writeJSONToFile(result *control.AnalysisResult, pc *configuration.PlumberConfig, s complianceSummary, p jsonOutputParams) error {
	payload, err := buildAnalysisJSONReport(result, pc, s, p)
	if err != nil {
		return err
	}
	if err := os.WriteFile(p.filePath, payload, 0o644); err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	return nil
}

// partialControlEntries lists controls whose evaluation was partial —
// some inputs reachable, others not. CI gates parse this to decide
// whether to fail loud ("we never actually checked your protection
// rules") even when the run passed its gate.
func partialControlEntries(result *control.AnalysisResult) []map[string]any {
	if result == nil || result.GitHubStats == nil {
		return nil
	}
	var out []map[string]any
	if n := result.GitHubStats.BranchesProtectionDetailsUnknown; n > 0 {
		out = append(out, map[string]any{
			"control":          "branchMustBeProtected",
			"reason":           "Token lacks Administration:Read scope; force-push and code-owner-approval rules (ISSUE-505) not evaluated.",
			"affectedBranches": n,
			"remediation":      "Re-run with a token carrying Administration:Read (fine-grained PAT) or `repo` scope (classic PAT).",
		})
	}
	return out
}

// analysisJSONLegacyKeyHead is the canonical top-level key order before any
// *Result control blocks so analysis.json reads: project → CI context →
// outcome/score → findings (per-control). plumberConfig is pinned to the very
// end instead (see analysisJSONLegacyKeyTail).
var analysisJSONLegacyKeyHead = []string{
	"projectPath", "projectId", "defaultBranch",
	"ciConfigSource", "ciValid", "ciMissing", "ciErrors",
	"pipelineOriginMetrics", "pipelineImageMetrics",
	"minPoints", "minScore", "threshold", "passed", "plumberScore",
}

// analysisJSONLegacyKeyTail lists keys pinned to the END of the object, after
// the per-control *Result blocks and everything else. plumberConfig is bulky
// (the full parsed policy) and self-describing, so it reads best last.
var analysisJSONLegacyKeyTail = []string{"plumberConfig"}

func legacyAnalysisJSONKeyOrder(m map[string]any) []string {
	seen := make(map[string]bool, len(m))
	order := make([]string, 0, len(m))
	for _, k := range analysisJSONLegacyKeyHead {
		if _, ok := m[k]; ok {
			order = append(order, k)
			seen[k] = true
		}
	}
	// Reserve the tail keys so they skip the middle groups below and land at
	// the very end, in their declared order.
	tail := make(map[string]bool, len(analysisJSONLegacyKeyTail))
	for _, k := range analysisJSONLegacyKeyTail {
		tail[k] = true
	}
	var suffixResult []string
	for k := range m {
		if seen[k] || tail[k] {
			continue
		}
		if strings.HasSuffix(k, "Result") {
			suffixResult = append(suffixResult, k)
		}
	}
	sort.Strings(suffixResult)
	for _, k := range suffixResult {
		order = append(order, k)
		seen[k] = true
	}
	var rest []string
	for k := range m {
		if seen[k] || tail[k] {
			continue
		}
		rest = append(rest, k)
	}
	sort.Strings(rest)
	order = append(order, rest...)
	for _, k := range analysisJSONLegacyKeyTail {
		if _, ok := m[k]; ok && !seen[k] {
			order = append(order, k)
			seen[k] = true
		}
	}
	return order
}

// writeLegacyJSONValue writes the JSON encoding of v into buf, applying
// pretty-print indentation for object and array values.
func writeLegacyJSONValue(buf *bytes.Buffer, k string, v any, step string) error {
	rawVal, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("%s value: %w", k, err)
	}
	if len(rawVal) == 0 || (rawVal[0] != '{' && rawVal[0] != '[') {
		buf.Write(rawVal)
		return nil
	}
	rawIndented, err := json.MarshalIndent(v, "", step)
	if err != nil {
		return fmt.Errorf("%s indentation: %w", k, err)
	}
	lines := bytes.Split(bytes.TrimSpace(rawIndented), []byte("\n"))
	if len(lines) == 1 {
		buf.Write(lines[0])
		return nil
	}
	// Opening bracket on the same line as the key; body lines indented.
	buf.Write(lines[0])
	buf.WriteByte('\n')
	for _, line := range lines[1 : len(lines)-1] {
		buf.WriteString(step)
		buf.Write(line)
		buf.WriteByte('\n')
	}
	buf.WriteString(step)
	buf.Write(lines[len(lines)-1])
	return nil
}

func marshalLegacyAnalysisJSONObject(output map[string]any) ([]byte, error) {
	keys := legacyAnalysisJSONKeyOrder(output)
	step := "  "
	var buf bytes.Buffer
	buf.WriteString("{\n")
	first := true
	for _, k := range keys {
		v, ok := output[k]
		if !ok {
			continue
		}
		if !first {
			buf.WriteString(",\n")
		}
		first = false

		keyBytes, err := json.Marshal(k)
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", k, err)
		}
		buf.WriteString(step)
		buf.Write(keyBytes)
		buf.WriteString(": ")
		if err := writeLegacyJSONValue(&buf, k, v, step); err != nil {
			return nil, err
		}
	}
	buf.WriteString("\n}\n")
	return buf.Bytes(), nil
}

// ANSI color codes
const (
	colorReset       = "\033[0m"
	colorRed         = "\033[31m"
	colorGreen       = "\033[32m"
	colorYellow      = "\033[33m"
	colorBlue        = "\033[34m"
	colorCyan        = "\033[36m"
	colorGreenBright = "\033[92m"
	colorBold        = "\033[1m"
	colorDim         = "\033[2m"
)

func severityTag(code control.ErrorCode) string {
	switch control.SeverityForCode(code) {
	case control.SeverityCritical:
		return renderSeverityBadge(control.SeverityCritical, " CRIT ")
	case control.SeverityHigh:
		return renderSeverityBadge(control.SeverityHigh, " HIGH ")
	case control.SeverityMedium:
		return renderSeverityBadge(control.SeverityMedium, " MED  ")
	case control.SeverityLow:
		return renderSeverityBadge(control.SeverityLow, " LOW  ")
	default:
		return renderSeverityBadge(control.SeverityMedium, " MED  ")
	}
}

// renderSeverityBadge renders a label as a filled severity badge in
// absolute truecolor: a fixed bright background plus a guaranteed-
// contrast ink, so it stays readable on dark, light, and beige
// terminals alike, because the badge brings its own background instead
// of depending on contrast with the terminal's. Uses truecolor rather
// than the remappable 16-color ANSI palette so themes can't mangle it.
// Shared by the controls table (highestSeverityLabel) and the
// per-finding inline tags (severityTag) so both look identical.
// See issue #170.
func renderSeverityBadge(sev control.IssueSeverity, label string) string {
	switch sev {
	case control.SeverityCritical:
		return lipgloss.NewStyle().Background(colCritical).Foreground(colInkLight).Bold(true).Render(label)
	case control.SeverityHigh:
		return lipgloss.NewStyle().Background(colHigh).Foreground(colInkDark).Bold(true).Render(label)
	case control.SeverityMedium:
		return lipgloss.NewStyle().Background(colMedium).Foreground(colInkDark).Bold(true).Render(label)
	case control.SeverityLow:
		return lipgloss.NewStyle().Background(colLow).Foreground(colInkDark).Bold(true).Render(label)
	default:
		return styleDim.Render(label)
	}
}

func highestSeverityLabel(c control.SeverityCounts, visibleWidth int) string {
	pad := func(label string) string {
		w := utf8.RuneCountInString(label)
		if w < visibleWidth {
			return label + strings.Repeat(" ", visibleWidth-w)
		}
		return label
	}
	switch {
	case c.Critical > 0:
		return renderSeverityBadge(control.SeverityCritical, pad("Critical"))
	case c.High > 0:
		return renderSeverityBadge(control.SeverityHigh, pad("High"))
	case c.Medium > 0:
		return renderSeverityBadge(control.SeverityMedium, pad("Medium"))
	case c.Low > 0:
		return renderSeverityBadge(control.SeverityLow, pad("Low"))
	default:
		return styleDim.Render(pad("-"))
	}
}

func scoreLetterColor(letter string) string {
	switch letter {
	case "A":
		return colorGreen
	case "B":
		return colorGreenBright
	case "C":
		return colorYellow
	case "D":
		return "\033[38;5;208m" // orange
	default:
		return colorRed
	}
}

func scoreBar(finalPoints float64, width int) string {
	filled := int(finalPoints / 100.0 * float64(width))
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	// Truecolor (theme-independent), matching the score-letter tier
	// colors: A/B green, C yellow, D amber, E red. The unfilled track
	// uses the faint attribute, which is background-agnostic.
	var barColor lipgloss.Color
	switch {
	case finalPoints >= 71:
		barColor = colPass
	case finalPoints >= 51:
		barColor = colMedium
	case finalPoints >= 31:
		barColor = colHigh
	default:
		barColor = colCritical
	}
	full := lipgloss.NewStyle().Foreground(barColor).Render(strings.Repeat("█", filled))
	track := styleDim.Render(strings.Repeat("░", width-filled))
	return full + track
}

// jsonOutputParams bundles the non-result arguments for writeJSONToFile.
type jsonOutputParams struct {
	filePath    string
	provider    string
	includeOnly []string
	skip        []string
}

// complianceSummary bundles the computed gate values passed to outputText.
type complianceSummary struct {
	// compliance is the legacy passing-controls percentage, computed only to
	// serve the deprecated --threshold gate. It is never emitted anymore.
	compliance   float64
	controlCount int
	threshold    float64
	thresholdSet bool
	minPoints    float64
	minPointsSet bool
	minScore     string
	score        *control.PlumberScoreResult
	scoreMode    bool
	scorePoint   bool
	// ciMissing / ciInvalid: nothing was scoreable. Zero findings on an
	// absent or unparseable CI configuration must not pass the score gate.
	ciMissing bool
	ciInvalid bool
}

// pointsGateActive reports whether the points gate applies: either it was set
// explicitly, or nothing was set at all (the default gate is min-points 100).
// When only --min-score is given, the letter alone gates.
func (s complianceSummary) pointsGateActive() bool {
	return s.minPointsSet || s.minScore == ""
}

// gateErr returns nil when the active gate passes, or the exit-code-1 error
// describing the failure. The deprecated --threshold gate wins when supplied;
// otherwise the Plumber Score gates the run.
func (s complianceSummary) gateErr() error {
	if s.thresholdSet {
		if s.compliance < s.threshold {
			return &ComplianceError{Compliance: s.compliance, Threshold: s.threshold}
		}
		return nil
	}
	if s.ciMissing {
		return &ScoreGateError{CiMissing: true}
	}
	if s.ciInvalid {
		return &ScoreGateError{CiInvalid: true}
	}
	// Zero controls evaluated (provider-mismatched or empty .plumber.yaml,
	// skip-all filter): zero findings score 100 pts, but nothing was checked,
	// so fail closed exactly like the missing/invalid-CI cases above.
	if s.controlCount == 0 {
		return &ScoreGateError{NoControls: true}
	}
	if s.score == nil {
		return nil
	}
	if s.minScore != "" && control.ScoreLetterRank(s.score.Score) < control.ScoreLetterRank(s.minScore) {
		return &ScoreGateError{Letter: s.score.Score, MinLetter: s.minScore, Points: s.score.FinalPoints}
	}
	if s.pointsGateActive() && s.score.FinalPoints < s.minPoints {
		return &ScoreGateError{Points: s.score.FinalPoints, MinPoints: s.minPoints, PointsGate: true, Letter: s.score.Score}
	}
	return nil
}

// passed reports whether the active gate is met. It is the value written to
// the JSON `passed` field and shown by the MR comment and job summaries.
func (s complianceSummary) passed() bool {
	return s.gateErr() == nil
}

// gateLine renders the active gate and its outcome as one human-readable
// sentence fragment, e.g. "score A — 100.0/100 pts, required ≥ 100 pts".
func (s complianceSummary) gateLine() string {
	if s.thresholdSet {
		return fmt.Sprintf("%.1f%% of controls passing, deprecated threshold %.0f%%", s.compliance, s.threshold)
	}
	if s.ciMissing {
		return "no CI configuration found, nothing to score"
	}
	if s.ciInvalid {
		return "invalid CI configuration, nothing to score"
	}
	if s.controlCount == 0 {
		return "no controls evaluated, nothing to score"
	}
	if s.score == nil {
		return ""
	}
	requirements := []string{}
	if s.pointsGateActive() {
		requirements = append(requirements, fmt.Sprintf("≥ %.0f pts", s.minPoints))
	}
	if s.minScore != "" {
		requirements = append(requirements, fmt.Sprintf("≥ %s", s.minScore))
	}
	return fmt.Sprintf("score %s — %.1f/100 pts, required %s", s.score.Score, s.score.FinalPoints, strings.Join(requirements, " and "))
}

// controlSummary holds summary data for a control
type controlSummary struct {
	name       string
	issues     int
	skipped    bool
	codes      []string
	bySeverity control.SeverityCounts // tallies from actual findings (C/H/M/L)
}

func uniqueSortedIssueCodeStrings(codes []control.ErrorCode) []string {
	seen := make(map[string]bool)
	var out []string
	for _, c := range codes {
		s := string(c)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// compareSeverityWorstFirst compares severity tallies for "which is worse".
// Returns negative if a is worse than b, positive if a is better, zero if equal.
func compareSeverityWorstFirst(a, b control.SeverityCounts) int {
	if a.Critical != b.Critical {
		if a.Critical > b.Critical {
			return -1
		}
		return 1
	}
	if a.High != b.High {
		if a.High > b.High {
			return -1
		}
		return 1
	}
	if a.Medium != b.Medium {
		if a.Medium > b.Medium {
			return -1
		}
		return 1
	}
	if a.Low != b.Low {
		if a.Low > b.Low {
			return -1
		}
		return 1
	}
	return 0
}

func sortControlSummariesForIssuesTable(s []controlSummary) {
	sort.SliceStable(s, func(i, j int) bool {
		a, b := s[i], s[j]
		if cmp := compareSeverityWorstFirst(a.bySeverity, b.bySeverity); cmp != 0 {
			return cmp < 0
		}
		if a.issues != b.issues {
			return a.issues > b.issues
		}
		return a.name < b.name
	})
}

// printBanner renders the Plumber ASCII-art banner followed by the
// tagline and community link. The banner keeps Plumber's signature
// green color for brand recognition.
func printBanner() {
	asciiArt := lipgloss.NewStyle().Foreground(colPass).Bold(true).Render(
		"  ██████╗ ██╗     ██╗   ██╗ ███╗   ███╗██████╗ ███████╗██████╗ \n" +
			"  ██╔══██╗██║     ██║   ██║ ████╗ ████║██╔══██╗██╔════╝██╔══██╗\n" +
			"  ██████╔╝██║     ██║   ██║ ██╔████╔██║██████╔╝█████╗  ██████╔╝\n" +
			"  ██╔═══╝ ██║     ██║   ██║ ██║╚██╔╝██║██╔══██╗██╔══╝  ██╔══██╗\n" +
			"  ██║     ███████╗╚██████╔╝ ██║ ╚═╝ ██║██████╔╝███████╗██║  ██║\n" +
			"  ╚═╝     ╚══════╝ ╚═════╝  ╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝",
	)
	fmt.Println()
	fmt.Println(asciiArt)
	fmt.Printf("  %s  %s\n",
		styleTitle.Render("CI/CD Compliance Scanner for GitLab & GitHub Actions"),
		styleMuted.Render("v"+Version),
	)
	fmt.Printf("  %s %s\n\n",
		styleMuted.Render("Join our community:"),
		styleAccent.Render("https://getplumber.io/discord"),
	)
}

// printNoControlsWarning prints the warning block shown when zero controls
// could be evaluated (CI missing, invalid, or data collection failure).
func printNoControlsWarning(result *control.AnalysisResult) {
	fmt.Printf(fmtIndentLine, styleError.Render("⚠ WARNING: No controls could be evaluated!"))
	if len(result.CiErrors) > 0 {
		fmt.Printf(fmtIndentLine, styleError.Render("CI configuration errors:"))
		bullet := styleError.Render("•")
		for _, e := range result.CiErrors {
			fmt.Printf("    %s %s\n", bullet, sanitizeTerminal(e))
		}
		fmt.Println()
		return
	}
	if result.CiMissing {
		fmt.Printf(fmtIndentPara, styleDim.Render("CI configuration file is missing from the project."))
		return
	}
	fmt.Printf(fmtIndentLine, styleDim.Render("Data collection failed - compliance defaults to 0%."))
	fmt.Printf(fmtIndentPara, styleDim.Render("Use --verbose for more info."))
}

// findingsToItems converts a slice of OPA findings into the parallel
// (codes, items) slices used by the table and group renderers.
func findingsToItems(findings []opaengine.Finding) ([]control.ErrorCode, []detailedFinding) {
	codes := make([]control.ErrorCode, 0, len(findings))
	items := make([]detailedFinding, 0, len(findings))
	for _, f := range findings {
		code := control.ErrorCode(f.Code)
		codes = append(codes, code)
		items = append(items, detailedFinding{
			Code:        code,
			Message:     f.Message,
			DocURL:      code.DocURL(),
			Location:    formatFindingLocation(f),
			DetailLines: detailLinesFromFinding(f),
		})
	}
	return codes, items
}

// scoreBreakdownWidths are inner text widths (padding applied after; borders use w+2 dashes per column).
const (
	sbWCode = 11
	sbWSev  = 10
	sbWCnt  = 5
	sbWWgt  = 6
	sbWCap  = 5
	sbWLoss = 8
)

func padRunesRight(s string, w int) string {
	n := utf8.RuneCountInString(s)
	if n >= w {
		return s
	}
	return s + strings.Repeat(" ", w-n)
}

func padRunesLeft(s string, w int) string {
	n := utf8.RuneCountInString(s)
	if n >= w {
		return s
	}
	return strings.Repeat(" ", w-n) + s
}

func scoreBreakdownBorderTop() string {
	parts := []int{sbWCode, sbWSev, sbWCnt, sbWWgt, sbWCap, sbWLoss}
	var segs []string
	for _, w := range parts {
		segs = append(segs, strings.Repeat("─", w+2))
	}
	return "┌" + strings.Join(segs, "┬") + "┐"
}

func scoreBreakdownBorderMid() string {
	parts := []int{sbWCode, sbWSev, sbWCnt, sbWWgt, sbWCap, sbWLoss}
	var segs []string
	for _, w := range parts {
		segs = append(segs, strings.Repeat("─", w+2))
	}
	return "├" + strings.Join(segs, "┼") + "┤"
}

func scoreBreakdownBorderMidFooter() string {
	parts := []int{sbWCode, sbWSev, sbWCnt, sbWWgt, sbWCap, sbWLoss}
	var segs []string
	for _, w := range parts {
		segs = append(segs, strings.Repeat("─", w+2))
	}
	// Merge the first five columns into a single "Total loss" cell, leaving the Loss column.
	return "├" + strings.Join(segs[:5], "┴") + "┼" + segs[5] + "┤"
}

func scoreBreakdownBorderBottom() string {
	parts := []int{sbWCode, sbWSev, sbWCnt, sbWWgt, sbWCap, sbWLoss}
	var segs []string
	for _, w := range parts {
		segs = append(segs, strings.Repeat("─", w+2))
	}
	return "└" + strings.Join(segs, "┴") + "┘"
}

func scoreBreakdownSevColor(sev control.IssueSeverity) string {
	switch sev {
	case control.SeverityCritical:
		return colorRed
	case control.SeverityHigh:
		return colorYellow
	case control.SeverityMedium:
		return colorCyan
	default:
		return colorBlue
	}
}

// printCodeLossTable renders the per-code breakdown table and returns the total
// loss so the caller can print the summary line.
func printCodeLossTable(losses []control.CodeLoss) float64 {
	fmt.Printf(fmtIndentColored, colorDim, scoreBreakdownBorderTop(), colorReset)
	fmt.Printf("  %s│ %s │ %s │ %s │ %s │ %s │ %s │%s\n", colorDim,
		padRunesRight("Code", sbWCode),
		padRunesRight("Severity", sbWSev),
		padRunesLeft("Count", sbWCnt),
		padRunesLeft("Weight", sbWWgt),
		padRunesLeft("Cap", sbWCap),
		padRunesLeft("Loss", sbWLoss),
		colorReset)
	fmt.Printf(fmtIndentColored, colorDim, scoreBreakdownBorderMid(), colorReset)

	var totalLoss float64
	for _, l := range losses {
		capPlain := "inf"
		if l.Severity != control.SeverityCritical {
			capPlain = fmt.Sprintf("%.0f", l.Cap)
		}
		sc := scoreBreakdownSevColor(l.Severity)
		fmt.Printf("  %s│ %s%s%s │ %s%s%s │ %s%s%s │ %s%s%s │ %s%s%s │ %s%s%s │%s\n", colorDim,
			colorDim, padRunesRight(string(l.Code), sbWCode), colorReset,
			sc, padRunesRight(string(l.Severity), sbWSev), colorReset,
			colorDim, padRunesLeft(fmt.Sprintf("%d", l.Count), sbWCnt), colorReset,
			colorDim, padRunesLeft(fmt.Sprintf("%.0f", l.Weight), sbWWgt), colorReset,
			colorDim, padRunesLeft(capPlain, sbWCap), colorReset,
			colorRed, padRunesLeft(fmt.Sprintf("-%.1f", l.CappedLoss), sbWLoss), colorReset,
			colorReset)
		totalLoss += l.CappedLoss
	}

	fmt.Printf(fmtIndentColored, colorDim, scoreBreakdownBorderMidFooter(), colorReset)
	// Merge the first five columns for the Total row.
	mergedW := sbWCode + 3 + sbWSev + 3 + sbWCnt + 3 + sbWWgt + 3 + sbWCap
	tl := "Total loss"
	tlPad := mergedW - utf8.RuneCountInString(tl)
	if tlPad < 0 {
		tlPad = 0
	}
	leftCell := colorBold + tl + colorReset + strings.Repeat(" ", tlPad)
	fmt.Printf("  %s│ %s │ %s%s%s │%s\n", colorDim,
		leftCell,
		colorRed, padRunesLeft(fmt.Sprintf("-%.1f", totalLoss), sbWLoss), colorReset,
		colorReset)
	fmt.Printf(fmtIndentColored, colorDim, scoreBreakdownBorderBottom(), colorReset)
	fmt.Println()
	return totalLoss
}

func printScoreBreakdown(score *control.PlumberScoreResult) {
	printSectionHeader("Points breakdown (beta)")
	fmt.Println()
	fmt.Printf("  %sProfile:%s %s\n\n", colorDim, colorReset, score.ProfileID)

	fmt.Printf("  Base points: %s100%s\n", colorGreen, colorReset)
	if len(score.CodeLosses) > 0 {
		totalLoss := printCodeLossTable(score.CodeLosses)
		fmt.Printf("  Total loss:  %s-%.1f%s\n", colorRed, totalLoss, colorReset)
	}
	fmt.Printf("  Raw points:  %.1f\n", score.RawPoints)

	if score.CriticalMalusApplied {
		fmt.Printf("  %sCritical malus: final points capped at %.0f%s\n", colorRed, score.CriticalMalusMax, colorReset)
	}
	gc := scoreLetterColor(score.Score)
	fmt.Printf("  %sFinal points:%s %s%s%.1f / 100%s\n", colorBold, colorReset, colorBold, gc, score.FinalPoints, colorReset)
	fmt.Printf("  %sScore:%s       %s%s%s%s\n", colorBold, colorReset, gc, colorBold, score.Score, colorReset)
	fmt.Println()
	fmt.Printf("  %sLetter score (from points):%s  %sA%s >=90  %s│%s  %sB%s >=71  %s│%s  %sC%s >=51  %s│%s  %sD%s >=31  %s│%s  %sE%s <31\n",
		colorDim, colorReset,
		colorGreen, colorReset, colorDim, colorReset,
		colorGreenBright, colorReset, colorDim, colorReset,
		colorYellow, colorReset, colorDim, colorReset,
		"\033[38;5;208m", colorReset, colorDim, colorReset,
		colorRed, colorReset)
	fmt.Println()
}

func printControlHeader(name string, issues int, skipped bool) {
	line := strings.Repeat("─", 50)
	fmt.Printf(fmtColored, colorDim, line, colorReset)
	switch {
	case skipped:
		fmt.Printf("%s%s%s %s(skipped)%s\n", colorBold, name, colorReset, colorDim, colorReset)
	case issues == 0:
		fmt.Printf("%s%s%s %s(passed)%s\n", colorBold, name, colorReset, colorGreen, colorReset)
	case issues == 1:
		fmt.Printf("%s%s%s %s(1 issue)%s\n", colorBold, name, colorReset, colorRed, colorReset)
	default:
		fmt.Printf("%s%s%s %s(%d issues)%s\n", colorBold, name, colorReset, colorRed, issues, colorReset)
	}
	fmt.Printf(fmtColored, colorDim, line, colorReset)
}

func printSectionHeader(name string) {
	line := strings.Repeat("─", 20)
	fmt.Printf(fmtColored, colorDim, line, colorReset)
	fmt.Printf(fmtColored, colorBold, name, colorReset)
	fmt.Printf(fmtColored, colorDim, line, colorReset)
}

// scoreLetterBadgeLines returns 5 pre-colored lines drawing a double-bordered badge
// around the letter score (A–E), e.g.
//
//	╔═══════╗
//	║       ║
//	║   E   ║
//	║       ║
//	╚═══════╝
//
// The whole badge (borders + letter) is rendered in bold, using the letter's
// tier color so it reads as a single coherent visual token.
// printSummaryScoreBanner renders the Plumber letter score in a
// modernised two-column layout: a large grade badge on the left, and
// a side panel on the right with points, progress bar, meaning text,
// severity chips, and any Critical malus warning.
func printSummaryScoreBanner(score *control.PlumberScoreResult, scoreMode, degraded bool) {
	if score == nil || !scoreMode {
		return
	}

	// When data collection was degraded the score ran on incomplete data, so
	// the letter grade would be meaningless (an empty pipeline reads as a clean
	// A). Withhold the badge and say so plainly (#220).
	if degraded {
		sep := styleRule.Render(strings.Repeat("─", hrWidth))
		fmt.Println()
		fmt.Println(" " + sep)
		fmt.Println(" " + styleMuted.Render("Plumber Score"))
		fmt.Println()
		fmt.Printf(" %s\n", styleFail.Render("Score withheld — analysis ran on incomplete data"))
		fmt.Printf(" %s\n", styleMuted.Render("Resolve the data-collection warnings above, then re-run for a grade."))
		fmt.Println()
		fmt.Println(" " + sep)
		fmt.Println()
		return
	}

	letterColor := scoreLetterLipglossColor(score.Score)

	// Block-letter ASCII badge — six lines tall, matches the project
	// banner lettering style.
	badge := scoreLetterAsciiArt(score.Score)

	letterStyle := lipgloss.NewStyle().Foreground(letterColor).Bold(true)
	pointsLine := letterStyle.Render(fmt.Sprintf("%.0f / 100 pts", score.FinalPoints))
	bar := scoreBar(score.FinalPoints, 28)
	meaning := ""
	if m := control.ScoreLetterMeaning(score.Score); m != "" {
		meaning = styleMuted.Render(m)
	}
	chips := fmt.Sprintf("%s   %s   %s   %s",
		severityChip("critical", "Critical", score.Counts.Critical),
		severityChip("high", "High", score.Counts.High),
		severityChip("medium", "Medium", score.Counts.Medium),
		severityChip("low", "Low", score.Counts.Low))

	// Six-line side panel matching the block-letter badge height:
	// blank line, points, bar, meaning, blank, chips.
	side := lipgloss.JoinVertical(lipgloss.Left,
		"",
		pointsLine,
		bar,
		meaning,
		"",
		chips,
	)
	// lipgloss.JoinHorizontal vertically centers the two blocks; the
	// side panel gets a small left gutter.
	body := lipgloss.JoinHorizontal(lipgloss.Center,
		badge,
		lipgloss.NewStyle().PaddingLeft(2).Render(side),
	)

	sep := styleRule.Render(strings.Repeat("─", hrWidth))

	fmt.Println()
	fmt.Println(" " + sep)
	fmt.Println(" " + styleMuted.Render("Plumber Score"))
	fmt.Println()
	fmt.Println(indentBlock(body, " "))

	if score.CriticalMalusApplied {
		fmt.Println()
		fmt.Printf(" %s  %s\n",
			styleFail.Render("▲ Critical malus applied"),
			styleMuted.Render(fmt.Sprintf("(final points capped at %.0f while any Critical remains)", score.CriticalMalusMax)))
	}

	fmt.Println()
	fmt.Println(" " + sep)
	fmt.Println()
}

// severityChip renders a single severity count as an emoji + label +
// colored count, used by the modern score banner.
func severityChip(sev, label string, n int) string {
	countStyle := lipgloss.NewStyle().Foreground(severityColor(sev)).Bold(true)
	return severityIcon(sev) + " " + styleMuted.Render(label) + " " + countStyle.Render(fmt.Sprintf("%d", n))
}

// issueTableCells returns the (codes, severity, count) cell strings for one
// issues-table row. Skipped controls and controls with no severity data show
// placeholder dashes.
func issueTableCells(ctrl controlSummary) (codesStr, sevLabel, issueStr string) {
	if ctrl.skipped {
		return "-", highestSeverityLabel(control.SeverityCounts{}, 10), "-"
	}
	noSev := ctrl.bySeverity.Critical+ctrl.bySeverity.High+ctrl.bySeverity.Medium+ctrl.bySeverity.Low == 0
	sev := ctrl.bySeverity
	if noSev {
		sev = control.SeverityCounts{}
	}
	return strings.Join(ctrl.codes, ", "), highestSeverityLabel(sev, 10), fmt.Sprintf("%d", ctrl.issues)
}

func printIssuesTable(controls []controlSummary) {
	var rows []controlSummary
	for _, c := range controls {
		if c.issues > 0 {
			rows = append(rows, c)
		}
	}

	fmt.Printf(fmtIndentLine, styleTitle.Render("Controls"))
	if len(rows) == 0 {
		fmt.Printf(fmtIndentLine, styleDim.Render("(none with open issues)"))
		return
	}

	sortControlSummariesForIssuesTable(rows)

	tbl := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(styleAccent).
		Headers("Control", "Codes", "Severity", "#").
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return styleHeader
			}
			if col == 3 && row >= 0 && row < len(rows) && rows[row].issues > 0 {
				return styleCell.Inherit(styleError)
			}
			return styleCell
		})

	for _, ctrl := range rows {
		codesStr, sevLabel, issueStr := issueTableCells(ctrl)
		tbl.Row(ctrl.name, codesStr, sevLabel, issueStr)
	}

	fmt.Println(indentBlock(tbl.String(), "  "))
	fmt.Printf(fmtIndentLine, styleDim.Render("↳ docs: https://getplumber.io/docs/cli/issues/<code>"))
}

// indentBlock prefixes every line of s with prefix. Used because
// lipgloss tables render flush-left and we want a little left margin.
func indentBlock(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

