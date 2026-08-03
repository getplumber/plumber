package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	ghauth "github.com/cli/go-gh/v2/pkg/auth"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	githubpkg "github.com/getplumber/plumber/github"
	plumberprovider "github.com/getplumber/plumber/provider"
	"github.com/getplumber/plumber/utils"
)

const githubDotCom = "github.com"

// runGitHubAnalyze handles `plumber analyze` for GitHub-hosted projects.
// Local-only MVP: walks .github/workflows/*.{yml,yaml} under the detected
// git repo root, evaluates the embedded Rego policies, and prints /
// writes the resulting findings. No GitHub API call, no token required.
//
// Returns an error (exit code 1) when at least one finding is reported,
// so the command can gate CI pipelines without any threshold flag.
// loadGitHubConfig loads the plumber config, prints any warnings, and returns
// the config and its path. It is the shared setup step for both GitHub analyze
// paths.
func loadGitHubConfig() (*configuration.PlumberConfig, string, error) {
	plumberConfig, configPath, configWarnings, err := loadConfigOrOffer(configFile, configExplicitlySet)
	if err != nil {
		return nil, "", err
	}
	if len(configWarnings) > 0 {
		fmt.Fprintf(os.Stderr, "Configuration validation warnings:\n")
		for _, w := range configWarnings {
			fmt.Fprintf(os.Stderr, "  - %s\n", w)
		}
		if failWarnings {
			return nil, "", fmt.Errorf("configuration has %d warning(s) and --fail-warnings is set", len(configWarnings))
		}
	}
	return plumberConfig, configPath, nil
}

func runGitHubAnalyze(info *utils.GitRemoteInfo, controlsFilterList, skipControlsList []string) error {
	plumberConfig, configPath, err := loadGitHubConfig()
	if err != nil {
		return err
	}

	if printOutput {
		printBanner()
	}

	conf := configuration.NewDefaultConfiguration()
	conf.ConfigFilePath = configPath
	conf.ProjectPath = info.ProjectPath
	conf.GitRepoRoot = info.RepoRoot
	// This command is the local-clone GitHub flow: the working tree
	// at info.RepoRoot is, by construction, the project we are about
	// to analyse. Flag it so downstream code (e.g. the source-link
	// builder) emits absolute local paths instead of remote blob URLs.
	conf.IsLocalProject = true
	conf.Branch = defaultBranch
	conf.PlumberConfig = plumberConfig
	conf.ControlsFilter = controlsFilterList
	conf.SkipControlsFilter = skipControlsList
	// API host for the settings/metadata controls. Precedence:
	//   1. --github-url, if the user passed it explicitly;
	//   2. otherwise the git remote host, when it is not github.com — this
	//      is a GitHub Enterprise Server clone, so target its API directly
	//      (mirrors how the GitLab path auto-uses the remote URL). go-gh
	//      resolves the matching token (GH_ENTERPRISE_TOKEN / gh auth login
	//      for that host);
	//   3. empty -> api.github.com.
	apiHost := strings.TrimPrefix(strings.TrimPrefix(githubURL, "https://"), "http://")
	if apiHost == "" && info.Host != "" && !strings.EqualFold(info.Host, githubDotCom) {
		apiHost = info.Host
	}
	conf.GithubAPIHost = apiHost

	printGitHubAuthBanner(apiHost, false)

	p, ok := plumberprovider.Get("github")
	if !ok {
		return fmt.Errorf("github provider not registered")
	}
	sp := installSpinner(conf)
	result, err := control.RunGitHubAnalysis(conf)
	sp.Stop()
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}
	return presentResultWithProvider(p, nil, result, conf)
}

// runGitHubAnalyzeRemote is the upstream-fetch counterpart of
// runGitHubAnalyze. Triggered by `plumber analyze --github-url X
// --project owner/repo [--branch Y]` when the user has not checked
// out the target repo locally. Symmetric to the GitLab path that
// fetches the merged CI YAML via API.
func runGitHubAnalyzeRemote(host, project, ref string, controlsFilterList, skipControlsList []string) error {
	parts := strings.SplitN(project, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("--project must be of the form owner/repo (got %q)", project)
	}
	owner, repo := parts[0], parts[1]

	plumberConfig, configPath, err := loadGitHubConfig()
	if err != nil {
		return err
	}

	if printOutput {
		printBanner()
	}

	apiHost := strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	printGitHubAuthBanner(apiHost, true)

	conf := configuration.NewDefaultConfiguration()
	conf.ConfigFilePath = configPath
	conf.ProjectPath = owner + "/" + repo
	conf.Branch = ref
	conf.PlumberConfig = plumberConfig
	conf.GithubAPIHost = apiHost
	conf.ControlsFilter = controlsFilterList
	conf.SkipControlsFilter = skipControlsList

	p, ok := plumberprovider.Get("github")
	if !ok {
		return fmt.Errorf("github provider not registered")
	}
	sp := installSpinner(conf)
	result, err := control.RunGitHubAnalysisRemote(conf, owner, repo, ref)
	sp.Stop()
	if err != nil {
		if errors.Is(err, githubpkg.ErrAuthRequired) {
			return err
		}
		return fmt.Errorf("analysis failed: %w", err)
	}
	return presentResultWithProvider(p, nil, result, conf)
}

// printGitHubAuthBanner emits a one-line stderr banner naming which
// auth source go-gh will use for this run. Cheap (no network) — pure
// env-var inspection — and complementary to the postflight skipped-
// control markers: tells the user up front "this is the credential
// I'm running with", so a later "ISSUE-505 was skipped because the
// token lacks Administration:Read" message lands with context.
//
// upstreamFetch=true means the run will fail outright if no auth is
// resolvable (ErrAuthRequired path). For local-clone runs, "no auth"
// is a degraded mode rather than a hard error, and the banner says so.
func printGitHubAuthBanner(apiHost string, upstreamFetch bool) {
	source := detectGitHubAuthSource(apiHost)
	switch source {
	case "":
		if upstreamFetch {
			// runGitHubAnalyzeRemote will surface ErrAuthRequired
			// almost immediately; banner here would just be noise
			// before the actionable error.
			return
		}
		fmt.Fprintf(os.Stderr, "GitHub auth: none — running in degraded mode (workflow-content controls only).\n")
	case "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN":
		fmt.Fprintf(os.Stderr, "GitHub auth: %s env var\n", source)
	case "gh":
		fmt.Fprintf(os.Stderr, "GitHub auth: gh CLI (~/.config/gh)\n")
	}
}

// detectGitHubAuthSource returns the highest-priority source go-gh
// would use, mirroring its resolution chain. Returns "" when no
// source is configured. Uses go-gh's auth package so the answer
// matches what the REST client actually picks up at request time.
//
// apiHost is the host the run will talk to (a GHES host, or "" /
// github.com for the SaaS default). The gh-CLI credential lookup is
// per-host, so a GHES clone authenticated only via `gh auth login` to
// its own host is correctly reported instead of falsely "degraded".
func detectGitHubAuthSource(apiHost string) string {
	if v := os.Getenv("GH_TOKEN"); v != "" {
		return "GH_TOKEN"
	}
	if v := os.Getenv("GITHUB_TOKEN"); v != "" {
		return "GITHUB_TOKEN"
	}
	if v := os.Getenv("GH_ENTERPRISE_TOKEN"); v != "" {
		return "GH_ENTERPRISE_TOKEN"
	}
	// Fall back to gh CLI's stored credential for the host we will hit.
	// auth.TokenForHost returns ("", "") when none is configured, so we
	// get an honest "" instead of pretending gh exists when it doesn't.
	host := apiHost
	if host == "" {
		host = githubDotCom
	}
	if token, _ := ghauth.TokenForHost(host); token != "" {
		return "gh"
	}
	return ""
}
