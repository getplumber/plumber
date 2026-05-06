package control

import (
	"strings"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/sirupsen/logrus"
)

// enrichGitHubBranches populates pipeline.Branches via the GitHub
// REST API when the user has enabled the branchMustBeProtected
// control AND that control is currently shipping (not benched) on
// GitHub. Silently skipped when the control is disabled in
// .plumber.yaml, when it is benched in code, or when projectPath
// isn't owner/repo shaped. Lacking auth or scope, the collector
// returns an empty slice and the rego rule emits no findings — the
// same degraded-mode contract as the action-metadata enrichment.
func enrichGitHubBranches(l *logrus.Entry, pipeline *ir.NormalizedPipeline, host string, pc *configuration.PlumberConfig, projectPath string) {
	if pipeline == nil || pc == nil {
		return
	}
	if configuration.IsBenched("github", "branchMustBeProtected") {
		return
	}
	cfg := pc.ControlsFor("github").BranchMustBeProtected
	if cfg == nil || !cfg.IsEnabled() {
		return
	}
	parts := strings.SplitN(projectPath, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return
	}
	branches, err := collector.FetchGitHubBranchProtection(host, parts[0], parts[1])
	if err != nil {
		l.WithError(err).Warn("GitHub branch-protection fetch failed; branchMustBeProtected will see zero branches")
		return
	}
	pipeline.Branches = branches

	// Resolve the repo's actual default branch so the rego rule's
	// `defaultMustBeProtected` clause matches against a real branch
	// name, not the (possibly empty) --branch CLI flag. Best-effort:
	// if the repo metadata fetch fails, keep whatever the caller
	// pre-populated (could be the --branch value or "").
	if pipeline.DefaultBranch == "" {
		if def, derr := collector.FetchGitHubDefaultBranch(host, parts[0], parts[1]); derr == nil && def != "" {
			pipeline.DefaultBranch = def
		}
	}
}

// RunGitHubAnalysis is the GitHub counterpart of RunAnalysis. It scans
// .github/workflows/*.{yml,yaml} under conf.GitRepoRoot, evaluates the
// embedded Rego policies against the resulting IR, and returns an
// AnalysisResult whose only populated fields are the project metadata
// and Findings. No legacy Go control fields are set — GitHub support is
// Rego-only by design (see docs/REFACTOR_MULTI_PROVIDER.md §4).
func RunGitHubAnalysis(conf *configuration.Configuration) (*AnalysisResult, error) {
	l := logrus.WithFields(logrus.Fields{
		"action":      "RunGitHubAnalysis",
		"projectPath": conf.ProjectPath,
		"gitRepoRoot": conf.GitRepoRoot,
	})
	l.Info("Starting GitHub Actions analysis")

	// Forward conf.ProgressFunc to the collector so the analyze-
	// command spinner animates during the slow GitHub API enrichment
	// phase. The collector's progress contract is ProgressFunc(step,
	// total, message); we map directly onto the same-shape callback
	// conf exposes.
	var progressFn collector.ProgressFunc
	if conf.ProgressFunc != nil {
		progressFn = collector.ProgressFunc(conf.ProgressFunc)
	}
	pipeline, partial, err := collector.ScanGitHubWorkflowsWithProgress(
		conf.ProjectPath,
		conf.Branch,
		conf.GitRepoRoot,
		conf.GithubAPIHost,
		configuration.ProviderNeedsActionMetadata("github"),
		progressFn,
	)
	if err != nil {
		l.WithError(err).Error("Failed to scan GitHub workflows")
		return nil, err
	}
	for _, perr := range partial {
		l.WithError(perr).Warn("GitHub workflow parse: partial failure (file skipped)")
	}

	enrichGitHubBranches(l, pipeline, conf.GithubAPIHost, conf.PlumberConfig, conf.ProjectPath)

	if conf.ProgressFunc != nil {
		total := collector.TotalProgressStepsForPipeline(pipeline)
		conf.ProgressFunc(total-1, total, "Evaluating policies")
	}
	result := &AnalysisResult{
		ProjectPath:    conf.ProjectPath,
		DefaultBranch:  conf.Branch,
		CIConfigSource: "local",
		CiValid:        len(pipeline.Jobs) > 0,
		CiMissing:      len(pipeline.Jobs) == 0,
		Findings:       evaluatePolicies(l, conf.PlumberConfig, "github", pipeline),
		GitHubStats:    AggregateGitHubStats(pipeline, conf.PlumberConfig),
	}
	if conf.ProgressFunc != nil {
		total := collector.TotalProgressStepsForPipeline(pipeline)
		conf.ProgressFunc(total, total, "Analysis complete")
	}

	l.WithFields(logrus.Fields{
		"jobCount":     len(pipeline.Jobs),
		"findingCount": len(result.Findings),
	}).Info("GitHub Actions analysis completed")

	return result, nil
}

// RunGitHubAnalysisRemote is the upstream-fetch counterpart of
// RunGitHubAnalysis. Instead of walking conf.GitRepoRoot, it fetches
// `.github/workflows/*.{yml,yaml}` from the provided owner/repo via
// the GitHub Contents API and runs the same Rego pipeline against
// the resulting IR. Used by `plumber analyze --github-url X --project
// owner/repo` when the user does not have a local clone.
//
// Auth is mandatory in remote mode (GH_TOKEN / GH_ENTERPRISE_TOKEN
// / GITHUB_TOKEN / gh auth login) — without it the Contents API
// rate-limits aggressively and returns 403 on private repos. Repo-
// side artefacts that need a local checkout (Dockerfiles,
// dependabot.yml, SECURITY.md) are not collected; controls that
// depend on them simply produce no findings.
func RunGitHubAnalysisRemote(conf *configuration.Configuration, owner, repo, ref string) (*AnalysisResult, error) {
	l := logrus.WithFields(logrus.Fields{
		"action":      "RunGitHubAnalysisRemote",
		"projectPath": owner + "/" + repo,
		"ref":         ref,
		"host":        conf.GithubAPIHost,
	})
	l.Info("Starting GitHub Actions analysis (remote fetch)")

	var progressFn collector.ProgressFunc
	if conf.ProgressFunc != nil {
		progressFn = collector.ProgressFunc(conf.ProgressFunc)
	}
	pipeline, partial, err := collector.ScanGitHubWorkflowsRemote(
		conf.GithubAPIHost,
		owner, repo, ref,
		configuration.ProviderNeedsActionMetadata("github"),
		progressFn,
	)
	if err != nil {
		l.WithError(err).Error("Failed to fetch GitHub workflows")
		return nil, err
	}
	for _, perr := range partial {
		l.WithError(perr).Warn("GitHub workflow parse: partial failure (file skipped)")
	}

	enrichGitHubBranches(l, pipeline, conf.GithubAPIHost, conf.PlumberConfig, owner+"/"+repo)

	if conf.ProgressFunc != nil {
		total := collector.TotalProgressStepsForPipeline(pipeline)
		conf.ProgressFunc(total-1, total, "Evaluating policies")
	}
	result := &AnalysisResult{
		ProjectPath:    owner + "/" + repo,
		DefaultBranch:  ref,
		CIConfigSource: "remote",
		CiValid:        len(pipeline.Jobs) > 0,
		CiMissing:      len(pipeline.Jobs) == 0,
		Findings:       evaluatePolicies(l, conf.PlumberConfig, "github", pipeline),
		GitHubStats:    AggregateGitHubStats(pipeline, conf.PlumberConfig),
	}
	if conf.ProgressFunc != nil {
		total := collector.TotalProgressStepsForPipeline(pipeline)
		conf.ProgressFunc(total, total, "Analysis complete")
	}

	l.WithFields(logrus.Fields{
		"jobCount":     len(pipeline.Jobs),
		"findingCount": len(result.Findings),
	}).Info("GitHub Actions analysis completed (remote fetch)")

	return result, nil
}
