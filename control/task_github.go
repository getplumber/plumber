package control

import (
	"errors"
	"strings"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/utils"
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
func enrichGitHubBranches(l *logrus.Entry, pipeline *ir.NormalizedPipeline, host string, pc *configuration.PlumberConfig, projectPath string, onProgress func(message string)) {
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

	// Resolve the repo's actual default branch FIRST: the targeted
	// fetch list below needs the real default-branch name to know
	// what to ask for. Best-effort: if the repo metadata fetch fails
	// we keep whatever the caller pre-populated (the --branch flag
	// or empty), and the targeted-fetch loop simply skips an empty
	// name.
	if pipeline.DefaultBranch == "" {
		if def, derr := collector.FetchGitHubDefaultBranch(host, parts[0], parts[1]); derr == nil && def != "" {
			pipeline.DefaultBranch = def
		}
	}

	// Build the targeted-fetch set from non-glob patterns plus the
	// default branch (when defaultMustBeProtected is on). Wildcard
	// patterns trip the listing fallthrough; on a typical config —
	// `main`, `master`, `default` — we never list at all.
	exact := make([]string, 0, len(cfg.NamePatterns)+1)
	listing := false
	for _, p := range cfg.NamePatterns {
		if isBranchGlob(p) {
			listing = true
			continue
		}
		if p != "" {
			exact = append(exact, p)
		}
	}
	if cfg.DefaultMustBeProtected != nil && *cfg.DefaultMustBeProtected && pipeline.DefaultBranch != "" {
		exact = append(exact, pipeline.DefaultBranch)
	}

	// Predicate used by the collector to skip protection-detail
	// fetches on branches the user did not ask about. Same scope
	// rule as branch_non_compliant.rego: a branch is in scope when
	// it matches any namePattern, or when it equals the repo's
	// default branch and defaultMustBeProtected is on. Patterns use
	// the same simple-glob shape as elsewhere (exact match or a
	// trailing `/*` directory suffix); anything more elaborate
	// falls through to false, and we just pay for that one branch.
	defaultRequired := cfg.DefaultMustBeProtected != nil && *cfg.DefaultMustBeProtected
	inScope := func(name string) bool {
		for _, p := range cfg.NamePatterns {
			if p == name {
				return true
			}
			if strings.HasSuffix(p, "/*") && strings.HasPrefix(name, strings.TrimSuffix(p, "/*")+"/") {
				return true
			}
		}
		if defaultRequired && pipeline.DefaultBranch != "" && name == pipeline.DefaultBranch {
			return true
		}
		return false
	}

	branches, err := collector.FetchGitHubBranchProtection(host, parts[0], parts[1], collector.BranchFetchOptions{
		ExactNames: exact,
		Listing:    listing,
		OnProgress: onProgress,
		InScope:    inScope,
	})
	if err != nil {
		l.WithError(err).Warn("GitHub branch-protection fetch failed; branchMustBeProtected will see zero branches")
		return
	}
	pipeline.Branches = branches
}

// isBranchGlob reports whether a branch-name pattern contains the
// wildcard characters glob.match treats as special. Keeps the call
// site free of a regexp dependency for a 3-character check.
func isBranchGlob(p string) bool {
	return strings.ContainsAny(p, "*?[")
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

	if shouldRunControl(controlBranchMustBeProtected, conf) {
		total := collector.TotalProgressStepsForPipeline(pipeline)
		if conf.ProgressFunc != nil {
			conf.ProgressFunc(total-2, total, "Resolving branch protection")
		}
		var onProgress func(string)
		if conf.ProgressFunc != nil {
			onProgress = func(message string) {
				// Re-emit at the same slot, just update the label.
				// The spinner re-renders the bar with the new text
				// so the user sees pagination/per-branch ticks live.
				conf.ProgressFunc(total-2, total, message)
			}
		}
		enrichGitHubBranches(l, pipeline, conf.GithubAPIHost, conf.PlumberConfig, conf.ProjectPath, onProgress)
	}

	if conf.ProgressFunc != nil {
		total := collector.TotalProgressStepsForPipeline(pipeline)
		conf.ProgressFunc(total-1, total, "Evaluating policies")
	}
	defaultBranch := conf.Branch
	if defaultBranch == "" {
		defaultBranch = pipeline.DefaultBranch
	}
	result := &AnalysisResult{
		ProjectPath:    conf.ProjectPath,
		DefaultBranch:  defaultBranch,
		AnalyzeBranch:  conf.Branch,
		CIConfigSource: "local",
		CiValid:        len(pipeline.Jobs) > 0,
		CiMissing:      len(pipeline.Jobs) == 0,
		Findings:       evaluatePolicies(l, conf, "github", pipeline),
		GitHubStats:    AggregateGitHubStats(pipeline, conf.PlumberConfig),
		GitHubPipeline: pipeline,
	}
	// Resolve the local clone's HEAD SHA so source links in the report
	// point at the exact commit being analysed instead of a mutable
	// branch name. CI runs already get the SHA from GITHUB_SHA; this
	// covers the developer-laptop case where `plumber analyze` runs
	// against a working tree on whatever branch they checked out.
	if conf.IsLocalProject && conf.GitRepoRoot != "" {
		result.HeadCommitSha = utils.DetectGitHeadSHA(conf.GitRepoRoot)
	}
	ApplyGitHubFindingCounts(result.GitHubStats, result.Findings)
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
		// ErrAuthRequired carries the actionable user-facing message;
		// a logrus.Error here would print it once through the structured
		// log formatter (newlines escaped, key=value frame around it),
		// then cobra prints it again cleanly. One copy is enough.
		if !errors.Is(err, collector.ErrAuthRequired) {
			l.WithError(err).Error("Failed to fetch GitHub workflows")
		}
		return nil, err
	}
	for _, perr := range partial {
		l.WithError(perr).Warn("GitHub workflow parse: partial failure (file skipped)")
	}

	if shouldRunControl(controlBranchMustBeProtected, conf) {
		total := collector.TotalProgressStepsForPipeline(pipeline)
		if conf.ProgressFunc != nil {
			conf.ProgressFunc(total-2, total, "Resolving branch protection")
		}
		var onProgress func(string)
		if conf.ProgressFunc != nil {
			onProgress = func(message string) {
				conf.ProgressFunc(total-2, total, message)
			}
		}
		enrichGitHubBranches(l, pipeline, conf.GithubAPIHost, conf.PlumberConfig, owner+"/"+repo, onProgress)
	}

	if conf.ProgressFunc != nil {
		total := collector.TotalProgressStepsForPipeline(pipeline)
		conf.ProgressFunc(total-1, total, "Evaluating policies")
	}
	defaultBranch := ref
	if defaultBranch == "" {
		defaultBranch = pipeline.DefaultBranch
	}
	result := &AnalysisResult{
		ProjectPath:    owner + "/" + repo,
		DefaultBranch:  defaultBranch,
		AnalyzeBranch:  ref,
		CIConfigSource: "remote",
		CiValid:        len(pipeline.Jobs) > 0,
		CiMissing:      len(pipeline.Jobs) == 0,
		Findings:       evaluatePolicies(l, conf, "github", pipeline),
		GitHubStats:    AggregateGitHubStats(pipeline, conf.PlumberConfig),
		GitHubPipeline: pipeline,
	}
	ApplyGitHubFindingCounts(result.GitHubStats, result.Findings)
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
