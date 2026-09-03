package control

import (
	"errors"
	"os"
	"strings"

	"github.com/getplumber/plumber/configuration"
	githubpkg "github.com/getplumber/plumber/github"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/utils"
	"github.com/sirupsen/logrus"
)

// fetchGitHubDefaultBranch is a test seam over the repo-metadata lookup.
// The default honors PLUMBER_DISABLE_GITHUB_API (same contract as the
// metadata client) so offline test suites never hit the network.
var fetchGitHubDefaultBranch = func(host, owner, repo string) (string, error) {
	if v := os.Getenv(githubpkg.EnvDisableGitHubAPI); v == "1" || v == "true" {
		return "", nil
	}
	return githubpkg.FetchGitHubDefaultBranch(host, owner, repo)
}

// scanGitHubWorkflowsRemote is a test seam over the remote workflow fetch,
// which otherwise needs network and auth.
var scanGitHubWorkflowsRemote = githubpkg.ScanGitHubWorkflowsRemote

// resolveGitHubDefaultBranch overwrites pipeline.DefaultBranch with the
// forge's answer. The scan seeds the field with the branch being ANALYZED
// (the --branch flag locally, the fetched ref remotely), which is only a
// stand-in: the seed is kept when the lookup degrades (no auth, API down),
// never preferred. This runs
// regardless of which controls are enabled: the score service only updates
// the public badge when the pushed report's defaultBranch matches the
// OIDC-attested branch, so a missing value silently strands every push on
// a per-branch record.
func resolveGitHubDefaultBranch(l *logrus.Entry, pipeline *ir.NormalizedPipeline, host, projectPath string) {
	if pipeline == nil {
		return
	}
	parts := strings.SplitN(projectPath, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return
	}
	def, err := fetchGitHubDefaultBranch(host, parts[0], parts[1])
	if err != nil {
		l.WithError(err).Debug("default-branch lookup failed; keeping the analyze-branch stand-in")
		return
	}
	if def != "" {
		pipeline.DefaultBranch = def
	}
}

// enrichGitHubBranches populates pipeline.Branches via the GitHub
// REST API when the user has enabled the branchMustBeProtected
// control AND that control is currently shipping (not benched) on
// GitHub. Silently skipped when the control is disabled in
// .plumber.yaml, when it is benched in code, or when projectPath
// isn't owner/repo shaped. Lacking auth or scope, the collector
// returns an empty slice and the rego rule emits no findings — the
// same degraded-mode contract as the action-metadata enrichment.
// Returns true when the protection fetch failed outright (network,
// rate-limit, lost connectivity) and the pipeline was left with zero
// branches, so the caller can flag the run degraded and route
// branchMustBeProtected to "not evaluated" rather than a vacuous 100%
// green (#220). Returns false when the control is disabled/benched/out
// of scope (nothing to fetch) or the fetch succeeded.
func enrichGitHubBranches(l *logrus.Entry, pipeline *ir.NormalizedPipeline, host string, pc *configuration.PlumberConfig, projectPath string, onProgress func(message string)) (fetchFailed bool) {
	if pipeline == nil || pc == nil {
		return false
	}
	if configuration.IsBenched("github", "branchMustBeProtected") {
		return false
	}
	cfg := pc.ControlsFor("github").BranchMustBeProtected
	if cfg == nil || !cfg.IsEnabled() {
		return false
	}
	parts := strings.SplitN(projectPath, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}

	// pipeline.DefaultBranch is resolved by the caller (see
	// resolveGitHubDefaultBranch) before this runs; the targeted-fetch
	// loop simply skips an empty name when that lookup degraded. An
	// invisible repo is not detectable from that lookup either
	// (FetchGitHubDefaultBranch folds 404/401 into a silent empty success
	// by contract), so the zero-branch probe below owns that case.

	// Build the targeted-fetch set from non-glob patterns plus the
	// default branch (when defaultMustBeProtected is on). Wildcard
	// patterns trip the listing fallthrough; on a typical config —
	// `main`, `master`, `default` — we never list at all.
	exact := make([]string, 0, len(cfg.NamePatterns))
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

	branches, err := githubpkg.FetchGitHubBranchProtection(host, parts[0], parts[1], githubpkg.BranchFetchOptions{
		ExactNames: exact,
		Listing:    listing,
		OnProgress: onProgress,
		InScope:    inScope,
	})
	if err != nil {
		l.WithError(err).Warn("GitHub branch-protection fetch failed; branchMustBeProtected will see zero branches")
		return true
	}
	if len(branches) == 0 {
		// Zero branches is ambiguous: legitimately nothing in scope, or
		// a repo that is nonexistent, renamed, or invisible to the
		// token, whose per-branch lookups all 404-swallowed (the fetch
		// correctly treats a 404 as "branch absent" for a real repo).
		// Disambiguate with the visibility probe: every visible GitHub
		// repo answers its metadata endpoint. Without this, an
		// invisible repo reads as a vacuous branch-protection pass
		// (caught empirically: a scan against an unreachable remote
		// reported branchMustBeProtected as passed).
		visible, derr := githubpkg.GitHubRepoVisible(host, parts[0], parts[1])
		if derr != nil {
			l.WithError(derr).Warn("GitHub repo visibility probe failed with zero branches fetched; branch protection cannot be evaluated")
			return true
		}
		if !visible {
			l.Warn("GitHub repo is not visible with the current credentials (nonexistent, renamed, or unauthorized); branch protection cannot be evaluated")
			return true
		}
	}
	pipeline.Branches = branches
	return false
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
// Rego-only by design.
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
	var progressFn githubpkg.ProgressFunc
	if conf.ProgressFunc != nil {
		progressFn = githubpkg.ProgressFunc(conf.ProgressFunc)
	}
	pipeline, partial, err := githubpkg.ScanGitHubWorkflowsWithProgress(
		conf.ProjectPath,
		conf.Branch,
		conf.GitRepoRoot,
		conf.GithubAPIHost,
		configuration.ProviderNeedsActionMetadata("github"),
		shouldScanMutableExec(conf),
		progressFn,
	)
	if err != nil {
		l.WithError(err).Error("Failed to scan GitHub workflows")
		return nil, err
	}
	for _, perr := range partial {
		l.WithError(perr).Warn("GitHub workflow parse: partial failure (file skipped)")
	}

	resolveGitHubDefaultBranch(l, pipeline, conf.GithubAPIHost, conf.ProjectPath)

	branchFetchFailed := false
	if shouldRunControl(controlBranchMustBeProtected, conf) {
		total := githubpkg.TotalProgressStepsForPipeline(pipeline)
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
		branchFetchFailed = enrichGitHubBranches(l, pipeline, conf.GithubAPIHost, conf.PlumberConfig, conf.ProjectPath, onProgress)
	}

	if conf.ProgressFunc != nil {
		total := githubpkg.TotalProgressStepsForPipeline(pipeline)
		conf.ProgressFunc(total-1, total, "Evaluating policies")
	}
	// The forge-resolved default branch is authoritative; conf.Branch is
	// the branch being ANALYZED and only stands in when the lookup degraded.
	defaultBranch := pipeline.DefaultBranch
	if defaultBranch == "" {
		defaultBranch = conf.Branch
	}
	result := &AnalysisResult{
		ProjectPath:      conf.ProjectPath,
		DefaultBranch:    defaultBranch,
		AnalyzeBranch:    conf.Branch,
		CIConfigSource:   "local",
		CiValid:          len(pipeline.Jobs) > 0,
		CiMissing:        len(pipeline.Jobs) == 0,
		Findings:         evaluatePolicies(l, conf, "github", pipeline),
		GitHubStats:      AggregateGitHubStats(pipeline, conf.PlumberConfig),
		GitHubPipeline:   pipeline,
		AnalyzedCIConfig: githubAnalyzedCIConfig(pipeline),
		Warnings:         pipeline.AdvisoryWarnings,
	}
	// Local scans read workflow files from disk, so a skipped file is a
	// parse/read problem (user-fixable), not a degraded collection — only
	// a failed branch-protection API fetch counts as degraded here (#220).
	applyGitHubDegraded(result, 0, branchFetchFailed)
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
		total := githubpkg.TotalProgressStepsForPipeline(pipeline)
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

	var progressFn githubpkg.ProgressFunc
	if conf.ProgressFunc != nil {
		progressFn = githubpkg.ProgressFunc(conf.ProgressFunc)
	}
	pipeline, partial, err := scanGitHubWorkflowsRemote(
		conf.GithubAPIHost,
		owner, repo, ref,
		configuration.ProviderNeedsActionMetadata("github"),
		shouldScanMutableExec(conf),
		progressFn,
	)
	if err != nil {
		// ErrAuthRequired carries the actionable user-facing message;
		// a logrus.Error here would print it once through the structured
		// log formatter (newlines escaped, key=value frame around it),
		// then cobra prints it again cleanly. One copy is enough.
		if !errors.Is(err, githubpkg.ErrAuthRequired) {
			l.WithError(err).Error("Failed to fetch GitHub workflows")
		}
		return nil, err
	}
	for _, perr := range partial {
		l.WithError(perr).Warn("GitHub workflow parse: partial failure (file skipped)")
	}

	resolveGitHubDefaultBranch(l, pipeline, conf.GithubAPIHost, owner+"/"+repo)

	branchFetchFailed := false
	if shouldRunControl(controlBranchMustBeProtected, conf) {
		total := githubpkg.TotalProgressStepsForPipeline(pipeline)
		if conf.ProgressFunc != nil {
			conf.ProgressFunc(total-2, total, "Resolving branch protection")
		}
		var onProgress func(string)
		if conf.ProgressFunc != nil {
			onProgress = func(message string) {
				conf.ProgressFunc(total-2, total, message)
			}
		}
		branchFetchFailed = enrichGitHubBranches(l, pipeline, conf.GithubAPIHost, conf.PlumberConfig, owner+"/"+repo, onProgress)
	}

	if conf.ProgressFunc != nil {
		total := githubpkg.TotalProgressStepsForPipeline(pipeline)
		conf.ProgressFunc(total-1, total, "Evaluating policies")
	}
	// Same precedence as the local path: the forge-resolved default branch
	// wins; ref is the analyzed ref and only stands in when the lookup
	// degraded.
	defaultBranch := pipeline.DefaultBranch
	if defaultBranch == "" {
		defaultBranch = ref
	}
	result := &AnalysisResult{
		ProjectPath:      owner + "/" + repo,
		DefaultBranch:    defaultBranch,
		AnalyzeBranch:    ref,
		CIConfigSource:   "remote",
		CiValid:          len(pipeline.Jobs) > 0,
		CiMissing:        len(pipeline.Jobs) == 0,
		Findings:         evaluatePolicies(l, conf, "github", pipeline),
		GitHubStats:      AggregateGitHubStats(pipeline, conf.PlumberConfig),
		GitHubPipeline:   pipeline,
		AnalyzedCIConfig: githubAnalyzedCIConfig(pipeline),
		Warnings:         pipeline.AdvisoryWarnings,
	}
	applyGitHubDegraded(result, len(partial), branchFetchFailed)
	ApplyGitHubFindingCounts(result.GitHubStats, result.Findings)
	if conf.ProgressFunc != nil {
		total := githubpkg.TotalProgressStepsForPipeline(pipeline)
		conf.ProgressFunc(total, total, "Analysis complete")
	}

	l.WithFields(logrus.Fields{
		"jobCount":     len(pipeline.Jobs),
		"findingCount": len(result.Findings),
	}).Info("GitHub Actions analysis completed (remote fetch)")

	return result, nil
}

// githubAnalyzedCIConfig projects the scanned workflow files onto the JSON
// report's analyzed-CI-config block (#443). Nil when no workflow file was
// read, so the field is omitted rather than emitted empty.
func githubAnalyzedCIConfig(pipeline *ir.NormalizedPipeline) *AnalyzedCIConfig {
	if pipeline == nil || len(pipeline.AnalyzedWorkflows) == 0 {
		return nil
	}
	out := &AnalyzedCIConfig{Workflows: make([]AnalyzedWorkflowFile, 0, len(pipeline.AnalyzedWorkflows))}
	for _, w := range pipeline.AnalyzedWorkflows {
		out.Workflows = append(out.Workflows, AnalyzedWorkflowFile{Path: w.Path, Content: w.Content})
	}
	return out
}

// gitlabAnalyzedCIConfig records the resolved GitLab merged pipeline as the
// report's analyzedCiConfig block (#443), or nil when no merged YAML resolved
// so the field is omitted. Symmetric with githubAnalyzedCIConfig, JSON-report
// only.
func gitlabAnalyzedCIConfig(ciConfPath, mergedYaml string) *AnalyzedCIConfig {
	if mergedYaml == "" {
		return nil
	}
	return &AnalyzedCIConfig{Path: ciConfPath, Content: mergedYaml, Merged: true}
}
