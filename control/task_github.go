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

// fetchGitHubEnvironments is a test seam over the environments lookup.
// The default honors PLUMBER_DISABLE_GITHUB_API (same contract as
// fetchGitHubDefaultBranch above) so offline test suites never hit the
// network.
var fetchGitHubEnvironments = func(host, owner, repo string) ([]ir.Environment, bool, error) {
	if v := os.Getenv(githubpkg.EnvDisableGitHubAPI); v == "1" || v == "true" {
		return nil, false, nil
	}
	return githubpkg.FetchGitHubEnvironments(host, owner, repo)
}

// fetchGitHubWorkflowStates is a test seam over the workflow-states
// lookup. The default honors PLUMBER_DISABLE_GITHUB_API (same contract
// as fetchGitHubDefaultBranch above) so offline test suites never hit
// the network.
var fetchGitHubWorkflowStates = func(host, owner, repo string) (map[string]string, bool, error) {
	if v := os.Getenv(githubpkg.EnvDisableGitHubAPI); v == "1" || v == "true" {
		return nil, false, nil
	}
	return githubpkg.FetchGitHubWorkflowStates(host, owner, repo)
}

// fetchGitHubDefaultTokenWrite is a test seam over the repository
// default-token lookup. The default honors PLUMBER_DISABLE_GITHUB_API
// (same contract as fetchGitHubDefaultBranch above) so offline test
// suites never hit the network; disabled and unreachable both
// degrade to "unknown"/"unknown", FetchGitHubDefaultTokenWrite's own
// contract.
var fetchGitHubDefaultTokenWrite = func(host, owner, repo, defaultBranch string, declaresContentsWrite bool, eligible func(string) bool) (write, source string) {
	if v := os.Getenv(githubpkg.EnvDisableGitHubAPI); v == "1" || v == "true" {
		return "unknown", "unknown"
	}
	return githubpkg.FetchGitHubDefaultTokenWrite(host, owner, repo, defaultBranch, declaresContentsWrite, eligible)
}

// fetchGitHubVisibility is a test seam over the repo-visibility lookup.
// The default honors PLUMBER_DISABLE_GITHUB_API (same contract as
// fetchGitHubDefaultBranch above) so offline test suites never hit the
// network. FetchGitHubRepoIdentity never errors, so disabled and
// unreachable both degrade straight to unknown and no canonical name.
// The same lookup answers the repository's canonical owner/repo.
var fetchGitHubVisibility = func(host, owner, repo string) (visibility, fullName string) {
	if v := os.Getenv(githubpkg.EnvDisableGitHubAPI); v == "1" || v == "true" {
		return ir.VisibilityUnknown, ""
	}
	return githubpkg.FetchGitHubRepoIdentity(host, owner, repo)
}

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

// applyGitHubVisibility records the repository's exposure on the
// pipeline. Without an owner/repo there is nothing to ask, and the
// answer is unknown rather than a lookup on a malformed path.
//
// The same lookup gives the repository's canonical owner/repo (the API
// follows renames and answers the current case), recorded as the
// pipeline's projectPath, which the policies read to tell the
// repository's own references from third-party ones. Only the policy
// input changes: the report keeps the path it was given, and a lookup
// with no answer keeps it on the pipeline too.
func applyGitHubVisibility(pipeline *ir.NormalizedPipeline, host, projectPath string) {
	owner, repo, ok := strings.Cut(projectPath, "/")
	if !ok || owner == "" || repo == "" {
		pipeline.Visibility = ir.VisibilityUnknown
		return
	}
	visibility, fullName := fetchGitHubVisibility(host, owner, repo)
	pipeline.Visibility = visibility
	if fullName != "" {
		pipeline.ProjectPath = fullName
	}
}

// enrichGitHubEnvironments populates pipeline.Environments and
// pipeline.EnvironmentsKnown via the GitHub REST API. Unlike
// enrichGitHubBranches this has no control toggle and always runs for
// GitHub: the situation facts read it for every job carrying an
// `environment:`, whatever controls are configured. A 401/403/404 or
// network failure degrades to EnvironmentsKnown=false silently (the
// situation fact then stays "unknown" and a claim resting on it is
// capped, never a reason to flag the run degraded, same contract as
// an optional fact elsewhere). Any other failure is logged at Warn,
// still without flagging the run degraded.
func enrichGitHubEnvironments(l *logrus.Entry, pipeline *ir.NormalizedPipeline, host, owner, repo string) {
	if pipeline == nil || owner == "" || repo == "" {
		return
	}
	envs, known, err := fetchGitHubEnvironments(host, owner, repo)
	if !known && err != nil {
		l.WithError(err).Warn("GitHub environments fetch failed; environment reviewer facts stay unknown")
	}
	pipeline.Environments = envs
	pipeline.EnvironmentsKnown = known
}

// enrichGitHubWorkflowStates populates pipeline.WorkflowStates,
// pipeline.WorkflowStatesKnown and the derived pipeline.ActionsDisabled
// via the GitHub REST API. Same contract as enrichGitHubEnvironments: no
// control toggle, always runs for GitHub (MarkInert reads it for every
// job, whatever controls are configured). A 401/403/404 or network
// failure degrades to WorkflowStatesKnown=false silently: MarkInert then
// has nothing to mark a job inert for from this lane, never a reason to
// flag the run degraded, same contract as an optional fact elsewhere.
func enrichGitHubWorkflowStates(l *logrus.Entry, pipeline *ir.NormalizedPipeline, host, owner, repo string) {
	if pipeline == nil || owner == "" || repo == "" {
		return
	}
	states, known, err := fetchGitHubWorkflowStates(host, owner, repo)
	if !known && err != nil {
		l.WithError(err).Warn("GitHub workflow states fetch failed; workflow-disabled facts stay unknown")
	}
	pipeline.WorkflowStates = states
	pipeline.WorkflowStatesKnown = known
	pipeline.ActionsDisabled = actionsDisabled(states, known)
}

// actionsDisabled derives pipeline.ActionsDisabled from the workflow
// states lane: true when the listing is known, names at least one
// workflow, and every one of them is disabled_manually or
// disabled_inactivity. A known but empty listing is never disabled on
// its own, whatever the pipeline parsed off disk: the workflows endpoint
// only lists what is registered on the default branch, so a workflow
// added on a feature branch would otherwise misread as Actions being
// off. For the same reason ir.MarkInert reads the flag only for a job
// whose workflow the listing names: one absent from it keeps running.
func actionsDisabled(states map[string]string, known bool) bool {
	if !known || len(states) == 0 {
		// The workflows-listing endpoint only lists workflows registered
		// on the repository's default branch: an empty, known list is
		// also what a repository answers when its workflow file was
		// only just added on a feature branch, or has none of its own
		// yet, neither of which means Actions is disabled. Without a
		// separate "Actions enabled" signal from the API, an empty list
		// is never enough evidence on its own, whatever the pipeline
		// itself parsed off disk.
		return false
	}
	for _, state := range states {
		if state != "disabled_manually" && state != "disabled_inactivity" {
			return false
		}
	}
	return true
}

// enrichGitHubDefaultToken populates pipeline.DefaultTokenWrite and
// pipeline.DefaultTokenSource via the GitHub REST API: the
// repository's real default GITHUB_TOKEN write, read from a run's own
// "GITHUB_TOKEN Permissions" log block or proved from a
// github-actions[bot]-authored write, never assumed. Same contract as
// enrichGitHubEnvironments/enrichGitHubWorkflowStates: no control
// toggle, always runs for GitHub, and FetchGitHubDefaultTokenWrite
// never errors, so there is nothing to log here either.
//
// The lane is skipped (no API call at all) when no job in the
// pipeline has nil Permissions: a workflow where every job declares
// its own permissions has nothing for the repository default to
// govern, and resolving it would answer a question nobody is asking.
func enrichGitHubDefaultToken(pipeline *ir.NormalizedPipeline, host, owner, repo string) {
	if pipeline == nil || owner == "" || repo == "" {
		return
	}
	if !hasEligibleDefaultTokenJob(pipeline) {
		return
	}
	eligible := func(workflowPath string) bool {
		return eligibleDefaultTokenWorkflow(pipeline, workflowPath)
	}
	write, source := fetchGitHubDefaultTokenWrite(
		host, owner, repo, pipeline.DefaultBranch,
		declaresDefaultTokenContentsWrite(pipeline), eligible,
	)
	// "unknown"/"unknown" is FetchGitHubDefaultTokenWrite's own way of
	// saying neither route decided it; the IR contract is that absent
	// (omitted) means unknown, so that case is left unset rather than
	// writing the literal string into the pipeline.
	if write == "true" || write == "false" {
		pipeline.DefaultTokenWrite = write
	}
	if source == "log" || source == "effect" {
		pipeline.DefaultTokenSource = source
	}
}

// declaresDefaultTokenContentsWrite reports whether some job of the
// pipeline already declares a contents write (an explicit
// "contents: write" entry, or the write-all shortcut): when one does,
// a release the repository's own bot identity authored is no longer
// safe evidence that the UNDECLARED default token can write too, only
// that some token in this repository can, so the effect route must be
// skipped rather than crediting the default with a write it was never
// shown to hold.
func declaresDefaultTokenContentsWrite(pipeline *ir.NormalizedPipeline) bool {
	for _, j := range pipeline.Jobs {
		switch perms := j.Permissions.(type) {
		case string:
			if perms == "write-all" {
				return true
			}
		case map[string]any:
			if level, _ := perms["contents"].(string); level == "write" {
				return true
			}
		case map[string]string:
			if perms["contents"] == "write" {
				return true
			}
		}
	}
	return false
}

// hasEligibleDefaultTokenJob reports whether at least one job of the
// pipeline has no declared permissions at all (its own, nor its
// workflow's, per ir.Job.Permissions' effective-permissions
// contract): the only jobs the repository's default token write
// governs. Gates enrichGitHubDefaultToken so a pipeline where every
// job declares its own permissions never spends an API call on a
// question nobody is asking.
func hasEligibleDefaultTokenJob(pipeline *ir.NormalizedPipeline) bool {
	for _, j := range pipeline.Jobs {
		if j.Permissions == nil {
			return true
		}
	}
	return false
}

// eligibleDefaultTokenWorkflow reports whether workflowPath (a
// repo-relative ".github/workflows/..." path, the form the runs and
// workflow-states listings both use) is one where EVERY job it
// carries has no declared permissions and calls no reusable workflow:
// ir.WorkflowStateKey normalizes job.OriginFile onto that same form,
// since the local scan's OriginFile is an absolute filesystem path
// rather than the repo-relative one the API speaks.
//
// Both conditions matter: a workflow is never eligible just because
// SOME job in it has nil Permissions, because the run the log route
// fetches is keyed by workflow, not by job, and GitHub always returns
// the run's first job (per_page=1) whichever one that happens to be.
// A sibling job that declares its own permissions would have its
// declaration misread as the repository default; a job that calls a
// reusable workflow (ReusableWorkflowUses set) runs with the called
// job's own effective permissions, never the calling workflow's
// default, so its presence disqualifies the workflow the same way.
func eligibleDefaultTokenWorkflow(pipeline *ir.NormalizedPipeline, workflowPath string) bool {
	matched := false
	for _, j := range pipeline.Jobs {
		if ir.WorkflowStateKey(j.OriginFile) != workflowPath {
			continue
		}
		matched = true
		if j.Permissions != nil || j.ReusableWorkflowUses != "" {
			return false
		}
	}
	return matched
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
	owner, repo, addressable := gitHubOwnerRepo(projectPath)
	if !addressable {
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

	branches, err := githubpkg.FetchGitHubBranchProtection(host, owner, repo, githubpkg.BranchFetchOptions{
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
		visible, derr := githubpkg.GitHubRepoVisible(host, owner, repo)
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

// gitHubOwnerRepo splits an owner/repo project path, reporting ok=false for
// anything else (empty, single-segment, or either half empty).
//
// One definition, because two places have to agree on what counts as
// fetchable: enrichGitHubBranches returns early on a path it cannot address,
// and the lane record (branchLaneCollected) has to return early on exactly
// the same paths, or the run would claim it collected branch protections
// when no request was ever made.
func gitHubOwnerRepo(projectPath string) (owner, repo string, ok bool) {
	parts := strings.SplitN(projectPath, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
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
	// In platform mode the decision to fetch is the union of the resolved
	// policies' configurations, not this run's own file (row 62). Computed
	// once and reused for the lane record below.
	scanMutableExec := anyCollectionConfig(conf, shouldScanMutableExec)
	pipeline, partial, err := githubpkg.ScanGitHubWorkflowsWithProgress(
		conf.ProjectPath,
		conf.Branch,
		conf.GitRepoRoot,
		conf.GithubAPIHost,
		configuration.ProviderNeedsActionMetadata("github"),
		scanMutableExec,
		progressFn,
	)
	if err != nil {
		l.WithError(err).Error("Failed to scan GitHub workflows")
		return nil, err
	}
	for _, perr := range partial {
		l.WithError(perr).Warn("GitHub workflow parse: partial failure (file skipped)")
	}
	for _, inv := range pipeline.InvalidWorkflows {
		l.WithField("file", inv.Path).Warn("GitHub workflow is not valid, reported as ISSUE-423")
	}

	resolveGitHubDefaultBranch(l, pipeline, conf.GithubAPIHost, conf.ProjectPath)
	applyGitHubVisibility(pipeline, conf.GithubAPIHost, conf.ProjectPath)
	if owner, repo, addressable := gitHubOwnerRepo(conf.ProjectPath); addressable {
		enrichGitHubEnvironments(l, pipeline, conf.GithubAPIHost, owner, repo)
		enrichGitHubWorkflowStates(l, pipeline, conf.GithubAPIHost, owner, repo)
		enrichGitHubDefaultToken(pipeline, conf.GithubAPIHost, owner, repo)
	}

	// The union of every collecting configuration's branchMustBeProtected
	// scope, so one fetch covers every policy's branches (row 62).
	branchScope := collectionBranchProtectionConfig(conf)
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
		branchFetchFailed = enrichGitHubBranches(l, pipeline, conf.GithubAPIHost, branchScope, conf.ProjectPath, onProgress)
	}

	// After every enrichment lane above (environments, workflow states,
	// branches) and before the situation facts are evaluated below: a job
	// MarkInert finds cannot run at all must read as inert everywhere
	// downstream, policy findings and the attack-path situation alike.
	ir.MarkInert(pipeline)
	// Who can make each privileged job run (ir.Job.Gate), read by the
	// policies and the situation alike, once the environments are known.
	ir.ClassifyGates(pipeline)

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
	findings, policyFailures := evaluatePolicies(l, conf, "github", pipeline)
	result := &AnalysisResult{
		ProjectPath:       conf.ProjectPath,
		DefaultBranch:     defaultBranch,
		AnalyzeBranch:     conf.Branch,
		CIConfigSource:    "local",
		CiValid:           len(pipeline.Jobs) > 0,
		CiMissing:         len(pipeline.Jobs) == 0,
		Findings:          findings,
		GitHubStats:       AggregateGitHubStats(pipeline, conf.PlumberConfig),
		GitHubPipeline:    pipeline,
		AnalyzedCIConfig:  githubAnalyzedCIConfig(pipeline),
		Warnings:          pipeline.AdvisoryWarnings,
		UnexpandedActions: pipeline.UnexpandedActions,
	}
	applyPolicyFailures(result, policyFailures)
	attachSituation(l, conf, "github", pipeline, result)
	markGitHubLanes(result, conf, conf.ProjectPath, scanMutableExec, branchScope)
	// Local scans read workflow files from disk, so a skipped file is a
	// parse/read problem (user-fixable), not a degraded collection — only
	// a failed branch-protection API fetch counts as degraded here (#220).
	applyGitHubDegraded(result, 0, branchFetchFailed)
	applyNestedActions(result, pipeline)
	// Resolve the local clone's HEAD SHA so source links in the report
	// point at the exact commit being analysed instead of a mutable
	// branch name. CI runs already get the SHA from GITHUB_SHA; this
	// covers the developer-laptop case where `plumber analyze` runs
	// against a working tree on whatever branch they checked out.
	if conf.IsLocalProject && conf.GitRepoRoot != "" {
		result.HeadCommitSha = utils.DetectGitHeadSHA(conf.GitRepoRoot)
	}
	// An enabled control asserting nothing until its substantive fields are set is not a clean
	// pass either (#459): it is not_evaluable, config_required, same as any other lane gap. Runs
	// before the finding-count aggregation below so a dropped not_evaluable finding never inflates
	// the report's stats, matching the GitLab task's mark-before-assembly ordering.
	MarkUnconfiguredControls(result, GitHubControls(conf.PlumberConfig), conf.PlumberConfig, configuration.ProviderGitHub)
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
	// Same union as the local path: a control any resolved policy enables
	// needs its data collected (row 62).
	scanMutableExec := anyCollectionConfig(conf, shouldScanMutableExec)
	pipeline, partial, err := scanGitHubWorkflowsRemote(
		conf.GithubAPIHost,
		owner, repo, ref,
		configuration.ProviderNeedsActionMetadata("github"),
		scanMutableExec,
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
	for _, inv := range pipeline.InvalidWorkflows {
		l.WithField("file", inv.Path).Warn("GitHub workflow is not valid, reported as ISSUE-423")
	}
	applyGitHubVisibility(pipeline, conf.GithubAPIHost, owner+"/"+repo)

	resolveGitHubDefaultBranch(l, pipeline, conf.GithubAPIHost, owner+"/"+repo)
	enrichGitHubEnvironments(l, pipeline, conf.GithubAPIHost, owner, repo)
	enrichGitHubWorkflowStates(l, pipeline, conf.GithubAPIHost, owner, repo)
	enrichGitHubDefaultToken(pipeline, conf.GithubAPIHost, owner, repo)

	branchScope := collectionBranchProtectionConfig(conf)
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
		branchFetchFailed = enrichGitHubBranches(l, pipeline, conf.GithubAPIHost, branchScope, owner+"/"+repo, onProgress)
	}

	// Same ordering as the local path: after every enrichment lane, before
	// the situation facts are evaluated below.
	ir.MarkInert(pipeline)
	// Who can make each privileged job run (ir.Job.Gate), read by the
	// policies and the situation alike, once the environments are known.
	ir.ClassifyGates(pipeline)

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
	findings, policyFailures := evaluatePolicies(l, conf, "github", pipeline)
	result := &AnalysisResult{
		ProjectPath:       owner + "/" + repo,
		DefaultBranch:     defaultBranch,
		AnalyzeBranch:     ref,
		CIConfigSource:    "remote",
		CiValid:           len(pipeline.Jobs) > 0,
		CiMissing:         len(pipeline.Jobs) == 0,
		Findings:          findings,
		GitHubStats:       AggregateGitHubStats(pipeline, conf.PlumberConfig),
		GitHubPipeline:    pipeline,
		AnalyzedCIConfig:  githubAnalyzedCIConfig(pipeline),
		Warnings:          pipeline.AdvisoryWarnings,
		UnexpandedActions: pipeline.UnexpandedActions,
	}
	applyPolicyFailures(result, policyFailures)
	attachSituation(l, conf, "github", pipeline, result)
	markGitHubLanes(result, conf, owner+"/"+repo, scanMutableExec, branchScope)
	applyGitHubDegraded(result, len(partial), branchFetchFailed)
	applyNestedActions(result, pipeline)
	// An enabled control asserting nothing until its substantive fields are set is not a clean
	// pass either (#459): it is not_evaluable, config_required, same as any other lane gap. Runs
	// before the finding-count aggregation below so a dropped not_evaluable finding never inflates
	// the report's stats, matching the GitLab task's mark-before-assembly ordering.
	MarkUnconfiguredControls(result, GitHubControls(conf.PlumberConfig), conf.PlumberConfig, configuration.ProviderGitHub)
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
