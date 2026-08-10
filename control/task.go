package control

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
	"github.com/getplumber/plumber/utils"
	"github.com/sirupsen/logrus"
)

// maxLocalCIConfigBytes bounds a local .gitlab-ci.yml read from the analyzed
// repository, whose size is not trusted.
const maxLocalCIConfigBytes = 2 << 20 // 2 MiB

// opaEvaluateTimeout bounds a single Rego/OPA evaluation. Policy evaluation
// over a normal pipeline is sub-second; this ceiling only exists so a
// pathologically large attacker-supplied pipeline/config cannot pin the scan
// process on CPU indefinitely. On timeout the evaluation errors and the
// provider's controls abstain, exactly like any other engine failure.
const opaEvaluateTimeout = 2 * time.Minute

// controlBranchMustBeProtected is the sole .plumber.yaml control key
// the task flow still references directly — to decide whether to fetch
// branch-protection metadata from the GitLab API before invoking the
// Rego engine. Every other control is config-driven end-to-end through
// the catalog in catalog.go.
const controlBranchMustBeProtected = "branchMustBeProtected"
const controlMutableRemoteExec = "actionsMustNotExecuteMutableRemoteCode"

// shouldScanMutableExec reports whether the collector should fetch and
// scan action source for actionsMustNotExecuteMutableRemoteCode
// (ISSUE-714/715). The scan is expensive (up to ~7 sequential HTTP
// requests per unique action), so it runs only when the control is
// actually active: not benched in code, enabled in .plumber.yaml, and
// not excluded by --controls / --skip-controls. When false the collector
// skips the fetch entirely, so disabling the control removes its
// scan-time and rate-limit cost — not just its findings.
func shouldScanMutableExec(conf *configuration.Configuration) bool {
	if conf == nil || conf.PlumberConfig == nil {
		return false
	}
	if configuration.IsBenched("github", controlMutableRemoteExec) {
		return false
	}
	cfg := conf.PlumberConfig.ControlsFor("github").ActionsMustNotExecuteMutableRemoteCode
	if cfg == nil || !cfg.IsEnabled() {
		return false
	}
	return shouldRunControl(controlMutableRemoteExec, conf)
}

// shouldRunControl applies --controls / --skip-controls filtering for a control.
// If --controls is set, only listed controls are eligible.
// Then --skip-controls removes controls from that eligible set.
// Normally the CLI will not allow setting both --controls and --skip-controls together
func shouldRunControl(controlName string, conf *configuration.Configuration) bool {
	if conf == nil {
		return true
	}

	// If --controls is set, only listed controls should run
	if len(conf.ControlsFilter) > 0 {
		found := false
		for _, name := range conf.ControlsFilter {
			if name == controlName {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// If --skip-controls is set, listed controls should not run
	for _, name := range conf.SkipControlsFilter {
		if name == controlName {
			return false
		}
	}

	return true
}

// reportProgress calls the optional progress callback if configured.
func reportProgress(conf *configuration.Configuration, step, total int, message string) {
	if conf.ProgressFunc != nil {
		conf.ProgressFunc(step, total, message)
	}
}

// clearProgressLine clears the spinner line before writing direct stderr output.
func clearProgressLine(conf *configuration.Configuration) {
	if conf.ProgressFunc != nil {
		fmt.Fprint(os.Stderr, "\r\033[K")
	}
}

// analysisStepCount is the total number of progress steps reported during analysis.
const analysisStepCount = 18

// runRegoEngine invokes the experimental Rego/OPA rule engine on the
// GitLab collector outputs and returns the aggregated findings plus the
// normalized pipeline they were evaluated against (retained by the
// caller on AnalysisResult.GitLabPipeline for stats rendering). The
// legacy Go controls always run and remain authoritative until parity
// is reached (see phases 2+). On any failure the returned slice is nil
// and the error is logged at Warn level so the overall analysis still
// completes.
func runRegoEngine(
	l *logrus.Entry,
	conf *configuration.Configuration,
	project *gitlab.Project,
	originData *gitlab.GitlabPipelineOriginData,
	imageData *gitlab.GitlabPipelineImageData,
	protectionData *gitlab.GitlabProtectionAnalysisData,
) ([]opaengine.Finding, *ir.NormalizedPipeline) {
	pipeline := gitlab.ToNormalizedPipeline(
		conf.ProjectPath,
		project.DefaultBranch,
		project.CiConfPath,
		originData,
		imageData,
		protectionData,
	)
	return evaluatePolicies(l, conf, "gitlab", pipeline), pipeline
}

// evaluatePolicies loads the embedded Rego policies and evaluates them
// against pipeline. The provider argument selects which per-provider
// ControlsConfig under conf.PlumberConfig is fed to the policies (and
// used to filter findings via the provider's enabledControls
// allowlist). conf.ControlsFilter / conf.SkipControlsFilter further
// restrict which controls' findings reach the caller. Callers pass
// "gitlab" or "github". Anything else returns no findings.
func evaluatePolicies(l *logrus.Entry, conf *configuration.Configuration, provider string, pipeline *ir.NormalizedPipeline) []opaengine.Finding {
	l.WithField("provider", provider).Info("Running Rego/OPA rule engine")
	// Empty (non-nil) so the eventual JSON output marshals an empty
	// findings array as `[]`, not `null` — `null` makes downstream
	// jq pipelines like `.findings[]` blow up on a clean run.
	empty := []opaengine.Finding{}
	engine := opaengine.New()
	skip := func(filename string, content []byte) bool {
		return IsRegoFileBenchedForProvider(content, provider)
	}
	if err := engine.LoadFromFSFiltered(policies.FS, skip); err != nil {
		l.WithError(err).Warn("Failed to load embedded Rego policies")
		return empty
	}
	controls := conf.PlumberConfig.ControlsFor(provider)
	ctx, cancel := context.WithTimeout(context.Background(), opaEvaluateTimeout)
	defer cancel()
	findings, err := engine.Evaluate(ctx, pipeline, buildEngineConfig(controls, conf.GitlabURL))
	if err != nil {
		l.WithError(err).Warn("Rego/OPA engine evaluation failed")
		return empty
	}
	findings = FilterFindingsByEnabledControls(findings, provider, controls, conf.ControlsFilter, conf.SkipControlsFilter)
	if findings == nil {
		findings = empty
	}
	l.WithField("findingCount", len(findings)).Info("Rego/OPA engine evaluation completed")
	return findings
}

// buildEngineConfig projects the relevant bits of the user's .plumber.yaml
// onto a Rego-friendly map. Policies read it as `input.config.<rule>.<key>`.
// Only the sections consumed by already-ported policies are included;
// additional entries land with each new policy. gitlabURL is
// conf.GitlabURL — only used to derive the scanned GitLab instance's host
// for componentAuthorizedSources; callers scoped to GitHub may pass "".
func buildEngineConfig(controls *configuration.ControlsConfig, gitlabURL string) map[string]any {
	if controls == nil {
		return nil
	}
	cfg := map[string]any{}

	if c := controls.ContainerImageMustNotUseForbiddenTags; c != nil {
		if len(c.Tags) > 0 {
			cfg["imageMutableTag"] = map[string]any{
				"forbiddenTags": c.Tags,
			}
		}
		if c.IsPinnedByDigestRequired() {
			cfg["containerImageMustNotUseForbiddenTags"] = map[string]any{
				"mustBePinnedByDigest": true,
			}
		}
	}

	if c := controls.PipelineMustNotEnableDebugTrace; c != nil && len(c.ForbiddenVariables) > 0 {
		cfg["debugTrace"] = map[string]any{
			"forbiddenVariables": c.ForbiddenVariables,
		}
	}

	if c := controls.ReleaseWorkflowsMustNotRestoreUntrustedCache; c != nil {
		entry := map[string]any{}
		if len(c.PublishActions) > 0 {
			entry["publishActions"] = c.PublishActions
		}
		if len(c.CacheActions) > 0 {
			specs := make([]map[string]any, 0, len(c.CacheActions))
			for _, s := range c.CacheActions {
				m := map[string]any{"action": s.Action, "mode": s.Mode}
				if s.DisableInput != "" {
					m["disableInput"] = s.DisableInput
				}
				if s.DisableValue != nil {
					m["disableValue"] = *s.DisableValue
				}
				if s.EnableInput != "" {
					m["enableInput"] = s.EnableInput
				}
				if s.EnableContains != "" {
					m["enableContains"] = s.EnableContains
				}
				specs = append(specs, m)
			}
			entry["cacheActions"] = specs
		}
		if len(c.PublishScriptPatterns) > 0 {
			entry["publishScriptPatterns"] = c.PublishScriptPatterns
		}
		if len(c.PublishScriptExcludePatterns) > 0 {
			entry["publishScriptExcludePatterns"] = c.PublishScriptExcludePatterns
		}
		if len(c.AllowedJobs) > 0 {
			entry["allowedJobs"] = c.AllowedJobs
		}
		if len(entry) > 0 {
			cfg["cachePoisoning"] = entry
		}
	}

	if c := controls.PipelineMustNotOverrideJobVariables; c != nil && len(c.Variables) > 0 {
		cfg["jobVariablesOverride"] = map[string]any{
			"protectedVariables": c.Variables,
		}
	}

	if c := controls.SecurityJobsMustNotBeWeakened; c != nil && len(c.SecurityJobPatterns) > 0 {
		cfg["securityJobsWeakened"] = map[string]any{
			"securityJobPatterns":     c.SecurityJobPatterns,
			"allowFailureMustBeFalse": c.AllowFailureMustBeFalse.IsEnabled(true),
			"whenMustNotBeManual":     c.WhenMustNotBeManual.IsEnabled(true),
			"rulesMustNotBeRedefined": c.RulesMustNotBeRedefined.IsEnabled(true),
		}
	}

	if c := controls.PipelineMustNotUseUnsafeVariableExpansion; c != nil && len(c.DangerousVariables) > 0 {
		cfg["unsafeVariableExpansion"] = map[string]any{
			"dangerousVariables": c.DangerousVariables,
			"allowedPatterns":    c.AllowedPatterns,
		}
	}

	if c := controls.BranchMustBeProtected; c != nil {
		entry := map[string]any{
			"namePatterns": c.NamePatterns,
		}
		if c.DefaultMustBeProtected != nil {
			entry["defaultMustBeProtected"] = *c.DefaultMustBeProtected
		}
		if c.AllowForcePush != nil {
			entry["allowForcePush"] = *c.AllowForcePush
		}
		if c.CodeOwnerApprovalRequired != nil {
			entry["codeOwnerApprovalRequired"] = *c.CodeOwnerApprovalRequired
		}
		if c.MinPushAccessLevel != nil {
			entry["minPushAccessLevel"] = *c.MinPushAccessLevel
		}
		if c.MinMergeAccessLevel != nil {
			entry["minMergeAccessLevel"] = *c.MinMergeAccessLevel
		}
		cfg["branchMustBeProtected"] = entry
	}

	if c := controls.IncludesMustNotUseForbiddenVersions; c != nil {
		defaultForbidden := false
		if c.DefaultBranchIsForbiddenVersion != nil {
			defaultForbidden = *c.DefaultBranchIsForbiddenVersion
		}
		cfg["includesForbiddenVersions"] = map[string]any{
			"forbiddenVersions":               c.ForbiddenVersions,
			"defaultBranchIsForbiddenVersion": defaultForbidden,
		}
	}

	if c := controls.ContainerImageMustComeFromAuthorizedSources; c != nil {
		trustOfficial := false
		if c.TrustDockerHubOfficialImages != nil {
			trustOfficial = *c.TrustDockerHubOfficialImages
		}
		cfg["imageAuthorizedSources"] = map[string]any{
			"trustedUrls":            c.TrustedUrls,
			"trustDockerHubOfficial": trustOfficial,
		}
	}

	if c := controls.PipelineMustNotExecuteUnverifiedScripts; c != nil && len(c.TrustedUrls) > 0 {
		cfg["unverifiedScripts"] = map[string]any{
			"trustedUrls": c.TrustedUrls,
		}
	}

	if c := controls.PipelineMustIncludeComponent; c != nil && c.IsEnabled() {
		if groups, err := c.GetResolvedRequiredGroups(); err == nil && len(groups) > 0 {
			cfg["pipelineMustIncludeComponent"] = map[string]any{
				"requiredGroups": toAnyGroups(groups),
			}
		}
	}

	if c := controls.PipelineMustIncludeTemplate; c != nil && c.IsEnabled() {
		if groups, err := c.GetResolvedRequiredGroups(); err == nil && len(groups) > 0 {
			cfg["pipelineMustIncludeTemplate"] = map[string]any{
				"requiredGroups": toAnyGroups(groups),
			}
		}
	}

	// componentAuthorizedSources: no environment-variable resolution.
	// Trust is either an explicit trustedComponents allowlist pattern, or
	// derived dynamically from the scanned project's own namespace/instance
	// via trustSameGroupComponents / trustSameInstanceComponents — modeled
	// on githubActionMustComeFromAuthorizedSources's trustSameOrgActions,
	// which reads input.pipeline.projectPath instead of trusting Plumber's
	// own process environment.
	if c := controls.ComponentMustComeFromAuthorizedSources; c != nil && c.IsEnabled() {
		trustSameGroup := true
		if c.TrustSameGroupComponents != nil {
			trustSameGroup = *c.TrustSameGroupComponents
		}

		trustSameInstance := true
		if c.TrustSameInstanceComponents != nil {
			trustSameInstance = *c.TrustSameInstanceComponents
		}

		if isGitlabSaaS(gitlabURL) {
			trustSameInstance = false
		}

		entry := map[string]any{
			"trustSameGroupComponents":    trustSameGroup,
			"trustSameInstanceComponents": trustSameInstance,
			"instanceHost":                gitlabInstanceHost(gitlabURL),
		}
		if len(c.TrustedComponents) > 0 {
			entry["trustedComponents"] = c.TrustedComponents
		}
		cfg["componentAuthorizedSources"] = entry
	}

	// functionAuthorizedSources: same dynamic same-namespace model as
	// componentAuthorizedSources — same-group trust is host-bound via
	// instanceHost for a literal same-instance ref.
	if c := controls.FunctionMustComeFromAuthorizedSources; c != nil && c.IsEnabled() {
		trustSameGroup := true
		if c.TrustSameGroupFunctions != nil {
			trustSameGroup = *c.TrustSameGroupFunctions
		}
		entry := map[string]any{
			"trustSameGroupFunctions": trustSameGroup,
			"instanceHost":            gitlabInstanceHost(gitlabURL),
		}
		if len(c.TrustedFunctions) > 0 {
			entry["trustedFunctions"] = c.TrustedFunctions
		}
		cfg["functionAuthorizedSources"] = entry
	}

	if c := controls.ActionsMustBePinnedByCommitSha; c != nil && c.IsEnabled() {
		entry := map[string]any{}
		if len(c.TrustedOwners) > 0 {
			entry["trustedOwners"] = c.TrustedOwners
		}
		cfg["actionsMustBePinnedByCommitSha"] = entry
	}

	if c := controls.GithubActionMustComeFromAuthorizedSources; c != nil && c.IsEnabled() {
		// trustGithubOfficialActions defaults to true: the first-party
		// actions/* and github/* owners are inside any workflow's
		// implicit trust boundary, so trust them unless explicitly
		// opted out.
		trustOfficial := true
		if c.TrustGithubOfficialActions != nil {
			trustOfficial = *c.TrustGithubOfficialActions
		}
		// trustSameOrgActions also defaults to true: an org's own actions
		// (same owner as the scanned repo) are inside its trust boundary.
		trustSameOrg := true
		if c.TrustSameOrgActions != nil {
			trustSameOrg = *c.TrustSameOrgActions
		}
		entry := map[string]any{
			"trustGithubOfficialActions": trustOfficial,
			"trustSameOrgActions":        trustSameOrg,
			"minimumStars":               c.MinimumStars,
		}
		if len(c.TrustedGithubActions) > 0 {
			entry["trustedGithubActions"] = c.TrustedGithubActions
		}
		cfg["githubActionMustComeFromAuthorizedSources"] = entry
	}

	if c := controls.WorkflowMustIncludeRequiredActions; c != nil && c.IsEnabled() {
		if groups, err := c.GetResolvedRequiredGroups(); err == nil && len(groups) > 0 {
			cfg["workflowMustIncludeRequiredActions"] = map[string]any{
				"requiredGroups": toAnyGroups(groups),
			}
		}
	}

	if len(cfg) == 0 {
		return nil
	}
	return cfg
}

// toAnyGroups converts a [][]string (DNF requiredGroups) into a nested
// []any slice so OPA sees it as a plain JSON array of arrays.
func toAnyGroups(groups [][]string) []any {
	out := make([]any, len(groups))
	for i, g := range groups {
		inner := make([]any, len(g))
		for j, p := range g {
			inner[j] = p
		}
		out[i] = inner
	}
	return out
}

// gitlabInstanceHost strips the scheme (and any trailing slash) from a
// GitLab base URL, e.g. "https://gitlab.com" -> "gitlab.com".
func gitlabInstanceHost(gitlabURL string) string {
	host := gitlabURL
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	return strings.TrimSuffix(host, "/")
}

// isGitlabSaaS reports whether gitlabURL points at gitlab.com, the
// multi-tenant SaaS instance — as opposed to a self-hosted instance,
// which is already inside the scanning org's trust boundary.
func isGitlabSaaS(gitlabURL string) bool {
	return gitlabInstanceHost(gitlabURL) == "gitlab.com"
}

// RunAnalysis executes the complete pipeline analysis for a GitLab project
func RunAnalysis(conf *configuration.Configuration) (*AnalysisResult, error) {
	l := l.WithFields(logrus.Fields{
		"action":      "RunAnalysis",
		"projectPath": conf.ProjectPath,
		"gitlabURL":   conf.GitlabURL,
	})
	l.Info("Starting pipeline analysis")

	result := &AnalysisResult{
		ProjectPath: conf.ProjectPath,
	}

	// /////////////////////
	// Fetch Project Info from GitLab
	// /////////////////////
	reportProgress(conf, 1, analysisStepCount, "Fetching project information")
	l.Info("Fetching project information from GitLab")
	project, err := gitlab.FetchProjectDetails(conf.ProjectPath, conf.GitlabToken, conf.GitlabURL, conf)
	if err != nil {
		// A network/timeout failure here is incomplete data, not a bad
		// project: degrade (exit 3, honest) instead of hard-failing (exit 2).
		// A definitive answer (404 not-found, auth) still hard-fails (#220).
		if isNetworkError(err) {
			l.WithError(err).Warn("Project information fetch failed (network); reporting incomplete data")
			markDegraded(result, "project information could not be fetched (network or timeout)")
			result.CiValid = false
			return result, nil
		}
		l.WithError(err).Error("Failed to fetch project from GitLab")
		result.CiValid = false
		result.CiMissing = true
		return result, err
	}

	// Update result with project info
	result.ProjectID = project.IdOnPlatform
	result.DefaultBranch = project.DefaultBranch
	result.HeadCommitSha = project.LatestHeadCommitSha

	l.WithFields(logrus.Fields{
		"projectID":     project.IdOnPlatform,
		"projectName":   project.Name,
		"defaultBranch": project.DefaultBranch,
		"ciConfigPath":  project.CiConfPath,
		"archived":      project.Archived,
	}).Info("Project information fetched")

	// Apply --ci-config-path override before converting to ProjectInfo so that
	// all downstream code (local file resolution, remote fetch) uses the custom path.
	if conf.CIConfigPathOverride != "" {
		project.CiConfPath = conf.CIConfigPathOverride
		clearProgressLine(conf)
		fmt.Fprintf(os.Stderr, "Using custom CI config path: %s\n", conf.CIConfigPathOverride)
		l.WithField("ciConfigPathOverride", conf.CIConfigPathOverride).Info("CI config path overridden by --ci-config-path flag")
	}

	// Convert to ProjectInfo for collectors
	projectInfo := project.ToProjectInfo()

	// The --branch flag specifies which branch's CI config to analyze,
	// NOT the project's default branch. Keep them separate.
	// projectInfo.DefaultBranch = actual default branch from GitLab API (e.g., "main")
	// projectInfo.AnalyzeBranch = branch to analyze from CLI (e.g., "testing-branch" or defaults to DefaultBranch)
	if conf.Branch != "" {
		projectInfo.AnalyzeBranch = conf.Branch

		// When analyzing a non-default branch, fetch the correct SHA so that
		// GitLab's ciConfig GraphQL query resolves include:local files from
		// the target branch's file tree, not the default branch's.
		if conf.Branch != projectInfo.DefaultBranch {
			branchSha, err := gitlab.FetchLatestCommitSha(
				conf.GitlabToken, conf.GitlabURL, conf.ProjectPath, conf.Branch, conf,
			)
			if err != nil {
				l.WithError(err).Warn("Unable to fetch commit SHA for analyze branch, using default branch SHA")
			} else {
				projectInfo.LatestHeadCommitSha = branchSha
			}
		}
	}
	result.AnalyzeBranch = projectInfo.AnalyzeBranch
	if projectInfo.LatestHeadCommitSha != "" {
		result.HeadCommitSha = projectInfo.LatestHeadCommitSha
	}

	// /////////////////////
	// Resolve CI config source (local file vs remote)
	// /////////////////////

	// Priority:
	// 1. If --branch is defined: use remote file on that branch
	// 2. If in a git repo, the local repo IS the analyzed project, and the CI config
	//    file exists locally: use local file (+ resolve include:local from filesystem)
	// 3. Otherwise: use remote file (current default behavior)
	if conf.Branch == "" && conf.IsLocalProject {
		localCIPath, cErr := gitlab.ResolveWithinRepo(conf.GitRepoRoot, project.CiConfPath)
		if cErr != nil {
			l.WithFields(logrus.Fields{
				"ciConfPath": project.CiConfPath,
				"error":      cErr,
			}).Warn("Local CI config path escapes the repository; using remote")
		} else if content, err := utils.ReadFileLimit(localCIPath, maxLocalCIConfigBytes); err == nil {
			conf.LocalCIConfigContent = content
			conf.UsingLocalCIConfig = true
			// The run header reports "CI config: local file"; the path and the
			// --branch hint stay in the verbose log to keep normal output clean.
			l.WithField("localCIPath", localCIPath).Info("Using local CI configuration file (pass --branch to fetch the CI config from GitLab instead)")
		} else if os.IsNotExist(err) {
			l.WithField("localCIPath", localCIPath).Debug("Local CI config file not found, will use remote")
		} else {
			// The file is present but could not be read (e.g. it exceeds the
			// size limit). Surface it instead of silently scoring against the
			// remote CI as though no local file existed.
			clearProgressLine(conf)
			fmt.Fprintf(os.Stderr, "Local CI configuration at %s could not be read (%v); using remote CI configuration instead\n", localCIPath, err)
			l.WithFields(logrus.Fields{
				"localCIPath": localCIPath,
				"error":       err,
			}).Warn("Local CI config file present but unreadable; using remote")
		}
	} else if conf.Branch != "" {
		clearProgressLine(conf)
		fmt.Fprintf(os.Stderr, "Using remote CI configuration from branch: %s\n", projectInfo.AnalyzeBranch)
	}

	result.CIConfigSource = "remote"
	if conf.UsingLocalCIConfig {
		result.CIConfigSource = "local"
	}

	// /////////////////////
	// Run Data Collections
	// /////////////////////

	// 1. Run Pipeline Origin data collection
	reportProgress(conf, 2, analysisStepCount, "Collecting pipeline origins")
	l.Info("Running Pipeline Origin data collection")
	originDC := &gitlab.GitlabPipelineOriginDataCollection{}
	pipelineOriginData, pipelineOriginMetrics, err := originDC.Run(projectInfo, conf.GitlabToken, conf)
	if err != nil {
		// Network/timeout → degrade (exit 3); a definitive error still hard-
		// fails (exit 2). Same gate as project resolution above (#220).
		if isNetworkError(err) {
			l.WithError(err).Warn("Pipeline Origin data collection failed (network); reporting incomplete data")
			markDegraded(result, "pipeline configuration could not be fetched (network or timeout)")
			result.CiValid = false
			return result, nil
		}
		l.WithError(err).Error("Pipeline Origin data collection failed")
		result.CiValid = false
		result.CiMissing = true
		return result, err
	}

	result.CiValid = pipelineOriginData.CiValid
	result.CiMissing = pipelineOriginData.CiMissing

	// An include that failed to resolve drops its jobs from the merged
	// pipeline, so the analysis ran on a partial config. Flag degraded (the
	// run still evaluates what it has, like a GitHub partial) so the score is
	// withheld rather than scored against an incomplete pipeline (#220).
	if n := len(pipelineOriginData.IncludesFailed); n > 0 {
		markDegraded(result, fmt.Sprintf("%d include(s) could not be resolved; their jobs were not analysed", n))
	}

	// Capture CI config errors for output
	if len(pipelineOriginData.CiErrors) > 0 {
		result.CiErrors = pipelineOriginData.CiErrors
		// A fetch-level error (GraphQL timeout, rate-limit, lost network)
		// leaves us with no pipeline data, so every control would score a
		// vacuous 100%. Flag the run degraded so the renderer withholds the
		// letter score and marks the controls "not evaluated" (#220). A
		// syntactically invalid but successfully fetched config (the
		// MergedResponse branch below) is a real user-fixable finding, not a
		// degraded collection, so it does not set the flag.
		result.DataCollectionDegraded = true
		result.DegradedReasons = append(result.DegradedReasons, pipelineOriginData.CiErrors...)
	} else if pipelineOriginData.MergedResponse != nil && len(pipelineOriginData.MergedResponse.CiConfig.Errors) > 0 {
		result.CiErrors = pipelineOriginData.MergedResponse.CiConfig.Errors
	}

	// Store origin metrics
	if pipelineOriginMetrics != nil {
		result.PipelineOriginMetrics = &PipelineOriginMetricsSummary{
			JobTotal:            pipelineOriginMetrics.JobTotal,
			JobHardcoded:        pipelineOriginMetrics.JobHardcoded,
			OriginTotal:         pipelineOriginMetrics.OriginTotal,
			OriginComponent:     pipelineOriginMetrics.OriginComponent,
			OriginLocal:         pipelineOriginMetrics.OriginLocal,
			OriginProject:       pipelineOriginMetrics.OriginProject,
			OriginRemote:        pipelineOriginMetrics.OriginRemote,
			OriginTemplate:      pipelineOriginMetrics.OriginTemplate,
			OriginGitLabCatalog: pipelineOriginMetrics.OriginGitLabCatalog,
			OriginOutdated:      pipelineOriginMetrics.OriginOutdated,
		}
	}

	// If limited analysis (CI invalid or missing), return early
	// Note: when using local CI config, errors are returned directly by the
	// collector (hard fail) and won't reach this point.
	if pipelineOriginData.LimitedAnalysis {
		l.Info("Limited analysis due to CI configuration issues")
		return result, nil
	}

	// 2. Run Pipeline Image data collection
	reportProgress(conf, 3, analysisStepCount, "Collecting pipeline images")
	l.Info("Running Pipeline Image data collection")
	imageDC := &gitlab.GitlabPipelineImageDataCollection{}
	pipelineImageData, pipelineImageMetrics, err := imageDC.Run(projectInfo, conf.GitlabToken, conf, pipelineOriginData)
	if err != nil {
		// Network/timeout during image/variable collection → degrade (exit 3)
		// instead of the raw exit-2 hard fail this used to produce, matching
		// the origin path. A definitive error still hard-fails (#220).
		if isNetworkError(err) {
			l.WithError(err).Warn("Pipeline Image data collection failed (network); reporting incomplete data")
			markDegraded(result, "pipeline image/variable data could not be fetched (network or timeout)")
			result.CiValid = false
			return result, nil
		}
		l.WithError(err).Error("Pipeline Image data collection failed")
		return result, err
	}

	// Store image metrics
	if pipelineImageMetrics != nil {
		result.PipelineImageMetrics = &PipelineImageMetricsSummary{
			Total: pipelineImageMetrics.Total,
		}
	}

	// Store raw collected data for PBOM generation
	result.PipelineImageData = pipelineImageData
	result.PipelineOriginData = pipelineOriginData

	// Fetch branch-protection metadata when the user configured the
	// corresponding control — the Rego policy needs the protection
	// settings to check every branch against the declared bar.
	var protectionData *gitlab.GitlabProtectionAnalysisData
	if shouldRunControl(controlBranchMustBeProtected, conf) {
		if cfg := conf.PlumberConfig.GetBranchMustBeProtectedConfig(); cfg != nil && cfg.IsEnabled() {
			reportProgress(conf, 9, analysisStepCount, "Checking branch protection")
			protectionDC := &gitlab.GitlabProtectionDataCollection{}
			pData, _, pErr := protectionDC.Run(projectInfo, conf.GitlabToken, conf)
			if pErr != nil {
				// A network failure here leaves branchMustBeProtected with zero
				// branches → a vacuous 100% green. Flag degraded so that control's
				// pass is not trusted (mirrors the GitHub branch path, #220). A
				// non-network failure stays a soft warn as before.
				if isNetworkError(pErr) {
					markDegraded(result, degradedReasonBranchProtectionPrefix+" (network or timeout)")
				}
				l.WithError(pErr).Warn("Protection data collection failed; branch policies will see no branches")
			} else {
				protectionData = pData
			}
		}
	}

	// Rego/OPA rule engine evaluation — the single authoritative
	// compliance path (the legacy Go controls were retired in
	// docs/REFACTOR_MULTI_PROVIDER.md §8 Phase A).
	result.Findings, result.GitLabPipeline = runRegoEngine(l, conf, project, pipelineOriginData, pipelineImageData, protectionData)
	result.ProtectionData = protectionData

	reportProgress(conf, analysisStepCount, analysisStepCount, "Analysis complete")

	l.WithFields(logrus.Fields{
		"ciValid":   result.CiValid,
		"ciMissing": result.CiMissing,
	}).Info("Pipeline analysis completed")

	return result, nil
}
