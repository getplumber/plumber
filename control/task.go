package control

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
	"github.com/sirupsen/logrus"
)

// controlBranchMustBeProtected is the sole .plumber.yaml control key
// the task flow still references directly — to decide whether to fetch
// branch-protection metadata from the GitLab API before invoking the
// Rego engine. Every other control is config-driven end-to-end through
// the catalog in catalog.go.
const controlBranchMustBeProtected = "branchMustBeProtected"

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
// GitLab collector outputs and returns the aggregated findings. The
// legacy Go controls always run and remain authoritative until parity
// is reached (see phases 2+). On any failure the returned slice is nil
// and the error is logged at Warn level so the overall analysis still
// completes.
func runRegoEngine(
	l *logrus.Entry,
	conf *configuration.Configuration,
	project *gitlab.Project,
	originData *collector.GitlabPipelineOriginData,
	imageData *collector.GitlabPipelineImageData,
	protectionData *collector.GitlabProtectionAnalysisData,
) []opaengine.Finding {
	pipeline := collector.ToNormalizedPipeline(
		conf.ProjectPath,
		project.DefaultBranch,
		project.CiConfPath,
		originData,
		imageData,
		protectionData,
	)
	return evaluatePolicies(l, conf, "gitlab", pipeline)
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
	findings, err := engine.Evaluate(context.Background(), pipeline, buildEngineConfig(controls))
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
// additional entries land with each new policy.
func buildEngineConfig(controls *configuration.ControlsConfig) map[string]any {
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
			"trustedUrls":           c.TrustedUrls,
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

	if c := controls.ActionsMustBePinnedByCommitSha; c != nil && c.IsEnabled() {
		entry := map[string]any{}
		if len(c.TrustedOwners) > 0 {
			entry["trustedOwners"] = c.TrustedOwners
		}
		cfg["actionsMustBePinnedByCommitSha"] = entry
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

	///////////////////////
	// Fetch Project Info from GitLab
	///////////////////////
	reportProgress(conf, 1, analysisStepCount, "Fetching project information")
	l.Info("Fetching project information from GitLab")
	project, err := gitlab.FetchProjectDetails(conf.ProjectPath, conf.GitlabToken, conf.GitlabURL, conf)
	if err != nil {
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

	///////////////////////
	// Resolve CI config source (local file vs remote)
	///////////////////////

	// Priority:
	// 1. If --branch is defined: use remote file on that branch
	// 2. If in a git repo, the local repo IS the analyzed project, and the CI config
	//    file exists locally: use local file (+ resolve include:local from filesystem)
	// 3. Otherwise: use remote file (current default behavior)
	if conf.Branch == "" && conf.IsLocalProject {
		localCIPath := filepath.Join(conf.GitRepoRoot, project.CiConfPath)
		if content, err := os.ReadFile(localCIPath); err == nil {
			conf.LocalCIConfigContent = content
			conf.UsingLocalCIConfig = true
			clearProgressLine(conf)
			fmt.Fprintf(os.Stderr, "Using local CI configuration (specify --branch to force upstream CI config fetch): %s\n", localCIPath)
			l.WithField("localCIPath", localCIPath).Info("Using local CI configuration file")
		} else {
			l.WithFields(logrus.Fields{
				"localCIPath": localCIPath,
				"error":       err,
			}).Debug("Local CI config file not found, will use remote")
		}
	} else if conf.Branch != "" {
		clearProgressLine(conf)
		fmt.Fprintf(os.Stderr, "Using remote CI configuration from branch: %s\n", projectInfo.AnalyzeBranch)
	}

	result.CIConfigSource = "remote"
	if conf.UsingLocalCIConfig {
		result.CIConfigSource = "local"
	}

	///////////////////////
	// Run Data Collections
	///////////////////////

	// 1. Run Pipeline Origin data collection
	reportProgress(conf, 2, analysisStepCount, "Collecting pipeline origins")
	l.Info("Running Pipeline Origin data collection")
	originDC := &collector.GitlabPipelineOriginDataCollection{}
	pipelineOriginData, pipelineOriginMetrics, err := originDC.Run(projectInfo, conf.GitlabToken, conf)
	if err != nil {
		l.WithError(err).Error("Pipeline Origin data collection failed")
		result.CiValid = false
		result.CiMissing = true
		return result, err
	}

	result.CiValid = pipelineOriginData.CiValid
	result.CiMissing = pipelineOriginData.CiMissing

	// Capture CI config errors for output
	if len(pipelineOriginData.CiErrors) > 0 {
		result.CiErrors = pipelineOriginData.CiErrors
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
	imageDC := &collector.GitlabPipelineImageDataCollection{}
	pipelineImageData, pipelineImageMetrics, err := imageDC.Run(projectInfo, conf.GitlabToken, conf, pipelineOriginData)
	if err != nil {
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
	var protectionData *collector.GitlabProtectionAnalysisData
	if shouldRunControl(controlBranchMustBeProtected, conf) {
		if cfg := conf.PlumberConfig.GetBranchMustBeProtectedConfig(); cfg != nil && cfg.IsEnabled() {
			reportProgress(conf, 9, analysisStepCount, "Checking branch protection")
			protectionDC := &collector.GitlabProtectionDataCollection{}
			pData, _, pErr := protectionDC.Run(projectInfo, conf.GitlabToken, conf)
			if pErr != nil {
				l.WithError(pErr).Warn("Protection data collection failed; branch policies will see no branches")
			} else {
				protectionData = pData
			}
		}
	}

	// Rego/OPA rule engine evaluation — the single authoritative
	// compliance path (the legacy Go controls were retired in
	// docs/REFACTOR_MULTI_PROVIDER.md §8 Phase A).
	result.Findings = runRegoEngine(l, conf, project, pipelineOriginData, pipelineImageData, protectionData)
	result.ProtectionData = protectionData

	reportProgress(conf, analysisStepCount, analysisStepCount, "Analysis complete")

	l.WithFields(logrus.Fields{
		"ciValid":   result.CiValid,
		"ciMissing": result.CiMissing,
	}).Info("Pipeline analysis completed")

	return result, nil
}
