package control

import (
	"fmt"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	"github.com/sirupsen/logrus"
)

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
	l.Info("Fetching project information from GitLab")
	project, err := gitlab.FetchProjectDetails(conf.ProjectPath, conf.GitlabToken, conf.GitlabURL, conf)
	if err != nil {
		l.WithError(err).Error("Failed to fetch project from GitLab")
		// Cannot fetch project - compliance is 0
		result.CiValid = false
		result.CiMissing = true
		result.ImageForbiddenTagsResult = &GitlabImageForbiddenTagsResult{
			Version:    ControlTypeGitlabImageForbiddenTagsVersion,
			Compliance: 0,
			Error:      err.Error(),
		}
		return result, err
	}

	// Update result with project info
	result.ProjectID = project.IdOnPlatform

	l.WithFields(logrus.Fields{
		"projectID":     project.IdOnPlatform,
		"projectName":   project.Name,
		"defaultBranch": project.DefaultBranch,
		"ciConfigPath":  project.CiConfPath,
		"archived":      project.Archived,
	}).Info("Project information fetched")

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

	///////////////////////
	// Run Data Collections
	///////////////////////

	// 1. Run Pipeline Origin data collection
	l.Info("Running Pipeline Origin data collection")
	originDC := &collector.GitlabPipelineOriginDataCollection{}
	pipelineOriginData, pipelineOriginMetrics, err := originDC.Run(projectInfo, conf.GitlabToken, conf)
	if err != nil {
		l.WithError(err).Error("Pipeline Origin data collection failed")
		// Data collection failed - compliance is 0, cannot continue to controls
		result.CiValid = false
		result.CiMissing = true
		result.ImageForbiddenTagsResult = &GitlabImageForbiddenTagsResult{
			Version:    ControlTypeGitlabImageForbiddenTagsVersion,
			Compliance: 0,
			Error:      err.Error(),
		}
		return result, err
	}

	result.CiValid = pipelineOriginData.CiValid
	result.CiMissing = pipelineOriginData.CiMissing

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
	if pipelineOriginData.LimitedAnalysis {
		l.Info("Limited analysis due to CI configuration issues")
		return result, nil
	}

	// 2. Run Pipeline Image data collection
	l.Info("Running Pipeline Image data collection")
	imageDC := &collector.GitlabPipelineImageDataCollection{}
	pipelineImageData, pipelineImageMetrics, err := imageDC.Run(projectInfo, conf.GitlabToken, conf, pipelineOriginData)
	if err != nil {
		l.WithError(err).Error("Pipeline Image data collection failed")
		// Data collection failed - compliance is 0, cannot continue to controls
		result.ImageForbiddenTagsResult = &GitlabImageForbiddenTagsResult{
			Version:    ControlTypeGitlabImageForbiddenTagsVersion,
			Compliance: 0,
			Error:      err.Error(),
		}
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

	///////////////////
	// Run Controls
	///////////////////

	// 3. Run Forbidden Image Tags control
	l.Info("Running Forbidden Image Tags control")

	// Load control configuration from PlumberConfig (required)
	forbiddenTagsConf := &GitlabImageForbiddenTagsConf{}
	if err := forbiddenTagsConf.GetConf(conf.PlumberConfig); err != nil {
		l.WithError(err).Error("Failed to load ImageForbiddenTags config from .plumber.yaml file")
		return result, fmt.Errorf("invalid configuration: %w", err)
	}

	forbiddenTagsResult := forbiddenTagsConf.Run(pipelineImageData)
	result.ImageForbiddenTagsResult = forbiddenTagsResult

	// 4. Run Image Authorized Sources control
	l.Info("Running Image Authorized Sources control")

	authorizedSourcesConf := &GitlabImageAuthorizedSourcesConf{}
	if err := authorizedSourcesConf.GetConf(conf.PlumberConfig); err != nil {
		l.WithError(err).Error("Failed to load ImageAuthorizedSources config from .plumber.yaml file")
		return result, fmt.Errorf("invalid configuration: %w", err)
	}

	authorizedSourcesResult := authorizedSourcesConf.Run(pipelineImageData)
	result.ImageAuthorizedSourcesResult = authorizedSourcesResult

	// 5. Run Pipeline Must Not Include Hardcoded Jobs control
	l.Info("Running Pipeline Must Not Include Hardcoded Jobs control")

	hardcodedJobsConf := &GitlabPipelineHardcodedJobsConf{}
	if err := hardcodedJobsConf.GetConf(conf.PlumberConfig); err != nil {
		l.WithError(err).Error("Failed to load HardcodedJobs config from .plumber.yaml file")
		return result, fmt.Errorf("invalid configuration: %w", err)
	}

	hardcodedJobsResult := hardcodedJobsConf.Run(pipelineOriginData)
	result.HardcodedJobsResult = hardcodedJobsResult

	// 6. Run Includes Must Be Up To Date control
	l.Info("Running Includes Must Be Up To Date control")

	outdatedConf := &GitlabPipelineIncludesOutdatedConf{}
	if err := outdatedConf.GetConf(conf.PlumberConfig); err != nil {
		l.WithError(err).Error("Failed to load IncludesOutdated config from .plumber.yaml file")
		return result, fmt.Errorf("invalid configuration: %w", err)
	}

	outdatedResult := outdatedConf.Run(pipelineOriginData)
	result.OutdatedIncludesResult = outdatedResult

	// 7. Run Includes Must Not Use Forbidden Versions control
	l.Info("Running Includes Must Not Use Forbidden Versions control")

	forbiddenVersionConf := &GitlabPipelineIncludesForbiddenVersionConf{}
	if err := forbiddenVersionConf.GetConf(conf.PlumberConfig); err != nil {
		l.WithError(err).Error("Failed to load ForbiddenVersions config from .plumber.yaml file")
		return result, fmt.Errorf("invalid configuration: %w", err)
	}

	forbiddenVersionResult := forbiddenVersionConf.Run(pipelineOriginData, projectInfo.DefaultBranch)
	result.ForbiddenVersionsIncludesResult = forbiddenVersionResult

	// 8. Run Branch Must Be Protected control (if enabled)
	branchProtectionConfig := conf.PlumberConfig.GetBranchMustBeProtectedConfig()
	if branchProtectionConfig != nil && branchProtectionConfig.IsEnabled() {
		l.Info("Running Branch Must Be Protected control")

		// Run Protection data collection first
		protectionDC := &collector.GitlabProtectionDataCollection{}
		protectionData, _, err := protectionDC.Run(projectInfo, conf.GitlabToken, conf)
		if err != nil {
			l.WithError(err).Error("Protection data collection failed")
			// Data collection failed - set compliance to 0 but continue
			result.BranchProtectionResult = &GitlabBranchProtectionResult{
				Enabled:    true,
				Compliance: 0,
				Version:    ControlTypeGitlabProtectionBranchProtectionNotCompliantVersion,
				Error:      err.Error(),
			}
		} else {
			// Run the branch protection control
			branchProtectionControl := NewGitlabBranchProtectionControl(branchProtectionConfig)
			branchProtectionResult := branchProtectionControl.Run(protectionData, projectInfo)
			result.BranchProtectionResult = branchProtectionResult
		}
	} else {
		l.Debug("Branch Must Be Protected control is disabled or not configured")
	}

	// 9. Run Pipeline Must Include Component control
	l.Info("Running Pipeline Must Include Component control")

	requiredComponentsConf := &GitlabPipelineRequiredComponentsConf{}
	if err := requiredComponentsConf.GetConf(conf.PlumberConfig); err != nil {
		l.WithError(err).Error("Failed to load RequiredComponents config from .plumber.yaml file")
		return result, fmt.Errorf("invalid configuration: %w", err)
	}

	requiredComponentsResult := requiredComponentsConf.Run(pipelineOriginData, conf.GitlabURL)
	result.RequiredComponentsResult = requiredComponentsResult

	// 10. Run Pipeline Must Include Template control
	l.Info("Running Pipeline Must Include Template control")

	requiredTemplatesConf := &GitlabPipelineRequiredTemplatesConf{}
	if err := requiredTemplatesConf.GetConf(conf.PlumberConfig); err != nil {
		l.WithError(err).Error("Failed to load RequiredTemplates config from .plumber.yaml file")
		return result, fmt.Errorf("invalid configuration: %w", err)
	}

	requiredTemplatesResult := requiredTemplatesConf.Run(pipelineOriginData)
	result.RequiredTemplatesResult = requiredTemplatesResult

	l.WithFields(logrus.Fields{
		"ciValid":   result.CiValid,
		"ciMissing": result.CiMissing,
	}).Info("Pipeline analysis completed")

	return result, nil
}
