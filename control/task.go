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
		result.ImageMutableResult = &GitlabImageMutableResult{
			Version:    ControlTypeGitlabImageMutableVersion,
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
		result.ImageMutableResult = &GitlabImageMutableResult{
			Version:    ControlTypeGitlabImageMutableVersion,
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
		result.ImageMutableResult = &GitlabImageMutableResult{
			Version:    ControlTypeGitlabImageMutableVersion,
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

	///////////////////
	// Run Controls
	///////////////////

	// 3. Run Mutable Image Tag control
	l.Info("Running Mutable Image Tag control")

	// Load control configuration from PlumberConfig (required)
	mutableConf := &GitlabImageMutableConf{}
	if err := mutableConf.GetConf(conf.PlumberConfig); err != nil {
		l.WithError(err).Error("Failed to load ImageMutable config from .plumber.yaml file")
		return result, fmt.Errorf("invalid configuration: %w", err)
	}

	mutableResult := mutableConf.Run(pipelineImageData)
	result.ImageMutableResult = mutableResult

	// 4. Run Untrusted Image control
	l.Info("Running Untrusted Image control")

	untrustedConf := &GitlabImageUntrustedConf{}
	if err := untrustedConf.GetConf(conf.PlumberConfig); err != nil {
		l.WithError(err).Error("Failed to load ImageUntrusted config from .plumber.yaml file")
		return result, fmt.Errorf("invalid configuration: %w", err)
	}

	untrustedResult := untrustedConf.Run(pipelineImageData)
	result.ImageUntrustedResult = untrustedResult

	// 5. Run Branch Protection control (if enabled)
	branchProtectionConfig := conf.PlumberConfig.GetBranchProtectionConfig()
	if branchProtectionConfig != nil && branchProtectionConfig.IsEnabled() {
		l.Info("Running Branch Protection control")

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
		l.Debug("Branch Protection control is disabled or not configured")
	}

	l.WithFields(logrus.Fields{
		"ciValid":   result.CiValid,
		"ciMissing": result.CiMissing,
	}).Info("Pipeline analysis completed")

	return result, nil
}
