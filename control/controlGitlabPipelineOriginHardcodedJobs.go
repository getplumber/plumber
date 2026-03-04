package control

import (
	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/sirupsen/logrus"
)

const ControlTypeGitlabPipelineOriginHardcodedJobsVersion = "0.1.0"

// GitlabPipelineHardcodedJobsConf holds the configuration for hardcoded job detection
type GitlabPipelineHardcodedJobsConf struct {
	// Enabled controls whether this check runs
	Enabled bool `json:"enabled"`
}

// GetConf loads configuration from PlumberConfig
// Returns error if config is nil (but control can still be disabled)
func (p *GitlabPipelineHardcodedJobsConf) GetConf(plumberConfig *configuration.PlumberConfig) error {
	// Plumber config is required
	if plumberConfig == nil {
		p.Enabled = false
		return nil
	}

	// Get control config from PlumberConfig
	hardcodedConfig := plumberConfig.GetPipelineMustNotIncludeHardcodedJobsConfig()
	if hardcodedConfig == nil {
		// Control not configured - disable it
		p.Enabled = false
		return nil
	}

	// Apply configuration
	p.Enabled = hardcodedConfig.IsEnabled()

	l.WithFields(logrus.Fields{
		"enabled": p.Enabled,
	}).Debug("pipelineMustNotIncludeHardcodedJobs control configuration loaded from .plumber.yaml file")

	return nil
}

// GitlabPipelineHardcodedJobsMetrics holds metrics about hardcoded jobs
type GitlabPipelineHardcodedJobsMetrics struct {
	Total         uint `json:"total"`
	HardcodedJobs uint `json:"hardcodedJobs"`
	CiInvalid     uint `json:"ciInvalid"`
	CiMissing     uint `json:"ciMissing"`
}

// GitlabPipelineHardcodedJobsResult holds the result of the hardcoded jobs control
type GitlabPipelineHardcodedJobsResult struct {
	Issues     []GitlabPipelineHardcodedJobIssue  `json:"issues"`
	Metrics    GitlabPipelineHardcodedJobsMetrics `json:"metrics"`
	Compliance float64                            `json:"compliance"`
	Version    string                             `json:"version"`
	CiValid    bool                               `json:"ciValid"`
	CiMissing  bool                               `json:"ciMissing"`
	Skipped    bool                               `json:"skipped"`         // True if control was disabled
	Error      string                             `json:"error,omitempty"` // Error message if data collection failed
}

////////////////////
// Control issues //
////////////////////

// GitlabPipelineHardcodedJobIssue represents an issue with a hardcoded job
type GitlabPipelineHardcodedJobIssue struct {
	Code    ErrorCode `json:"code"`
	DocURL  string    `json:"docUrl"`
	JobName string    `json:"jobName"`
}

///////////////////////
// Control functions //
///////////////////////

// Run executes the hardcoded job detection control
func (p *GitlabPipelineHardcodedJobsConf) Run(pipelineOriginData *collector.GitlabPipelineOriginData) *GitlabPipelineHardcodedJobsResult {
	l := l.WithFields(logrus.Fields{
		"control":        "GitlabPipelineHardcodedJobs",
		"controlVersion": ControlTypeGitlabPipelineOriginHardcodedJobsVersion,
	})
	l.Info("Start hardcoded jobs control")

	result := &GitlabPipelineHardcodedJobsResult{
		Issues:     []GitlabPipelineHardcodedJobIssue{},
		Metrics:    GitlabPipelineHardcodedJobsMetrics{},
		Compliance: 100.0,
		Version:    ControlTypeGitlabPipelineOriginHardcodedJobsVersion,
		CiValid:    pipelineOriginData.CiValid,
		CiMissing:  pipelineOriginData.CiMissing,
		Skipped:    false,
	}

	// Check if control is enabled
	if !p.Enabled {
		l.Info("Hardcoded jobs control is disabled, skipping")
		result.Skipped = true
		return result
	}

	// If CI is invalid or missing, return early
	if !pipelineOriginData.CiValid || pipelineOriginData.CiMissing {
		result.Compliance = 0.0
		if !pipelineOriginData.CiValid {
			result.Metrics.CiInvalid = 1
		}
		if pipelineOriginData.CiMissing {
			result.Metrics.CiMissing = 1
		}
		return result
	}

	// Loop over all jobs to check for hardcoded ones
	for jobName, isHardcoded := range pipelineOriginData.JobHardcodedMap {
		if isHardcoded {
			l.WithField("jobName", jobName).Debug("Found hardcoded job")

			issue := GitlabPipelineHardcodedJobIssue{
				Code:    CodeJobHardcoded,
				DocURL:  CodeJobHardcoded.DocURL(),
				JobName: jobName,
			}
			result.Issues = append(result.Issues, issue)
			result.Metrics.HardcodedJobs++
		}
	}

	// Calculate compliance based on issues
	if len(result.Issues) > 0 {
		result.Compliance = 0.0
		l.WithField("issuesCount", len(result.Issues)).Debug("Found hardcoded jobs, setting compliance to 0")
	}

	// Set metrics
	result.Metrics.Total = uint(len(pipelineOriginData.JobMap))

	l.WithFields(logrus.Fields{
		"totalJobs":          result.Metrics.Total,
		"hardcodedJobsCount": result.Metrics.HardcodedJobs,
		"compliance":         result.Compliance,
	}).Info("Hardcoded jobs control completed")

	return result
}
