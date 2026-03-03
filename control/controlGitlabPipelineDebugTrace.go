package control

import (
	"fmt"
	"strings"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	"github.com/sirupsen/logrus"
)

const ControlTypeGitlabPipelineDebugTraceVersion = "0.1.0"

//////////////////
// Control conf //
//////////////////

// GitlabPipelineDebugTraceConf holds the configuration for debug trace detection
type GitlabPipelineDebugTraceConf struct {
	// Enabled controls whether this check runs
	Enabled bool `json:"enabled"`

	// ForbiddenVariables is a list of CI/CD variable names that must not be set to "true"
	ForbiddenVariables []string `json:"forbiddenVariables"`
}

// GetConf loads configuration from PlumberConfig
// If config is nil or the control section is missing, the control is disabled (skipped).
func (p *GitlabPipelineDebugTraceConf) GetConf(plumberConfig *configuration.PlumberConfig) error {
	if plumberConfig == nil {
		p.Enabled = false
		return nil
	}

	debugTraceConfig := plumberConfig.GetPipelineMustNotEnableDebugTraceConfig()
	if debugTraceConfig == nil {
		l.Debug("pipelineMustNotEnableDebugTrace control configuration is missing from .plumber.yaml file, skipping")
		p.Enabled = false
		return nil
	}

	if debugTraceConfig.Enabled == nil {
		return fmt.Errorf("pipelineMustNotEnableDebugTrace.enabled field is required in .plumber.yaml config file")
	}

	p.Enabled = debugTraceConfig.IsEnabled()
	p.ForbiddenVariables = debugTraceConfig.ForbiddenVariables

	l.WithFields(logrus.Fields{
		"enabled":            p.Enabled,
		"forbiddenVariables": p.ForbiddenVariables,
	}).Debug("pipelineMustNotEnableDebugTrace control configuration loaded from .plumber.yaml file")

	return nil
}

////////////////////////////
// Control data & metrics //
////////////////////////////

// GitlabPipelineDebugTraceMetrics holds metrics about debug trace detection
type GitlabPipelineDebugTraceMetrics struct {
	TotalVariablesChecked uint `json:"totalVariablesChecked"`
	ForbiddenFound        uint `json:"forbiddenFound"`
}

// GitlabPipelineDebugTraceResult holds the result of the debug trace control
type GitlabPipelineDebugTraceResult struct {
	Issues     []GitlabPipelineDebugTraceIssue  `json:"issues"`
	Metrics    GitlabPipelineDebugTraceMetrics  `json:"metrics"`
	Compliance float64                          `json:"compliance"`
	Version    string                           `json:"version"`
	CiValid    bool                             `json:"ciValid"`
	CiMissing  bool                             `json:"ciMissing"`
	Skipped    bool                             `json:"skipped"`
	Error      string                           `json:"error,omitempty"`
}

////////////////////
// Control issues //
////////////////////

// GitlabPipelineDebugTraceIssue represents a forbidden debug variable found in the CI config
type GitlabPipelineDebugTraceIssue struct {
	VariableName string `json:"variableName"`
	Value        string `json:"value"`
	Location     string `json:"location"` // "global" or job name
}

///////////////////////
// Control functions //
///////////////////////

// Run executes the debug trace detection control
func (p *GitlabPipelineDebugTraceConf) Run(pipelineOriginData *collector.GitlabPipelineOriginData) *GitlabPipelineDebugTraceResult {
	l := l.WithFields(logrus.Fields{
		"control":        "GitlabPipelineDebugTrace",
		"controlVersion": ControlTypeGitlabPipelineDebugTraceVersion,
	})
	l.Info("Start debug trace detection control")

	result := &GitlabPipelineDebugTraceResult{
		Issues:     []GitlabPipelineDebugTraceIssue{},
		Metrics:    GitlabPipelineDebugTraceMetrics{},
		Compliance: 100.0,
		Version:    ControlTypeGitlabPipelineDebugTraceVersion,
		CiValid:    pipelineOriginData.CiValid,
		CiMissing:  pipelineOriginData.CiMissing,
		Skipped:    false,
	}

	if !p.Enabled {
		l.Info("Debug trace detection control is disabled, skipping")
		result.Skipped = true
		return result
	}

	if len(p.ForbiddenVariables) == 0 {
		l.Info("No forbidden variables configured, skipping")
		result.Skipped = true
		return result
	}

	// Use merged conf to check variables after all includes are resolved
	mergedConf := pipelineOriginData.MergedConf
	if mergedConf == nil {
		l.Warn("Merged CI configuration not available, cannot check variables")
		result.Compliance = 0
		result.Error = "merged CI configuration not available"
		return result
	}

	// Build a set of forbidden variable names (case-insensitive)
	forbiddenSet := make(map[string]bool, len(p.ForbiddenVariables))
	for _, v := range p.ForbiddenVariables {
		forbiddenSet[strings.ToUpper(v)] = true
	}

	// Check global variables
	globalVars, err := gitlab.ParseGlobalVariables(mergedConf)
	if err != nil {
		l.WithError(err).Warn("Unable to parse global variables")
	} else {
		for key, value := range globalVars {
			result.Metrics.TotalVariablesChecked++
			if forbiddenSet[strings.ToUpper(key)] && isTrueValue(value) {
				result.Issues = append(result.Issues, GitlabPipelineDebugTraceIssue{
					VariableName: key,
					Value:        value,
					Location:     "global",
				})
				result.Metrics.ForbiddenFound++
				l.WithFields(logrus.Fields{
					"variable": key,
					"value":    value,
					"location": "global",
				}).Debug("Forbidden debug variable found in global variables")
			}
		}
	}

	// Check per-job variables
	for jobName, jobContent := range mergedConf.GitlabJobs {
		job, err := gitlab.ParseGitlabCIJob(jobContent)
		if err != nil {
			l.WithError(err).WithField("job", jobName).Debug("Unable to parse job, skipping")
			continue
		}
		if job == nil {
			continue
		}

		jobVars, err := gitlab.ParseJobVariables(job)
		if err != nil {
			l.WithError(err).WithField("job", jobName).Debug("Unable to parse job variables, skipping")
			continue
		}

		for key, value := range jobVars {
			result.Metrics.TotalVariablesChecked++
			if forbiddenSet[strings.ToUpper(key)] && isTrueValue(value) {
				result.Issues = append(result.Issues, GitlabPipelineDebugTraceIssue{
					VariableName: key,
					Value:        value,
					Location:     jobName,
				})
				result.Metrics.ForbiddenFound++
				l.WithFields(logrus.Fields{
					"variable": key,
					"value":    value,
					"location": jobName,
				}).Debug("Forbidden debug variable found in job variables")
			}
		}
	}

	// Calculate compliance
	if len(result.Issues) > 0 {
		result.Compliance = 0.0
		l.WithField("issuesCount", len(result.Issues)).Info("Forbidden debug variables found, setting compliance to 0")
	}

	l.WithFields(logrus.Fields{
		"totalChecked":  result.Metrics.TotalVariablesChecked,
		"forbiddenFound": result.Metrics.ForbiddenFound,
		"compliance":    result.Compliance,
	}).Info("Debug trace detection control completed")

	return result
}

// isTrueValue checks if a variable value is truthy
// GitLab considers "true", "1", "yes" as truthy for CI_DEBUG_TRACE
func isTrueValue(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	return v == "true" || v == "1" || v == "yes"
}
