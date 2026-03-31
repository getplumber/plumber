package control

import (
	"fmt"
	"strings"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	"github.com/sirupsen/logrus"
)

const ControlTypeGitlabPipelineJobVariablesOverrideVersion = "0.1.0"

//////////////////
// Control conf //
//////////////////

// GitlabPipelineJobVariablesOverrideConf holds the configuration for job variable override detection
type GitlabPipelineJobVariablesOverrideConf struct {
	Enabled   bool     `json:"enabled"`
	Variables []string `json:"variables"`
}

// GetConf loads configuration from PlumberConfig.
// If config is nil or the control section is missing, the control is disabled (skipped).
func (p *GitlabPipelineJobVariablesOverrideConf) GetConf(plumberConfig *configuration.PlumberConfig) error {
	if plumberConfig == nil {
		p.Enabled = false
		return nil
	}

	cfg := plumberConfig.GetPipelineMustNotOverrideJobVariablesConfig()
	if cfg == nil {
		l.Debug("pipelineMustNotOverrideJobVariables control configuration is missing from .plumber.yaml file, skipping")
		p.Enabled = false
		return nil
	}

	if cfg.Enabled == nil {
		return fmt.Errorf("pipelineMustNotOverrideJobVariables.enabled field is required in .plumber.yaml config file")
	}

	p.Enabled = cfg.IsEnabled()
	p.Variables = cfg.Variables

	l.WithFields(logrus.Fields{
		"enabled":   p.Enabled,
		"variables": p.Variables,
	}).Debug("pipelineMustNotOverrideJobVariables control configuration loaded from .plumber.yaml file")

	return nil
}

////////////////////////////
// Control data & metrics //
////////////////////////////

// GitlabPipelineJobVariablesOverrideMetrics holds metrics about variable override detection
type GitlabPipelineJobVariablesOverrideMetrics struct {
	TotalVariablesChecked uint `json:"totalVariablesChecked"`
	OverriddenFound       uint `json:"overriddenFound"`
}

// GitlabPipelineJobVariablesOverrideResult holds the result of the control
type GitlabPipelineJobVariablesOverrideResult struct {
	Issues     []GitlabPipelineJobVariablesOverrideIssue  `json:"issues"`
	Metrics    GitlabPipelineJobVariablesOverrideMetrics   `json:"metrics"`
	Compliance float64                                     `json:"compliance"`
	Version    string                                      `json:"version"`
	CiValid    bool                                        `json:"ciValid"`
	CiMissing  bool                                        `json:"ciMissing"`
	Skipped    bool                                        `json:"skipped"`
	Error      string                                      `json:"error,omitempty"`
}

////////////////////
// Control issues //
////////////////////

// GitlabPipelineJobVariablesOverrideIssue represents a variable that should not be defined in the CI config
type GitlabPipelineJobVariablesOverrideIssue struct {
	Code         ErrorCode `json:"code"`
	DocURL       string    `json:"docUrl"`
	VariableName string    `json:"variableName"`
	Value        string    `json:"value"`
	Location     string    `json:"location"` // "global" or job name
}

///////////////////////
// Control functions //
///////////////////////

// Run executes the job variable override detection control.
// It scans the raw (pre-merge) CI config so that only variables the user
// actually wrote in .gitlab-ci.yml are checked. Variables injected by
// included templates/components are ignored.
func (p *GitlabPipelineJobVariablesOverrideConf) Run(pipelineOriginData *collector.GitlabPipelineOriginData) *GitlabPipelineJobVariablesOverrideResult {
	l := l.WithFields(logrus.Fields{
		"control":        "GitlabPipelineJobVariablesOverride",
		"controlVersion": ControlTypeGitlabPipelineJobVariablesOverrideVersion,
	})
	l.Info("Start job variable override detection control")

	result := &GitlabPipelineJobVariablesOverrideResult{
		Issues:     []GitlabPipelineJobVariablesOverrideIssue{},
		Metrics:    GitlabPipelineJobVariablesOverrideMetrics{},
		Compliance: 100.0,
		Version:    ControlTypeGitlabPipelineJobVariablesOverrideVersion,
		CiValid:    pipelineOriginData.CiValid,
		CiMissing:  pipelineOriginData.CiMissing,
		Skipped:    false,
	}

	if !p.Enabled {
		l.Info("Job variable override detection control is disabled, skipping")
		result.Skipped = true
		return result
	}

	if len(p.Variables) == 0 {
		l.Info("No variables configured, skipping")
		result.Skipped = true
		return result
	}

	// Use the raw (pre-merge) config so we only see variables the user
	// actually wrote, not variables injected by included templates.
	rawConf := pipelineOriginData.Conf
	if rawConf == nil {
		l.Warn("Raw CI configuration not available, cannot check variables")
		result.Compliance = 0
		result.Error = "raw CI configuration not available"
		return result
	}

	// Build a set of variable names to detect (case-insensitive)
	varSet := make(map[string]bool, len(p.Variables))
	for _, v := range p.Variables {
		varSet[strings.ToUpper(v)] = true
	}

	// Check global variables
	globalVars, err := gitlab.ParseGlobalVariables(rawConf)
	if err != nil {
		l.WithError(err).Warn("Unable to parse global variables")
	} else {
		for key, value := range globalVars {
			result.Metrics.TotalVariablesChecked++
			if varSet[strings.ToUpper(key)] {
				result.Issues = append(result.Issues, GitlabPipelineJobVariablesOverrideIssue{
					Code:         CodeJobVariableOverridden,
					DocURL:       CodeJobVariableOverridden.DocURL(),
					VariableName: key,
					Value:        value,
					Location:     "global",
				})
				result.Metrics.OverriddenFound++
				l.WithFields(logrus.Fields{
					"variable": key,
					"value":    value,
					"location": "global",
				}).Debug("Overridden variable found in global variables")
			}
		}
	}

	// Check per-job variables (only jobs the user defined in .gitlab-ci.yml)
	for jobName, jobContent := range rawConf.GitlabJobs {
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
			if varSet[strings.ToUpper(key)] {
				result.Issues = append(result.Issues, GitlabPipelineJobVariablesOverrideIssue{
					Code:         CodeJobVariableOverridden,
					DocURL:       CodeJobVariableOverridden.DocURL(),
					VariableName: key,
					Value:        value,
					Location:     jobName,
				})
				result.Metrics.OverriddenFound++
				l.WithFields(logrus.Fields{
					"variable": key,
					"value":    value,
					"location": jobName,
				}).Debug("Overridden variable found in job variables")
			}
		}
	}

	if len(result.Issues) > 0 {
		result.Compliance = 0.0
		l.WithField("issuesCount", len(result.Issues)).Info("Overridden variables found, setting compliance to 0")
	}

	l.WithFields(logrus.Fields{
		"totalChecked":    result.Metrics.TotalVariablesChecked,
		"overriddenFound": result.Metrics.OverriddenFound,
		"compliance":      result.Compliance,
	}).Info("Job variable override detection control completed")

	return result
}
