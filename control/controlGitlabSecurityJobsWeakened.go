package control

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const ControlTypeGitlabSecurityJobsWeakenedVersion = "0.1.0"

//////////////////
// Control conf //
//////////////////

// GitlabSecurityJobsWeakenedConf holds the runtime configuration for this control
type GitlabSecurityJobsWeakenedConf struct {
	Enabled             bool
	SecurityJobPatterns []string
	AllowFailureCheck   bool
	RulesCheck          bool
	WhenManualCheck     bool
}

// GetConf loads configuration from PlumberConfig
func (p *GitlabSecurityJobsWeakenedConf) GetConf(plumberConfig *configuration.PlumberConfig) error {
	if plumberConfig == nil {
		p.Enabled = false
		return nil
	}

	cfg := plumberConfig.GetSecurityJobsMustNotBeWeakenedConfig()
	if cfg == nil {
		l.Debug("securityJobsMustNotBeWeakened control configuration is missing from .plumber.yaml file, skipping")
		p.Enabled = false
		return nil
	}

	if cfg.Enabled == nil {
		return fmt.Errorf("securityJobsMustNotBeWeakened.enabled field is required in .plumber.yaml config file")
	}

	p.Enabled = cfg.IsEnabled()
	p.SecurityJobPatterns = cfg.SecurityJobPatterns

	// Sub-control defaults: allowFailure off, rules on, whenManual on
	p.AllowFailureCheck = cfg.AllowFailureMustBeFalse.IsEnabled(false)
	p.RulesCheck = cfg.RulesMustNotBeRedefined.IsEnabled(true)
	p.WhenManualCheck = cfg.WhenMustNotBeManual.IsEnabled(true)

	l.WithFields(logrus.Fields{
		"enabled":           p.Enabled,
		"patterns":          p.SecurityJobPatterns,
		"allowFailureCheck": p.AllowFailureCheck,
		"rulesCheck":        p.RulesCheck,
		"whenManualCheck":   p.WhenManualCheck,
	}).Debug("securityJobsMustNotBeWeakened control configuration loaded from .plumber.yaml file")

	return nil
}

////////////////////////////
// Control data & metrics //
////////////////////////////

// GitlabSecurityJobsWeakenedMetrics holds metrics about security job weakening detection
type GitlabSecurityJobsWeakenedMetrics struct {
	SecurityJobsFound uint `json:"securityJobsFound"`
	WeakenedJobs      uint `json:"weakenedJobs"`
}

// GitlabSecurityJobsWeakenedResult holds the result of the security jobs weakened control
type GitlabSecurityJobsWeakenedResult struct {
	Issues     []GitlabSecurityJobsWeakenedIssue  `json:"issues"`
	Metrics    GitlabSecurityJobsWeakenedMetrics   `json:"metrics"`
	Compliance float64                             `json:"compliance"`
	Version    string                              `json:"version"`
	CiValid    bool                                `json:"ciValid"`
	CiMissing  bool                                `json:"ciMissing"`
	Skipped    bool                                `json:"skipped"`
	Error      string                              `json:"error,omitempty"`
}

////////////////////
// Control issues //
////////////////////

// GitlabSecurityJobsWeakenedIssue represents a weakened security job
type GitlabSecurityJobsWeakenedIssue struct {
	JobName    string `json:"jobName"`
	SubControl string `json:"subControl"` // "allowFailureMustBeFalse", "rulesMustNotBeRedefined", "whenMustNotBeManual"
	Detail     string `json:"detail"`
}

///////////////////////
// Control functions //
///////////////////////

// Run executes the security jobs weakening detection control
func (p *GitlabSecurityJobsWeakenedConf) Run(pipelineOriginData *collector.GitlabPipelineOriginData) *GitlabSecurityJobsWeakenedResult {
	l := l.WithFields(logrus.Fields{
		"control":        "GitlabSecurityJobsWeakened",
		"controlVersion": ControlTypeGitlabSecurityJobsWeakenedVersion,
	})
	l.Info("Start security jobs weakening detection control")

	result := &GitlabSecurityJobsWeakenedResult{
		Issues:     []GitlabSecurityJobsWeakenedIssue{},
		Metrics:    GitlabSecurityJobsWeakenedMetrics{},
		Compliance: 100.0,
		Version:    ControlTypeGitlabSecurityJobsWeakenedVersion,
		CiValid:    pipelineOriginData.CiValid,
		CiMissing:  pipelineOriginData.CiMissing,
		Skipped:    false,
	}

	if !p.Enabled {
		l.Info("Security jobs weakening detection control is disabled, skipping")
		result.Skipped = true
		return result
	}

	if !p.AllowFailureCheck && !p.RulesCheck && !p.WhenManualCheck {
		l.Info("All sub-controls are disabled, skipping")
		result.Skipped = true
		return result
	}

	if !pipelineOriginData.CiValid || pipelineOriginData.CiMissing {
		result.Compliance = 0.0
		return result
	}

	mergedConf := pipelineOriginData.MergedConf
	if mergedConf == nil {
		result.Compliance = 0
		result.Error = "merged CI configuration not available"
		return result
	}

	// Build set of security job names from two sources:
	// 1. Jobs originating from known security templates
	// 2. Jobs matching user-configured name patterns
	securityJobs := p.identifySecurityJobs(pipelineOriginData)

	result.Metrics.SecurityJobsFound = uint(len(securityJobs))

	if len(securityJobs) == 0 {
		l.Info("No security jobs found in pipeline")
		return result
	}

	// Track which jobs have been flagged to avoid double-counting in metrics
	weakenedSet := make(map[string]bool)

	// Sub-control 1: allowFailureMustBeFalse
	if p.AllowFailureCheck {
		for jobName := range securityJobs {
			jobContent, exists := mergedConf.GitlabJobs[jobName]
			if !exists {
				continue
			}
			job, err := gitlab.ParseGitlabCIJob(jobContent)
			if err != nil || job == nil {
				continue
			}
			if isAllowFailureTrue(job.AllowFailure) {
				result.Issues = append(result.Issues, GitlabSecurityJobsWeakenedIssue{
					JobName:    jobName,
					SubControl: "allowFailureMustBeFalse",
					Detail:     "allow_failure is true (should be false for blocking security)",
				})
				weakenedSet[jobName] = true
				l.WithField("job", jobName).Debug("Security job has allow_failure: true")
			}
		}
	}

	// Sub-control 2: rulesMustNotBeRedefined
	// Check the unmerged Conf (raw .gitlab-ci.yml) and JobHardcodedContent for rules overrides
	if p.RulesCheck {
		for jobName := range securityJobs {
			var rawContent interface{}
			found := false

			// First check raw .gitlab-ci.yml (unmerged Conf)
			if pipelineOriginData.Conf != nil {
				if content, exists := pipelineOriginData.Conf.GitlabJobs[jobName]; exists {
					rawContent = content
					found = true
				}
			}

			// Fall back to JobHardcodedContent (covers local overrides)
			if !found {
				if content, exists := pipelineOriginData.JobHardcodedContent[jobName]; exists {
					rawContent = content
					found = true
				}
			}

			if !found {
				continue
			}

			rulesOverride := extractRulesFromRawContent(rawContent)
			if rulesOverride == nil {
				continue
			}

			for _, rule := range rulesOverride {
				whenVal := strings.ToLower(strings.TrimSpace(rule.When))
				if whenVal == "never" {
					result.Issues = append(result.Issues, GitlabSecurityJobsWeakenedIssue{
						JobName:    jobName,
						SubControl: "rulesMustNotBeRedefined",
						Detail:     "rules overridden with 'when: never', job will not run",
					})
					weakenedSet[jobName] = true
					l.WithField("job", jobName).Debug("Security job has rules overridden with when: never")
					break
				}
				if whenVal == "manual" {
					result.Issues = append(result.Issues, GitlabSecurityJobsWeakenedIssue{
						JobName:    jobName,
						SubControl: "rulesMustNotBeRedefined",
						Detail:     "rules overridden with 'when: manual', job requires manual trigger",
					})
					weakenedSet[jobName] = true
					l.WithField("job", jobName).Debug("Security job has rules overridden with when: manual")
					break
				}
			}
		}
	}

	// Sub-control 3: whenMustNotBeManual
	if p.WhenManualCheck {
		for jobName := range securityJobs {
			jobContent, exists := mergedConf.GitlabJobs[jobName]
			if !exists {
				continue
			}
			job, err := gitlab.ParseGitlabCIJob(jobContent)
			if err != nil || job == nil {
				continue
			}
			if isWhenManual(job.When) {
				result.Issues = append(result.Issues, GitlabSecurityJobsWeakenedIssue{
					JobName:    jobName,
					SubControl: "whenMustNotBeManual",
					Detail:     "when set to 'manual', job requires manual trigger",
				})
				weakenedSet[jobName] = true
				l.WithField("job", jobName).Debug("Security job has when: manual")
			}
		}
	}

	result.Metrics.WeakenedJobs = uint(len(weakenedSet))

	if len(result.Issues) > 0 {
		result.Compliance = 0.0
		l.WithField("issuesCount", len(result.Issues)).Info("Weakened security jobs found, setting compliance to 0")
	}

	l.WithFields(logrus.Fields{
		"securityJobsFound": result.Metrics.SecurityJobsFound,
		"weakenedJobs":      result.Metrics.WeakenedJobs,
		"compliance":        result.Compliance,
	}).Info("Security jobs weakening detection control completed")

	return result
}

// identifySecurityJobs returns a set of job names that are considered security jobs.
// A job qualifies if its name matches any of the user-configured securityJobPatterns.
func (p *GitlabSecurityJobsWeakenedConf) identifySecurityJobs(data *collector.GitlabPipelineOriginData) map[string]bool {
	securityJobs := make(map[string]bool)

	if len(p.SecurityJobPatterns) == 0 || data.MergedConf == nil {
		return securityJobs
	}

	for jobName := range data.MergedConf.GitlabJobs {
		if matchesAnyPattern(jobName, p.SecurityJobPatterns) {
			securityJobs[jobName] = true
		}
	}

	return securityJobs
}

// matchesAnyPattern checks if a job name matches any of the provided glob patterns
func matchesAnyPattern(jobName string, patterns []string) bool {
	for _, pattern := range patterns {
		matched, err := filepath.Match(pattern, jobName)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// isAllowFailureTrue checks if the allow_failure field is set to true.
// allow_failure can be a bool, a string "true", or a map with exit_codes.
func isAllowFailureTrue(af interface{}) bool {
	if af == nil {
		return false
	}
	switch v := af.(type) {
	case bool:
		return v
	case string:
		return strings.ToLower(strings.TrimSpace(v)) == "true"
	case map[interface{}]interface{}:
		// allow_failure: {exit_codes: [1, 2]} is a partial allow, treat as true
		return true
	}
	return false
}

// isWhenManual checks if the when field is set to "manual"
func isWhenManual(when interface{}) bool {
	if when == nil {
		return false
	}
	switch v := when.(type) {
	case string:
		return strings.ToLower(strings.TrimSpace(v)) == "manual"
	}
	return false
}

// extractRulesFromRawContent extracts the rules from a raw job content (interface{})
// and parses them into a slice of Rule structs.
func extractRulesFromRawContent(rawContent interface{}) []gitlab.Rule {
	contentMap, ok := rawContent.(map[interface{}]interface{})
	if !ok {
		// Try string-keyed map (from JSON or some YAML parsers)
		if strMap, ok2 := rawContent.(map[string]interface{}); ok2 {
			contentMap = make(map[interface{}]interface{}, len(strMap))
			for k, v := range strMap {
				contentMap[k] = v
			}
		} else {
			return nil
		}
	}

	rulesRaw, exists := contentMap["rules"]
	if !exists {
		return nil
	}

	// Marshal and unmarshal to get properly typed rules
	yamlData, err := yaml.Marshal(rulesRaw)
	if err != nil {
		return nil
	}

	var rules []gitlab.Rule
	if err := yaml.Unmarshal(yamlData, &rules); err != nil {
		return nil
	}

	return rules
}
