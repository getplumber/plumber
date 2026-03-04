package control

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	"github.com/sirupsen/logrus"
)

const ControlTypeGitlabPipelineVariableInjectionVersion = "0.1.0"

//////////////////
// Control conf //
//////////////////

// GitlabPipelineVariableInjectionConf holds the configuration for unsafe variable expansion detection
type GitlabPipelineVariableInjectionConf struct {
	Enabled            bool     `json:"enabled"`
	DangerousVariables []string `json:"dangerousVariables"`
	AllowedPatterns    []string `json:"allowedPatterns"`
}

// GetConf loads configuration from PlumberConfig
func (p *GitlabPipelineVariableInjectionConf) GetConf(plumberConfig *configuration.PlumberConfig) error {
	if plumberConfig == nil {
		p.Enabled = false
		return nil
	}

	cfg := plumberConfig.GetPipelineMustNotUseUnsafeVariableExpansionConfig()
	if cfg == nil {
		l.Debug("pipelineMustNotUseUnsafeVariableExpansion control configuration is missing from .plumber.yaml file, skipping")
		p.Enabled = false
		return nil
	}

	if cfg.Enabled == nil {
		return fmt.Errorf("pipelineMustNotUseUnsafeVariableExpansion.enabled field is required in .plumber.yaml config file")
	}

	p.Enabled = cfg.IsEnabled()
	p.DangerousVariables = cfg.DangerousVariables
	p.AllowedPatterns = cfg.AllowedPatterns

	l.WithFields(logrus.Fields{
		"enabled":            p.Enabled,
		"dangerousVariables": len(p.DangerousVariables),
		"allowedPatterns":    len(p.AllowedPatterns),
	}).Debug("pipelineMustNotUseUnsafeVariableExpansion control configuration loaded from .plumber.yaml file")

	return nil
}

////////////////////////////
// Control data & metrics //
////////////////////////////

// GitlabPipelineVariableInjectionMetrics holds metrics about unsafe variable expansion detection
type GitlabPipelineVariableInjectionMetrics struct {
	JobsChecked             uint `json:"jobsChecked"`
	TotalScriptLinesChecked uint `json:"totalScriptLinesChecked"`
	UnsafeExpansionsFound   uint `json:"unsafeExpansionsFound"`
}

// GitlabPipelineVariableInjectionResult holds the result of the control
type GitlabPipelineVariableInjectionResult struct {
	Issues     []GitlabPipelineVariableInjectionIssue `json:"issues"`
	Metrics    GitlabPipelineVariableInjectionMetrics  `json:"metrics"`
	Compliance float64                                 `json:"compliance"`
	Version    string                                  `json:"version"`
	CiValid    bool                                    `json:"ciValid"`
	CiMissing  bool                                    `json:"ciMissing"`
	Skipped    bool                                    `json:"skipped"`
	Error      string                                  `json:"error,omitempty"`
}

////////////////////
// Control issues //
////////////////////

// GitlabPipelineVariableInjectionIssue represents a dangerous variable found in a code-execution context
type GitlabPipelineVariableInjectionIssue struct {
	JobName      string `json:"jobName"`
	VariableName string `json:"variableName"`
	ScriptLine   string `json:"scriptLine"`
	ScriptBlock  string `json:"scriptBlock"` // "script", "before_script", "after_script"
}

///////////////////////
// Control functions //
///////////////////////

// Patterns that introduce a shell re-interpretation context.
// A variable expanded by the outer shell and passed to one of these
// is re-parsed as code, enabling command injection.
var shellReparsePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\beval\b`),
	regexp.MustCompile(`\bsh\s+-c\b`),
	regexp.MustCompile(`\bbash\s+-c\b`),
	regexp.MustCompile(`\bdash\s+-c\b`),
	regexp.MustCompile(`\bzsh\s+-c\b`),
	regexp.MustCompile(`\bksh\s+-c\b`),
	regexp.MustCompile(`\benvsubst\b.*\|\s*(sh|bash|dash|zsh)`),
	regexp.MustCompile(`\bxargs\s+(sh|bash)\b`),
	regexp.MustCompile(`\bsource\b`),
	regexp.MustCompile(`^\s*\.(\s|$)`),
}

// isShellReparseContext returns true if the line contains a command that
// re-interprets its arguments as shell code (eval, sh -c, bash -c, etc.).
func isShellReparseContext(line string) bool {
	for _, re := range shellReparsePatterns {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// Run executes the unsafe variable expansion detection control.
//
// GitLab CI sets CI variables as environment variables; the shell does
// NOT re-parse expanded values for command substitution. So plain usage
// like `echo $CI_COMMIT_BRANCH` is safe: the shell treats the expanded
// value as an inert string.
//
// The real injection surface is commands that RE-INTERPRET their input
// as shell code: eval, sh -c, bash -c, source, etc. A user-controlled
// variable passed to these is executed as code.
func (p *GitlabPipelineVariableInjectionConf) Run(pipelineOriginData *collector.GitlabPipelineOriginData) *GitlabPipelineVariableInjectionResult {
	l := l.WithFields(logrus.Fields{
		"control":        "GitlabPipelineVariableInjection",
		"controlVersion": ControlTypeGitlabPipelineVariableInjectionVersion,
	})
	l.Info("Start unsafe variable expansion detection control")

	result := &GitlabPipelineVariableInjectionResult{
		Issues:     []GitlabPipelineVariableInjectionIssue{},
		Metrics:    GitlabPipelineVariableInjectionMetrics{},
		Compliance: 100.0,
		Version:    ControlTypeGitlabPipelineVariableInjectionVersion,
		CiValid:    pipelineOriginData.CiValid,
		CiMissing:  pipelineOriginData.CiMissing,
		Skipped:    false,
	}

	if !p.Enabled {
		l.Info("Unsafe variable expansion detection control is disabled, skipping")
		result.Skipped = true
		return result
	}

	if len(p.DangerousVariables) == 0 {
		l.Info("No dangerous variables configured, skipping")
		result.Skipped = true
		return result
	}

	mergedConf := pipelineOriginData.MergedConf
	if mergedConf == nil {
		l.Warn("Merged CI configuration not available, cannot check scripts")
		result.Compliance = 0
		result.Error = "merged CI configuration not available"
		return result
	}

	// Build regexes for each dangerous variable.
	// Match $VAR or ${VAR} ensuring the unbraced form has a word boundary.
	varRegexes := make(map[string]*regexp.Regexp, len(p.DangerousVariables))
	for _, v := range p.DangerousVariables {
		pattern := fmt.Sprintf(`\$(?:\{%s\}|%s(?:[^a-zA-Z0-9_]|$))`, regexp.QuoteMeta(v), regexp.QuoteMeta(v))
		varRegexes[v] = regexp.MustCompile(pattern)
	}

	// Compile allowed patterns
	var allowedRegexes []*regexp.Regexp
	for _, pat := range p.AllowedPatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			l.WithError(err).WithField("pattern", pat).Warn("Invalid allowed pattern, ignoring")
			continue
		}
		allowedRegexes = append(allowedRegexes, re)
	}

	// Check global before_script and after_script
	p.scanScriptBlock(mergedConf.BeforeScript, "(global)", "before_script", varRegexes, allowedRegexes, result)
	p.scanScriptBlock(mergedConf.AfterScript, "(global)", "after_script", varRegexes, allowedRegexes, result)

	// Check per-job scripts
	for jobName, jobContent := range mergedConf.GitlabJobs {
		job, err := gitlab.ParseGitlabCIJob(jobContent)
		if err != nil {
			l.WithError(err).WithField("job", jobName).Debug("Unable to parse job, skipping")
			continue
		}
		if job == nil {
			continue
		}

		result.Metrics.JobsChecked++

		p.scanScriptBlock(job.Script, jobName, "script", varRegexes, allowedRegexes, result)
		p.scanScriptBlock(job.BeforeScript, jobName, "before_script", varRegexes, allowedRegexes, result)
		p.scanScriptBlock(job.AfterScript, jobName, "after_script", varRegexes, allowedRegexes, result)
	}

	if len(result.Issues) > 0 {
		result.Compliance = 0.0
		l.WithField("issuesCount", len(result.Issues)).Info("Unsafe variable expansions found, setting compliance to 0")
	}

	l.WithFields(logrus.Fields{
		"jobsChecked":            result.Metrics.JobsChecked,
		"totalScriptLines":      result.Metrics.TotalScriptLinesChecked,
		"unsafeExpansionsFound":  result.Metrics.UnsafeExpansionsFound,
		"compliance":            result.Compliance,
	}).Info("Unsafe variable expansion detection control completed")

	return result
}

// scanScriptBlock scans a script block for dangerous variables used in
// shell re-interpretation contexts (eval, sh -c, bash -c, etc.).
func (p *GitlabPipelineVariableInjectionConf) scanScriptBlock(
	scriptField interface{},
	jobName string,
	blockType string,
	varRegexes map[string]*regexp.Regexp,
	allowedRegexes []*regexp.Regexp,
	result *GitlabPipelineVariableInjectionResult,
) {
	lines := gitlab.GetScriptLines(scriptField)
	for _, line := range lines {
		result.Metrics.TotalScriptLinesChecked++

		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if !isShellReparseContext(trimmed) {
			continue
		}

		if isAllowedLine(trimmed, allowedRegexes) {
			continue
		}

		for varName, re := range varRegexes {
			if re.MatchString(line) {
				result.Issues = append(result.Issues, GitlabPipelineVariableInjectionIssue{
					JobName:      jobName,
					VariableName: varName,
					ScriptLine:   truncateLine(trimmed, 200),
					ScriptBlock:  blockType,
				})
				result.Metrics.UnsafeExpansionsFound++
			}
		}
	}
}

// isAllowedLine returns true if the line matches any of the allowed patterns
func isAllowedLine(line string, allowedRegexes []*regexp.Regexp) bool {
	for _, re := range allowedRegexes {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// truncateLine shortens a script line for display, appending "..." if truncated
func truncateLine(line string, maxLen int) string {
	if len(line) <= maxLen {
		return line
	}
	return line[:maxLen] + "..."
}
