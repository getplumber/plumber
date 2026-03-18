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

const ControlTypeGitlabPipelineUnverifiedScriptsVersion = "0.1.0"

//////////////////
// Control conf //
//////////////////

// GitlabPipelineUnverifiedScriptsConf holds the configuration for unverified script execution detection
type GitlabPipelineUnverifiedScriptsConf struct {
	Enabled     bool     `json:"enabled"`
	TrustedUrls []string `json:"trustedUrls"`
}

// GetConf loads configuration from PlumberConfig
func (p *GitlabPipelineUnverifiedScriptsConf) GetConf(plumberConfig *configuration.PlumberConfig) error {
	if plumberConfig == nil {
		p.Enabled = false
		return nil
	}

	cfg := plumberConfig.GetPipelineMustNotExecuteUnverifiedScriptsConfig()
	if cfg == nil {
		l.Debug("pipelineMustNotExecuteUnverifiedScripts control configuration is missing from .plumber.yaml file, skipping")
		p.Enabled = false
		return nil
	}

	if cfg.Enabled == nil {
		return fmt.Errorf("pipelineMustNotExecuteUnverifiedScripts.enabled field is required in .plumber.yaml config file")
	}

	p.Enabled = cfg.IsEnabled()
	p.TrustedUrls = cfg.TrustedUrls

	l.WithFields(logrus.Fields{
		"enabled":     p.Enabled,
		"trustedUrls": len(p.TrustedUrls),
	}).Debug("pipelineMustNotExecuteUnverifiedScripts control configuration loaded from .plumber.yaml file")

	return nil
}

////////////////////////////
// Control data & metrics //
////////////////////////////

// GitlabPipelineUnverifiedScriptsMetrics holds metrics about unverified script detection
type GitlabPipelineUnverifiedScriptsMetrics struct {
	JobsChecked             uint `json:"jobsChecked"`
	TotalScriptLinesChecked uint `json:"totalScriptLinesChecked"`
	UnverifiedScriptsFound  uint `json:"unverifiedScriptsFound"`
}

// GitlabPipelineUnverifiedScriptsResult holds the result of the control
type GitlabPipelineUnverifiedScriptsResult struct {
	Issues     []GitlabPipelineUnverifiedScriptsIssue  `json:"issues"`
	Metrics    GitlabPipelineUnverifiedScriptsMetrics   `json:"metrics"`
	Compliance float64                                  `json:"compliance"`
	Version    string                                   `json:"version"`
	CiValid    bool                                     `json:"ciValid"`
	CiMissing  bool                                     `json:"ciMissing"`
	Skipped    bool                                     `json:"skipped"`
	Error      string                                   `json:"error,omitempty"`
}

////////////////////
// Control issues //
////////////////////

// GitlabPipelineUnverifiedScriptsIssue represents an unverified script execution found in a CI job
type GitlabPipelineUnverifiedScriptsIssue struct {
	Code        ErrorCode `json:"code"`
	DocURL      string    `json:"docUrl"`
	JobName     string    `json:"jobName"`
	ScriptLine  string    `json:"scriptLine"`
	ScriptBlock string    `json:"scriptBlock"`
	PatternType string    `json:"patternType"`
}

///////////////////////
// Control functions //
///////////////////////

// Compiled regexes for detecting unverified script execution patterns.

// pipeToShell: curl ... | bash, wget ... | sh, etc. (with optional sudo)
var pipeToShellRe = regexp.MustCompile(
	`(?i)(curl|wget)\s+[^|]*\|\s*(sudo\s+)?(bash|sh|zsh|python[23]?|perl|ruby)\b`,
)

// downloadAndExec: curl -o file && bash file, wget -O file && sh file
var downloadAndExecRe = regexp.MustCompile(
	`(?i)(curl|wget)\s+.*(-o|-O)\s+(\S+).*&&\s*(sudo\s+)?(bash|sh|source|\.)\s+`,
)

// downloadRedirectExec: curl ... > file.sh; sh file.sh
var downloadRedirectExecRe = regexp.MustCompile(
	`(?i)(curl|wget)\s+.*>\s*(\S+\.sh)\s*[;&]+\s*(sudo\s+)?(bash|sh|source|\.)\s+`,
)

// checksumVerificationRe matches lines that include a checksum or signature
// verification step between the download and execution. These lines show that
// the user is verifying integrity before running the script.
var checksumVerificationRe = regexp.MustCompile(
	`(?i)(sha256sum|sha512sum|sha1sum|md5sum|shasum|gpg\s+--verify|gpg2\s+--verify|cosign\s+verify)`,
)

var unverifiedScriptPatterns = []struct {
	re          *regexp.Regexp
	patternType string
}{
	{pipeToShellRe, "pipe-to-shell"},
	{downloadAndExecRe, "download-and-execute"},
	{downloadRedirectExecRe, "download-redirect-execute"},
}

// Run executes the unverified script execution detection control
func (p *GitlabPipelineUnverifiedScriptsConf) Run(pipelineOriginData *collector.GitlabPipelineOriginData) *GitlabPipelineUnverifiedScriptsResult {
	l := l.WithFields(logrus.Fields{
		"control":        "GitlabPipelineUnverifiedScripts",
		"controlVersion": ControlTypeGitlabPipelineUnverifiedScriptsVersion,
	})
	l.Info("Start unverified script execution detection control")

	result := &GitlabPipelineUnverifiedScriptsResult{
		Issues:     []GitlabPipelineUnverifiedScriptsIssue{},
		Metrics:    GitlabPipelineUnverifiedScriptsMetrics{},
		Compliance: 100.0,
		Version:    ControlTypeGitlabPipelineUnverifiedScriptsVersion,
		CiValid:    pipelineOriginData.CiValid,
		CiMissing:  pipelineOriginData.CiMissing,
		Skipped:    false,
	}

	if !p.Enabled {
		l.Info("Unverified script execution detection control is disabled, skipping")
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

	// Compile trusted URL patterns into regexes for matching
	trustedPatterns := compileTrustedURLPatterns(p.TrustedUrls)

	// Check global before_script and after_script
	p.scanForUnverifiedScripts(mergedConf.BeforeScript, "(global)", "before_script", trustedPatterns, result)
	p.scanForUnverifiedScripts(mergedConf.AfterScript, "(global)", "after_script", trustedPatterns, result)

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

		p.scanForUnverifiedScripts(job.Script, jobName, "script", trustedPatterns, result)
		p.scanForUnverifiedScripts(job.BeforeScript, jobName, "before_script", trustedPatterns, result)
		p.scanForUnverifiedScripts(job.AfterScript, jobName, "after_script", trustedPatterns, result)
	}

	if len(result.Issues) > 0 {
		result.Compliance = 0.0
	}

	l.WithFields(logrus.Fields{
		"compliance":             result.Compliance,
		"issuesFound":            len(result.Issues),
		"jobsChecked":            result.Metrics.JobsChecked,
		"totalScriptLines":       result.Metrics.TotalScriptLinesChecked,
		"unverifiedScriptsFound": result.Metrics.UnverifiedScriptsFound,
	}).Info("Unverified script execution detection control complete")

	return result
}

// scanForUnverifiedScripts checks a script block for unverified script execution patterns.
func (p *GitlabPipelineUnverifiedScriptsConf) scanForUnverifiedScripts(
	scriptField interface{},
	jobName string,
	blockType string,
	trustedPatterns []*regexp.Regexp,
	result *GitlabPipelineUnverifiedScriptsResult,
) {
	lines := gitlab.GetScriptLines(scriptField)
	for _, line := range lines {
		result.Metrics.TotalScriptLinesChecked++

		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		for _, pattern := range unverifiedScriptPatterns {
			if pattern.re.MatchString(trimmed) {
				if containsTrustedURL(trimmed, trustedPatterns) {
					continue
				}
				if checksumVerificationRe.MatchString(trimmed) {
					continue
				}

				result.Issues = append(result.Issues, GitlabPipelineUnverifiedScriptsIssue{
					Code:        CodeUnverifiedScriptExecution,
					DocURL:      CodeUnverifiedScriptExecution.DocURL(),
					JobName:     jobName,
					ScriptLine:  truncateScriptLine(trimmed, 200),
					ScriptBlock: blockType,
					PatternType: pattern.patternType,
				})
				result.Metrics.UnverifiedScriptsFound++
				break
			}
		}
	}
}

// compileTrustedURLPatterns converts trusted URL patterns into compiled regexes.
// Each pattern is matched exactly unless it contains a wildcard (*), which
// matches any sequence of characters. Patterns are anchored so that
// "https://example.com" only matches that exact URL, not subpaths. Use
// "https://example.com/*" to match all subpaths.
func compileTrustedURLPatterns(trustedUrls []string) []*regexp.Regexp {
	var patterns []*regexp.Regexp
	for _, u := range trustedUrls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		escaped := regexp.QuoteMeta(u)
		// Convert \* (escaped wildcard) back to .* for glob-style matching
		regexStr := `(?:^|[\s"'])` + strings.ReplaceAll(escaped, `\*`, `.*`) + `(?:$|[\s"'])`
		re, err := regexp.Compile(regexStr)
		if err != nil {
			l.WithError(err).WithField("pattern", u).Warn("Invalid trusted URL pattern, skipping")
			continue
		}
		patterns = append(patterns, re)
	}
	return patterns
}

// containsTrustedURL checks whether the script line contains a URL that matches
// any of the compiled trusted URL patterns.
func containsTrustedURL(line string, trustedPatterns []*regexp.Regexp) bool {
	for _, re := range trustedPatterns {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// truncateScriptLine truncates a script line to the given max length.
func truncateScriptLine(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
