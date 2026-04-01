package control

import (
	"fmt"
	"strings"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const ControlTypeGitlabPipelineDockerInDockerVersion = "0.1.0"

//////////////////
// Control conf //
//////////////////

// GitlabPipelineDockerInDockerConf holds the configuration for Docker-in-Docker detection
type GitlabPipelineDockerInDockerConf struct {
	Enabled              bool `json:"enabled"`
	DetectInsecureDaemon bool `json:"detectInsecureDaemon"`
}

// GetConf loads configuration from PlumberConfig.
// If config is nil or the control section is missing, the control is disabled (skipped).
func (p *GitlabPipelineDockerInDockerConf) GetConf(plumberConfig *configuration.PlumberConfig) error {
	if plumberConfig == nil {
		p.Enabled = false
		return nil
	}

	cfg := plumberConfig.GetPipelineMustNotUseDockerInDockerConfig()
	if cfg == nil {
		l.Debug("pipelineMustNotUseDockerInDocker control configuration is missing from .plumber.yaml file, skipping")
		p.Enabled = false
		return nil
	}

	if cfg.Enabled == nil {
		return fmt.Errorf("pipelineMustNotUseDockerInDocker.enabled field is required in .plumber.yaml config file")
	}

	p.Enabled = cfg.IsEnabled()
	p.DetectInsecureDaemon = cfg.IsDetectInsecureDaemonEnabled()

	l.WithFields(logrus.Fields{
		"enabled":              p.Enabled,
		"detectInsecureDaemon": p.DetectInsecureDaemon,
	}).Debug("pipelineMustNotUseDockerInDocker control configuration loaded from .plumber.yaml file")

	return nil
}

////////////////////////////
// Control data & metrics //
////////////////////////////

// GitlabPipelineDockerInDockerMetrics holds metrics about DinD detection
type GitlabPipelineDockerInDockerMetrics struct {
	TotalJobsChecked    uint `json:"totalJobsChecked"`
	DindServicesFound   uint `json:"dindServicesFound"`
	InsecureDaemonFound uint `json:"insecureDaemonFound"`
}

// GitlabPipelineDockerInDockerResult holds the result of the DinD control
type GitlabPipelineDockerInDockerResult struct {
	Issues     []GitlabPipelineDockerInDockerIssue  `json:"issues"`
	Metrics    GitlabPipelineDockerInDockerMetrics   `json:"metrics"`
	Compliance float64                               `json:"compliance"`
	Version    string                                `json:"version"`
	CiValid    bool                                  `json:"ciValid"`
	CiMissing  bool                                  `json:"ciMissing"`
	Skipped    bool                                  `json:"skipped"`
	Error      string                                `json:"error,omitempty"`
}

////////////////////
// Control issues //
////////////////////

// GitlabPipelineDockerInDockerIssue represents a DinD finding in the CI config
type GitlabPipelineDockerInDockerIssue struct {
	Code         ErrorCode `json:"code"`
	DocURL       string    `json:"docUrl"`
	JobName      string    `json:"jobName"`
	ServiceImage string    `json:"serviceImage,omitempty"`
	Detail       string    `json:"detail,omitempty"`
}

///////////////////////
// Control functions //
///////////////////////

// isDindImage returns true if the image name refers to a Docker-in-Docker service.
func isDindImage(image string) bool {
	image = strings.ToLower(strings.TrimSpace(image))
	if image == "" {
		return false
	}

	// Strip registry prefix to normalize (e.g. docker.io/docker:dind -> docker:dind)
	parts := strings.Split(image, "/")
	shortName := parts[len(parts)-1]

	// Match docker:dind, docker:*-dind, docker:latest
	if !strings.HasPrefix(shortName, "docker:") && shortName != "docker" {
		return false
	}

	// docker (no tag) is not necessarily dind
	if shortName == "docker" {
		return false
	}

	tag := strings.TrimPrefix(shortName, "docker:")
	if tag == "dind" || tag == "latest" {
		return true
	}
	// Match version-dind patterns like 27.3.1-dind, 27-dind-rootless
	if strings.Contains(tag, "dind") {
		return true
	}
	return false
}

// parseServiceNames extracts service image names from the Services field of a GitlabJob.
// GitLab allows services as a list of strings or a list of maps with a "name" key.
func parseServiceNames(services interface{}) []string {
	if services == nil {
		return nil
	}

	switch s := services.(type) {
	case []interface{}:
		var names []string
		for _, item := range s {
			switch entry := item.(type) {
			case string:
				names = append(names, entry)
			case map[interface{}]interface{}:
				// Try to parse as gitlab.Service struct
				svc := gitlab.Service{}
				yamlData, err := yaml.Marshal(entry)
				if err == nil {
					_ = yaml.Unmarshal(yamlData, &svc)
				}
				if svc.Name != "" {
					names = append(names, svc.Name)
				}
			}
		}
		return names
	default:
		return nil
	}
}

// Run executes the Docker-in-Docker detection control
func (p *GitlabPipelineDockerInDockerConf) Run(pipelineOriginData *collector.GitlabPipelineOriginData) *GitlabPipelineDockerInDockerResult {
	l := l.WithFields(logrus.Fields{
		"control":        "GitlabPipelineDockerInDocker",
		"controlVersion": ControlTypeGitlabPipelineDockerInDockerVersion,
	})
	l.Info("Start Docker-in-Docker detection control")

	result := &GitlabPipelineDockerInDockerResult{
		Issues:     []GitlabPipelineDockerInDockerIssue{},
		Metrics:    GitlabPipelineDockerInDockerMetrics{},
		Compliance: 100.0,
		Version:    ControlTypeGitlabPipelineDockerInDockerVersion,
		CiValid:    pipelineOriginData.CiValid,
		CiMissing:  pipelineOriginData.CiMissing,
		Skipped:    false,
	}

	if !p.Enabled {
		l.Info("Docker-in-Docker detection control is disabled, skipping")
		result.Skipped = true
		return result
	}

	mergedConf := pipelineOriginData.MergedConf
	if mergedConf == nil {
		l.Warn("Merged CI configuration not available, cannot check services")
		result.Compliance = 0
		result.Error = "merged CI configuration not available"
		return result
	}

	for jobName, jobContent := range mergedConf.GitlabJobs {
		job, err := gitlab.ParseGitlabCIJob(jobContent)
		if err != nil {
			l.WithError(err).WithField("job", jobName).Debug("Unable to parse job, skipping")
			continue
		}
		if job == nil {
			continue
		}

		result.Metrics.TotalJobsChecked++

		serviceNames := parseServiceNames(job.Services)
		hasDind := false
		var dindImage string

		for _, svc := range serviceNames {
			if isDindImage(svc) {
				hasDind = true
				dindImage = svc
				break
			}
		}

		if !hasDind {
			continue
		}

		// DinD service found: emit ISSUE-412
		result.Issues = append(result.Issues, GitlabPipelineDockerInDockerIssue{
			Code:         CodeDockerInDockerUsage,
			DocURL:       CodeDockerInDockerUsage.DocURL(),
			JobName:      jobName,
			ServiceImage: dindImage,
		})
		result.Metrics.DindServicesFound++

		l.WithFields(logrus.Fields{
			"job":     jobName,
			"service": dindImage,
		}).Debug("Docker-in-Docker service found")

		// If detectInsecureDaemon is enabled, check for insecure config in the same job
		if p.DetectInsecureDaemon {
			if detail := detectInsecureDaemon(job, mergedConf); detail != "" {
				result.Issues = append(result.Issues, GitlabPipelineDockerInDockerIssue{
					Code:    CodeDockerInDockerInsecure,
					DocURL:  CodeDockerInDockerInsecure.DocURL(),
					JobName: jobName,
					Detail:  detail,
				})
				result.Metrics.InsecureDaemonFound++

				l.WithFields(logrus.Fields{
					"job":    jobName,
					"detail": detail,
				}).Debug("Insecure Docker daemon configuration found")
			}
		}
	}

	if len(result.Issues) > 0 {
		result.Compliance = 0.0
		l.WithField("issuesCount", len(result.Issues)).Info("Docker-in-Docker issues found, setting compliance to 0")
	}

	l.WithFields(logrus.Fields{
		"totalJobsChecked":    result.Metrics.TotalJobsChecked,
		"dindServicesFound":   result.Metrics.DindServicesFound,
		"insecureDaemonFound": result.Metrics.InsecureDaemonFound,
		"compliance":          result.Compliance,
	}).Info("Docker-in-Docker detection control completed")

	return result
}

// detectInsecureDaemon checks job-level and global variables for insecure Docker daemon settings.
// Returns a description of the finding, or empty string if none.
func detectInsecureDaemon(job *gitlab.GitlabJob, mergedConf *gitlab.GitlabCIConf) string {
	var findings []string

	// Check job variables first
	jobVars, err := gitlab.ParseJobVariables(job)
	if err == nil {
		if checkInsecureVars(jobVars) != "" {
			findings = append(findings, checkInsecureVars(jobVars))
		}
	}

	// Also check global variables
	globalVars, err := gitlab.ParseGlobalVariables(mergedConf)
	if err == nil {
		if result := checkInsecureVars(globalVars); result != "" {
			// Avoid duplicates if already found in job vars
			if len(findings) == 0 || findings[0] != result {
				findings = append(findings, result)
			}
		}
	}

	return strings.Join(findings, "; ")
}

// checkInsecureVars inspects a variable map for insecure Docker daemon settings.
func checkInsecureVars(vars map[string]string) string {
	var parts []string

	for key, value := range vars {
		upperKey := strings.ToUpper(key)
		if upperKey == "DOCKER_TLS_CERTDIR" && strings.TrimSpace(value) == "" {
			parts = append(parts, "DOCKER_TLS_CERTDIR is empty (TLS disabled)")
		}
		if upperKey == "DOCKER_HOST" && strings.Contains(value, ":2375") {
			parts = append(parts, fmt.Sprintf("DOCKER_HOST uses non-TLS port 2375 (%s)", value))
		}
	}

	return strings.Join(parts, "; ")
}
