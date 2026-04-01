package control

import (
	"testing"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/gitlab"
)

func buildOriginDataForDinD(globalVars map[string]interface{}, jobs map[string]interface{}) *collector.GitlabPipelineOriginData {
	mergedConf := &gitlab.GitlabCIConf{
		GlobalVariables: globalVars,
		GitlabJobs:      jobs,
	}
	return &collector.GitlabPipelineOriginData{
		MergedConf: mergedConf,
		CiValid:    true,
		CiMissing:  false,
	}
}

func TestDockerInDocker_Disabled(t *testing.T) {
	conf := &GitlabPipelineDockerInDockerConf{
		Enabled:              false,
		DetectInsecureDaemon: true,
	}
	jobContent := map[interface{}]interface{}{
		"script":   "docker build .",
		"services": []interface{}{"docker:dind"},
	}
	data := buildOriginDataForDinD(nil, map[string]interface{}{"build": jobContent})

	result := conf.Run(data)

	if !result.Skipped {
		t.Fatal("expected control to be skipped when disabled")
	}
	if result.Compliance != 100.0 {
		t.Fatalf("expected compliance 100 when skipped, got %v", result.Compliance)
	}
}

func TestDockerInDocker_NilMergedConf(t *testing.T) {
	conf := &GitlabPipelineDockerInDockerConf{
		Enabled:              true,
		DetectInsecureDaemon: true,
	}
	data := &collector.GitlabPipelineOriginData{
		MergedConf: nil,
		CiValid:    true,
		CiMissing:  false,
	}

	result := conf.Run(data)

	if result.Skipped {
		t.Fatal("expected control not to be skipped")
	}
	if result.Compliance != 0 {
		t.Fatalf("expected compliance 0 when merged conf unavailable, got %v", result.Compliance)
	}
	if result.Error == "" {
		t.Fatal("expected error message when merged conf unavailable")
	}
}

func TestDockerInDocker_DindServiceDetected(t *testing.T) {
	conf := &GitlabPipelineDockerInDockerConf{
		Enabled:              true,
		DetectInsecureDaemon: false,
	}
	jobContent := map[interface{}]interface{}{
		"script":   "docker build .",
		"services": []interface{}{"docker:dind"},
	}
	data := buildOriginDataForDinD(nil, map[string]interface{}{"build-image": jobContent})

	result := conf.Run(data)

	if result.Skipped {
		t.Fatal("expected control to run")
	}
	if result.Compliance != 0.0 {
		t.Fatalf("expected compliance 0, got %v", result.Compliance)
	}
	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(result.Issues))
	}
	issue := result.Issues[0]
	if issue.Code != CodeDockerInDockerUsage {
		t.Fatalf("expected code %s, got %s", CodeDockerInDockerUsage, issue.Code)
	}
	if issue.JobName != "build-image" {
		t.Fatalf("expected job name 'build-image', got %s", issue.JobName)
	}
	if issue.ServiceImage != "docker:dind" {
		t.Fatalf("expected service image 'docker:dind', got %s", issue.ServiceImage)
	}
	if result.Metrics.DindServicesFound != 1 {
		t.Fatalf("expected DindServicesFound 1, got %d", result.Metrics.DindServicesFound)
	}
}

func TestDockerInDocker_VersionedDindTag(t *testing.T) {
	conf := &GitlabPipelineDockerInDockerConf{
		Enabled:              true,
		DetectInsecureDaemon: false,
	}
	jobContent := map[interface{}]interface{}{
		"script":   "docker build .",
		"services": []interface{}{"docker:27.3.1-dind"},
	}
	data := buildOriginDataForDinD(nil, map[string]interface{}{"build": jobContent})

	result := conf.Run(data)

	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue for versioned dind tag, got %d", len(result.Issues))
	}
	if result.Issues[0].ServiceImage != "docker:27.3.1-dind" {
		t.Fatalf("expected service image 'docker:27.3.1-dind', got %s", result.Issues[0].ServiceImage)
	}
}

func TestDockerInDocker_LatestTag(t *testing.T) {
	conf := &GitlabPipelineDockerInDockerConf{
		Enabled:              true,
		DetectInsecureDaemon: false,
	}
	jobContent := map[interface{}]interface{}{
		"script":   "docker build .",
		"services": []interface{}{"docker:latest"},
	}
	data := buildOriginDataForDinD(nil, map[string]interface{}{"build": jobContent})

	result := conf.Run(data)

	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue for docker:latest, got %d", len(result.Issues))
	}
}

func TestDockerInDocker_ServiceAsMap(t *testing.T) {
	conf := &GitlabPipelineDockerInDockerConf{
		Enabled:              true,
		DetectInsecureDaemon: false,
	}
	svcMap := map[interface{}]interface{}{
		"name":  "docker:27-dind",
		"alias": "docker",
	}
	jobContent := map[interface{}]interface{}{
		"script":   "docker build .",
		"services": []interface{}{svcMap},
	}
	data := buildOriginDataForDinD(nil, map[string]interface{}{"build": jobContent})

	result := conf.Run(data)

	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue for service map with dind, got %d", len(result.Issues))
	}
	if result.Issues[0].ServiceImage != "docker:27-dind" {
		t.Fatalf("expected service image 'docker:27-dind', got %s", result.Issues[0].ServiceImage)
	}
}

func TestDockerInDocker_NoDindService(t *testing.T) {
	conf := &GitlabPipelineDockerInDockerConf{
		Enabled:              true,
		DetectInsecureDaemon: true,
	}
	jobContent := map[interface{}]interface{}{
		"script":   "echo hello",
		"services": []interface{}{"postgres:15"},
	}
	data := buildOriginDataForDinD(nil, map[string]interface{}{"test": jobContent})

	result := conf.Run(data)

	if result.Compliance != 100.0 {
		t.Fatalf("expected compliance 100 with no dind, got %v", result.Compliance)
	}
	if len(result.Issues) != 0 {
		t.Fatalf("expected no issues, got %d", len(result.Issues))
	}
}

func TestDockerInDocker_InsecureVarsWithoutDind(t *testing.T) {
	conf := &GitlabPipelineDockerInDockerConf{
		Enabled:              true,
		DetectInsecureDaemon: true,
	}
	jobContent := map[interface{}]interface{}{
		"script":   "echo hello",
		"services": []interface{}{"postgres:15"},
		"variables": map[interface{}]interface{}{
			"DOCKER_TLS_CERTDIR": "",
			"DOCKER_HOST":        "tcp://docker:2375",
		},
	}
	data := buildOriginDataForDinD(nil, map[string]interface{}{"test": jobContent})

	result := conf.Run(data)

	if len(result.Issues) != 0 {
		t.Fatalf("expected no issues when insecure vars present but no dind service, got %d", len(result.Issues))
	}
	if result.Compliance != 100.0 {
		t.Fatalf("expected compliance 100, got %v", result.Compliance)
	}
}

func TestDockerInDocker_DindWithInsecureJobVars(t *testing.T) {
	conf := &GitlabPipelineDockerInDockerConf{
		Enabled:              true,
		DetectInsecureDaemon: true,
	}
	jobContent := map[interface{}]interface{}{
		"script":   "docker build .",
		"services": []interface{}{"docker:dind"},
		"variables": map[interface{}]interface{}{
			"DOCKER_TLS_CERTDIR": "",
			"DOCKER_HOST":        "tcp://docker:2375",
		},
	}
	data := buildOriginDataForDinD(nil, map[string]interface{}{"build": jobContent})

	result := conf.Run(data)

	if result.Compliance != 0.0 {
		t.Fatalf("expected compliance 0, got %v", result.Compliance)
	}
	// Should have 2 issues: ISSUE-412 (dind usage) + ISSUE-413 (insecure daemon)
	if len(result.Issues) != 2 {
		t.Fatalf("expected 2 issues (dind + insecure), got %d", len(result.Issues))
	}
	if result.Issues[0].Code != CodeDockerInDockerUsage {
		t.Fatalf("expected first issue code %s, got %s", CodeDockerInDockerUsage, result.Issues[0].Code)
	}
	if result.Issues[1].Code != CodeDockerInDockerInsecure {
		t.Fatalf("expected second issue code %s, got %s", CodeDockerInDockerInsecure, result.Issues[1].Code)
	}
	if result.Issues[1].Detail == "" {
		t.Fatal("expected detail on insecure daemon issue")
	}
	if result.Metrics.DindServicesFound != 1 {
		t.Fatalf("expected DindServicesFound 1, got %d", result.Metrics.DindServicesFound)
	}
	if result.Metrics.InsecureDaemonFound != 1 {
		t.Fatalf("expected InsecureDaemonFound 1, got %d", result.Metrics.InsecureDaemonFound)
	}
}

func TestDockerInDocker_DindWithInsecureGlobalVars(t *testing.T) {
	conf := &GitlabPipelineDockerInDockerConf{
		Enabled:              true,
		DetectInsecureDaemon: true,
	}
	jobContent := map[interface{}]interface{}{
		"script":   "docker build .",
		"services": []interface{}{"docker:dind"},
	}
	globalVars := map[string]interface{}{
		"DOCKER_TLS_CERTDIR": "",
	}
	data := buildOriginDataForDinD(globalVars, map[string]interface{}{"build": jobContent})

	result := conf.Run(data)

	if len(result.Issues) != 2 {
		t.Fatalf("expected 2 issues (dind + insecure from global), got %d", len(result.Issues))
	}
	if result.Issues[1].Code != CodeDockerInDockerInsecure {
		t.Fatalf("expected second issue to be insecure daemon, got %s", result.Issues[1].Code)
	}
}

func TestDockerInDocker_DindSecureDaemonNoInsecureIssue(t *testing.T) {
	conf := &GitlabPipelineDockerInDockerConf{
		Enabled:              true,
		DetectInsecureDaemon: true,
	}
	jobContent := map[interface{}]interface{}{
		"script":   "docker build .",
		"services": []interface{}{"docker:dind"},
		"variables": map[interface{}]interface{}{
			"DOCKER_TLS_CERTDIR": "/certs",
			"DOCKER_HOST":        "tcp://docker:2376",
		},
	}
	data := buildOriginDataForDinD(nil, map[string]interface{}{"build": jobContent})

	result := conf.Run(data)

	// Only dind usage issue, no insecure daemon issue
	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue (dind only, no insecure), got %d", len(result.Issues))
	}
	if result.Issues[0].Code != CodeDockerInDockerUsage {
		t.Fatalf("expected code %s, got %s", CodeDockerInDockerUsage, result.Issues[0].Code)
	}
}

func TestDockerInDocker_DetectInsecureDaemonDisabled(t *testing.T) {
	conf := &GitlabPipelineDockerInDockerConf{
		Enabled:              true,
		DetectInsecureDaemon: false,
	}
	jobContent := map[interface{}]interface{}{
		"script":   "docker build .",
		"services": []interface{}{"docker:dind"},
		"variables": map[interface{}]interface{}{
			"DOCKER_TLS_CERTDIR": "",
		},
	}
	data := buildOriginDataForDinD(nil, map[string]interface{}{"build": jobContent})

	result := conf.Run(data)

	// Only dind usage, insecure daemon check skipped
	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue (detect insecure disabled), got %d", len(result.Issues))
	}
	if result.Issues[0].Code != CodeDockerInDockerUsage {
		t.Fatalf("expected code %s, got %s", CodeDockerInDockerUsage, result.Issues[0].Code)
	}
}

func TestDockerInDocker_MultipleJobs(t *testing.T) {
	conf := &GitlabPipelineDockerInDockerConf{
		Enabled:              true,
		DetectInsecureDaemon: false,
	}
	job1 := map[interface{}]interface{}{
		"script":   "docker build .",
		"services": []interface{}{"docker:dind"},
	}
	job2 := map[interface{}]interface{}{
		"script":   "echo test",
		"services": []interface{}{"postgres:15"},
	}
	job3 := map[interface{}]interface{}{
		"script":   "docker push",
		"services": []interface{}{"docker:27-dind"},
	}
	data := buildOriginDataForDinD(nil, map[string]interface{}{
		"build":  job1,
		"test":   job2,
		"deploy": job3,
	})

	result := conf.Run(data)

	if result.Compliance != 0.0 {
		t.Fatalf("expected compliance 0, got %v", result.Compliance)
	}
	if len(result.Issues) != 2 {
		t.Fatalf("expected 2 issues (two dind jobs), got %d", len(result.Issues))
	}
	if result.Metrics.DindServicesFound != 2 {
		t.Fatalf("expected DindServicesFound 2, got %d", result.Metrics.DindServicesFound)
	}
}

func TestDockerInDocker_NonDindDockerImage(t *testing.T) {
	conf := &GitlabPipelineDockerInDockerConf{
		Enabled:              true,
		DetectInsecureDaemon: false,
	}
	// docker:27 without -dind suffix is just the Docker CLI, not DinD
	jobContent := map[interface{}]interface{}{
		"script":   "docker version",
		"services": []interface{}{"docker:27"},
	}
	data := buildOriginDataForDinD(nil, map[string]interface{}{"check": jobContent})

	result := conf.Run(data)

	if len(result.Issues) != 0 {
		t.Fatalf("expected no issues for docker:27 (not dind), got %d", len(result.Issues))
	}
	if result.Compliance != 100.0 {
		t.Fatalf("expected compliance 100, got %v", result.Compliance)
	}
}

func TestIsDindImage(t *testing.T) {
	tests := []struct {
		image    string
		expected bool
	}{
		{"docker:dind", true},
		{"docker:latest", true},
		{"docker:27-dind", true},
		{"docker:27.3.1-dind", true},
		{"docker:dind-rootless", true},
		{"docker:27-dind-rootless", true},
		{"docker:27", false},
		{"docker:27.3.1", false},
		{"docker", false},
		{"postgres:15", false},
		{"", false},
		{"registry.example.com/docker:dind", true},
		{"docker.io/library/docker:dind", true},
	}

	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			got := isDindImage(tt.image)
			if got != tt.expected {
				t.Fatalf("isDindImage(%q) = %v, want %v", tt.image, got, tt.expected)
			}
		})
	}
}
