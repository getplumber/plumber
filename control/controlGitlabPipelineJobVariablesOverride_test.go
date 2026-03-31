package control

import (
	"testing"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/gitlab"
)

func buildOriginDataForVarOverride(globalVars map[string]interface{}, jobs map[string]interface{}) *collector.GitlabPipelineOriginData {
	rawConf := &gitlab.GitlabCIConf{
		GlobalVariables: globalVars,
		GitlabJobs:      jobs,
	}
	return &collector.GitlabPipelineOriginData{
		Conf:      rawConf,
		CiValid:   true,
		CiMissing: false,
	}
}

func TestJobVarOverride_Disabled(t *testing.T) {
	conf := &GitlabPipelineJobVariablesOverrideConf{
		Enabled:   false,
		Variables: []string{"SECURE_ANALYZERS_PREFIX"},
	}
	data := buildOriginDataForVarOverride(
		map[string]interface{}{"SECURE_ANALYZERS_PREFIX": "evil.example.com"},
		nil,
	)

	result := conf.Run(data)

	if !result.Skipped {
		t.Fatal("expected control to be skipped when disabled")
	}
	if result.Compliance != 100.0 {
		t.Fatalf("expected compliance 100 when skipped, got %v", result.Compliance)
	}
}

func TestJobVarOverride_NoVariablesConfigured(t *testing.T) {
	conf := &GitlabPipelineJobVariablesOverrideConf{
		Enabled:   true,
		Variables: []string{},
	}
	data := buildOriginDataForVarOverride(
		map[string]interface{}{"SECURE_ANALYZERS_PREFIX": "evil.example.com"},
		nil,
	)

	result := conf.Run(data)

	if !result.Skipped {
		t.Fatal("expected control to be skipped when no variables configured")
	}
}

func TestJobVarOverride_NilRawConf(t *testing.T) {
	conf := &GitlabPipelineJobVariablesOverrideConf{
		Enabled:   true,
		Variables: []string{"SECURE_ANALYZERS_PREFIX"},
	}
	data := &collector.GitlabPipelineOriginData{
		Conf:      nil,
		CiValid:   true,
		CiMissing: false,
	}

	result := conf.Run(data)

	if result.Skipped {
		t.Fatal("expected control not to be skipped")
	}
	if result.Compliance != 0 {
		t.Fatalf("expected compliance 0 when raw conf unavailable, got %v", result.Compliance)
	}
	if result.Error == "" {
		t.Fatal("expected error message when raw conf unavailable")
	}
}

func TestJobVarOverride_GlobalVariable(t *testing.T) {
	conf := &GitlabPipelineJobVariablesOverrideConf{
		Enabled:   true,
		Variables: []string{"SECURE_ANALYZERS_PREFIX"},
	}
	data := buildOriginDataForVarOverride(
		map[string]interface{}{"SECURE_ANALYZERS_PREFIX": "evil-registry.example.com"},
		nil,
	)

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
	if issue.VariableName != "SECURE_ANALYZERS_PREFIX" {
		t.Fatalf("expected variable SECURE_ANALYZERS_PREFIX, got %s", issue.VariableName)
	}
	if issue.Location != "global" {
		t.Fatalf("expected location 'global', got %s", issue.Location)
	}
	if issue.Code != CodeJobVariableOverridden {
		t.Fatalf("expected code %s, got %s", CodeJobVariableOverridden, issue.Code)
	}
	if result.Metrics.OverriddenFound != 1 {
		t.Fatalf("expected OverriddenFound 1, got %d", result.Metrics.OverriddenFound)
	}
}

func TestJobVarOverride_JobVariable(t *testing.T) {
	conf := &GitlabPipelineJobVariablesOverrideConf{
		Enabled:   true,
		Variables: []string{"SAST_DISABLED"},
	}

	jobContent := map[interface{}]interface{}{
		"script": "echo scanning",
		"variables": map[interface{}]interface{}{
			"SAST_DISABLED": "true",
		},
	}
	data := buildOriginDataForVarOverride(
		nil,
		map[string]interface{}{"sast-job": jobContent},
	)

	result := conf.Run(data)

	if result.Compliance != 0.0 {
		t.Fatalf("expected compliance 0, got %v", result.Compliance)
	}
	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(result.Issues))
	}
	if result.Issues[0].Location != "sast-job" {
		t.Fatalf("expected location 'sast-job', got %s", result.Issues[0].Location)
	}
}

func TestJobVarOverride_MultipleGlobalAndJob(t *testing.T) {
	conf := &GitlabPipelineJobVariablesOverrideConf{
		Enabled:   true,
		Variables: []string{"SECURE_ANALYZERS_PREFIX", "SAST_DISABLED"},
	}

	jobContent := map[interface{}]interface{}{
		"script": "echo test",
		"variables": map[interface{}]interface{}{
			"SAST_DISABLED": "true",
		},
	}
	data := buildOriginDataForVarOverride(
		map[string]interface{}{"SECURE_ANALYZERS_PREFIX": "evil.example.com"},
		map[string]interface{}{"scan-job": jobContent},
	)

	result := conf.Run(data)

	if result.Compliance != 0.0 {
		t.Fatalf("expected compliance 0, got %v", result.Compliance)
	}
	if len(result.Issues) != 2 {
		t.Fatalf("expected 2 issues, got %d", len(result.Issues))
	}
	if result.Metrics.OverriddenFound != 2 {
		t.Fatalf("expected OverriddenFound 2, got %d", result.Metrics.OverriddenFound)
	}
}

func TestJobVarOverride_CaseInsensitive(t *testing.T) {
	conf := &GitlabPipelineJobVariablesOverrideConf{
		Enabled:   true,
		Variables: []string{"secure_analyzers_prefix"},
	}
	data := buildOriginDataForVarOverride(
		map[string]interface{}{"SECURE_ANALYZERS_PREFIX": "evil.example.com"},
		nil,
	)

	result := conf.Run(data)

	if len(result.Issues) != 1 {
		t.Fatalf("expected case-insensitive match to find 1 issue, got %d", len(result.Issues))
	}
}

func TestJobVarOverride_NoMatches(t *testing.T) {
	conf := &GitlabPipelineJobVariablesOverrideConf{
		Enabled:   true,
		Variables: []string{"SECURE_ANALYZERS_PREFIX", "SAST_DISABLED"},
	}

	jobContent := map[interface{}]interface{}{
		"script": "echo hello",
		"variables": map[interface{}]interface{}{
			"MY_SAFE_VAR": "hello",
		},
	}
	data := buildOriginDataForVarOverride(
		map[string]interface{}{"SOME_VAR": "value"},
		map[string]interface{}{"build": jobContent},
	)

	result := conf.Run(data)

	if result.Compliance != 100.0 {
		t.Fatalf("expected compliance 100, got %v", result.Compliance)
	}
	if len(result.Issues) != 0 {
		t.Fatalf("expected no issues, got %d", len(result.Issues))
	}
	if result.Metrics.TotalVariablesChecked < 2 {
		t.Fatalf("expected at least 2 variables checked, got %d", result.Metrics.TotalVariablesChecked)
	}
}

func TestJobVarOverride_AnyValueIsDetected(t *testing.T) {
	conf := &GitlabPipelineJobVariablesOverrideConf{
		Enabled:   true,
		Variables: []string{"SAST_DISABLED"},
	}
	data := buildOriginDataForVarOverride(
		map[string]interface{}{"SAST_DISABLED": "false"},
		nil,
	)

	result := conf.Run(data)

	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue even when value is 'false' (variable should not be defined at all), got %d", len(result.Issues))
	}
	if result.Compliance != 0.0 {
		t.Fatalf("expected compliance 0, got %v", result.Compliance)
	}
}
