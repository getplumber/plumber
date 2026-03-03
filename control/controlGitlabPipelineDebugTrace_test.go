package control

import (
	"testing"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/gitlab"
)

// helper to build a GitlabPipelineOriginData with global variables and optional jobs
func buildPipelineOriginDataWithVars(globalVars map[string]interface{}, jobs map[string]interface{}) *collector.GitlabPipelineOriginData {
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

func TestDebugTrace_Disabled(t *testing.T) {
	conf := &GitlabPipelineDebugTraceConf{
		Enabled:            false,
		ForbiddenVariables: []string{"CI_DEBUG_TRACE"},
	}
	data := buildPipelineOriginDataWithVars(
		map[string]interface{}{"CI_DEBUG_TRACE": "true"},
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

func TestDebugTrace_NoForbiddenVariablesConfigured(t *testing.T) {
	conf := &GitlabPipelineDebugTraceConf{
		Enabled:            true,
		ForbiddenVariables: []string{},
	}
	data := buildPipelineOriginDataWithVars(
		map[string]interface{}{"CI_DEBUG_TRACE": "true"},
		nil,
	)

	result := conf.Run(data)

	if !result.Skipped {
		t.Fatal("expected control to be skipped when no forbidden variables configured")
	}
}

func TestDebugTrace_NilMergedConf(t *testing.T) {
	conf := &GitlabPipelineDebugTraceConf{
		Enabled:            true,
		ForbiddenVariables: []string{"CI_DEBUG_TRACE"},
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

func TestDebugTrace_GlobalVarTrue(t *testing.T) {
	conf := &GitlabPipelineDebugTraceConf{
		Enabled:            true,
		ForbiddenVariables: []string{"CI_DEBUG_TRACE"},
	}
	data := buildPipelineOriginDataWithVars(
		map[string]interface{}{"CI_DEBUG_TRACE": "true"},
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
	if issue.VariableName != "CI_DEBUG_TRACE" {
		t.Fatalf("expected variable CI_DEBUG_TRACE, got %s", issue.VariableName)
	}
	if issue.Location != "global" {
		t.Fatalf("expected location 'global', got %s", issue.Location)
	}
	if result.Metrics.ForbiddenFound != 1 {
		t.Fatalf("expected ForbiddenFound 1, got %d", result.Metrics.ForbiddenFound)
	}
}

func TestDebugTrace_GlobalVarFalse(t *testing.T) {
	conf := &GitlabPipelineDebugTraceConf{
		Enabled:            true,
		ForbiddenVariables: []string{"CI_DEBUG_TRACE"},
	}
	data := buildPipelineOriginDataWithVars(
		map[string]interface{}{"CI_DEBUG_TRACE": "false"},
		nil,
	)

	result := conf.Run(data)

	if result.Compliance != 100.0 {
		t.Fatalf("expected compliance 100 when value is false, got %v", result.Compliance)
	}
	if len(result.Issues) != 0 {
		t.Fatalf("expected no issues, got %d", len(result.Issues))
	}
}

func TestDebugTrace_JobVarTrue(t *testing.T) {
	conf := &GitlabPipelineDebugTraceConf{
		Enabled:            true,
		ForbiddenVariables: []string{"CI_DEBUG_TRACE"},
	}

	// Build job content as YAML-like map (how GitlabJobs stores parsed CI jobs)
	jobContent := map[interface{}]interface{}{
		"script": "echo hello",
		"variables": map[interface{}]interface{}{
			"CI_DEBUG_TRACE": "true",
		},
	}
	data := buildPipelineOriginDataWithVars(
		nil,
		map[string]interface{}{"build": jobContent},
	)

	result := conf.Run(data)

	if result.Compliance != 0.0 {
		t.Fatalf("expected compliance 0, got %v", result.Compliance)
	}
	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(result.Issues))
	}
	if result.Issues[0].Location != "build" {
		t.Fatalf("expected location 'build', got %s", result.Issues[0].Location)
	}
}

func TestDebugTrace_MultipleVarsGlobalAndJob(t *testing.T) {
	conf := &GitlabPipelineDebugTraceConf{
		Enabled:            true,
		ForbiddenVariables: []string{"CI_DEBUG_TRACE", "CI_DEBUG_SERVICES"},
	}

	jobContent := map[interface{}]interface{}{
		"script": "echo test",
		"variables": map[interface{}]interface{}{
			"CI_DEBUG_SERVICES": "true",
		},
	}
	data := buildPipelineOriginDataWithVars(
		map[string]interface{}{"CI_DEBUG_TRACE": "true"},
		map[string]interface{}{"test-job": jobContent},
	)

	result := conf.Run(data)

	if result.Compliance != 0.0 {
		t.Fatalf("expected compliance 0, got %v", result.Compliance)
	}
	if len(result.Issues) != 2 {
		t.Fatalf("expected 2 issues, got %d", len(result.Issues))
	}
	if result.Metrics.ForbiddenFound != 2 {
		t.Fatalf("expected ForbiddenFound 2, got %d", result.Metrics.ForbiddenFound)
	}
}

func TestDebugTrace_CaseInsensitiveVariableMatch(t *testing.T) {
	conf := &GitlabPipelineDebugTraceConf{
		Enabled:            true,
		ForbiddenVariables: []string{"ci_debug_trace"},
	}
	data := buildPipelineOriginDataWithVars(
		map[string]interface{}{"CI_DEBUG_TRACE": "true"},
		nil,
	)

	result := conf.Run(data)

	if len(result.Issues) != 1 {
		t.Fatalf("expected case-insensitive match to find 1 issue, got %d", len(result.Issues))
	}
}

func TestDebugTrace_NoIssuesCleanConfig(t *testing.T) {
	conf := &GitlabPipelineDebugTraceConf{
		Enabled:            true,
		ForbiddenVariables: []string{"CI_DEBUG_TRACE", "CI_DEBUG_SERVICES"},
	}

	jobContent := map[interface{}]interface{}{
		"script": "echo hello",
		"variables": map[interface{}]interface{}{
			"MY_VAR": "hello",
		},
	}
	data := buildPipelineOriginDataWithVars(
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

func TestIsTrueValue(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{" true ", true},
		{"1", true},
		{"yes", true},
		{"YES", true},
		{"Yes", true},
		{"false", false},
		{"0", false},
		{"no", false},
		{"", false},
		{"random", false},
		{"truthy", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isTrueValue(tt.input)
			if got != tt.want {
				t.Fatalf("isTrueValue(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
