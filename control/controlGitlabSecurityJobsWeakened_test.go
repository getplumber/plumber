package control

import (
	"testing"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/gitlab"
)

// helper to build pipeline origin data with merged conf and origins
func buildSecurityJobsPipelineData(
	mergedJobs map[string]interface{},
	rawJobs map[string]interface{},
	origins []collector.GitlabPipelineOriginDataFull,
) *collector.GitlabPipelineOriginData {
	mergedConf := &gitlab.GitlabCIConf{
		GitlabJobs: mergedJobs,
	}
	var rawConf *gitlab.GitlabCIConf
	if rawJobs != nil {
		rawConf = &gitlab.GitlabCIConf{
			GitlabJobs: rawJobs,
		}
	}
	return &collector.GitlabPipelineOriginData{
		MergedConf:          mergedConf,
		Conf:                rawConf,
		CiValid:             true,
		CiMissing:           false,
		Origins:             origins,
		JobMap:              make(map[string]*collector.GitlabPipelineJobData),
		JobHardcodedMap:     make(map[string]bool),
		JobHardcodedContent: make(map[string]interface{}),
	}
}

func TestSecurityJobsWeakened_Disabled(t *testing.T) {
	conf := &GitlabSecurityJobsWeakenedConf{
		Enabled: false,
	}
	data := buildSecurityJobsPipelineData(nil, nil, nil)

	result := conf.Run(data)

	if !result.Skipped {
		t.Fatal("expected control to be skipped when disabled")
	}
	if result.Compliance != 100.0 {
		t.Fatalf("expected compliance 100 when skipped, got %v", result.Compliance)
	}
}

func TestSecurityJobsWeakened_AllSubControlsDisabled(t *testing.T) {
	conf := &GitlabSecurityJobsWeakenedConf{
		Enabled:           true,
		AllowFailureCheck: false,
		RulesCheck:        false,
		WhenManualCheck:   false,
	}
	data := buildSecurityJobsPipelineData(nil, nil, nil)

	result := conf.Run(data)

	if !result.Skipped {
		t.Fatal("expected control to be skipped when all sub-controls disabled")
	}
}

func TestSecurityJobsWeakened_CiInvalid(t *testing.T) {
	conf := &GitlabSecurityJobsWeakenedConf{
		Enabled:         true,
		WhenManualCheck: true,
	}
	data := &collector.GitlabPipelineOriginData{
		CiValid:   false,
		CiMissing: false,
	}

	result := conf.Run(data)

	if result.Compliance != 0 {
		t.Fatalf("expected compliance 0 for invalid CI, got %v", result.Compliance)
	}
}

func TestSecurityJobsWeakened_NoSecurityJobs(t *testing.T) {
	conf := &GitlabSecurityJobsWeakenedConf{
		Enabled:         true,
		WhenManualCheck: true,
	}
	mergedJobs := map[string]interface{}{
		"build": map[interface{}]interface{}{
			"script": "echo build",
		},
	}
	data := buildSecurityJobsPipelineData(mergedJobs, nil, nil)

	result := conf.Run(data)

	if result.Skipped {
		t.Fatal("expected control to run, not be skipped")
	}
	if result.Compliance != 100.0 {
		t.Fatalf("expected compliance 100 when no security jobs found, got %v", result.Compliance)
	}
	if result.Metrics.SecurityJobsFound != 0 {
		t.Fatalf("expected 0 security jobs found, got %d", result.Metrics.SecurityJobsFound)
	}
}

func TestSecurityJobsWeakened_AllowFailureTrue(t *testing.T) {
	conf := &GitlabSecurityJobsWeakenedConf{
		Enabled:             true,
		SecurityJobPatterns: []string{"*-sast"},
		AllowFailureCheck:   true,
		RulesCheck:          false,
		WhenManualCheck:     false,
	}

	mergedJobs := map[string]interface{}{
		"semgrep-sast": map[interface{}]interface{}{
			"script":        "/analyzer run",
			"allow_failure": true,
		},
	}
	data := buildSecurityJobsPipelineData(mergedJobs, nil, nil)

	result := conf.Run(data)

	if result.Compliance != 0 {
		t.Fatalf("expected compliance 0, got %v", result.Compliance)
	}
	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(result.Issues))
	}
	if result.Issues[0].SubControl != "allowFailureMustBeFalse" {
		t.Fatalf("expected sub-control allowFailureMustBeFalse, got %s", result.Issues[0].SubControl)
	}
	if result.Issues[0].JobName != "semgrep-sast" {
		t.Fatalf("expected job semgrep-sast, got %s", result.Issues[0].JobName)
	}
}

func TestSecurityJobsWeakened_AllowFailureFalse_NoIssue(t *testing.T) {
	conf := &GitlabSecurityJobsWeakenedConf{
		Enabled:             true,
		SecurityJobPatterns: []string{"*-sast"},
		AllowFailureCheck:   true,
		RulesCheck:          false,
		WhenManualCheck:     false,
	}

	mergedJobs := map[string]interface{}{
		"semgrep-sast": map[interface{}]interface{}{
			"script":        "/analyzer run",
			"allow_failure": false,
		},
	}
	data := buildSecurityJobsPipelineData(mergedJobs, nil, nil)

	result := conf.Run(data)

	if result.Compliance != 100.0 {
		t.Fatalf("expected compliance 100, got %v", result.Compliance)
	}
	if len(result.Issues) != 0 {
		t.Fatalf("expected 0 issues, got %d", len(result.Issues))
	}
}

func TestSecurityJobsWeakened_WhenManual(t *testing.T) {
	conf := &GitlabSecurityJobsWeakenedConf{
		Enabled:             true,
		SecurityJobPatterns: []string{"container_scanning"},
		AllowFailureCheck:   false,
		RulesCheck:          false,
		WhenManualCheck:     true,
	}

	mergedJobs := map[string]interface{}{
		"container_scanning": map[interface{}]interface{}{
			"script": "/analyzer run",
			"when":   "manual",
		},
	}
	data := buildSecurityJobsPipelineData(mergedJobs, nil, nil)

	result := conf.Run(data)

	if result.Compliance != 0 {
		t.Fatalf("expected compliance 0, got %v", result.Compliance)
	}
	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(result.Issues))
	}
	if result.Issues[0].SubControl != "whenMustNotBeManual" {
		t.Fatalf("expected sub-control whenMustNotBeManual, got %s", result.Issues[0].SubControl)
	}
}

func TestSecurityJobsWeakened_RulesWhenNever(t *testing.T) {
	conf := &GitlabSecurityJobsWeakenedConf{
		Enabled:             true,
		SecurityJobPatterns: []string{"secret_detection"},
		AllowFailureCheck:   false,
		RulesCheck:          true,
		WhenManualCheck:     false,
	}

	mergedJobs := map[string]interface{}{
		"secret_detection": map[interface{}]interface{}{
			"script": "/analyzer run",
		},
	}
	rawJobs := map[string]interface{}{
		"secret_detection": map[interface{}]interface{}{
			"rules": []interface{}{
				map[interface{}]interface{}{
					"when": "never",
				},
			},
		},
	}
	data := buildSecurityJobsPipelineData(mergedJobs, rawJobs, nil)

	result := conf.Run(data)

	if result.Compliance != 0 {
		t.Fatalf("expected compliance 0, got %v", result.Compliance)
	}
	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(result.Issues))
	}
	if result.Issues[0].SubControl != "rulesMustNotBeRedefined" {
		t.Fatalf("expected sub-control rulesMustNotBeRedefined, got %s", result.Issues[0].SubControl)
	}
	if result.Issues[0].JobName != "secret_detection" {
		t.Fatalf("expected job secret_detection, got %s", result.Issues[0].JobName)
	}
}

func TestSecurityJobsWeakened_RulesWhenManual(t *testing.T) {
	conf := &GitlabSecurityJobsWeakenedConf{
		Enabled:             true,
		SecurityJobPatterns: []string{"secret_detection"},
		AllowFailureCheck:   false,
		RulesCheck:          true,
		WhenManualCheck:     false,
	}

	mergedJobs := map[string]interface{}{
		"secret_detection": map[interface{}]interface{}{
			"script": "/analyzer run",
		},
	}
	rawJobs := map[string]interface{}{
		"secret_detection": map[interface{}]interface{}{
			"rules": []interface{}{
				map[interface{}]interface{}{
					"when":          "manual",
					"allow_failure": true,
				},
			},
		},
	}
	data := buildSecurityJobsPipelineData(mergedJobs, rawJobs, nil)

	result := conf.Run(data)

	if result.Compliance != 0 {
		t.Fatalf("expected compliance 0, got %v", result.Compliance)
	}
	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(result.Issues))
	}
}

func TestSecurityJobsWeakened_NoPatterns(t *testing.T) {
	conf := &GitlabSecurityJobsWeakenedConf{
		Enabled:             true,
		SecurityJobPatterns: []string{},
		AllowFailureCheck:   false,
		RulesCheck:          false,
		WhenManualCheck:     true,
	}

	mergedJobs := map[string]interface{}{
		"semgrep-sast": map[interface{}]interface{}{
			"script": "/analyzer run",
			"when":   "manual",
		},
	}
	data := buildSecurityJobsPipelineData(mergedJobs, nil, nil)

	result := conf.Run(data)

	if result.Metrics.SecurityJobsFound != 0 {
		t.Fatalf("expected 0 security jobs when no patterns configured, got %d", result.Metrics.SecurityJobsFound)
	}
	if result.Compliance != 100.0 {
		t.Fatalf("expected compliance 100 when no patterns configured, got %v", result.Compliance)
	}
}

func TestSecurityJobsWeakened_MultiplePatternMatches(t *testing.T) {
	conf := &GitlabSecurityJobsWeakenedConf{
		Enabled:             true,
		SecurityJobPatterns: []string{"*-sast", "semgrep-*"},
		AllowFailureCheck:   false,
		RulesCheck:          false,
		WhenManualCheck:     true,
	}

	mergedJobs := map[string]interface{}{
		"semgrep-sast": map[interface{}]interface{}{
			"script": "/analyzer run",
			"when":   "manual",
		},
	}
	data := buildSecurityJobsPipelineData(mergedJobs, nil, nil)

	result := conf.Run(data)

	// Job matches both patterns but should only appear once
	if result.Metrics.SecurityJobsFound != 1 {
		t.Fatalf("expected 1 security job (deduped), got %d", result.Metrics.SecurityJobsFound)
	}
	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(result.Issues))
	}
}

func TestSecurityJobsWeakened_MultipleSubControlIssues(t *testing.T) {
	conf := &GitlabSecurityJobsWeakenedConf{
		Enabled:             true,
		SecurityJobPatterns: []string{"*-sast", "container_scanning", "secret_detection"},
		AllowFailureCheck:   true,
		RulesCheck:          true,
		WhenManualCheck:     true,
	}

	mergedJobs := map[string]interface{}{
		"semgrep-sast": map[interface{}]interface{}{
			"script":        "/analyzer run",
			"allow_failure": true,
		},
		"container_scanning": map[interface{}]interface{}{
			"script": "/analyzer run",
			"when":   "manual",
		},
		"secret_detection": map[interface{}]interface{}{
			"script": "/analyzer run",
		},
	}
	rawJobs := map[string]interface{}{
		"secret_detection": map[interface{}]interface{}{
			"rules": []interface{}{
				map[interface{}]interface{}{
					"when": "never",
				},
			},
		},
	}
	data := buildSecurityJobsPipelineData(mergedJobs, rawJobs, nil)

	result := conf.Run(data)

	if result.Compliance != 0 {
		t.Fatalf("expected compliance 0, got %v", result.Compliance)
	}
	if len(result.Issues) != 3 {
		t.Fatalf("expected 3 issues, got %d", len(result.Issues))
	}
	if result.Metrics.WeakenedJobs != 3 {
		t.Fatalf("expected 3 weakened jobs, got %d", result.Metrics.WeakenedJobs)
	}
}

func TestSecurityJobsWeakened_CleanConfig(t *testing.T) {
	conf := &GitlabSecurityJobsWeakenedConf{
		Enabled:             true,
		SecurityJobPatterns: []string{"*-sast", "secret_detection"},
		AllowFailureCheck:   true,
		RulesCheck:          true,
		WhenManualCheck:     true,
	}

	mergedJobs := map[string]interface{}{
		"semgrep-sast": map[interface{}]interface{}{
			"script":        "/analyzer run",
			"allow_failure": false,
			"when":          "on_success",
		},
		"secret_detection": map[interface{}]interface{}{
			"script": "/analyzer run",
		},
	}
	data := buildSecurityJobsPipelineData(mergedJobs, nil, nil)

	result := conf.Run(data)

	if result.Compliance != 100.0 {
		t.Fatalf("expected compliance 100, got %v", result.Compliance)
	}
	if len(result.Issues) != 0 {
		t.Fatalf("expected 0 issues, got %d", len(result.Issues))
	}
	if result.Metrics.SecurityJobsFound != 2 {
		t.Fatalf("expected 2 security jobs found, got %d", result.Metrics.SecurityJobsFound)
	}
}

func TestSecurityJobsWeakened_WildcardPatterns(t *testing.T) {
	conf := &GitlabSecurityJobsWeakenedConf{
		Enabled:             true,
		SecurityJobPatterns: []string{"gemnasium-*"},
		AllowFailureCheck:   false,
		RulesCheck:          false,
		WhenManualCheck:     true,
	}

	mergedJobs := map[string]interface{}{
		"gemnasium-dependency_scanning": map[interface{}]interface{}{
			"script": "/analyzer run",
			"when":   "manual",
		},
		"gemnasium-maven-dependency_scanning": map[interface{}]interface{}{
			"script": "/analyzer run",
		},
	}
	data := buildSecurityJobsPipelineData(mergedJobs, nil, nil)

	result := conf.Run(data)

	if result.Metrics.SecurityJobsFound != 2 {
		t.Fatalf("expected 2 security jobs, got %d", result.Metrics.SecurityJobsFound)
	}
	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(result.Issues))
	}
	if result.Issues[0].JobName != "gemnasium-dependency_scanning" {
		t.Fatalf("expected job gemnasium-dependency_scanning, got %s", result.Issues[0].JobName)
	}
}

func TestSecurityJobsWeakened_RulesCheckUsesJobHardcodedContent(t *testing.T) {
	conf := &GitlabSecurityJobsWeakenedConf{
		Enabled:             true,
		SecurityJobPatterns: []string{"secret_detection"},
		AllowFailureCheck:   false,
		RulesCheck:          true,
		WhenManualCheck:     false,
	}

	mergedJobs := map[string]interface{}{
		"secret_detection": map[interface{}]interface{}{
			"script": "/analyzer run",
		},
	}
	// Raw conf does NOT have the job, but JobHardcodedContent does
	data := buildSecurityJobsPipelineData(mergedJobs, nil, nil)
	data.JobHardcodedContent["secret_detection"] = map[interface{}]interface{}{
		"rules": []interface{}{
			map[interface{}]interface{}{
				"when": "never",
			},
		},
	}

	result := conf.Run(data)

	if result.Compliance != 0 {
		t.Fatalf("expected compliance 0, got %v", result.Compliance)
	}
	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(result.Issues))
	}
}

func TestIsAllowFailureTrue(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  bool
	}{
		{"nil", nil, false},
		{"bool true", true, false},        // direct bool in test context
		{"bool false", false, false},       // not flagged
		{"string true", "true", true},
		{"string false", "false", false},
		{"map with exit_codes", map[interface{}]interface{}{"exit_codes": []int{1}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAllowFailureTrue(tt.input)
			// For the "bool true" case, the function should return true
			if tt.name == "bool true" {
				if !got {
					t.Fatalf("isAllowFailureTrue(true) = false, want true")
				}
				return
			}
			if got != tt.want {
				t.Fatalf("isAllowFailureTrue(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsWhenManual(t *testing.T) {
	tests := []struct {
		input interface{}
		want  bool
	}{
		{nil, false},
		{"manual", true},
		{"Manual", true},
		{" manual ", true},
		{"on_success", false},
		{"always", false},
		{42, false},
	}

	for _, tt := range tests {
		got := isWhenManual(tt.input)
		if got != tt.want {
			t.Fatalf("isWhenManual(%v) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestMatchesAnyPattern(t *testing.T) {
	tests := []struct {
		jobName  string
		patterns []string
		want     bool
	}{
		{"semgrep-sast", []string{"*-sast"}, true},
		{"bandit-sast", []string{"*-sast"}, true},
		{"secret_detection", []string{"secret_detection"}, true},
		{"container_scanning", []string{"container_scanning"}, true},
		{"gemnasium-dependency_scanning", []string{"gemnasium-*"}, true},
		{"dast_api", []string{"dast_*"}, true},
		{"build", []string{"*-sast", "secret_detection"}, false},
		{"my-sast-job", []string{"*-sast"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.jobName, func(t *testing.T) {
			got := matchesAnyPattern(tt.jobName, tt.patterns)
			if got != tt.want {
				t.Fatalf("matchesAnyPattern(%q, %v) = %v, want %v", tt.jobName, tt.patterns, got, tt.want)
			}
		})
	}
}
