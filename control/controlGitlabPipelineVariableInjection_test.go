package control

import (
	"testing"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/gitlab"
)

func buildPipelineOriginDataWithJobs(jobs map[string]interface{}) *collector.GitlabPipelineOriginData {
	mergedConf := &gitlab.GitlabCIConf{
		GitlabJobs: jobs,
	}
	return &collector.GitlabPipelineOriginData{
		MergedConf: mergedConf,
		CiValid:    true,
		CiMissing:  false,
	}
}

func TestVariableInjection_Disabled(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            false,
		DangerousVariables: []string{"CI_COMMIT_MESSAGE"},
	}
	data := buildPipelineOriginDataWithJobs(nil)

	result := conf.Run(data)

	if !result.Skipped {
		t.Fatal("expected control to be skipped when disabled")
	}
	if result.Compliance != 100.0 {
		t.Fatalf("expected compliance 100 when skipped, got %v", result.Compliance)
	}
}

func TestVariableInjection_NoDangerousVariablesConfigured(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            true,
		DangerousVariables: []string{},
	}
	data := buildPipelineOriginDataWithJobs(nil)

	result := conf.Run(data)

	if !result.Skipped {
		t.Fatal("expected control to be skipped when no dangerous variables configured")
	}
}

func TestVariableInjection_NilMergedConf(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            true,
		DangerousVariables: []string{"CI_COMMIT_MESSAGE"},
	}
	data := &collector.GitlabPipelineOriginData{
		MergedConf: nil,
		CiValid:    true,
		CiMissing:  false,
	}

	result := conf.Run(data)

	if result.Compliance != 0 {
		t.Fatalf("expected compliance 0 when merged conf unavailable, got %v", result.Compliance)
	}
	if result.Error == "" {
		t.Fatal("expected error message when merged conf unavailable")
	}
}

// -- Safe patterns: shell does NOT re-parse expanded env vars --

func TestVariableInjection_EchoIsSafe(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            true,
		DangerousVariables: []string{"CI_COMMIT_MESSAGE"},
	}

	tests := []struct {
		name   string
		script string
	}{
		{"unquoted", "echo $CI_COMMIT_MESSAGE"},
		{"double quoted", `echo "$CI_COMMIT_MESSAGE"`},
		{"braced", "echo ${CI_COMMIT_MESSAGE}"},
		{"braced quoted", `echo "${CI_COMMIT_MESSAGE}"`},
		{"printf", `printf '%s\n' "$CI_COMMIT_MESSAGE"`},
		{"curl data", `curl -d "$CI_COMMIT_MESSAGE" https://example.com`},
		{"git checkout", "git checkout $CI_COMMIT_MESSAGE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jobContent := map[interface{}]interface{}{
				"script": []interface{}{tt.script},
			}
			data := buildPipelineOriginDataWithJobs(map[string]interface{}{"build": jobContent})
			result := conf.Run(data)
			if len(result.Issues) != 0 {
				t.Fatalf("script %q should be safe, but got %d issues", tt.script, len(result.Issues))
			}
			if result.Compliance != 100.0 {
				t.Fatalf("expected compliance 100, got %v", result.Compliance)
			}
		})
	}
}

// -- Dangerous patterns: commands that re-interpret args as shell code --

func TestVariableInjection_EvalIsDangerous(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            true,
		DangerousVariables: []string{"CI_MERGE_REQUEST_TITLE"},
	}

	tests := []struct {
		name   string
		script string
	}{
		{"eval bare", "eval $CI_MERGE_REQUEST_TITLE"},
		{"eval quoted", `eval "echo $CI_MERGE_REQUEST_TITLE"`},
		{"eval braced", `eval "${CI_MERGE_REQUEST_TITLE}"`},
		{"eval braced no quotes", `eval ${CI_MERGE_REQUEST_TITLE}`},
		{"eval in middle", `RESULT=$(eval "echo $CI_MERGE_REQUEST_TITLE")`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jobContent := map[interface{}]interface{}{
				"script": []interface{}{tt.script},
			}
			data := buildPipelineOriginDataWithJobs(map[string]interface{}{"build": jobContent})
			result := conf.Run(data)
			if len(result.Issues) != 1 {
				t.Fatalf("script %q should be dangerous, expected 1 issue, got %d", tt.script, len(result.Issues))
			}
		})
	}
}

func TestVariableInjection_ShCIsDangerous(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            true,
		DangerousVariables: []string{"CI_COMMIT_BRANCH"},
	}

	tests := []struct {
		name   string
		script string
	}{
		// sh -c variants
		{"sh -c quoted", `sh -c "echo $CI_COMMIT_BRANCH"`},
		{"sh -c unquoted", `sh -c $CI_COMMIT_BRANCH`},
		{"sh -c braced", `sh -c ${CI_COMMIT_BRANCH}`},
		{"sh -c braced quoted", `sh -c "${CI_COMMIT_BRANCH}"`},
		// bash -c variants
		{"bash -c quoted", `bash -c "deploy $CI_COMMIT_BRANCH"`},
		{"bash -c unquoted", `bash -c $CI_COMMIT_BRANCH`},
		{"bash -c braced quoted", `bash -c "${CI_COMMIT_BRANCH}"`},
		// dash -c variants
		{"dash -c quoted", `dash -c "$CI_COMMIT_BRANCH"`},
		{"dash -c braced", `dash -c ${CI_COMMIT_BRANCH}`},
		// zsh -c variants
		{"zsh -c quoted", `zsh -c "$CI_COMMIT_BRANCH"`},
		{"zsh -c unquoted", `zsh -c $CI_COMMIT_BRANCH`},
		{"zsh -c braced quoted", `zsh -c "${CI_COMMIT_BRANCH}"`},
		// ksh -c variants
		{"ksh -c unquoted", `ksh -c $CI_COMMIT_BRANCH`},
		{"ksh -c quoted", `ksh -c "$CI_COMMIT_BRANCH"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jobContent := map[interface{}]interface{}{
				"script": []interface{}{tt.script},
			}
			data := buildPipelineOriginDataWithJobs(map[string]interface{}{"deploy": jobContent})
			result := conf.Run(data)
			if len(result.Issues) != 1 {
				t.Fatalf("script %q should be dangerous, expected 1 issue, got %d", tt.script, len(result.Issues))
			}
		})
	}
}

func TestVariableInjection_XargsShIsDangerous(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            true,
		DangerousVariables: []string{"CI_COMMIT_BRANCH"},
	}

	tests := []struct {
		name   string
		script string
	}{
		{"xargs sh", `echo "$CI_COMMIT_BRANCH" | xargs sh`},
		{"xargs bash", `echo "$CI_COMMIT_BRANCH" | xargs bash`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jobContent := map[interface{}]interface{}{
				"script": []interface{}{tt.script},
			}
			data := buildPipelineOriginDataWithJobs(map[string]interface{}{"build": jobContent})
			result := conf.Run(data)
			if len(result.Issues) != 1 {
				t.Fatalf("script %q should be dangerous, expected 1 issue, got %d", tt.script, len(result.Issues))
			}
		})
	}
}

func TestVariableInjection_ShellWithoutCFlagIsSafe(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            true,
		DangerousVariables: []string{"CI_COMMIT_BRANCH"},
	}

	tests := []struct {
		name   string
		script string
	}{
		{"bash filename", `bash "$CI_COMMIT_BRANCH"`},
		{"bash filename braced", `bash ${CI_COMMIT_BRANCH}`},
		{"dash filename", `dash $CI_COMMIT_BRANCH`},
		{"zsh filename", `zsh "$CI_COMMIT_BRANCH"`},
		{"ksh filename", `ksh $CI_COMMIT_BRANCH`},
		{"envsubst no pipe", `envsubst "$CI_COMMIT_BRANCH"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jobContent := map[interface{}]interface{}{
				"script": []interface{}{tt.script},
			}
			data := buildPipelineOriginDataWithJobs(map[string]interface{}{"build": jobContent})
			result := conf.Run(data)
			if len(result.Issues) != 0 {
				t.Fatalf("script %q should be safe (no -c flag), but got %d issues", tt.script, len(result.Issues))
			}
		})
	}
}

func TestVariableInjection_SourceIsDangerous(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            true,
		DangerousVariables: []string{"CI_COMMIT_REF_NAME"},
	}

	jobContent := map[interface{}]interface{}{
		"script": []interface{}{
			`source <(echo "$CI_COMMIT_REF_NAME")`,
		},
	}
	data := buildPipelineOriginDataWithJobs(map[string]interface{}{"build": jobContent})
	result := conf.Run(data)

	if len(result.Issues) != 1 {
		t.Fatalf("source with dangerous var should flag, got %d issues", len(result.Issues))
	}
}

func TestVariableInjection_EnvsubstPipeIsDangerous(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            true,
		DangerousVariables: []string{"CI_COMMIT_MESSAGE"},
	}

	jobContent := map[interface{}]interface{}{
		"script": []interface{}{
			`envsubst '$CI_COMMIT_MESSAGE' < template.sh | sh`,
		},
	}
	data := buildPipelineOriginDataWithJobs(map[string]interface{}{"build": jobContent})
	result := conf.Run(data)

	if len(result.Issues) != 1 {
		t.Fatalf("envsubst | sh with dangerous var should flag, got %d issues", len(result.Issues))
	}
}

// -- Aliasing through variables: block does NOT help for eval/sh -c --

func TestVariableInjection_AliasedVarInEvalStillDangerous(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            true,
		DangerousVariables: []string{"CI_COMMIT_BRANCH"},
	}

	jobContent := map[interface{}]interface{}{
		"variables": map[interface{}]interface{}{
			"BRANCH": "$CI_COMMIT_BRANCH",
		},
		"script": []interface{}{
			`eval "deploy $CI_COMMIT_BRANCH"`,
		},
	}
	data := buildPipelineOriginDataWithJobs(map[string]interface{}{"deploy": jobContent})
	result := conf.Run(data)

	if len(result.Issues) != 1 {
		t.Fatalf("eval with dangerous var should flag even when aliased, got %d issues", len(result.Issues))
	}
}

// -- Edge cases --

func TestVariableInjection_SkipsComments(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            true,
		DangerousVariables: []string{"CI_COMMIT_MESSAGE"},
	}

	jobContent := map[interface{}]interface{}{
		"script": []interface{}{
			"# eval $CI_COMMIT_MESSAGE",
			"  # sh -c $CI_COMMIT_MESSAGE",
		},
	}
	data := buildPipelineOriginDataWithJobs(map[string]interface{}{"build": jobContent})
	result := conf.Run(data)

	if len(result.Issues) != 0 {
		t.Fatalf("comment lines should be skipped, got %d issues", len(result.Issues))
	}
}

func TestVariableInjection_DoesNotMatchLongerVariable(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            true,
		DangerousVariables: []string{"CI_COMMIT_BRANCH"},
	}

	jobContent := map[interface{}]interface{}{
		"script": []interface{}{
			"eval $CI_COMMIT_BRANCH_NAME_EXTRA",
		},
	}
	data := buildPipelineOriginDataWithJobs(map[string]interface{}{"build": jobContent})
	result := conf.Run(data)

	if len(result.Issues) != 0 {
		t.Fatalf("longer variable name should not match, got %d issues", len(result.Issues))
	}
}

func TestVariableInjection_MultipleVarsMultipleJobs(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            true,
		DangerousVariables: []string{"CI_COMMIT_MESSAGE", "CI_COMMIT_REF_NAME"},
	}

	job1 := map[interface{}]interface{}{
		"script": []interface{}{
			`eval "echo $CI_COMMIT_MESSAGE"`,
		},
	}
	job2 := map[interface{}]interface{}{
		"script": []interface{}{
			`bash -c "deploy $CI_COMMIT_REF_NAME"`,
		},
	}
	data := buildPipelineOriginDataWithJobs(map[string]interface{}{
		"build":  job1,
		"deploy": job2,
	})
	result := conf.Run(data)

	if len(result.Issues) != 2 {
		t.Fatalf("expected 2 issues, got %d", len(result.Issues))
	}
	if result.Compliance != 0.0 {
		t.Fatalf("expected compliance 0, got %v", result.Compliance)
	}
}

func TestVariableInjection_DetectsInBeforeScript(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            true,
		DangerousVariables: []string{"CI_COMMIT_REF_NAME"},
	}

	jobContent := map[interface{}]interface{}{
		"script":        "echo hello",
		"before_script": []interface{}{`sh -c "setup $CI_COMMIT_REF_NAME"`},
	}
	data := buildPipelineOriginDataWithJobs(map[string]interface{}{"deploy": jobContent})
	result := conf.Run(data)

	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(result.Issues))
	}
	if result.Issues[0].ScriptBlock != "before_script" {
		t.Fatalf("expected scriptBlock 'before_script', got %s", result.Issues[0].ScriptBlock)
	}
}

func TestVariableInjection_DetectsInAfterScript(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            true,
		DangerousVariables: []string{"CI_COMMIT_TITLE"},
	}

	jobContent := map[interface{}]interface{}{
		"script":       "echo hello",
		"after_script": []interface{}{`eval "notify $CI_COMMIT_TITLE"`},
	}
	data := buildPipelineOriginDataWithJobs(map[string]interface{}{"notify": jobContent})
	result := conf.Run(data)

	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(result.Issues))
	}
	if result.Issues[0].ScriptBlock != "after_script" {
		t.Fatalf("expected scriptBlock 'after_script', got %s", result.Issues[0].ScriptBlock)
	}
}

func TestVariableInjection_GlobalBeforeScript(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            true,
		DangerousVariables: []string{"CI_COMMIT_BRANCH"},
	}

	mergedConf := &gitlab.GitlabCIConf{
		BeforeScript: []interface{}{
			`eval "setup $CI_COMMIT_BRANCH"`,
		},
		GitlabJobs: map[string]interface{}{},
	}
	data := &collector.GitlabPipelineOriginData{
		MergedConf: mergedConf,
		CiValid:    true,
		CiMissing:  false,
	}
	result := conf.Run(data)

	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue from global before_script, got %d", len(result.Issues))
	}
	if result.Issues[0].JobName != "(global)" {
		t.Fatalf("expected job '(global)', got %s", result.Issues[0].JobName)
	}
}

func TestVariableInjection_AllowedPattern(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            true,
		DangerousVariables: []string{"CI_COMMIT_REF_NAME"},
		AllowedPatterns:    []string{`deploy\.sh`},
	}

	jobContent := map[interface{}]interface{}{
		"script": []interface{}{
			`sh -c "deploy.sh $CI_COMMIT_REF_NAME"`,
			`sh -c "echo $CI_COMMIT_REF_NAME"`,
		},
	}
	data := buildPipelineOriginDataWithJobs(map[string]interface{}{"build": jobContent})
	result := conf.Run(data)

	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue (second line only), got %d", len(result.Issues))
	}
}

func TestVariableInjection_CleanConfig(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            true,
		DangerousVariables: []string{"CI_COMMIT_MESSAGE", "CI_MERGE_REQUEST_TITLE"},
	}

	jobContent := map[interface{}]interface{}{
		"script": []interface{}{
			"echo $CI_COMMIT_MESSAGE",
			"make build",
			`printf '%s' "$CI_MERGE_REQUEST_TITLE"`,
		},
	}
	data := buildPipelineOriginDataWithJobs(map[string]interface{}{"build": jobContent})
	result := conf.Run(data)

	if result.Compliance != 100.0 {
		t.Fatalf("expected compliance 100, got %v", result.Compliance)
	}
	if len(result.Issues) != 0 {
		t.Fatalf("expected no issues for safe usage, got %d", len(result.Issues))
	}
}

func TestVariableInjection_MixedSafeAndDangerous(t *testing.T) {
	conf := &GitlabPipelineVariableInjectionConf{
		Enabled:            true,
		DangerousVariables: []string{"CI_COMMIT_BRANCH"},
	}

	jobContent := map[interface{}]interface{}{
		"script": []interface{}{
			"echo $CI_COMMIT_BRANCH",
			`git checkout "$CI_COMMIT_BRANCH"`,
			`eval "deploy $CI_COMMIT_BRANCH"`,
		},
	}
	data := buildPipelineOriginDataWithJobs(map[string]interface{}{"build": jobContent})
	result := conf.Run(data)

	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue (only the eval line), got %d", len(result.Issues))
	}
	if result.Issues[0].ScriptLine != `eval "deploy $CI_COMMIT_BRANCH"` {
		t.Fatalf("expected eval line flagged, got %s", result.Issues[0].ScriptLine)
	}
}
