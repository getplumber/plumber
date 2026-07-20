package cmd

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
)

// findRow returns the value of the header row with the given label, and whether
// such a row exists.
func findRow(rows []headerRow, label string) (string, bool) {
	for _, r := range rows {
		if r.label == label {
			return r.value, true
		}
	}
	return "", false
}

// TestBuildRunHeaderRows locks in the condition-dependent run-header logic:
// platform/host selection per provider, the optional Config row, and the
// CI-config-source mapping. renderRunHeader only formats these rows, so testing
// the builder covers the branching that could silently regress.
func TestBuildRunHeaderRows(t *testing.T) {
	tests := []struct {
		name         string
		provider     string
		result       *control.AnalysisResult
		conf         *configuration.Configuration
		wantPlatform string
		wantConfig   string // "" means the row must be absent
		wantCIConfig string // "" means the row must be absent
	}{
		{
			name:         "gitlab with instance URL",
			provider:     "gitlab",
			result:       &control.AnalysisResult{ProjectPath: "group/project", CIConfigSource: "remote"},
			conf:         &configuration.Configuration{GitlabURL: "https://gitlab.example.com"},
			wantPlatform: "GitLab · https://gitlab.example.com",
			wantCIConfig: "fetched from GitLab",
		},
		{
			name:         "gitlab without instance URL",
			provider:     "gitlab",
			result:       &control.AnalysisResult{ProjectPath: "group/project"},
			conf:         &configuration.Configuration{},
			wantPlatform: "GitLab",
		},
		{
			name:         "github with GHES host",
			provider:     "github",
			result:       &control.AnalysisResult{ProjectPath: "owner/repo"},
			conf:         &configuration.Configuration{GithubAPIHost: "ghe.example.com"},
			wantPlatform: "GitHub · ghe.example.com",
		},
		{
			name:         "github on github.com has no host suffix",
			provider:     "github",
			result:       &control.AnalysisResult{ProjectPath: "owner/repo"},
			conf:         &configuration.Configuration{},
			wantPlatform: "GitHub",
		},
		{
			name:         "gitlab URL is not shown for a github run",
			provider:     "github",
			result:       &control.AnalysisResult{ProjectPath: "owner/repo"},
			conf:         &configuration.Configuration{GitlabURL: "https://gitlab.example.com"},
			wantPlatform: "GitHub",
		},
		{
			name:         "config path present adds a Config row",
			provider:     "gitlab",
			result:       &control.AnalysisResult{ProjectPath: "group/project"},
			conf:         &configuration.Configuration{ConfigFilePath: ".plumber.yaml"},
			wantPlatform: "GitLab",
			wantConfig:   ".plumber.yaml",
		},
		{
			name:         "local CI config source",
			provider:     "gitlab",
			result:       &control.AnalysisResult{ProjectPath: "group/project", CIConfigSource: "local"},
			conf:         &configuration.Configuration{},
			wantPlatform: "GitLab",
			wantCIConfig: "local file",
		},
		{
			name:         "unknown CI config source yields no row",
			provider:     "gitlab",
			result:       &control.AnalysisResult{ProjectPath: "group/project", CIConfigSource: ""},
			conf:         &configuration.Configuration{},
			wantPlatform: "GitLab",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := buildRunHeaderRows(tt.provider, tt.result, tt.conf)

			// Project is always the first row.
			if got, ok := findRow(rows, "Project"); !ok || got != tt.result.ProjectPath {
				t.Errorf("Project row = %q (present=%v), want %q", got, ok, tt.result.ProjectPath)
			}
			if rows[0].label != "Project" {
				t.Errorf("first row label = %q, want Project", rows[0].label)
			}

			if got, ok := findRow(rows, "Platform"); !ok || got != tt.wantPlatform {
				t.Errorf("Platform row = %q (present=%v), want %q", got, ok, tt.wantPlatform)
			}

			got, ok := findRow(rows, "Config")
			if tt.wantConfig == "" {
				if ok {
					t.Errorf("Config row present (%q), want absent", got)
				}
			} else if !ok || got != tt.wantConfig {
				t.Errorf("Config row = %q (present=%v), want %q", got, ok, tt.wantConfig)
			}

			gotCI, okCI := findRow(rows, "CI config")
			if tt.wantCIConfig == "" {
				if okCI {
					t.Errorf("CI config row present (%q), want absent", gotCI)
				}
			} else if !okCI || gotCI != tt.wantCIConfig {
				t.Errorf("CI config row = %q (present=%v), want %q", gotCI, okCI, tt.wantCIConfig)
			}
		})
	}
}
