package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseGitRemoteURL(t *testing.T) {
	tests := []struct {
		name        string
		remoteURL   string
		wantHost    string
		wantProject string
		wantURL     string
		wantNil     bool
	}{
		// SSH SCP-like format (git@host:path)
		{
			name:        "SSH SCP-like basic",
			remoteURL:   "git@gitlab.com:group/project.git",
			wantHost:    "gitlab.com",
			wantProject: "group/project",
			wantURL:     "https://gitlab.com",
		},
		{
			name:        "SSH SCP-like without .git suffix",
			remoteURL:   "git@gitlab.com:group/project",
			wantHost:    "gitlab.com",
			wantProject: "group/project",
			wantURL:     "https://gitlab.com",
		},
		{
			name:        "SSH SCP-like with nested groups",
			remoteURL:   "git@gitlab.example.com:group/subgroup/project.git",
			wantHost:    "gitlab.example.com",
			wantProject: "group/subgroup/project",
			wantURL:     "https://gitlab.example.com",
		},

		// SSH URL format (ssh://user@host[:port]/path)
		{
			name:        "SSH URL with custom port",
			remoteURL:   "ssh://git@git.toto.intra:2222/areno/areno-opensearch.git",
			wantHost:    "git.toto.intra",
			wantProject: "areno/areno-opensearch",
			wantURL:     "https://git.toto.intra",
		},
		{
			name:        "SSH URL without port",
			remoteURL:   "ssh://git@gitlab.com/group/project.git",
			wantHost:    "gitlab.com",
			wantProject: "group/project",
			wantURL:     "https://gitlab.com",
		},
		{
			name:        "SSH URL without .git suffix",
			remoteURL:   "ssh://git@gitlab.com/group/project",
			wantHost:    "gitlab.com",
			wantProject: "group/project",
			wantURL:     "https://gitlab.com",
		},
		{
			name:        "SSH URL with nested groups and port",
			remoteURL:   "ssh://git@gitlab.example.com:2222/group/subgroup/project.git",
			wantHost:    "gitlab.example.com",
			wantProject: "group/subgroup/project",
			wantURL:     "https://gitlab.example.com",
		},
		{
			name:        "SSH URL with standard port 22",
			remoteURL:   "ssh://git@gitlab.com:22/group/project.git",
			wantHost:    "gitlab.com",
			wantProject: "group/project",
			wantURL:     "https://gitlab.com",
		},

		// HTTPS format
		{
			name:        "HTTPS basic",
			remoteURL:   "https://gitlab.com/group/project.git",
			wantHost:    "gitlab.com",
			wantProject: "group/project",
			wantURL:     "https://gitlab.com",
		},
		{
			name:        "HTTPS without .git suffix",
			remoteURL:   "https://gitlab.com/group/project",
			wantHost:    "gitlab.com",
			wantProject: "group/project",
			wantURL:     "https://gitlab.com",
		},
		{
			name:        "HTTPS with port",
			remoteURL:   "https://gitlab.example.com:8443/group/project.git",
			wantHost:    "gitlab.example.com:8443",
			wantProject: "group/project",
			wantURL:     "https://gitlab.example.com:8443",
		},
		{
			name:        "HTTPS with nested groups",
			remoteURL:   "https://gitlab.com/group/subgroup/project.git",
			wantHost:    "gitlab.com",
			wantProject: "group/subgroup/project",
			wantURL:     "https://gitlab.com",
		},
		{
			name:        "HTTP format",
			remoteURL:   "http://gitlab.example.com/group/project.git",
			wantHost:    "gitlab.example.com",
			wantProject: "group/project",
			wantURL:     "https://gitlab.example.com",
		},

		// Git protocol format
		{
			name:        "Git protocol basic",
			remoteURL:   "git://gitlab.com/group/project.git",
			wantHost:    "gitlab.com",
			wantProject: "group/project",
			wantURL:     "https://gitlab.com",
		},
		{
			name:        "Git protocol with port",
			remoteURL:   "git://gitlab.example.com:9418/group/project.git",
			wantHost:    "gitlab.example.com",
			wantProject: "group/project",
			wantURL:     "https://gitlab.example.com",
		},

		// Invalid URLs
		{
			name:      "Empty string",
			remoteURL: "",
			wantNil:   true,
		},
		{
			name:      "Invalid format",
			remoteURL: "not-a-valid-url",
			wantNil:   true,
		},
		{
			name:      "FTP protocol unsupported",
			remoteURL: "ftp://gitlab.com/group/project.git",
			wantNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseGitRemoteURL(tt.remoteURL)

			if tt.wantNil {
				if result != nil {
					t.Errorf("ParseGitRemoteURL(%q) = %+v, want nil", tt.remoteURL, result)
				}
				return
			}

			if result == nil {
				t.Fatalf("ParseGitRemoteURL(%q) = nil, want non-nil", tt.remoteURL)
				return
			}

			if result.Host != tt.wantHost {
				t.Errorf("ParseGitRemoteURL(%q).Host = %q, want %q", tt.remoteURL, result.Host, tt.wantHost)
			}

			if result.ProjectPath != tt.wantProject {
				t.Errorf("ParseGitRemoteURL(%q).ProjectPath = %q, want %q", tt.remoteURL, result.ProjectPath, tt.wantProject)
			}

			if result.URL != tt.wantURL {
				t.Errorf("ParseGitRemoteURL(%q).URL = %q, want %q", tt.remoteURL, result.URL, tt.wantURL)
			}
		})
	}
}

func TestDetectProvider(t *testing.T) {
	// Build a repo root that contains a GitHub Actions workflow file, so the
	// .github/workflows positive signal is exercised against the real FS.
	withWorkflows := t.TempDir()
	if err := os.MkdirAll(filepath.Join(withWorkflows, ".github", "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(withWorkflows, ".github", "workflows", "ci.yml"), []byte("name: ci\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A repo with the directory but no workflow file is NOT a GitHub signal.
	emptyWorkflowsDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(emptyWorkflowsDir, ".github", "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}

	noWorkflows := t.TempDir() // plain repo, no .github/workflows

	tests := []struct {
		name     string
		host     string
		repoRoot string
		want     string
	}{
		// github.com is always GitHub, regardless of contents.
		{"github.com no workflows", "github.com", noWorkflows, "github"},
		{"github.com case-insensitive", "GitHub.com", noWorkflows, "github"},
		// GHES: corporate host disambiguated by the workflows marker.
		{"GHES host with workflows", "github.corp.example.com", withWorkflows, "github"},
		// Self-hosted GitLab: corporate host, no GitHub marker -> default GitLab.
		{"self-hosted gitlab no workflows", "gitlab.corp.example.com", noWorkflows, "gitlab"},
		{"corp host empty workflows dir", "git.corp.example.com", emptyWorkflowsDir, "gitlab"},
		// gitlab.com stays GitLab even if a stray workflows dir exists
		// (only matters for the corporate-host ambiguity; SaaS hosts are
		// matched by name first for github.com, default otherwise).
		{"gitlab.com with workflows stays gitlab", "gitlab.com", withWorkflows, "gitlab"},
		// No repo root available (detection ran before tree was known):
		// fall back to host-only behaviour.
		{"GHES host no repo root", "github.corp.example.com", "", "gitlab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := detectProvider(tt.host, tt.repoRoot)
			if got != tt.want {
				t.Errorf("detectProvider(%q, repoRoot) = %q, want %q", tt.host, got, tt.want)
			}
			if reason == "" {
				t.Errorf("detectProvider(%q, repoRoot) returned empty reason", tt.host)
			}
		})
	}
}
