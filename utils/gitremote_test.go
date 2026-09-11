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

		// Row51/UserinfoStripped: a runner clone carries the job token as
		// userinfo in the remote (gitlab-ci-token:<token>@host), and it must
		// never survive into Host or URL.
		{
			name:        "Row51 GitLab CI job token stripped from HTTPS host",
			remoteURL:   "https://gitlab-ci-token:glcbt-xxxx@gitlab.example.com/group/project.git",
			wantHost:    "gitlab.example.com",
			wantProject: "group/project",
			wantURL:     "https://gitlab.example.com",
		},
		{
			name:        "Row51 GHES access token stripped from HTTPS host",
			remoteURL:   "https://x-access-token:ghs_xxx@ghes.example.com/org/repo.git",
			wantHost:    "ghes.example.com",
			wantProject: "org/repo",
			wantURL:     "https://ghes.example.com",
		},
		{
			name:        "Row51 UserinfoStripped bare username stripped from HTTPS host",
			remoteURL:   "https://user@gitlab.example.com/g/p.git",
			wantHost:    "gitlab.example.com",
			wantProject: "g/p",
			wantURL:     "https://gitlab.example.com",
		},
		{
			name:        "Row51 UserinfoStripped SSH URL unchanged",
			remoteURL:   "ssh://git@gitlab.example.com:2222/g/p.git",
			wantHost:    "gitlab.example.com",
			wantProject: "g/p",
			wantURL:     "https://gitlab.example.com",
		},
		{
			name:        "Row51 UserinfoStripped SCP-like unchanged",
			remoteURL:   "git@gitlab.example.com:g/p.git",
			wantHost:    "gitlab.example.com",
			wantProject: "g/p",
			wantURL:     "https://gitlab.example.com",
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

// TestParseGitRemoteURLStripsCredentialsUpToTheLastAt pins the parse of the remote a CI
// runner actually leaves behind. GitLab's runner rewrites origin to
// CI_REPOSITORY_URL, which embeds the job token as userinfo
// (https://gitlab-ci-token:<token>@host/path.git). Keeping that userinfo in
// Host made every derived value wrong: URL became
// https://gitlab-ci-token:<token>@gitlab.com, which can never equal the
// instance URL, so the checkout was never recognised as the analyzed
// project and the CI config digest was never computed. Every component job
// then ran as digest-divergent and lost its include attribution. Provider
// detection saw the same mangled host and fell through to its default.
//
// Credentials are transport, not identity: they are stripped, and the host
// keeps its port.
func TestParseGitRemoteURLStripsCredentialsUpToTheLastAt(t *testing.T) {
	cases := []struct {
		name         string
		remoteURL    string
		wantHost     string
		wantProject  string
		wantURL      string
		wantProvider string
	}{
		{
			// An unencoded "@" inside the password is invalid per the URL
			// spec but is exactly what a hand-typed or generated token can
			// contain. The userinfo group must still eat everything up to
			// the LAST "@" before the first "/", not stop at the first one
			// it sees, or "ss" would be misread as the host.
			name:         "HTTPS with an unencoded @ inside the password",
			remoteURL:    "https://user:p@ss@gitlab.example.com/group/proj.git",
			wantHost:     "gitlab.example.com",
			wantProject:  "group/proj",
			wantURL:      "https://gitlab.example.com",
			wantProvider: "gitlab",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ParseGitRemoteURL(c.remoteURL)
			if got == nil {
				t.Fatalf("ParseGitRemoteURL(%q) = nil, want a parsed remote", c.remoteURL)
			}
			if got.Host != c.wantHost {
				t.Errorf("Host = %q, want %q", got.Host, c.wantHost)
			}
			if got.ProjectPath != c.wantProject {
				t.Errorf("ProjectPath = %q, want %q", got.ProjectPath, c.wantProject)
			}
			if got.URL != c.wantURL {
				t.Errorf("URL = %q, want %q", got.URL, c.wantURL)
			}
			if got.Provider != c.wantProvider {
				t.Errorf("Provider = %q, want %q", got.Provider, c.wantProvider)
			}
		})
	}
}

// An @ inside the path is not userinfo. Stripping it would eat the first
// path segment of a legitimate project.
func TestParseGitRemoteURLKeepsAnAtInThePath(t *testing.T) {
	got := ParseGitRemoteURL("https://gitlab.com/group/proj@1.0.0.git")
	if got == nil {
		t.Fatal("ParseGitRemoteURL = nil, want a parsed remote")
	}
	if got.Host != "gitlab.com" {
		t.Errorf("Host = %q, want %q", got.Host, "gitlab.com")
	}
	if got.ProjectPath != "group/proj@1.0.0" {
		t.Errorf("ProjectPath = %q, want %q", got.ProjectPath, "group/proj@1.0.0")
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
