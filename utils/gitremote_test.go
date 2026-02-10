package utils

import (
	"testing"
)

func TestParseGitRemoteURL(t *testing.T) {
	tests := []struct {
		name         string
		remoteURL    string
		wantHost     string
		wantProject  string
		wantURL      string
		wantNil      bool
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
