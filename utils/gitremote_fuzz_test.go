package utils

import "testing"

// FuzzParseGitRemoteURL exercises the git remote URL parser with arbitrary inputs
// to detect panics, regex catastrophic backtracking, and unexpected crashes.
//
// Run with: go test -fuzz=FuzzParseGitRemoteURL ./utils/
func FuzzParseGitRemoteURL(f *testing.F) {
	// Seed corpus with representative git remote URL formats
	seeds := []string{
		"",
		"git@gitlab.com:group/project.git",
		"git@gitlab.com:group/project",
		"git@gitlab.example.com:group/subgroup/project.git",
		"ssh://git@git.example.com:2222/group/project.git",
		"ssh://git@gitlab.com/group/project.git",
		"ssh://git@gitlab.com/group/project",
		"ssh://git@gitlab.example.com:2222/group/subgroup/project.git",
		"https://gitlab.com/group/project.git",
		"https://gitlab.com/group/project",
		"https://gitlab.example.com:8443/group/project.git",
		"http://gitlab.com/group/project.git",
		"git://gitlab.com/group/project.git",
		"not-a-url",
		"://invalid",
		"git@:missing-host",
		"https://",
		"ssh://",
		"git@host:",
		string([]byte{0x00, 0x01, 0x02}),
		"git@" + string(make([]byte, 1000)) + ":group/project.git",
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, remoteURL string) {
		// The function should never panic — it returns nil for invalid input
		info := ParseGitRemoteURL(remoteURL)
		if info != nil {
			// If parsing succeeded, host and project path should not be empty
			if info.Host == "" {
				t.Errorf("parsed URL %q has empty host", remoteURL)
			}
			if info.ProjectPath == "" {
				t.Errorf("parsed URL %q has empty project path", remoteURL)
			}
		}
	})
}
