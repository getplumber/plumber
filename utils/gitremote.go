package utils

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// GitRemoteInfo contains parsed information from a git remote URL.
type GitRemoteInfo struct {
	Host        string // e.g., "gitlab.com", "github.com", "gitlab.example.com"
	ProjectPath string // e.g., "group/project" or "group/subgroup/project"
	URL         string // The full instance URL, e.g., "https://gitlab.com"
	RepoRoot    string // Absolute path to the git repository root
	Provider    string // "gitlab" or "github" — derived from Host; default "gitlab" for unknown hosts (self-hosted GitLab is the common case).
}

// detectProviderFromHost maps a git remote host name to the provider name
// expected by the rest of Plumber. GitHub is identified exactly;
// everything else (including self-hosted and gitlab.com) maps to GitLab
// since that is what Plumber has historically supported.
func detectProviderFromHost(host string) string {
	switch strings.ToLower(host) {
	case "github.com":
		return "github"
	default:
		return "gitlab"
	}
}

// DetectGitRemote attempts to detect GitLab URL and project path from git remote.
// It tries the "origin" remote first.
// Returns nil if detection fails (not a git repo, no remote, not a GitLab URL, etc.)
func DetectGitRemote() *GitRemoteInfo {
	// Try to get the origin remote URL
	cmd := exec.Command("git", "remote", "get-url", "origin")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	remoteURL := strings.TrimSpace(string(output))
	if remoteURL == "" {
		return nil
	}

	info := ParseGitRemoteURL(remoteURL)
	if info == nil {
		return nil
	}

	// Also detect the git repository root directory
	info.RepoRoot = DetectGitRepoRoot()

	return info
}

// DetectGitRepoRoot returns the absolute path to the root of the current git repository.
// Returns an empty string if not in a git repository.
func DetectGitRepoRoot() string {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// ParseGitRemoteURL parses a git remote URL and extracts host and project path.
// Supports the following formats:
//   - SSH URL:       ssh://git@host[:port]/group/project.git
//   - SSH SCP-like:  git@host:group/project.git
//   - HTTPS:         https://host[:port]/group/project.git
//   - Git protocol:  git://host[:port]/group/project.git
//
// Returns nil if the URL cannot be parsed.
func ParseGitRemoteURL(remoteURL string) *GitRemoteInfo {
	// Try SSH URL format: ssh://[user@]host[:port]/path.git
	// The port is intentionally ignored as the platform API uses HTTPS.
	sshURLRegex := regexp.MustCompile(`^ssh://[^@]+@([^/:]+)(?::\d+)?/(.+?)(?:\.git)?$`)
	if matches := sshURLRegex.FindStringSubmatch(remoteURL); matches != nil {
		return newGitRemoteInfo(matches[1], matches[2])
	}

	// Try SSH SCP-like format: git@host:path.git
	sshRegex := regexp.MustCompile(`^git@([^:]+):(.+?)(?:\.git)?$`)
	if matches := sshRegex.FindStringSubmatch(remoteURL); matches != nil {
		return newGitRemoteInfo(matches[1], matches[2])
	}

	// Try HTTPS format: https://host[:port]/path.git
	httpsRegex := regexp.MustCompile(`^https?://([^/]+)/(.+?)(?:\.git)?$`)
	if matches := httpsRegex.FindStringSubmatch(remoteURL); matches != nil {
		return newGitRemoteInfo(matches[1], matches[2])
	}

	// Try Git protocol format: git://host[:port]/path.git
	gitRegex := regexp.MustCompile(`^git://([^/:]+)(?::\d+)?/(.+?)(?:\.git)?$`)
	if matches := gitRegex.FindStringSubmatch(remoteURL); matches != nil {
		return newGitRemoteInfo(matches[1], matches[2])
	}

	return nil
}

func newGitRemoteInfo(host, projectPath string) *GitRemoteInfo {
	return &GitRemoteInfo{
		Host:        host,
		ProjectPath: projectPath,
		URL:         fmt.Sprintf("https://%s", host),
		Provider:    detectProviderFromHost(host),
	}
}
