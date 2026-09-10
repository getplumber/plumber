package utils

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
)

// GitRemoteInfo contains parsed information from a git remote URL.
type GitRemoteInfo struct {
	Host        string // e.g., "gitlab.com", "github.com", "gitlab.example.com"
	ProjectPath string // e.g., "group/project" or "group/subgroup/project"
	URL         string // The full instance URL, e.g., "https://gitlab.com"
	RepoRoot    string // Absolute path to the git repository root
	Provider    string // "gitlab" or "github" — derived from Host; default "gitlab" for unknown hosts (self-hosted GitLab is the common case).
	// ProviderReason is a short, user-facing explanation of why Provider was
	// chosen (host match, .github/workflows marker, or the GitLab default),
	// surfaced in the detection banner. Empty when set host-only by
	// ParseGitRemoteURL (no working tree available).
	ProviderReason string
}

// detectProviderFromHost maps a git remote host name to the provider name
// expected by the rest of Plumber, using the host name alone. GitHub is
// identified exactly; everything else (including self-hosted and gitlab.com)
// maps to GitLab since that is what Plumber has historically supported.
//
// Host name alone cannot tell GitHub Enterprise Server apart from a
// self-hosted GitLab — both live on arbitrary corporate domains. Callers
// that have the working tree available should prefer detectProvider, which
// disambiguates using the repository contents.
func detectProviderFromHost(host string) string {
	switch strings.ToLower(host) {
	case "github.com":
		return "github"
	default:
		return "gitlab"
	}
}

// detectProvider picks the provider for a remote, using the checked-out
// repository to disambiguate when the host name is not conclusive.
//
// github.com is always GitHub. For any other host — self-managed GitLab and
// GitHub Enterprise Server share corporate domains and are indistinguishable
// by URL — a .github/workflows directory is treated as a positive GitHub
// signal: GitHub mandates that exact path for Actions workflows, so its
// presence is reliable. We deliberately do NOT look for a GitLab CI file:
// its name and path are user-configurable ($CI_CONFIG_PATH), so its absence
// proves nothing. Anything without the GitHub marker defaults to GitLab,
// preserving historical behaviour.
func detectProvider(host, repoRoot string) (provider, reason string) {
	// Known SaaS hosts are conclusive by name; never let repository contents
	// reclassify them (a gitlab.com mirror may legitimately carry a
	// .github/workflows directory).
	switch strings.ToLower(host) {
	case "github.com":
		return "github", "host is github.com"
	case "gitlab.com":
		return "gitlab", "host is gitlab.com"
	}
	// Unknown corporate host (self-managed GitLab vs GHES): use the GitHub
	// workflows marker as a positive signal, else default to GitLab.
	if hasGitHubWorkflows(repoRoot) {
		return "github", fmt.Sprintf("host %q is unrecognized but the repository has a .github/workflows directory", host)
	}
	return "gitlab", fmt.Sprintf("host %q is unrecognized; defaulting to GitLab", host)
}

// hasGitHubWorkflows reports whether repoRoot contains at least one GitHub
// Actions workflow file under the GitHub-mandated .github/workflows path.
func hasGitHubWorkflows(repoRoot string) bool {
	if repoRoot == "" {
		return false
	}
	entries, err := os.ReadDir(filepath.Join(repoRoot, ".github", "workflows"))
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") {
			return true
		}
	}
	return false
}

// gitCommand builds a git invocation scoped to dir with dir declared as safe.directory (#464).
// -c is protected configuration, so git honors safe.directory from it even when the repository
// is owned by another uid (the GitLab docker executor clones $CI_PROJECT_DIR as root while the
// image runs as uid 65532); git >= 2.35.2 otherwise refuses with "detected dubious ownership".
// The single inspected directory is named, never '*': the trust decision stays as narrow as the
// question being asked.
func gitCommand(dir string, args ...string) *exec.Cmd {
	full := append([]string{"-c", "safe.directory=" + dir}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	return cmd
}

// runGit runs a gitCommand and returns its trimmed stdout. On failure it logs the first stderr
// line (#464): before this, a dubious-ownership refusal and "not a git repository" were
// indistinguishable to every caller, and platform mode silently lost five controls on the
// default executor with nothing in the job log to explain it.
//
// "not a git repository" is the routine, expected case for every plumber invocation outside a
// git checkout (`plumber analyze` runs at Warn by default), so it logs at Debug; any other
// failure, dubious ownership included, is unexpected in a real checkout and logs at Warn.
func runGit(dir string, args ...string) (string, error) {
	cmd := gitCommand(dir, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		first := strings.SplitN(strings.TrimSpace(stderr.String()), "\n", 2)[0]
		entry := logrus.WithFields(logrus.Fields{"dir": dir, "args": strings.Join(args, " ")})
		if strings.Contains(first, "not a git repository") {
			entry.Debugf("git %s failed: %s", strings.Join(args, " "), first)
		} else {
			entry.Warnf("git %s failed: %s", strings.Join(args, " "), first)
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// DetectGitRemote attempts to detect GitLab URL and project path from git remote.
// It tries the "origin" remote first.
// Returns nil if detection fails (not a git repo, no remote, not a GitLab URL, etc.)
func DetectGitRemote() *GitRemoteInfo {
	// Try to get the origin remote URL
	dir, _ := os.Getwd()
	remoteURL, err := runGit(dir, "remote", "get-url", "origin")
	if err != nil {
		return nil
	}

	if remoteURL == "" {
		return nil
	}

	info := ParseGitRemoteURL(remoteURL)
	if info == nil {
		return nil
	}

	// Also detect the git repository root directory
	info.RepoRoot = DetectGitRepoRoot()

	// Re-evaluate the provider now that the working tree is available.
	// ParseGitRemoteURL set it from the host alone (no repo root); with the
	// tree we can tell GitHub Enterprise Server apart from self-hosted GitLab
	// via the .github/workflows marker. github.com and the GitLab default are
	// unchanged by this.
	info.Provider, info.ProviderReason = detectProvider(info.Host, info.RepoRoot)

	return info
}

// DetectGitRepoRoot returns the absolute path to the root of the current git repository.
// Returns an empty string if not in a git repository.
func DetectGitRepoRoot() string {
	dir, _ := os.Getwd()
	out, err := runGit(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return ""
	}
	return out
}

// DetectGitHeadSHA returns the full commit SHA of HEAD at repoRoot.
// Used to anchor remote source links to the exact code that was
// analysed instead of a mutable branch name. Returns "" when repoRoot
// is empty, not a git repository, or in a detached state with no
// resolvable HEAD (rare); callers fall back to a branch-name link.
func DetectGitHeadSHA(repoRoot string) string {
	if repoRoot == "" {
		return ""
	}
	out, err := runGit(repoRoot, "rev-parse", "HEAD")
	if err != nil {
		return ""
	}
	return out
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
