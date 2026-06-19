package cmd

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	providerPkg "github.com/getplumber/plumber/provider"
)

// locationLinker turns a finding's repo-relative file path + line into
// a single best-effort link. There are three regimes:
//
//   - In a CI environment we always emit the host forge's web blob URL
//     for the exact commit, so artifacts uploaded to GitHub Code
//     Scanning / GitLab Security Dashboard / a downloaded JSON file
//     all carry a clickable pointer that survives the run.
//   - In a local CLI run against a remote project (no matching local
//     clone) we still want a remote URL, because the file does not
//     exist on the user's filesystem.
//   - In a local CLI run against the local clone we keep the
//     pre-existing behaviour: an absolute filesystem path with a
//     `:line` suffix that VS Code / iTerm pick up as a source
//     reference.
//
// When mandatory pieces (project path, ref, file) are missing we fall
// back to whatever a previous Plumber version would have emitted — no
// silent breakage.
type locationLinker struct {
	provider  string // "github" or "gitlab"
	serverURL string // web URL of the forge, without trailing slash
	repo      string // owner/repo or group/project
	ref       string // commit SHA preferred, branch name as fallback
	useRemote bool   // true => emit a remote blob URL; false => emit absolute local path
}

// newLocationLinker constructs a linker from the run's configuration
// and analysis result. The decision tree (remote vs local link) is
// captured here so callers just call BuildURL.
func newLocationLinker(conf *configuration.Configuration, result *control.AnalysisResult, provider string) *locationLinker {
	if conf == nil || result == nil {
		return &locationLinker{}
	}
	l := &locationLinker{provider: provider}

	if reg, ok := providerPkg.Get(l.provider); ok {
		env := reg.CIEnvVars()
		serverURLFallback := conf.GitlabURL
		if l.provider == "github" {
			serverURLFallback = githubWebURL(conf.GithubAPIHost)
		}
		l.serverURL = strings.TrimRight(firstNonEmpty(os.Getenv(env.ServerURL), serverURLFallback), "/")
		l.repo = firstNonEmpty(os.Getenv(env.RepoPath), result.ProjectPath, conf.ProjectPath)
		l.ref = firstNonEmpty(os.Getenv(env.CommitSHA), result.HeadCommitSha, result.AnalyzeBranch, conf.Branch, result.DefaultBranch)
	} else {
		// Fallback for unknown providers: use GitLab defaults.
		l.serverURL = strings.TrimRight(firstNonEmpty(os.Getenv("CI_SERVER_URL"), conf.GitlabURL), "/")
		l.repo = firstNonEmpty(os.Getenv("CI_PROJECT_PATH"), result.ProjectPath, conf.ProjectPath)
		l.ref = firstNonEmpty(os.Getenv("CI_COMMIT_SHA"), result.HeadCommitSha, result.AnalyzeBranch, conf.Branch, result.DefaultBranch)
	}

	// Decide whether to prefer remote URLs. The artifact-portability
	// rule wins: any CI run or any run where the local filesystem
	// does not contain the project we just analysed.
	l.useRemote = isCI() || !conf.IsLocalProject

	return l
}

// BuildURL returns a clickable pointer to (file, line). file is the
// finding's recorded path — relative for GitLab, absolute for GitHub;
// the linker normalises it to a repo-relative path before composing
// the URL.
//
// Returns "" when there is not enough information to build any kind
// of link (e.g. file is empty).
func (l *locationLinker) BuildURL(file string, line int) string {
	if l == nil || file == "" {
		return ""
	}
	rel := reportFilePath(file)

	if l.useRemote && l.serverURL != "" && l.repo != "" && l.ref != "" && rel != "" {
		return buildBlobURL(l.provider, l.serverURL, l.repo, l.ref, rel, line)
	}

	// Local fallback: prefer the original absolute path the collector
	// recorded. Editors detect `<path>:<line>` as a source reference.
	abs := file
	if !filepath.IsAbs(abs) {
		if wd, err := os.Getwd(); err == nil {
			abs = filepath.Join(wd, abs)
		}
	}
	if line > 0 {
		return fmt.Sprintf("%s:%d", abs, line)
	}
	return abs
}

// Annotate copies the linker's BuildURL output onto every finding in
// place. Called once per run, just before any output writer reads the
// findings.
func (l *locationLinker) Annotate(findings []opaengine.Finding) {
	if l == nil {
		return
	}
	for i := range findings {
		findings[i].URL = l.BuildURL(findings[i].File, findings[i].Line)
	}
}

// buildBlobURL composes a forge web URL. Path segments are URL-escaped
// individually so that file names with spaces or unicode (uncommon in
// CI configs but possible) do not produce a broken link.
func buildBlobURL(provider, serverURL, repo, ref, relPath string, line int) string {
	// Slashes are structural — they separate path segments and (for
	// the ref) are part of branch names like "feature/foo". Escape
	// each segment individually so "feature/foo" stays as
	// "feature/foo" instead of becoming "feature%2Ffoo", which
	// confuses GitHub's tree-walking resolver. Same logic for repo
	// (group/sub/proj on GitLab) and the file path.
	escapeSegments := func(s string) string {
		parts := strings.Split(s, "/")
		for i, p := range parts {
			parts[i] = url.PathEscape(p)
		}
		return strings.Join(parts, "/")
	}
	infix := "/blob/"
	if p, ok := providerPkg.Get(provider); ok {
		infix = p.BlobURLInfix()
	}
	u := serverURL + "/" + escapeSegments(repo) + infix + escapeSegments(ref) + "/" + escapeSegments(relPath)
	if line > 0 {
		u += fmt.Sprintf("#L%d", line)
	}
	return u
}

// githubWebURL turns the configured API host into a web URL. For
// github.com this is just the constant; for GitHub Enterprise Server
// the API host can be `ghes.example.com` or `ghes.example.com/api/v3`
// and the web host is the same hostname without the API path. CI also
// exports GITHUB_SERVER_URL which we honour first when set.
func githubWebURL(apiHost string) string {
	if v := strings.TrimSpace(os.Getenv("GITHUB_SERVER_URL")); v != "" {
		return v
	}
	apiHost = strings.TrimSpace(apiHost)
	if apiHost == "" {
		return "https://github.com"
	}
	// Split scheme off first so the API-path trimming below doesn't
	// chop "https:" off the front when callers pass a fully-qualified
	// host like "https://ghes.example.com/api/v3".
	scheme := "https"
	host := apiHost
	if i := strings.Index(host, "://"); i >= 0 {
		scheme = host[:i]
		host = host[i+3:]
	}
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	return scheme + "://" + host
}

// isCI returns true when one of the well-known CI env vars is set.
// GitLab CI / GitHub Actions both set CI=true; we also accept their
// vendor-specific markers in case CI is wiped by a wrapper.
func isCI() bool {
	if strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		return true
	}
	if strings.EqualFold(os.Getenv("GITLAB_CI"), "true") {
		return true
	}
	return strings.EqualFold(os.Getenv("CI"), "true")
}

// firstNonEmpty returns the first argument whose trimmed value is
// non-empty, or "" if none are. Used to walk a priority list of
// possible sources for a single piece of metadata.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
