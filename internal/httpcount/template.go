package httpcount

import (
	"regexp"
	"strings"
)

// rawHost serves repository files; its paths are /{owner}/{repo}/{ref}/{file}.
const rawHost = "raw.githubusercontent.com"

// ghesPrefix is where a GitHub Enterprise Server host serves the REST API.
const ghesPrefix = "/api/v3"

// apiRoutes turns the REST paths the CLI calls into endpoint templates, so
// the report groups requests by endpoint. Order matters: a longer route
// comes before the route it extends (a branch named x/protection reads as
// the protection route, which is fine for counting).
var apiRoutes = []struct {
	pattern  *regexp.Regexp
	template string
}{
	{regexp.MustCompile(`^/repos/[^/]+/[^/]+$`), "/repos/{owner}/{repo}"},
	{regexp.MustCompile(`^/repos/[^/]+/[^/]+/git/ref/tags/.+$`), "/repos/{owner}/{repo}/git/ref/tags/{tag}"},
	{regexp.MustCompile(`^/repos/[^/]+/[^/]+/git/tags/[^/]+$`), "/repos/{owner}/{repo}/git/tags/{sha}"},
	{regexp.MustCompile(`^/repos/[^/]+/[^/]+/branches$`), "/repos/{owner}/{repo}/branches"},
	{regexp.MustCompile(`^/repos/[^/]+/[^/]+/branches/.+/protection$`), "/repos/{owner}/{repo}/branches/{branch}/protection"},
	{regexp.MustCompile(`^/repos/[^/]+/[^/]+/branches/.+$`), "/repos/{owner}/{repo}/branches/{branch}"},
	{regexp.MustCompile(`^/repos/[^/]+/[^/]+/rules/branches/.+$`), "/repos/{owner}/{repo}/rules/branches/{branch}"},
	{regexp.MustCompile(`^/repos/[^/]+/[^/]+/commits/[^/]+$`), "/repos/{owner}/{repo}/commits/{ref}"},
	{regexp.MustCompile(`^/repos/[^/]+/[^/]+/releases$`), "/repos/{owner}/{repo}/releases"},
	{regexp.MustCompile(`^/repos/[^/]+/[^/]+/releases/latest$`), "/repos/{owner}/{repo}/releases/latest"},
	{regexp.MustCompile(`^/repos/[^/]+/[^/]+/releases/tags/.+$`), "/repos/{owner}/{repo}/releases/tags/{tag}"},
	{regexp.MustCompile(`^/repos/[^/]+/[^/]+/tags$`), "/repos/{owner}/{repo}/tags"},
	{regexp.MustCompile(`^/repos/[^/]+/[^/]+/contents(/.*)?$`), "/repos/{owner}/{repo}/contents/{path}"},
	{regexp.MustCompile(`^/repos/[^/]+/[^/]+/environments$`), "/repos/{owner}/{repo}/environments"},
	{regexp.MustCompile(`^/repos/[^/]+/[^/]+/actions/workflows$`), "/repos/{owner}/{repo}/actions/workflows"},
	{regexp.MustCompile(`^/repos/[^/]+/[^/]+/actions/runs$`), "/repos/{owner}/{repo}/actions/runs"},
	{regexp.MustCompile(`^/repos/[^/]+/[^/]+/actions/runs/\d+/jobs$`), "/repos/{owner}/{repo}/actions/runs/{run_id}/jobs"},
	{regexp.MustCompile(`^/repos/[^/]+/[^/]+/actions/jobs/\d+/logs$`), "/repos/{owner}/{repo}/actions/jobs/{job_id}/logs"},
}

// Template is the endpoint a request path belongs to, e.g.
// /repos/actions/checkout/git/ref/tags/v4 → /repos/{owner}/{repo}/git/ref/tags/{tag}.
// On raw.githubusercontent.com the file stays visible
// (/{owner}/{repo}/{ref}/action.yml), as which files are probed is what
// costs. A path no route knows (/advisories, /rate_limit, a log store) is
// its own template, so a new endpoint never disappears from the report.
func Template(host, path string) string {
	if host == rawHost {
		parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 4)
		if len(parts) == 4 {
			return "/{owner}/{repo}/{ref}/" + parts[3]
		}
		return path
	}
	prefix := ""
	if strings.HasPrefix(path, ghesPrefix+"/") {
		prefix, path = ghesPrefix, strings.TrimPrefix(path, ghesPrefix)
	}
	for _, r := range apiRoutes {
		if r.pattern.MatchString(path) {
			return prefix + r.template
		}
	}
	return prefix + path
}
