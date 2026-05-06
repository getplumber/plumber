package collector

import (
	"encoding/base64"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/cli/go-gh/v2/pkg/api"

	"github.com/getplumber/plumber/internal/ir"
)

// ScanGitHubWorkflowsRemote fetches `.github/workflows/*.{yml,yaml}`
// from a GitHub project via the Contents API and runs them through
// the same parser as the local scanner. Used by `plumber analyze
// --project owner/repo` (with optional --github-url for GHES) when
// the user is not inside a local checkout.
//
// host empty → api.github.com. ref empty → repo's default branch.
// Auth resolves via the same go-gh chain the metadata client uses
// (GH_TOKEN / GH_ENTERPRISE_TOKEN / GITHUB_TOKEN / gh auth login).
//
// Repo-side artefacts that need a local checkout (Dockerfiles,
// dependabot.yml, SECURITY.md, Renovate config) are NOT collected in
// remote mode — controls that depend on them simply see absent
// inputs and produce no findings. Same degraded-mode contract as
// missing API auth elsewhere.
func ScanGitHubWorkflowsRemote(host, owner, repo, ref string, enrichActionMetadata bool, progressFn ProgressFunc) (*ir.NormalizedPipeline, []error, error) {
	if owner == "" || repo == "" {
		return nil, nil, fmt.Errorf("owner and repo are required for remote scan")
	}

	pipeline := &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitHub,
		ProjectPath:   owner + "/" + repo,
		DefaultBranch: ref,
	}

	rest, err := newGitHubRESTClient(host)
	if err != nil {
		return nil, nil, fmt.Errorf("github api client: %w", err)
	}

	listing, err := listWorkflowFiles(rest, owner, repo, ref)
	if err != nil {
		return nil, nil, fmt.Errorf("list workflows: %w", err)
	}

	// Total = list + per-file fetch + (optional) per-action API
	// enrich. Caller can compute the action count after parsing.
	totalSteps := 1 + len(listing)
	if progressFn != nil {
		progressFn(1, totalSteps, "Listing workflow files")
	}

	var partialErrors []error
	for i, item := range listing {
		baseName := workflowBaseName(item.Name)
		if progressFn != nil {
			progressFn(2+i, totalSteps, "Fetching "+item.Path)
		}
		raw, fetchErr := fetchFileContent(rest, owner, repo, item.Path, ref)
		if fetchErr != nil {
			partialErrors = append(partialErrors, fmt.Errorf("%s: %w", item.Name, fetchErr))
			continue
		}
		jobs, parseErr := parseGitHubWorkflowJobs(raw, baseName, item.Path)
		if parseErr != nil {
			partialErrors = append(partialErrors, fmt.Errorf("%s: %w", item.Name, parseErr))
			continue
		}
		pipeline.Jobs = append(pipeline.Jobs, jobs...)
	}

	sort.Slice(pipeline.Jobs, func(i, j int) bool {
		return pipeline.Jobs[i].Name < pipeline.Jobs[j].Name
	})

	if enrichActionMetadata {
		enrichActionsWithAPIMetadata(pipeline, host, nil)
	}

	return pipeline, partialErrors, nil
}

// newGitHubRESTClient returns a go-gh REST client bound to host (or
// api.github.com when host is empty). Mirrors the constructor in
// github_metadata.go so both consumers share the same auth chain.
func newGitHubRESTClient(host string) (*api.RESTClient, error) {
	if host == "" {
		return api.DefaultRESTClient()
	}
	return api.NewRESTClient(api.ClientOptions{Host: host})
}

// remoteContentEntry is a slim subset of the GitHub Contents API
// directory-listing schema. Only the fields the listing-then-fetch
// flow consumes are unmarshalled.
type remoteContentEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
}

// remoteContentFile is the single-file fetch shape: content is
// Base64 (RFC 4648, line-wrapped) per the API spec; Encoding is
// always "base64" today but the field is kept so a future API
// change surfaces loudly instead of silently corrupting.
type remoteContentFile struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

func listWorkflowFiles(rest *api.RESTClient, owner, repo, ref string) ([]remoteContentEntry, error) {
	endpoint := fmt.Sprintf("repos/%s/%s/contents/%s", owner, repo, githubWorkflowsSubdir)
	if ref != "" {
		endpoint += "?ref=" + ref
	}
	var entries []remoteContentEntry
	if err := rest.Get(endpoint, &entries); err != nil {
		// 404 on the directory means no workflows — return empty,
		// not an error. Anything else (auth, rate-limit) propagates.
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	out := entries[:0]
	for _, e := range entries {
		if e.Type != "file" {
			continue
		}
		if !strings.HasSuffix(e.Name, ".yml") && !strings.HasSuffix(e.Name, ".yaml") {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func fetchFileContent(rest *api.RESTClient, owner, repo, filePath, ref string) ([]byte, error) {
	endpoint := fmt.Sprintf("repos/%s/%s/contents/%s", owner, repo, filePath)
	if ref != "" {
		endpoint += "?ref=" + ref
	}
	var f remoteContentFile
	if err := rest.Get(endpoint, &f); err != nil {
		return nil, err
	}
	if f.Encoding != "" && f.Encoding != "base64" {
		return nil, fmt.Errorf("unexpected content encoding %q for %s", f.Encoding, filePath)
	}
	// GitHub wraps Base64 content at column 60 with newlines per the
	// API docs. encoding/base64 with StdEncoding already accepts the
	// wrapped form when used via DecodeString — but go's standard
	// library is strict about whitespace, so strip newlines first.
	clean := strings.ReplaceAll(f.Content, "\n", "")
	clean = strings.ReplaceAll(clean, " ", "")
	decoded, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("decode base64 for %s: %w", filePath, err)
	}
	return decoded, nil
}

// isNotFound reports whether err is a go-gh HTTPError with status
// 404. The error type lives in cli/go-gh/v2/pkg/api; we type-assert
// to avoid importing the type explicitly at every call site.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	type httpError interface {
		Error() string
	}
	// Best-effort match on the message — go-gh's HTTPError.Error()
	// includes "HTTP 404" verbatim.
	_ = httpError(nil)
	return strings.Contains(err.Error(), "HTTP 404")
}

// workflowOriginPath builds an "owner/repo/.github/workflows/x.yml"
// origin string for findings emitted from a remote scan, so issue
// reports can still point at where the source lives even when there
// is no local file path.
func workflowOriginPath(owner, repo, p string) string {
	return path.Join(owner+"/"+repo, p)
}
