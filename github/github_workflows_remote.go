package github

import (
	"encoding/base64"
	"errors"
	"fmt"
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
func ScanGitHubWorkflowsRemote(host, owner, repo, ref string, enrichActionMetadata, scanMutableExec bool, progressFn ProgressFunc) (*ir.NormalizedPipeline, []error, error) {
	if owner == "" || repo == "" {
		return nil, nil, fmt.Errorf("owner and repo are required for remote scan")
	}

	pipeline := &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitHub,
		ProjectPath:   owner + "/" + repo,
		DefaultBranch: ref,
	}

	// Producer-side check: if the scanned repo is itself an action whose
	// own source fetches mutable remote code, flag it (fetched over raw).
	// Gated on the control being active so a disabled control performs no
	// network fetch of the repo's own action source.
	if scanMutableExec && host == "" {
		pipeline.SelfActionMutableExec = ScanRemoteSelfAction(owner, repo, ref)
	}

	rest, err := newGitHubRESTClient(host)
	if err != nil {
		// ErrAuthRequired carries an actionable multi-line message;
		// wrapping it with "github api client:" turns it into a stack
		// frame in the user-facing output. Pass it through verbatim.
		if errors.Is(err, ErrAuthRequired) {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("github api client: %w", err)
	}

	listing, err := listWorkflowFiles(rest, owner, repo, ref)
	if err != nil {
		return nil, nil, fmt.Errorf("list workflows: %w", err)
	}

	// Record the file count on the pipeline so the caller can use
	// TotalProgressStepsForPipeline for the post-scan slots without
	// having to thread `len(listing)` through extra return values.
	pipeline.WorkflowFileCount = len(listing)

	// Progress bar layout (slots 1..(4+N+M), see
	// TotalProgressStepsForPipeline for the full breakdown):
	//   1                slot for the listing call itself
	//   2..(1+N)         one slot per workflow file fetched here
	//   (2+N)..(1+N+M)   one slot per unique action ref (enrichment
	//                    phase below; M known only after parsing)
	//   (2+N+M)..(4+N+M) caller's trailing slots (branch protection
	//                    resolve, policy eval, analysis complete)
	//
	// During the listing + fetch phase M is unknown, so we report
	// against a partial total (1+N) to keep the bar's percentage
	// monotonic for the visible phase. After parsing we switch to
	// the full total via wrapProgress.
	listingTotal := 1 + len(listing)
	if progressFn != nil {
		progressFn(1, listingTotal, "Listing workflow files")
	}

	var partialErrors []error
	for i, item := range listing {
		baseName := workflowBaseName(item.Name)
		if progressFn != nil {
			progressFn(2+i, listingTotal, "Fetching "+item.Path)
		}
		raw, fetchErr := fetchFileContent(rest, owner, repo, item.Path, ref)
		if fetchErr != nil {
			partialErrors = append(partialErrors, fmt.Errorf("%s: %w", item.Name, fetchErr))
			continue
		}
		// Retain the file for the JSON report's analyzed-CI-config block (#443).
		pipeline.AnalyzedWorkflows = append(pipeline.AnalyzedWorkflows, ir.AnalyzedWorkflow{Path: item.Path, Content: string(raw)})
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
		// Now that parsing is done, we know the unique action count
		// and can switch to the grand total. wrapProgressRemote maps
		// the enrichment's local 1..M counter into global slots
		// (2+N)..(1+N+M).
		enrichActionsWithAPIMetadata(pipeline, host, scanMutableExec, wrapProgressRemote(progressFn, pipeline))
	}

	return pipeline, partialErrors, nil
}

// newGitHubRESTClient returns a go-gh REST client bound to host (or
// api.github.com when host is empty).
//
// Auth resolution order (delegated to go-gh): GH_TOKEN → GITHUB_TOKEN
// → `gh auth login` stored credential. When all three are absent we
// surface an actionable error instead of silently degrading to
// anonymous reads — GitHub's anonymous tier is rate-limited to
// 60 req/hour, which on any non-trivial repo produces a partial run
// with rate-limit 403s mid-scan and no clear signal to the user that
// the output is incomplete. The require-auth contract matches the
// GitLab path (which always demands a token) and gives a single
// mental model across providers.
//
// Exposed as a package-level variable so tests can replace it with
// an httptest-backed client (with t.Cleanup() to restore). Production
// code never reassigns it.
var newGitHubRESTClient = func(host string) (*api.RESTClient, error) {
	rest, err := newGoghRESTClient(host)
	if err == nil {
		return rest, nil
	}
	if isAuthTokenMissing(err) {
		return nil, ErrAuthRequired
	}
	return nil, err
}

func newGoghRESTClient(host string) (*api.RESTClient, error) {
	if host == "" {
		return api.DefaultRESTClient()
	}
	return api.NewRESTClient(api.ClientOptions{Host: host})
}

// ErrAuthRequired is the actionable error surfaced when go-gh cannot
// resolve any auth credential. The message points the user at the
// three supported sources and the README section that documents
// scopes. Exported so cmd/ and control/ layers can detect the
// sentinel via errors.Is and short-circuit their normal wrap/log
// behaviour — a redundant logrus error log on top of cobra's "Error:"
// prefix on top of "analysis failed:" on top of "github api client:"
// produces a frame stack instead of the actionable message we want.
var ErrAuthRequired = fmt.Errorf(
	"GitHub authentication required for upstream-fetch mode (--github-url). " +
		"Set up one of:\n" +
		"  export GH_TOKEN=<token>          # personal token (see README §Step 3 for scope guidance)\n" +
		"  export GITHUB_TOKEN=<token>      # auto-set in GitHub Actions runners\n" +
		"  gh auth login                    # recommended for local dev")

// isAuthTokenMissing matches the error go-gh returns when none of
// GH_TOKEN, GITHUB_TOKEN, or `gh auth login` provides a credential.
// Best-effort string match because go-gh does not export a sentinel.
func isAuthTokenMissing(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "authentication token not found")
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
		// A 404 here is ambiguous: it fires for a missing repository, a
		// missing ref, AND for a repo+ref that simply has no
		// .github/workflows directory. Treating all three as "no
		// workflows" let a non-existent project or branch score a
		// vacuous 100% compliant (ISSUE #222). Disambiguate: a missing
		// repo or ref is a hard error; only a genuinely absent workflows
		// directory degrades to an empty set. Anything else (auth,
		// rate-limit) propagates.
		if isNotFound(err) {
			if verr := verifyRepoAndRefExist(rest, owner, repo, ref); verr != nil {
				return nil, verr
			}
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

// verifyRepoAndRefExist probes the repository and, when ref is non-empty, the
// requested ref, so a 404 on the workflows listing can be told apart from a
// missing repo or branch. It returns a descriptive error when the repository
// or ref does not exist; nil means both exist and the listing 404 genuinely
// means the repo has no .github/workflows directory. See ISSUE #222: without
// this, a non-existent --project or --branch scored a vacuous 100% compliant.
func verifyRepoAndRefExist(rest *api.RESTClient, owner, repo, ref string) error {
	var repoMeta struct {
		FullName string `json:"full_name"`
	}
	if err := rest.Get(fmt.Sprintf("repos/%s/%s", owner, repo), &repoMeta); err != nil {
		if isNotFound(err) {
			return fmt.Errorf("repository %s/%s not found", owner, repo)
		}
		return err
	}
	if ref == "" {
		return nil
	}
	var commit struct {
		SHA string `json:"sha"`
	}
	if err := rest.Get(fmt.Sprintf("repos/%s/%s/commits/%s", owner, repo, ref), &commit); err != nil {
		if isRefMissing(err) {
			return fmt.Errorf("branch or ref %q not found in %s/%s", ref, owner, repo)
		}
		return err
	}
	return nil
}

// isRefMissing reports whether err indicates the requested ref does not
// exist. GitHub answers a missing ref on the commits endpoint with 422
// ("No commit found for SHA"); a 404 is also possible, so accept both.
func isRefMissing(err error) bool {
	return isNotFound(err) || (err != nil && strings.Contains(err.Error(), "HTTP 422"))
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
