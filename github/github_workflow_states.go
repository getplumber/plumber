package github

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// workflowStatesPerPage is the page size requested from
// /repos/{owner}/{repo}/actions/workflows. GitHub's own max for this
// endpoint is higher, but 100 keeps individual pages reasonable while
// pagination (see nextPageLink) still walks every page on a repository
// with more workflow files than that.
const workflowStatesPerPage = 100

// remoteWorkflowStatesResponse is the slim subset of the workflows
// listing endpoint response we consume.
type remoteWorkflowStatesResponse struct {
	Workflows []remoteWorkflowState `json:"workflows"`
}

// remoteWorkflowState is one entry of the workflows listing: the
// workflow's repo-relative path, exactly as GitHub returns it (e.g.
// ".github/workflows/ci.yml", matching the collector's Job.OriginFile),
// and its state ("active", "disabled_manually", "disabled_inactivity",
// "disabled_fork", "deleted", ...).
type remoteWorkflowState struct {
	Path  string `json:"path"`
	State string `json:"state"`
}

// FetchGitHubWorkflowStates resolves the enabled/disabled state of every
// workflow file in the repository via GET
// /repos/{owner}/{repo}/actions/workflows, mapping each workflow's path
// to its state. Pagination follows the response's `Link: <...>;
// rel="next"` header rather than counting pages, same contract as
// FetchGitHubEnvironments.
//
// The bool return is known: a repository's workflow states are an
// optional fact a job's "cannot run" claim can be capped by, never one
// that fails collection. known is false, with a nil error, when the
// endpoint answers 401/403 (no access), 404 (the repository itself is
// not visible) or when the request never reaches a response at all
// (DNS, connection refused, timeout). known is also false on any other
// failure, but that error is returned too, for the caller to log; it is
// never meant to propagate as a collection failure.
func FetchGitHubWorkflowStates(host, owner, repo string) (map[string]string, bool, error) {
	if owner == "" || repo == "" {
		return nil, false, nil
	}
	rest, err := newGitHubRESTClient(host)
	if err != nil {
		return nil, false, err
	}

	out := map[string]string{}
	path := fmt.Sprintf("repos/%s/%s/actions/workflows?per_page=%d", owner, repo, workflowStatesPerPage)
	for path != "" {
		resp, rerr := rest.Request(http.MethodGet, path, nil)
		if rerr != nil {
			if isUnauthorized(rerr) || isNotFound(rerr) || isNetworkFailure(rerr) {
				return nil, false, nil
			}
			return nil, false, rerr
		}

		var page remoteWorkflowStatesResponse
		decodeErr := json.NewDecoder(resp.Body).Decode(&page)
		closeErr := resp.Body.Close()
		if decodeErr != nil {
			return nil, false, decodeErr
		}
		if closeErr != nil {
			return nil, false, closeErr
		}

		for _, w := range page.Workflows {
			if w.Path == "" {
				continue
			}
			out[w.Path] = w.State
		}
		path = nextPageLink(resp.Header.Get("Link"))
	}
	return out, true, nil
}
