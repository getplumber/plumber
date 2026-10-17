package github

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/getplumber/plumber/internal/ir"
)

// environmentsPerPage is the page size requested from
// /repos/{owner}/{repo}/environments. GitHub's own default and max for
// this endpoint are both higher, but 30 keeps individual pages small on
// repositories with a handful of deployment environments, the common
// case, while pagination (see nextPageLink) still walks every page on
// the rare repository with more.
const environmentsPerPage = 30

// remoteEnvironmentsResponse is the slim subset of the environments
// listing endpoint response we consume.
type remoteEnvironmentsResponse struct {
	Environments []remoteEnvironment `json:"environments"`
}

// remoteEnvironment is one entry of the environments listing.
// protection_rules carries the union of GitHub's rule types; only the
// three the situation facts read (required_reviewers, wait_timer,
// branch_policy) are unmarshaled here, same contract as
// remoteBranchRule in github_branch_protection.go. deployment_branch_policy
// is a second, independent signal of a branch restriction: GitHub sets
// it to a non-null object whenever the environment limits which
// branches may deploy to it, with or without a branch_policy
// protection rule alongside it.
type remoteEnvironment struct {
	Name                   string                 `json:"name"`
	ProtectionRules        []remoteProtectionRule `json:"protection_rules"`
	DeploymentBranchPolicy *struct{}              `json:"deployment_branch_policy"`
}

// remoteProtectionRule is one entry of an environment's protection_rules.
// Reviewers is only ever counted (len), never read field by field, so
// its element type stays the raw JSON object.
type remoteProtectionRule struct {
	Type              string            `json:"type"`
	Reviewers         []json.RawMessage `json:"reviewers"`
	PreventSelfReview bool              `json:"prevent_self_review"`
	WaitTimer         int               `json:"wait_timer"`
}

// FetchGitHubEnvironments resolves the repository's deployment
// environments and the reviewer rules each one carries, via GET
// /repos/{owner}/{repo}/environments. Pagination follows the response's
// `Link: <...>; rel="next"` header rather than counting pages, so a
// host that answers fewer or more entries per page than requested is
// still walked correctly.
//
// The bool return is known: a repository's environments are an
// optional fact a claim about a protected job can be capped by, never
// one that fails collection. known is false, with a nil error, when
// the endpoint answers 401/403 (no access), 404 (environments not
// supported, or the repository itself is not visible) or when the
// request never reaches a response at all (DNS, connection refused,
// timeout). known is also false on any other failure, but that error
// is returned too, for the caller to log; it is never meant to
// propagate as a collection failure.
func FetchGitHubEnvironments(host, owner, repo string) ([]ir.Environment, bool, error) {
	if owner == "" || repo == "" {
		return nil, false, nil
	}
	rest, err := newGitHubRESTClient(host)
	if err != nil {
		return nil, false, err
	}

	var out []ir.Environment
	path := fmt.Sprintf("repos/%s/%s/environments?per_page=%d", owner, repo, environmentsPerPage)
	for pages := 0; path != ""; pages++ {
		if pages == maxLanePages {
			// Still a next page after the cap: the list is not the
			// whole one, so nothing about a missing environment holds.
			return nil, false, nil
		}
		resp, rerr := rest.Request(http.MethodGet, path, nil)
		if rerr != nil {
			if isUnauthorized(rerr) || isNotFound(rerr) || isNetworkFailure(rerr) {
				logRefusedLane("environments", rerr)
				return nil, false, nil
			}
			return nil, false, rerr
		}

		var page remoteEnvironmentsResponse
		decodeErr := json.NewDecoder(resp.Body).Decode(&page)
		closeErr := resp.Body.Close()
		if decodeErr != nil {
			return nil, false, decodeErr
		}
		if closeErr != nil {
			return nil, false, closeErr
		}

		for _, e := range page.Environments {
			out = append(out, mapRemoteEnvironment(e))
		}
		path = nextPageLink(resp.Header.Get("Link"))
	}
	return out, true, nil
}

// mapRemoteEnvironment projects one remoteEnvironment onto the IR
// shape. required_reviewers sets RequiredReviewers, the count of
// Reviewers and PreventSelfReview; wait_timer sets WaitTimer;
// branch_policy, or a non-null deployment_branch_policy, sets
// BranchPolicy. Known is always true here: every entry returned came
// from a successful page of the listing.
func mapRemoteEnvironment(e remoteEnvironment) ir.Environment {
	out := ir.Environment{Name: e.Name, Known: true}
	for _, rule := range e.ProtectionRules {
		switch rule.Type {
		case "required_reviewers":
			out.RequiredReviewers = true
			out.Reviewers = len(rule.Reviewers)
			out.PreventSelfReview = rule.PreventSelfReview
		case "wait_timer":
			out.WaitTimer = rule.WaitTimer
		case "branch_policy":
			out.BranchPolicy = true
		}
	}
	if e.DeploymentBranchPolicy != nil {
		out.BranchPolicy = true
	}
	return out
}

// nextPageLink extracts the rel="next" URL from an HTTP Link header
// (RFC 8288, the shape GitHub's REST API uses for pagination), empty
// when the header is empty or carries no next relation (the last
// page).
func nextPageLink(header string) string {
	if header == "" {
		return ""
	}
	for _, part := range strings.Split(header, ",") {
		segs := strings.Split(part, ";")
		if len(segs) < 2 {
			continue
		}
		url := strings.TrimSpace(segs[0])
		url = strings.TrimPrefix(url, "<")
		url = strings.TrimSuffix(url, ">")
		for _, attr := range segs[1:] {
			if strings.TrimSpace(attr) == `rel="next"` {
				return url
			}
		}
	}
	return ""
}

// isNetworkFailure reports whether err never reached an HTTP response:
// go-gh's HTTPError.Error() always starts with "HTTP " followed by the
// status code (see HandleHTTPError), so its absence marks a
// transport-level failure (DNS, connection refused, TLS, timeout)
// rather than a server answer.
func isNetworkFailure(err error) bool {
	if err == nil {
		return false
	}
	return !strings.Contains(err.Error(), "HTTP ")
}
