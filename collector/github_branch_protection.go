package collector

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cli/go-gh/v2/pkg/api"

	"github.com/getplumber/plumber/internal/ir"
)

// FetchGitHubBranchProtection lists every branch on the given
// owner/repo via the GitHub REST API and resolves the protection
// rule details for each one. The returned []ir.Branch matches the
// shape the GitLab path populates so the existing
// branch_unprotected / branch_non_compliant Rego rules apply
// unchanged.
//
// host is the GitHub API host (empty → api.github.com; non-empty →
// GHES). Auth is consumed from the same go-gh chain used elsewhere
// (GH_TOKEN / GH_ENTERPRISE_TOKEN / gh auth login). Without auth, or
// when the token lacks `repo` / Administration:read scope, the API
// returns 403/404 — those degrade silently to an empty branch list
// (the rego rule then sees zero branches and emits no findings,
// same contract as the action-metadata enrichment elsewhere).
//
// Mapping decisions GitHub → GitLab IR shape:
//   - branch.protected = true when /branches/{b} returns
//     `protected: true` (the API tells us directly).
//   - allowForcePush = api.AllowForcePushes.Enabled.
//   - codeOwnerApprovalRequired = api.RequiredPullRequestReviews
//     .RequireCodeOwnerReviews.
//   - min*AccessLevel: GitHub has no numeric access ladder. We map
//     "branch has push restrictions configured" to 30 (Developer in
//     GitLab terms), nothing-configured to 0. This lets the rego
//     min-access-level guards fire when `restrictions:` is unset on
//     a critical branch — matches the spirit of the GitLab control.
func FetchGitHubBranchProtection(host, owner, repo string) ([]ir.Branch, error) {
	if owner == "" || repo == "" {
		return nil, fmt.Errorf("owner and repo are required")
	}
	rest, err := newGitHubRESTClient(host)
	if err != nil {
		return nil, fmt.Errorf("github api client: %w", err)
	}

	listing, err := listBranches(rest, owner, repo)
	if err != nil {
		// 403/404 on the listing → no auth or no access. Return
		// empty rather than failing the whole analysis; the rego
		// rule will see zero branches and stay quiet.
		if isUnauthorized(err) || isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	out := make([]ir.Branch, 0, len(listing))
	for _, b := range listing {
		entry := ir.Branch{
			Name:      b.Name,
			Protected: b.Protected,
		}
		if b.Protected {
			detail, derr := fetchBranchProtection(rest, owner, repo, b.Name)
			// Some protected branches use the newer Repository
			// Rulesets API; the legacy /branches/{b}/protection
			// endpoint returns 404 for those. Treat as "protected
			// but details unknown" rather than failing.
			if derr != nil && !isNotFound(derr) {
				return nil, fmt.Errorf("branch %q protection: %w", b.Name, derr)
			}
			if detail != nil {
				entry.AllowForcePush = detail.AllowForcePushes.Enabled
				entry.CodeOwnerApprovalRequired = detail.RequiredPullRequestReviews.RequireCodeOwnerReviews
				if detail.Restrictions != nil &&
					(len(detail.Restrictions.Users) > 0 ||
						len(detail.Restrictions.Teams) > 0 ||
						len(detail.Restrictions.Apps) > 0) {
					// Push restrictions configured → at least
					// Developer-equivalent in GitLab terms.
					entry.MinPushAccessLevel = 30
				}
				if detail.RequiredPullRequestReviews.RequiredApprovingReviewCount > 0 {
					entry.MinMergeAccessLevel = 30
				}
			}
		}
		out = append(out, entry)
	}
	return out, nil
}

// remoteBranchEntry is the slim subset of /repos/{o}/{r}/branches we
// consume.
type remoteBranchEntry struct {
	Name      string `json:"name"`
	Protected bool   `json:"protected"`
}

// remoteBranchProtection is the slim subset of
// /repos/{o}/{r}/branches/{b}/protection. The GitHub API returns far
// more fields (signature requirements, conversation resolution, …) —
// we only unmarshal the ones the rego rules read.
type remoteBranchProtection struct {
	AllowForcePushes struct {
		Enabled bool `json:"enabled"`
	} `json:"allow_force_pushes"`
	RequiredPullRequestReviews struct {
		RequireCodeOwnerReviews      bool `json:"require_code_owner_reviews"`
		RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
	} `json:"required_pull_request_reviews"`
	Restrictions *struct {
		Users []any `json:"users"`
		Teams []any `json:"teams"`
		Apps  []any `json:"apps"`
	} `json:"restrictions"`
}

func listBranches(rest *api.RESTClient, owner, repo string) ([]remoteBranchEntry, error) {
	// GitHub paginates at 30/page by default; bump to 100 to keep
	// a typical repo to one round-trip. For repos with >100
	// branches the rest get silently skipped — acceptable for a
	// "scan main + master + release/*" use case.
	endpoint := fmt.Sprintf("repos/%s/%s/branches?per_page=100", owner, repo)
	var out []remoteBranchEntry
	if err := rest.Get(endpoint, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func fetchBranchProtection(rest *api.RESTClient, owner, repo, branch string) (*remoteBranchProtection, error) {
	endpoint := fmt.Sprintf("repos/%s/%s/branches/%s/protection", owner, repo, branch)
	var out remoteBranchProtection
	if err := rest.Get(endpoint, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// isUnauthorized reports whether err is a 401 or 403 from the
// GitHub REST API. Mirrors isNotFound: best-effort match on the
// stringified message because go-gh's HTTPError type is not
// exported in a way that lets us type-assert cleanly.
func isUnauthorized(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	if strings.Contains(msg, "HTTP 401") || strings.Contains(msg, "HTTP 403") {
		return true
	}
	// go-gh returns api.ErrAuthRequired for some no-auth paths.
	return errors.Is(err, errAuthRequiredSentinel)
}

// errAuthRequiredSentinel is intentionally unexported and never
// returned from this package; it exists so the errors.Is branch
// above keeps compiling even on go-gh versions that don't expose
// the sentinel directly. Real auth failures still flow through the
// HTTP-403 string match.
var errAuthRequiredSentinel = errors.New("auth required")
