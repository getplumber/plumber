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
//   - min*AccessLevel: deliberately left 0 on GitHub. GitLab uses a
//     numeric 0..60 access ladder where 0 = "no one allowed"
//     (strictest). The legacy ISSUE-505 rule treats config min=0 as
//     "always violates", which would false-positive on every
//     GitHub branch that simply requires PR reviews. GitHub has no
//     equivalent ladder; encoding an approximation produced
//     misleading findings. The other ISSUE-505 reasons
//     (allowForcePush, codeOwnerApprovalRequired) still apply.
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
				// MinMergeAccessLevel / MinPushAccessLevel
				// intentionally left 0 — see package doc.
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
		RequireCodeOwnerReviews bool `json:"require_code_owner_reviews"`
	} `json:"required_pull_request_reviews"`
}

// remoteRepoMetadata is the subset of /repos/{o}/{r} we need today —
// only the default_branch field. Used so the rego rule's
// `defaultMustBeProtected` clause can match against the repo's
// actual default rather than relying on a possibly-empty CLI flag.
type remoteRepoMetadata struct {
	DefaultBranch string `json:"default_branch"`
}

// FetchGitHubDefaultBranch resolves the repo's default branch name
// via the REST API. Returns an empty string with no error when the
// repo can't be queried (degraded mode), which keeps the
// `defaultMustBeProtected` rule a silent no-op rather than a noisy
// crash.
func FetchGitHubDefaultBranch(host, owner, repo string) (string, error) {
	rest, err := newGitHubRESTClient(host)
	if err != nil {
		return "", fmt.Errorf("github api client: %w", err)
	}
	endpoint := fmt.Sprintf("repos/%s/%s", owner, repo)
	var meta remoteRepoMetadata
	if err := rest.Get(endpoint, &meta); err != nil {
		if isUnauthorized(err) || isNotFound(err) {
			return "", nil
		}
		return "", err
	}
	return meta.DefaultBranch, nil
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
