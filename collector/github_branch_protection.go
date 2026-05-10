package collector

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cli/go-gh/v2/pkg/api"

	"github.com/getplumber/plumber/internal/ir"
)

// BranchFetchOptions controls which branches FetchGitHubBranchProtection
// reaches out for. The split between targeted and listing modes is
// deliberate: a single `?per_page=100` page on a busy repo (think
// grafana/grafana with thousands of `dependabot/*` and `release-*`
// branches) does not necessarily contain `main` — the alphabetical
// page-1 falls through long before we reach the default branch — so a
// naive listing silently produces "0 branches to protect" findings on
// every realistic config. Targeted /branches/{name} bypasses that
// problem entirely; listing is only used when the user has at least
// one wildcard pattern (e.g. `release/*`) we cannot enumerate ahead
// of time.
type BranchFetchOptions struct {
	// ExactNames are branch names without glob characters. Each is
	// fetched directly via /repos/{owner}/{repo}/branches/{name}; a
	// 404 is treated as "branch doesn't exist on this repo" and
	// silently skipped (the rego rule then has nothing to flag for
	// that name). Duplicates are deduped.
	ExactNames []string

	// Listing, when true, additionally paginates the /branches
	// endpoint (capped at maxBranchListingPages * 100 entries) so
	// wildcard patterns can match. Off by default because the
	// targeted path covers the typical config and avoids the
	// pagination foot-gun.
	Listing bool
}

// maxBranchListingPages caps the number of /branches?page=N requests
// when Listing is true. 10 pages × 100 entries = up to 1000 branches,
// which is plenty for a "release/*", "hotfix/*" use case while
// preventing a runaway scan on a repo with tens of thousands of
// dependabot branches.
const maxBranchListingPages = 10

// FetchGitHubBranchProtection resolves branch-protection state for
// the names the caller asks about, with pagination/cost optimised for
// the typical "I just want main protected" config. See
// BranchFetchOptions for how ExactNames and Listing combine.
//
// host is the GitHub API host (empty → api.github.com; non-empty →
// GHES). Auth is consumed from the same go-gh chain used elsewhere
// (GH_TOKEN / GH_ENTERPRISE_TOKEN / gh auth login). Without auth, or
// when the token lacks `repo` / Administration:read scope, the API
// returns 403/404 — those degrade silently to whatever subset we have
// already collected (the rego rule then sees fewer branches and may
// emit fewer findings; quiet is preferable to crash for a partial-
// data control).
//
// Mapping decisions GitHub → IR shape:
//   - branch.protected = true when the API marks the branch as such
//     (the listing endpoint already merges classic Branch Protection
//     and the newer Repository Rulesets, so this flag is correct
//     regardless of which mechanism the repo uses).
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
func FetchGitHubBranchProtection(host, owner, repo string, opts BranchFetchOptions) ([]ir.Branch, error) {
	if owner == "" || repo == "" {
		return nil, fmt.Errorf("owner and repo are required")
	}
	if len(opts.ExactNames) == 0 && !opts.Listing {
		return nil, nil
	}
	rest, err := newGitHubRESTClient(host)
	if err != nil {
		if errors.Is(err, ErrAuthRequired) {
			return nil, err
		}
		return nil, fmt.Errorf("github api client: %w", err)
	}

	seen := map[string]bool{}
	out := make([]ir.Branch, 0, len(opts.ExactNames))

	// Targeted fetches first. Each name lands on /branches/{name}
	// directly — no pagination, no alphabetical ordering quirks —
	// which is the whole point of this code path.
	for _, name := range opts.ExactNames {
		if name == "" || seen[name] {
			continue
		}
		entry, ferr := fetchBranchByName(rest, owner, repo, name)
		if ferr != nil {
			if isUnauthorized(ferr) {
				// 401/403 on a targeted fetch usually means the
				// token can list branches but cannot resolve
				// protection details (or the repo is private and
				// the token lacks the scope). Treat as degraded
				// across the board: stop collecting and return
				// the empty-or-partial result so the rego rule
				// stays quiet rather than emitting half-baked
				// findings.
				return nil, nil
			}
			if isNotFound(ferr) {
				// Branch simply doesn't exist on this repo. Not
				// a finding source, just a no-op.
				continue
			}
			return nil, fmt.Errorf("branch %q: %w", name, ferr)
		}
		if entry != nil {
			out = append(out, *entry)
			seen[name] = true
		}
	}

	if !opts.Listing {
		return out, nil
	}

	listed, err := listBranchesPaginated(rest, owner, repo)
	if err != nil {
		// Listing failure on top of a successful targeted phase:
		// degrade quietly. Wildcard patterns will simply have no
		// extra branches to match, but the targeted ones the rego
		// rule cares about (default branch, exact names) are
		// still represented.
		if isUnauthorized(err) || isNotFound(err) {
			return out, nil
		}
		return nil, err
	}

	for _, b := range listed {
		if seen[b.Name] {
			continue
		}
		entry := ir.Branch{Name: b.Name, Protected: b.Protected}
		if b.Protected {
			detail, derr := fetchBranchProtection(rest, owner, repo, b.Name)
			// 200 → ProtectionDetailsKnown=true; 404 (rulesets-only)
			// or 403 (token lacks admin scope) → leave it false so
			// branch_non_compliant.rego abstains instead of false-
			// positiving on the zero defaults. Same three-way contract
			// as fetchBranchByName above.
			switch {
			case derr == nil && detail != nil:
				entry.AllowForcePush = detail.AllowForcePushes.Enabled
				entry.CodeOwnerApprovalRequired = detail.RequiredPullRequestReviews.RequireCodeOwnerReviews
				entry.ProtectionDetailsKnown = true
			case derr != nil && (isNotFound(derr) || isUnauthorized(derr)):
				// Detail unavailable.
			case derr != nil:
				return nil, fmt.Errorf("branch %q protection: %w", b.Name, derr)
			}
		}
		out = append(out, entry)
		seen[b.Name] = true
	}
	return out, nil
}

// fetchBranchByName resolves /repos/{owner}/{repo}/branches/{branch}
// for a single branch. When the API marks it protected, the
// protection-detail endpoint is consulted (admin-only on GitHub).
//
// Three outcomes for the protection-detail call:
//   - 200: AllowForcePush + CodeOwnerApprovalRequired land in the IR
//     and ProtectionDetailsKnown=true so branch_non_compliant.rego
//     trusts those values.
//   - 404: ruleset-only branch, the legacy /protection endpoint
//     doesn't apply. ProtectionDetailsKnown=false; the branch_non_
//     compliant rule abstains, branch_unprotected still uses the
//     authoritative `Protected` flag from the listing.
//   - 403: token lacks Administration:read / repo scope. Same
//     contract as 404 (preserve the entry, mark detail unknown). A
//     prior implementation propagated the error and wiped the whole
//     result, which silently dropped ISSUE-501 too — this branch is
//     authored for content-only tokens to keep ISSUE-501 working.
func fetchBranchByName(rest *api.RESTClient, owner, repo, name string) (*ir.Branch, error) {
	endpoint := fmt.Sprintf("repos/%s/%s/branches/%s", owner, repo, name)
	var entry remoteBranchEntry
	if err := rest.Get(endpoint, &entry); err != nil {
		return nil, err
	}
	out := &ir.Branch{Name: entry.Name, Protected: entry.Protected}
	if entry.Protected {
		detail, derr := fetchBranchProtection(rest, owner, repo, name)
		switch {
		case derr == nil && detail != nil:
			out.AllowForcePush = detail.AllowForcePushes.Enabled
			out.CodeOwnerApprovalRequired = detail.RequiredPullRequestReviews.RequireCodeOwnerReviews
			out.ProtectionDetailsKnown = true
		case derr != nil && (isNotFound(derr) || isUnauthorized(derr)):
			// Detail unavailable; ProtectionDetailsKnown stays false.
		case derr != nil:
			return nil, fmt.Errorf("branch %q protection: %w", name, derr)
		}
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
		if errors.Is(err, ErrAuthRequired) {
			return "", err
		}
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

// listBranchesPaginated walks /repos/{o}/{r}/branches one page at a
// time until either the API returns a short page (signalling the
// last page) or maxBranchListingPages is hit. Errors short-circuit
// and return whatever was collected up to that point alongside the
// error — the caller decides whether to degrade or propagate.
func listBranchesPaginated(rest *api.RESTClient, owner, repo string) ([]remoteBranchEntry, error) {
	const perPage = 100
	var out []remoteBranchEntry
	for page := 1; page <= maxBranchListingPages; page++ {
		endpoint := fmt.Sprintf("repos/%s/%s/branches?per_page=%d&page=%d", owner, repo, perPage, page)
		var batch []remoteBranchEntry
		if err := rest.Get(endpoint, &batch); err != nil {
			return out, err
		}
		if len(batch) == 0 {
			break
		}
		out = append(out, batch...)
		if len(batch) < perPage {
			break
		}
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
