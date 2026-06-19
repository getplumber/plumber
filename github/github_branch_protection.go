package github

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

	// OnProgress, when non-nil, is invoked at user-meaningful
	// checkpoints during the fetch: each listing page (with a
	// running branches-seen count) and each per-branch protection-
	// detail call. The caller is expected to forward these to its
	// progress spinner as label updates at the same global slot;
	// the messages are short single-line strings already shaped for
	// terminal display. Used by the CLI to keep the bar's label
	// alive during the otherwise-silent "Resolving branch
	// protection" phase on large repos (grafana/grafana has 772
	// branches across 8 listing pages, ~10s of API time).
	OnProgress func(message string)

	// InScope, when non-nil, gates the slow protection-detail calls
	// during the listing pagination: branches for which InScope
	// returns false are still added to the IR (Protected flag
	// preserved from the listing so ISSUE-501 still has the data it
	// needs) but the classic /protection + Rulesets endpoints are
	// skipped for them. Saves hundreds of API calls on repos where
	// the listing returns many protected branches that do not match
	// any of the user's configured namePatterns (grafana's hundreds
	// of `release-X.Y.Z` branches when the config asks for
	// `release/*`, for example). The rego rule applies the same
	// scope check at evaluation time; this just avoids paying for
	// data the rule is going to discard.
	InScope func(name string) bool
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
	//
	// GitHub silently redirects /branches/{stale-or-missing} to the
	// repo's default branch in some cases (typical scenario: the user
	// renamed `master` to `main` and the old URL still 200s with main
	// data). We detect that by comparing the API-returned entry.Name
	// against the input `name` and skipping the entry when they
	// differ — otherwise main gets added twice (once for the explicit
	// `main` lookup, once for the redirected `master`), inflating
	// BranchesMatched and falsely triggering the "protection details
	// unknown" postflight on the duplicate.
	for _, name := range opts.ExactNames {
		if name == "" || seen[name] {
			continue
		}
		if opts.OnProgress != nil {
			opts.OnProgress(fmt.Sprintf("Resolving protection for %s", name))
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
		if entry == nil {
			continue
		}
		// Drop entries where GitHub silently redirected us to a
		// different branch (default-branch fallback for stale or
		// renamed names). The user did not ask about that branch.
		if entry.Name != name {
			continue
		}
		if seen[entry.Name] {
			continue
		}
		out = append(out, *entry)
		seen[entry.Name] = true
	}

	if !opts.Listing {
		return out, nil
	}

	listed, err := listBranchesPaginated(rest, owner, repo, opts.OnProgress)
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
		// Only pay for protection-detail calls on branches the user
		// asked about. Out-of-scope protected branches stay in the
		// IR with Protected=true but no detail data; the rego rule
		// abstains on them anyway via its own scope check.
		if b.Protected && (opts.InScope == nil || opts.InScope(b.Name)) {
			if opts.OnProgress != nil {
				opts.OnProgress(fmt.Sprintf("Resolving protection for %s", b.Name))
			}
			// Same two-source merge as fetchBranchByName: classic
			// Branch Protection + Rulesets effective-rules. Stricter
			// wins; ProtectionDetailsKnown turns true if either
			// source returned 200. See fetchBranchByName for the
			// rationale.
			detail, derr := fetchBranchProtection(rest, owner, repo, b.Name)
			classicOK := false
			switch {
			case derr == nil && detail != nil:
				entry.AllowForcePush = detail.AllowForcePushes.Enabled
				entry.CodeOwnerApprovalRequired = detail.RequiredPullRequestReviews.RequireCodeOwnerReviews
				classicOK = true
			case derr != nil && (isNotFound(derr) || isUnauthorized(derr)):
				// Detail unavailable on this source.
			case derr != nil:
				return nil, fmt.Errorf("branch %q protection: %w", b.Name, derr)
			}

			rules, rulesOK, rerr := fetchBranchEffectiveRules(rest, owner, repo, b.Name)
			if rerr != nil {
				return nil, rerr
			}
			if rulesOK {
				applyEffectiveRules(&entry, rules)
			}
			if classicOK || rulesOK {
				entry.ProtectionDetailsKnown = true
			}
		}
		out = append(out, entry)
		seen[b.Name] = true
	}
	return out, nil
}

// fetchBranchByName resolves /repos/{owner}/{repo}/branches/{branch}
// for a single branch. When the API marks it protected, two endpoints
// are consulted and their results merged into the IR:
//
//   - /branches/{name}/protection — classic Branch Protection (older
//     mechanism). Provides AllowForcePush + CodeOwnerApprovalRequired.
//   - /rules/branches/{name} — the effective rules from Repository
//     Rulesets (newer mechanism, GA 2023) plus any org-level Rulesets
//     the repo inherits. Stricter wins: a `non_fast_forward` rule
//     blocks force-push regardless of what classic says, and any
//     `pull_request` rule with require_code_owner_review:true makes
//     code-owner approval required.
//
// `ProtectionDetailsKnown` is set when EITHER source returned 200 —
// branches managed purely by Rulesets used to land at PDK=false
// because classic /protection 404s, and that hid real ISSUE-505
// findings (or false-positived them when classic had stale data).
func fetchBranchByName(rest *api.RESTClient, owner, repo, name string) (*ir.Branch, error) {
	endpoint := fmt.Sprintf("repos/%s/%s/branches/%s", owner, repo, name)
	var entry remoteBranchEntry
	if err := rest.Get(endpoint, &entry); err != nil {
		return nil, err
	}
	out := &ir.Branch{Name: entry.Name, Protected: entry.Protected}
	if !entry.Protected {
		return out, nil
	}

	// Classic Branch Protection — may 404 (ruleset-only branch) or
	// 403 (token lacks scope); both degrade to "detail unknown".
	detail, derr := fetchBranchProtection(rest, owner, repo, name)
	classicOK := false
	switch {
	case derr == nil && detail != nil:
		out.AllowForcePush = detail.AllowForcePushes.Enabled
		out.CodeOwnerApprovalRequired = detail.RequiredPullRequestReviews.RequireCodeOwnerReviews
		classicOK = true
	case derr != nil && (isNotFound(derr) || isUnauthorized(derr)):
		// Detail unavailable on this source; rulesets may still answer.
	case derr != nil:
		return nil, fmt.Errorf("branch %q protection: %w", name, derr)
	}

	// Repository + Organization Rulesets via the effective-rules
	// endpoint. Stricter wins: applyEffectiveRules can only tighten
	// flags relative to what classic returned, never loosen them.
	rules, rulesOK, rerr := fetchBranchEffectiveRules(rest, owner, repo, name)
	if rerr != nil {
		return nil, rerr
	}
	if rulesOK {
		applyEffectiveRules(out, rules)
	}

	if classicOK || rulesOK {
		out.ProtectionDetailsKnown = true
	}
	return out, nil
}

// remoteBranchEntry is the slim subset of /repos/{o}/{r}/branches we
// consume.
type remoteBranchEntry struct {
	Name      string `json:"name"`
	Protected bool   `json:"protected"`
}

// remoteBranchRule is one entry in the array returned by
// /repos/{o}/{r}/rules/branches/{branch}. GitHub returns the union of
// all *active* rules effective for that branch — classic Branch
// Protection, repo-level Rulesets, and any org-level Rulesets the
// repo inherits, in a single flat list. `type` discriminates which
// `parameters` shape applies; we only unmarshal the two types that
// map to ISSUE-505 sub-checks today. New rule types can be added by
// extending RuleParameters without breaking existing callers.
type remoteBranchRule struct {
	Type              string         `json:"type"`
	RulesetSourceType string         `json:"ruleset_source_type,omitempty"`
	RulesetID         int            `json:"ruleset_id,omitempty"`
	Parameters        RuleParameters `json:"parameters"`
}

// RuleParameters is the union of parameter shapes across rule types
// we care about. JSON unmarshal populates only the fields present in
// the source — extras are silently ignored.
type RuleParameters struct {
	// pull_request rule
	RequireCodeOwnerReview bool `json:"require_code_owner_review,omitempty"`
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

// fetchBranchEffectiveRules calls /repos/{o}/{r}/rules/branches/{branch}
// and returns the effective rules unioned across classic Branch
// Protection, repo-level Rulesets, and org-level Rulesets the repo
// inherits. Walks pages until a short page or the listing cap so
// repos with dozens of rules don't silently truncate. Returns:
//
//   - (rules, true, nil) on a 200 (even an empty array — that's an
//     authoritative "no active rules" answer, callers can mark
//     ProtectionDetailsKnown=true on the back of it).
//   - (nil, false, nil) on a 401/403/404, mirroring the same
//     graceful degradation contract as fetchBranchProtection above.
//   - (nil, false, err) on any other failure.
func fetchBranchEffectiveRules(rest *api.RESTClient, owner, repo, branch string) ([]remoteBranchRule, bool, error) {
	const perPage = 100
	var out []remoteBranchRule
	for page := 1; page <= maxBranchListingPages; page++ {
		endpoint := fmt.Sprintf("repos/%s/%s/rules/branches/%s?per_page=%d&page=%d", owner, repo, branch, perPage, page)
		var batch []remoteBranchRule
		if err := rest.Get(endpoint, &batch); err != nil {
			if isUnauthorized(err) || isNotFound(err) {
				return nil, false, nil
			}
			return nil, false, fmt.Errorf("branch %q rules: %w", branch, err)
		}
		if len(batch) == 0 {
			break
		}
		out = append(out, batch...)
		if len(batch) < perPage {
			break
		}
	}
	return out, true, nil
}

// applyEffectiveRules folds the rules endpoint's output into b's
// protection-state flags. Stricter wins:
//
//   - any "non_fast_forward" rule ⇒ force-push is blocked ⇒
//     b.AllowForcePush stays / becomes false.
//   - any "pull_request" rule with require_code_owner_review:true ⇒
//     b.CodeOwnerApprovalRequired becomes true.
//
// Other rule types are ignored — they don't map to ISSUE-505
// sub-checks today. Idempotent: calling repeatedly with the same
// rules cannot un-set a stricter flag.
func applyEffectiveRules(b *ir.Branch, rules []remoteBranchRule) {
	if b == nil {
		return
	}
	for _, r := range rules {
		switch r.Type {
		case "non_fast_forward":
			b.AllowForcePush = false
		case "pull_request":
			if r.Parameters.RequireCodeOwnerReview {
				b.CodeOwnerApprovalRequired = true
			}
		}
	}
}

// listBranchesPaginated walks /repos/{o}/{r}/branches one page at a
// time until either the API returns a short page (signalling the
// last page) or maxBranchListingPages is hit. Errors short-circuit
// and return whatever was collected up to that point alongside the
// error; the caller decides whether to degrade or propagate.
// onProgress, when non-nil, receives a short label after each page
// so the CLI's progress spinner can keep the user informed during
// long pagination runs (grafana-class repos can take 5-15s here).
func listBranchesPaginated(rest *api.RESTClient, owner, repo string, onProgress func(message string)) ([]remoteBranchEntry, error) {
	const perPage = 100
	var out []remoteBranchEntry
	for page := 1; page <= maxBranchListingPages; page++ {
		if onProgress != nil {
			onProgress(fmt.Sprintf("Listing branches (page %d, %d collected)", page, len(out)))
		}
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
