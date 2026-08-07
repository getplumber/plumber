package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
	version "github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
)

// EnvDisableGitHubAPI, when set to a truthy value, forces every
// GitHub API consumer that honors it (the metadata client, the
// default-branch lookup seam in control) into degraded mode
// regardless of gh auth state. Set to "1" by the test suites to
// keep unit tests offline and fast.
const EnvDisableGitHubAPI = "PLUMBER_DISABLE_GITHUB_API"

// EnvMetadataToken, when set, supplies the token the metadata client uses
// to resolve third-party action versions. It takes precedence over the
// go-gh default chain (gh auth, GH_TOKEN, GITHUB_TOKEN) and is the
// supported way to resolve actions hosted in an org that gates the Actions
// GITHUB_TOKEN behind an IP allow list (ISSUE-228); it also carries the
// 5,000/hr user rate limit rather than the 60/hr anonymous fallback. A
// token with public-repository read is sufficient.
const EnvMetadataToken = "PLUMBER_METADATA_TOKEN"

// GitHubMetadata is the facts the API-backed policies need to know
// about a single `owner/repo@ref` action reference.
//
//   - RepoArchived:     the GitHub repo hosting the action is archived.
//   - RefExists:        the ref (tag / branch / commit SHA) resolves.
//   - RefKind:          "tag", "branch", "commit", "unknown".
//   - TagSha:           when RefKind=="tag", the commit SHA the tag
//     currently points at.
//   - LatestTag:        the repo's newest release tag, "" when the
//     API returns no releases.
//   - LatestReleaseSha: the SHA that tag resolves to upstream.
//   - RefIsAmbiguous:   the ref resolves as BOTH a tag and a branch
//     (ref-confusion).
//   - Advisories:       security advisory identifiers from the
//     GitHub Advisory Database whose affected
//     version range covers this ref, if any.
//
// Zero value (all fields empty / false) is explicitly "unknown" — it
// is also what the policies see when the API call failed. They
// should treat zero value as "I don't know" and stay silent.
type GitHubMetadata struct {
	RepoArchived bool
	RefExists    bool
	// RefKnownAbsent is true ONLY when the upstream API definitively
	// answered that the ref does not exist (a 404 / 422 on a readable
	// repo). It stays false when the ref could not be verified (private
	// repo, rate limit, network error) so impostor-commit (ISSUE-707)
	// never flags a valid SHA it merely failed to reach.
	RefKnownAbsent bool
	RefKind        string
	// RefCommitSha is set only when the pinned ref is the SHA of an
	// annotated tag OBJECT: it carries the commit that tag object
	// dereferences to. Empty for every other ref shape, including a
	// plain commit pin (there the ref already IS the commit).
	RefCommitSha     string
	TagSha           string
	LatestTag        string
	LatestReleaseSha string
	RefIsAmbiguous   bool
	Advisories       []string
	StargazersCount  int
}

// GitHubMetadataClient resolves `owner/repo@ref` references against
// the real GitHub REST API (via github.com/cli/go-gh which reuses
// the installed `gh` CLI's stored credentials) and caches every
// answer so the collector never hits the API twice for the same
// key. Safe for concurrent use.
//
// When `gh` is not authenticated — or go-gh cannot find a token —
// the client operates in degraded mode: every lookup returns an
// empty GitHubMetadata and Available() returns false. Policies are
// expected to key their deny rules on the positive evidence the
// client surfaces, so the degraded-mode output is a zero-finding
// run rather than a crash.
type GitHubMetadataClient struct {
	rest *api.RESTClient
	// apiBaseURL is the REST base used for unauthenticated fallback reads
	// (e.g. https://api.github.com). When an authenticated read of a public
	// action repo is blocked by the owner org's IP allow list (403), the
	// tags fetch retries anonymously against this base, which the allow
	// list does not gate (confirmed on a runner, ISSUE-228).
	apiBaseURL string
	mu         sync.Mutex
	// repoCache maps "owner/repo" to archived state; populated lazily.
	repoCache map[string]repoCacheEntry
	// refCache maps "owner/repo@ref" to the resolved metadata.
	refCache    map[string]GitHubMetadata
	latestCache map[string]string
	// advisoryCache stores every advisory known for an action (id +
	// vulnerable version range), keyed by "owner/repo". Filtering to
	// advisories that actually cover the pinned ref happens on read.
	advisoryCache map[string][]advisoryInfo
	// sha2tagCache stores the tag list of a repo indexed by commit
	// SHA so a pinned SHA can be resolved back to its release tag.
	// nil entry means "tag list fetched and nothing matches".
	sha2tagCache map[string]map[string]string
	disabled     bool
	disableCause error
	// degraded accumulates one message per action ref whose known-CVE
	// check could not be completed because the pinned commit could not be
	// resolved to a version (tag list unavailable). degradedSeen dedupes
	// by "owner/repo@ref" so a ref used in many jobs warns once.
	degraded     []string
	degradedSeen map[string]struct{}
}

// advisoryInfo is one vulnerability entry from the GitHub Advisory
// Database, narrowed to what the policy needs.
type advisoryInfo struct {
	GhsaID          string
	VulnerableRange string
	PatchedVersions string
}

type repoCacheEntry struct {
	archived bool
	stars    int
	fetched  bool
	err      error
}

// NewGitHubMetadataClientForHost builds a client using the gh-CLI auth
// store. Returns a usable client even when authentication is
// missing — see Available() to check. Honors the
// PLUMBER_DISABLE_GITHUB_API env var which short-circuits the
// client into degraded mode regardless of auth state.
//
// When host is empty the client targets api.github.com via the default
// go-gh resolution chain (gh auth, GH_TOKEN, GITHUB_TOKEN). When
// host is non-empty the client is bound to that host — for GitHub
// Enterprise Server pass the GHES API host (e.g. "ghes.example.com"
// or "ghes.example.com/api/v3") paired with a GH_TOKEN (or
// GH_ENTERPRISE_TOKEN) that has access to the GHES instance.
func NewGitHubMetadataClientForHost(host string) *GitHubMetadataClient {
	c := &GitHubMetadataClient{
		apiBaseURL:    apiBaseURLForHost(host),
		repoCache:     map[string]repoCacheEntry{},
		refCache:      map[string]GitHubMetadata{},
		latestCache:   map[string]string{},
		advisoryCache: map[string][]advisoryInfo{},
		sha2tagCache:  map[string]map[string]string{},
	}
	if v := os.Getenv(EnvDisableGitHubAPI); v == "1" || v == "true" {
		c.disabled = true
		return c
	}
	// Credential precedence (ISSUE-228):
	//   1. PLUMBER_METADATA_TOKEN, when supplied, wins. It resolves action
	//      versions from orgs that gate the Actions GITHUB_TOKEN behind an IP
	//      allow list, at the 5,000/hr user limit.
	//   2. otherwise the go-gh default chain (gh auth, GH_TOKEN, GITHUB_TOKEN).
	// Either way a 403 on a public action repo still falls back to an
	// anonymous read (see fetchAllTags), so a no-token run keeps working.
	var rest *api.RESTClient
	var err error
	opts, token := metadataClientOptions(host)
	switch {
	case token != "":
		rest, err = api.NewRESTClient(opts)
	case host == "":
		rest, err = api.DefaultRESTClient()
	default:
		rest, err = api.NewRESTClient(opts)
	}
	if err != nil {
		c.disabled = true
		c.disableCause = err
		return c
	}
	c.rest = rest
	return c
}

// metadataClientOptions resolves the REST client options for the metadata
// client. When EnvMetadataToken is set its (trimmed) value is returned as
// both the AuthToken on opts and the second return value, signalling the
// caller to use it in preference to the go-gh default chain. token is empty
// otherwise. A non-empty host targets a GitHub Enterprise Server instance.
func metadataClientOptions(host string) (opts api.ClientOptions, token string) {
	token = strings.TrimSpace(os.Getenv(EnvMetadataToken))
	if token != "" {
		opts.AuthToken = token
	}
	if host != "" {
		opts.Host = host
	}
	return opts, token
}

// Available reports whether the client has a usable gh auth token.
func (c *GitHubMetadataClient) Available() bool {
	return !c.disabled
}

// Resolve looks up "owner/repo@ref" and returns what the API told
// us. Never returns an error — all failures degrade to "unknown"
// (zero-valued GitHubMetadata). Repeated calls for the same key
// return the cached value.
func (c *GitHubMetadataClient) Resolve(ownerRepoRef string) GitHubMetadata {
	if c.disabled {
		return GitHubMetadata{}
	}
	owner, repo, ref, ok := splitActionRef(ownerRepoRef)
	if !ok {
		return GitHubMetadata{}
	}
	key := owner + "/" + repo + "@" + ref

	c.mu.Lock()
	if v, cached := c.refCache[key]; cached {
		c.mu.Unlock()
		return v
	}
	c.mu.Unlock()

	meta := c.resolveUncached(owner, repo, ref)

	c.mu.Lock()
	c.refCache[key] = meta
	c.mu.Unlock()
	return meta
}

func (c *GitHubMetadataClient) resolveUncached(owner, repo, ref string) GitHubMetadata {
	m := GitHubMetadata{}
	info := c.repoInfo(owner, repo)
	m.RepoArchived = info.archived
	m.StargazersCount = info.stars
	m.LatestTag = c.latestReleaseTag(owner, repo)
	if m.LatestTag != "" {
		if sha, ok := c.resolveTag(owner, repo, m.LatestTag); ok {
			m.LatestReleaseSha = sha
		}
	}
	m.Advisories = c.advisoriesForRef(owner, repo, ref)

	// Probe in order: tag → branch → commit. First hit wins, but
	// when we match a tag we still check whether a same-named branch
	// exists upstream — that cross-existence is what ref-confusion
	// (ISSUE-402) is about.
	if sha, ok := c.resolveTag(owner, repo, ref); ok {
		m.RefKind = "tag"
		m.TagSha = sha
		m.RefExists = true
		if c.branchExists(owner, repo, ref) {
			m.RefIsAmbiguous = true
		}
		return m
	}
	if c.branchExists(owner, repo, ref) {
		m.RefKind = "branch"
		m.RefExists = true
		return m
	}
	if exists, checked := c.commitResolves(owner, repo, ref); exists {
		m.RefKind = "commit"
		m.RefExists = true
		return m
	} else if checked && info.err == nil {
		// The commits endpoint only accepts commit SHAs, so it answers
		// 422 for a pin that names an annotated tag OBJECT. Dereference
		// that object before concluding anything (ISSUE-401): the pin is
		// immutable, resolves in GitHub Actions, and reporting it as
		// absent is a critical false positive.
		//
		if commit, tagExists, tagChecked := c.tagObjectResolves(owner, repo, ref); tagExists {
			m.RefKind = "commit"
			m.RefExists = true
			m.RefCommitSha = commit
			return m
		} else if !tagChecked {
			// The tag lookup itself could not be completed, so we cannot
			// rule the tag-object shape out. Stay silent.
			return m
		}
		// A definitive absence answer (404 / 422) on a repo we CAN read
		// means the SHA is not tag, branch, tag object, nor commit
		// upstream — a genuine impostor commit or typo. We require
		// info.err == nil so a private / missing repo (whose commits
		// endpoint also 404s) is never mistaken for an absent commit.
		// Left false when the repo itself is unreadable so ISSUE-707
		// stays silent (see commitResolves).
		m.RefKnownAbsent = true
	}
	// Unknown ref — keep RefKind empty, RefExists false.
	return m
}

// advisoriesForRef returns only the advisories whose vulnerable
// version range actually covers the pinned ref. The raw advisory
// list is fetched once per `owner/repo` and cached; the per-ref
// filtering uses a semver comparison against every vulnerability
// entry the advisory declares for this package.
//
// When a commit SHA cannot be resolved to a comparable version
// (the repo's tag list is unavailable, or the SHA is not a tagged
// release), the filter abstains rather than reporting every advisory:
// it cannot prove the pin sits in an affected range, and crying wolf
// on SHA-pinned actions is the ISSUE-228 false positive. A mutable
// non-numeric tag / branch (`rc`, `main`) abstains for the same reason:
// it names no fixed version (see _refCoveredByRange). Whether a ref is
// pinned at all is ISSUE-701's job.
//
// A moving major / major.minor tag (`v4`, `v4.1`) is matched against
// the whole version span it can float across, not against its floor —
// see _refCoveredByRange.
func (c *GitHubMetadataClient) advisoriesForRef(owner, repo, ref string) []string {
	infos := c.advisoriesForRepo(owner, repo)
	if len(infos) == 0 {
		return nil
	}
	refVersion := c.resolveRefToVersion(owner, repo, ref)
	if refVersion == nil && _isCommitSha(ref) {
		// Advisories exist for this repo but we could not resolve the
		// pinned commit to a version, so the range filter abstains below
		// (see _refCoveredByRange). Record it so the degraded check is
		// surfaced rather than silently passing (ISSUE-228).
		c.recordDegraded(owner, repo, ref)
	}
	out := []string{}
	seen := map[string]struct{}{}
	for _, a := range infos {
		if a.GhsaID == "" {
			continue
		}
		if _, dup := seen[a.GhsaID]; dup {
			continue
		}
		if _refCoveredByRange(ref, refVersion, a.VulnerableRange) {
			out = append(out, a.GhsaID)
			seen[a.GhsaID] = struct{}{}
		}
	}
	return out
}

// recordDegraded notes that the known-CVE check for owner/repo@ref could
// not be completed because the pinned commit did not resolve to a version.
// Deduped by ref so a heavily-reused action warns only once.
func (c *GitHubMetadataClient) recordDegraded(owner, repo, ref string) {
	key := owner + "/" + repo + "@" + ref
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.degradedSeen == nil {
		c.degradedSeen = map[string]struct{}{}
	}
	if _, dup := c.degradedSeen[key]; dup {
		return
	}
	c.degradedSeen[key] = struct{}{}
	c.degraded = append(c.degraded, fmt.Sprintf(
		"%s: tag list unavailable, could not resolve the pinned commit to a version, so the known-CVE check was skipped for this action",
		key,
	))
}

// DegradedChecks returns the accumulated "could not verify" messages, one
// per action ref whose known-CVE check was skipped. Returns nil when none.
func (c *GitHubMetadataClient) DegradedChecks() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.degraded) == 0 {
		return nil
	}
	out := make([]string, len(c.degraded))
	copy(out, c.degraded)
	return out
}

// advisoriesForRepo fetches every GitHub Advisory Database entry
// for an `owner/repo` action package, flattens each vulnerability
// entry to an advisoryInfo, and caches the result so repeated
// callers of the same action cost one API call.
func (c *GitHubMetadataClient) advisoriesForRepo(owner, repo string) []advisoryInfo {
	key := owner + "/" + repo
	c.mu.Lock()
	if v, ok := c.advisoryCache[key]; ok {
		c.mu.Unlock()
		return v
	}
	c.mu.Unlock()

	var resp []struct {
		GhsaID          string `json:"ghsa_id"`
		Vulnerabilities []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			VulnerableVersionRange string `json:"vulnerable_version_range"`
			PatchedVersions        string `json:"patched_versions"`
		} `json:"vulnerabilities"`
	}
	out := []advisoryInfo{}
	if err := c.rest.Get(fmt.Sprintf("advisories?ecosystem=actions&affects=%s/%s&per_page=100", owner, repo), &resp); err == nil {
		want := key
		for _, a := range resp {
			for _, v := range a.Vulnerabilities {
				if !strings.EqualFold(v.Package.Name, want) {
					continue
				}
				out = append(out, advisoryInfo{
					GhsaID:          a.GhsaID,
					VulnerableRange: v.VulnerableVersionRange,
					PatchedVersions: v.PatchedVersions,
				})
			}
		}
	}
	c.mu.Lock()
	c.advisoryCache[key] = out
	c.mu.Unlock()
	return out
}

// resolveRefToVersion turns the ref string into a comparable semver
// value: a 40-char commit SHA is looked up in the repo's tag list and
// the matching tag is parsed; any other ref is parsed directly as a
// tag. Returns nil when the version cannot be determined; for a commit
// SHA the caller then abstains rather than matching every advisory, so
// an unresolvable SHA pin is not reported as vulnerable to everything
// (see _refCoveredByRange and ISSUE-228).
//
// The SHA branch is tried first on purpose: hashicorp/go-version
// parses a hex SHA that begins with a digit as a semver value
// (e.g. "2d756ea…" -> 2.0.0-d756ea…, the leading digit becoming the
// core and the rest a prerelease label). Parsing the ref as a tag
// first would short-circuit the SHA lookup and, because a prerelease
// version satisfies no plain constraint, silently drop every advisory.
func (c *GitHubMetadataClient) resolveRefToVersion(owner, repo, ref string) *version.Version {
	// SHA-shaped ref: resolve through the repo's tag list.
	if _isCommitSha(ref) {
		if tag := c.resolveCommitToTag(owner, repo, ref); tag != "" {
			if v, err := version.NewVersion(strings.TrimPrefix(tag, "v")); err == nil {
				return v
			}
		}
		return nil
	}
	// Tag-shaped ref: parse directly.
	if v, err := version.NewVersion(strings.TrimPrefix(ref, "v")); err == nil {
		return v
	}
	return nil
}

// Case-insensitive: git / the GitHub API resolve SHAs regardless of
// case, so an uppercase pin must take the same code paths (degraded
// warnings, advisory abstains) as a lowercase one.
var _shaOnly = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

func _isCommitSha(ref string) bool {
	return _shaOnly.MatchString(ref)
}

var (
	_majorTagOnly      = regexp.MustCompile(`^v?([0-9]+)$`)
	_majorMinorTagOnly = regexp.MustCompile(`^v?([0-9]+\.[0-9]+)$`)
)

// _partialTagBounds recognises a moving major (`v4`) or major.minor
// (`v4.1`) tag and returns the inclusive version span it can resolve
// to. ok is false for exact `vX.Y.Z` tags, commit SHAs and any
// non-semver ref. The high bound uses a saturated patch (and minor)
// component so no real release sorts above it.
func _partialTagBounds(ref string) (floor, ceil *version.Version, ok bool) {
	if m := _majorTagOnly.FindStringSubmatch(ref); m != nil {
		floor, _ = version.NewVersion(m[1])
		ceil, _ = version.NewVersion(m[1] + ".999999.999999")
		return floor, ceil, floor != nil && ceil != nil
	}
	if m := _majorMinorTagOnly.FindStringSubmatch(ref); m != nil {
		floor, _ = version.NewVersion(m[1])
		ceil, _ = version.NewVersion(m[1] + ".999999")
		return floor, ceil, floor != nil && ceil != nil
	}
	return nil, nil, false
}

// _refCoveredByRange reports whether an action ref should be treated
// as affected by an advisory whose vulnerable range is rangeExpr.
//
// A moving major / major.minor tag (`v4`, `v4.1`) is not a fixed
// version — it floats across a whole span of releases. Parsing it as
// its floor (`v4` -> 4.0.0) and point-checking that floor false-
// positives whenever an advisory only affects the start of the series,
// because the tag actually points at the latest, patched release. Such
// a tag is therefore reported only when the ENTIRE span it can float
// across is vulnerable.
//
// Exact tags (`v4.1.0`) and SHA-resolved versions use a plain single-
// version check. Any ref we cannot resolve to a concrete version — an
// unresolvable commit SHA, or a mutable non-numeric tag / branch
// (`rc`, `main`) — abstains rather than matching every advisory, since
// it cannot be placed in a range (ISSUE-228, and the harden-runner
// `@rc` over-match). Whether a ref is pinned is ISSUE-701's concern.
func _refCoveredByRange(ref string, refVersion *version.Version, rangeExpr string) bool {
	if floor, ceil, ok := _partialTagBounds(ref); ok {
		return _versionInRange(floor, rangeExpr) && _versionInRange(ceil, rangeExpr)
	}
	if refVersion == nil {
		// The ref could not be resolved to a concrete release version:
		// either a commit SHA whose tag list was unavailable (org IP
		// allow list 403, rate limit, network) or which is not a tagged
		// release, or a mutable non-numeric tag / branch (`rc`, `latest`,
		// `main`) that names no fixed version. Either way we cannot place
		// it in the advisory's affected range, so do NOT flag it. Matching
		// every advisory for an unresolved ref is the ISSUE-228 false
		// positive (a SHA-pinned action scoring A locally and E in CI);
		// the same over-match hits mutable tags such as `rc`, which
		// usually point at the latest, patched release (validated on
		// step-security/harden-runner@rc). That a ref is not pinned is
		// ISSUE-701's concern, not the CVE check's.
		return false
	}
	return _versionInRange(refVersion, rangeExpr)
}

// resolveCommitToTag returns the release tag pointing at the given
// commit SHA, or "" when the SHA is not the head of any published
// tag. The repo's full tag list is fetched once and cached.
func (c *GitHubMetadataClient) resolveCommitToTag(owner, repo, sha string) string {
	key := owner + "/" + repo
	c.mu.Lock()
	tags, cached := c.sha2tagCache[key]
	c.mu.Unlock()
	if !cached {
		tags = c.fetchAllTags(owner, repo)
		c.mu.Lock()
		c.sha2tagCache[key] = tags
		c.mu.Unlock()
	}
	return tags[sha]
}

// fetchAllTags walks the paginated `/repos/{owner}/{repo}/tags`
// endpoint and returns a SHA → tag-name map. When several tags point
// at the same commit — typically a moving major alias (`v4`) and the
// exact release tag (`v4.3.0`) — the most specific tag wins, so the
// advisory range filter compares against the real pinned version
// rather than the alias.
// tagRef is one entry from the GitHub `/tags` listing: a tag name and the
// commit it points at.
type tagRef struct {
	Name   string `json:"name"`
	Commit struct {
		Sha string `json:"sha"`
	} `json:"commit"`
}

func (c *GitHubMetadataClient) fetchAllTags(owner, repo string) map[string]string {
	out := map[string]string{}
	if c.rest == nil {
		return out
	}
	anonymous := false // flips to true once the authenticated read is blocked
	for page := 1; page <= 20; page++ { // hard cap 2000 tags
		resp, blocked, err := c.fetchTagsPage(owner, repo, page, anonymous)
		if blocked {
			// The authenticated action token hit the owner org's IP allow
			// list. Action repos are public and an anonymous read is not
			// gated by the allow list (confirmed on a runner, ISSUE-228),
			// so retry this page and the rest of them without auth.
			anonymous = true
			var anonErr error
			resp, _, anonErr = c.fetchTagsPage(owner, repo, page, true)
			if anonErr != nil {
				err = fmt.Errorf("authenticated read blocked by the org IP allow list (403); the anonymous retry also failed: %w", anonErr)
			} else {
				err = nil
				// The normal authenticated read was blocked but the
				// anonymous retry resolved it. Surface this at warn level
				// (visible without --verbose) so the fallback is on the
				// record: the version was resolved anonymously, not by the
				// usual token read. Fires once per repo, since `anonymous`
				// is now set for the remaining pages.
				logrus.WithField("context", "collector").
					Warnf("authenticated tags read for %s/%s was blocked by the org IP allow list (403); resolved it with an anonymous retry instead", owner, repo)
			}
		}
		if err != nil {
			// A tag fetch that fails even anonymously (allow list with no
			// public route, rate limit, network) means SHA-pinned refs for
			// this repo cannot be resolved to a version; the advisory filter
			// then abstains rather than emitting false-positive CVEs (see
			// _refCoveredByRange and ISSUE-228). Warn so it stays visible.
			logrus.WithField("context", "collector").
				Warnf("could not fetch tags for %s/%s on page %d; advisory version checks for SHA-pinned refs will be skipped: %v", owner, repo, page, err)
			break
		}
		if len(resp) == 0 {
			break
		}
		for _, t := range resp {
			if t.Name == "" || t.Commit.Sha == "" {
				continue
			}
			if prev, ok := out[t.Commit.Sha]; ok {
				out[t.Commit.Sha] = _moreSpecificTag(prev, t.Name)
				continue
			}
			out[t.Commit.Sha] = t.Name
		}
		if len(resp) < 100 {
			break
		}
	}
	return out
}

// fetchTagsPage reads one page of a repo's tags. With anonymous=false it
// uses the authenticated client and returns blocked=true (and no error)
// when the owner org's IP allow list answers 403, signalling the caller to
// retry anonymously. With anonymous=true it reads without auth.
func (c *GitHubMetadataClient) fetchTagsPage(owner, repo string, page int, anonymous bool) (tags []tagRef, blocked bool, err error) {
	if anonymous {
		t, _, e := c.anonGetTagsPage(owner, repo, page)
		return t, false, e
	}
	path := fmt.Sprintf("repos/%s/%s/tags?per_page=100&page=%d", owner, repo, page)
	var resp []tagRef
	if e := c.rest.Get(path, &resp); e != nil {
		var httpErr *api.HTTPError
		if errors.As(e, &httpErr) && httpErr.StatusCode == http.StatusForbidden {
			return nil, true, nil
		}
		return nil, false, e
	}
	return resp, false, nil
}

// anonGetTagsPage reads one page of a repo's tags without authentication,
// against apiBaseURL. It is the fallback when the authenticated read is
// blocked by an org IP allow list: public repos are world-readable and the
// allow list does not gate anonymous reads (confirmed on a runner,
// ISSUE-228). Subject to GitHub's 60/hour-per-IP unauthenticated limit, so
// any failure here propagates and the caller abstains. On non-github.com
// hosts the base URL is best effort; a wrong URL simply fails and abstains.
func (c *GitHubMetadataClient) anonGetTagsPage(owner, repo string, page int) ([]tagRef, int, error) {
	reqURL := fmt.Sprintf("%s/repos/%s/%s/tags?per_page=100&page=%d", c.apiBaseURL, owner, repo, page)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("anonymous tags read returned HTTP %d", resp.StatusCode)
	}
	var tags []tagRef
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return nil, resp.StatusCode, err
	}
	return tags, resp.StatusCode, nil
}

// apiBaseURLForHost returns the REST base used for unauthenticated fallback
// reads. An empty host means github.com; any other host (GHES) is used as
// given, best effort.
func apiBaseURLForHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return "https://api.github.com"
	}
	if !strings.Contains(host, "://") {
		host = "https://" + host
	}
	return strings.TrimRight(host, "/")
}

// _moreSpecificTag returns whichever of two tag names that point at the
// same commit pins a version most precisely. A release commit is often
// reachable from both a moving major alias ("v4") and the exact release
// tag ("v4.3.0"); the advisory range filter must compare against the
// exact release, otherwise "v4" parses as 4.0.0 and can fall inside a
// vulnerable range the real version sits outside of. A semver tag beats
// a non-semver one; among semver tags the one with more dotted segments
// wins; an exact version comparison breaks any remaining tie.
func _moreSpecificTag(a, b string) string {
	av, aerr := version.NewVersion(strings.TrimPrefix(a, "v"))
	bv, berr := version.NewVersion(strings.TrimPrefix(b, "v"))
	switch {
	case aerr == nil && berr != nil:
		return a
	case berr == nil && aerr != nil:
		return b
	case aerr != nil && berr != nil:
		return a
	}
	if da, db := strings.Count(a, "."), strings.Count(b, "."); da != db {
		if da > db {
			return a
		}
		return b
	}
	if bv.GreaterThan(av) {
		return b
	}
	return a
}

// _versionInRange parses the GitHub-advisory version range syntax
// (`>= 3.26.11, <= 3.28.2`, `< 3.0.0`, `1.2.3`) with
// hashicorp/go-version and reports whether v falls inside. A range
// string Plumber cannot parse is treated as "affects everything"
// so a parser failure never hides a real CVE.
func _versionInRange(v *version.Version, rangeExpr string) bool {
	rangeExpr = strings.TrimSpace(rangeExpr)
	if rangeExpr == "" {
		return true
	}
	// Advisory ranges come comma-separated, which is hashicorp/go-
	// version's native multi-constraint syntax.
	constraints, err := version.NewConstraint(rangeExpr)
	if err != nil {
		return true
	}
	return constraints.Check(v)
}

// repoInfo fetches and caches the repository object once per
// owner/repo. The archived flag and the stargazer count both come
// from the same `GET repos/{owner}/{repo}` response, so callers that
// need either share a single API round-trip.
func (c *GitHubMetadataClient) repoInfo(owner, repo string) repoCacheEntry {
	key := owner + "/" + repo
	c.mu.Lock()
	cached, ok := c.repoCache[key]
	c.mu.Unlock()
	if ok && cached.fetched {
		return cached
	}
	var resp struct {
		Archived        bool `json:"archived"`
		StargazersCount int  `json:"stargazers_count"`
	}
	entry := repoCacheEntry{fetched: true}
	if err := c.rest.Get(fmt.Sprintf("repos/%s/%s", owner, repo), &resp); err != nil {
		entry.err = err
	} else {
		entry.archived = resp.Archived
		entry.stars = resp.StargazersCount
	}
	c.mu.Lock()
	c.repoCache[key] = entry
	c.mu.Unlock()
	return entry
}

// latestReleaseTag returns the highest semver tag across a repo's
// releases. `/releases/latest` alone is not reliable: many action
// repos (github/codeql-action, actions/download-artifact) publish
// out-of-band tags — internal bundle snapshots like
// `codeql-bundle-v2.25.2` or compatibility bridges like
// `v3.1.0-node20` — that rank as "latest" by date even though they
// are not the user-facing release. The date-sorted order is also
// misleading when maintainers backport a fix to an older line and
// republish it *after* a newer major (e.g. v3.1.0 republished after
// v8.0.1). ISSUE-709 is a semver-drift signal, so Plumber walks the
// first few pages and picks the highest semver among non-draft,
// non-prerelease tags whose semver itself has no prerelease segment.
func (c *GitHubMetadataClient) latestReleaseTag(owner, repo string) string {
	key := owner + "/" + repo
	c.mu.Lock()
	if v, ok := c.latestCache[key]; ok {
		c.mu.Unlock()
		return v
	}
	c.mu.Unlock()

	var best *version.Version
	bestTag := ""
	for page := 1; page <= 3; page++ {
		var resp []struct {
			TagName    string `json:"tag_name"`
			Draft      bool   `json:"draft"`
			Prerelease bool   `json:"prerelease"`
		}
		path := fmt.Sprintf("repos/%s/%s/releases?per_page=50&page=%d", owner, repo, page)
		if err := c.rest.Get(path, &resp); err != nil || len(resp) == 0 {
			break
		}
		for _, r := range resp {
			if r.Draft || r.Prerelease {
				continue
			}
			parsed, err := version.NewVersion(strings.TrimPrefix(r.TagName, "v"))
			if err != nil {
				continue
			}
			// Reject compatibility bridges / betas whose semver
			// carries a prerelease segment (e.g. `v3.1.0-node20`,
			// `v1.0.0-beta`). GitHub sometimes publishes these with
			// `prerelease: false`, so the API flag alone is not
			// sufficient.
			if parsed.Prerelease() != "" {
				continue
			}
			if best == nil || parsed.GreaterThan(best) {
				best = parsed
				bestTag = r.TagName
			}
		}
		if len(resp) < 50 {
			break
		}
	}
	c.mu.Lock()
	c.latestCache[key] = bestTag
	c.mu.Unlock()
	return bestTag
}

// ResolveTagSha exposes the tag → SHA lookup publicly so the
// ref-version-mismatch enrichment can query the commented tag
// without going through the full Resolve() probe chain.
func (c *GitHubMetadataClient) ResolveTagSha(ownerRepo, tag string) string {
	if c.disabled || tag == "" {
		return ""
	}
	parts := strings.SplitN(ownerRepo, "/", 2)
	if len(parts) < 2 {
		return ""
	}
	sha, ok := c.resolveTag(parts[0], parts[1], tag)
	if !ok {
		return ""
	}
	return sha
}

// resolveTag returns (sha, true) when ref is a tag on the repo and
// we can read the SHA it points at. Returns ("", false) otherwise.
func (c *GitHubMetadataClient) resolveTag(owner, repo, ref string) (string, bool) {
	var resp json.RawMessage
	err := c.rest.Get(fmt.Sprintf("repos/%s/%s/git/ref/tags/%s", owner, repo, ref), &resp)
	if err != nil {
		return "", false
	}
	// The reply is either a tag ref (object.type="commit") or a tag
	// object (object.type="tag") — in the latter case, the SHA
	// points at the tag object, not the commit. Resolving the tag
	// object to its target commit requires a second call.
	var parsed struct {
		Object struct {
			Sha  string `json:"sha"`
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"object"`
	}
	if err := json.Unmarshal(resp, &parsed); err != nil {
		return "", false
	}
	if parsed.Object.Type == "tag" {
		var tagObj struct {
			Object struct {
				Sha string `json:"sha"`
			} `json:"object"`
		}
		// git/tags/<sha> resolves the annotated-tag object to the
		// commit. If this secondary call fails we still return the
		// tag-object SHA: the policy only needs "is this a tag" plus
		// a stable identifier.
		if err := c.rest.Get(fmt.Sprintf("repos/%s/%s/git/tags/%s", owner, repo, parsed.Object.Sha), &tagObj); err == nil {
			return tagObj.Object.Sha, true
		}
	}
	return parsed.Object.Sha, true
}

// maxTagObjectDepth caps the ^{commit} walk in tagObjectResolves. A tag
// object pointing at another tag object is legal but does not occur in
// released actions; the cap exists so a malformed or self-referential
// chain cannot spin.
const maxTagObjectDepth = 4

// tagObjectResolves reports whether ref is the SHA of an annotated tag
// OBJECT in the upstream repository, and returns the commit that tag
// object dereferences to. That shape is what `git rev-parse v1.2.3`
// yields without `^{commit}`, so it is a normal outcome of pinning an
// action by hand or with a script (ISSUE-401), yet the commits endpoint
// answers 422 for it because it only accepts commit SHAs.
//
// Every call is scoped to the upstream repository, and the dereferenced
// commit is confirmed in that same repository before the pin is called
// resolvable. (GitHub serves fork-network objects from the parent, so a
// fork-only object can still satisfy a same-repo lookup. That is the
// pre-existing scope limit of this control, documented in
// impostor_commit.rego, and the tag-object path neither widens nor
// narrows it.)
//
// The tri-state contract matches commitResolves: checked is true ONLY
// on a definitive answer (a resolvable tag object, or a 404 / 422 that
// rules one out). Any other failure (403, rate limit, network) leaves
// checked false so impostor-commit (ISSUE-707) stays silent on a SHA we
// merely failed to reach.
func (c *GitHubMetadataClient) tagObjectResolves(owner, repo, ref string) (commitSha string, exists, checked bool) {
	// git/tags is keyed by object SHA, so only a SHA-shaped ref can name
	// a tag object. Answering `v99` or a typo'd branch costs a round trip
	// against the same rate limit for a guaranteed 404, so rule those out
	// locally: the answer is definitive without asking.
	if !_isCommitSha(ref) {
		return "", false, true
	}
	// Git resolves SHAs case-insensitively and every other SHA path here
	// lowercases before comparing, but the git database endpoints are
	// keyed by the exact object SHA: GitHub answers a mixed-case one with
	// 500, which is not a definitive absence. Normalise so an uppercase
	// pin takes the same path as its lowercase equivalent.
	sha := strings.ToLower(ref)

	// `git rev-parse <tag>^{commit}` peels through however many tag
	// objects sit in the chain. Nesting beyond one level does not occur
	// in practice, so the cap is a cheap guard against a malformed or
	// self-referential chain rather than a real traversal budget.
	for depth := 0; depth < maxTagObjectDepth; depth++ {
		var resp struct {
			Object struct {
				Sha  string `json:"sha"`
				Type string `json:"type"`
			} `json:"object"`
		}
		err := c.rest.Get(fmt.Sprintf("repos/%s/%s/git/tags/%s", owner, repo, sha), &resp)
		if err != nil {
			var httpErr *api.HTTPError
			if errors.As(err, &httpErr) {
				switch httpErr.StatusCode {
				// 404 / 422: the SHA is not a tag object on a repo we can
				// read. Definitive for the ref we were asked about, so the
				// caller may fall through to "absent upstream". Deeper in
				// the chain it only means we lost the thread, so abstain.
				case http.StatusNotFound, http.StatusUnprocessableEntity:
					return "", false, depth == 0
				}
			}
			return "", false, false
		}
		// Past this point git/tags served the SHA, so it plainly exists in
		// the upstream repository. Anything we cannot turn into a confirmed
		// commit abstains (checked=false) rather than falling through to
		// "does not exist upstream", which would be a false statement at
		// critical severity.
		switch {
		case resp.Object.Sha == "":
			return "", false, false
		case resp.Object.Type == "commit":
			if ok, _ := c.commitResolves(owner, repo, resp.Object.Sha); !ok {
				return "", false, false
			}
			return resp.Object.Sha, true, true
		case resp.Object.Type == "tag":
			sha = resp.Object.Sha
		default:
			// A tag pointing at a tree or blob is legal in git but is not
			// something we can describe as a commit pin.
			return "", false, false
		}
	}
	return "", false, false
}

func (c *GitHubMetadataClient) branchExists(owner, repo, ref string) bool {
	var resp json.RawMessage
	err := c.rest.Get(fmt.Sprintf("repos/%s/%s/branches/%s", owner, repo, ref), &resp)
	return err == nil
}

// commitResolves reports whether ref resolves to a commit upstream.
// The second return value, checked, is true ONLY when the API gave a
// definitive answer: exists=true on success, or exists=false on a 404 /
// 422. On any other error (403, rate limit, private repo, network)
// checked is false and the caller must not conclude the commit is
// absent — impostor-commit (ISSUE-707) fires only on a confirmed
// absence, never on a SHA it merely failed to reach.
func (c *GitHubMetadataClient) commitResolves(owner, repo, ref string) (exists, checked bool) {
	// GitHub's commits endpoint accepts short SHAs too, but for
	// impostor-commit we specifically want to know if a full 40-
	// char SHA resolves.
	var resp json.RawMessage
	err := c.rest.Get(fmt.Sprintf("repos/%s/%s/commits/%s", owner, repo, ref), &resp)
	if err == nil {
		return true, true
	}
	var httpErr *api.HTTPError
	if errors.As(err, &httpErr) {
		switch httpErr.StatusCode {
		// 404: the ref (short SHA / branch form) is not present. 422
		// "No commit found for SHA": a well-formed 40-char SHA the repo
		// does not contain — the endpoint's answer for the exact case
		// impostor-commit cares about. Both are definitive "does not
		// exist" answers for a repo we can read (resolveUncached only
		// trusts this after repoInfo succeeded).
		case http.StatusNotFound, http.StatusUnprocessableEntity:
			return false, true
		}
	}
	return false, false
}

// isZeroMetadata reports whether meta has no content. GitHubMetadata
// now carries a slice field, which Go refuses to compare with `==`,
// so we spell the zero-check out field by field.
func isZeroMetadata(meta GitHubMetadata) bool {
	if meta.RepoArchived || meta.RefExists || meta.RefIsAmbiguous || meta.RefKnownAbsent {
		return false
	}
	if meta.RefKind != "" || meta.TagSha != "" || meta.LatestTag != "" || meta.LatestReleaseSha != "" {
		return false
	}
	if len(meta.Advisories) > 0 {
		return false
	}
	// A resolved star count is meaningful even when the ref itself could
	// not be resolved — the authorized-sources control (ISSUE-713) reads
	// it for the minimumStars threshold, so keep the metadata.
	if meta.StargazersCount > 0 {
		return false
	}
	return true
}

// splitActionRef parses "owner/repo@ref" into its three parts. For
// path-scoped composite actions ("owner/repo/path/to/action@ref")
// the repo portion is "repo" (first path segment) — we never need
// the sub-path for metadata lookups. Returns ok=false for forms
// plumber cannot check against the GitHub API (local actions,
// docker:// refs, bare strings).
func splitActionRef(uses string) (owner, repo, ref string, ok bool) {
	if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "docker://") {
		return "", "", "", false
	}
	at := strings.Index(uses, "@")
	if at < 0 {
		return "", "", "", false
	}
	head, tail := uses[:at], uses[at+1:]
	parts := strings.SplitN(head, "/", 3)
	if len(parts) < 2 {
		return "", "", "", false
	}
	return parts[0], parts[1], tail, true
}
