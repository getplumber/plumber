package github

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/cli/go-gh/v2/pkg/api"
	version "github.com/hashicorp/go-version"

	"github.com/getplumber/plumber/internal/httpcount"
)

// EnvDisableGitHubAPI is the variable that, when set to a truthy value, forces every
// GitHub API consumer that honors it (the metadata client, the
// default-branch lookup seam in control) into degraded mode
// regardless of gh auth state. Set to "1" by the test suites to
// keep unit tests offline and fast.
const EnvDisableGitHubAPI = "PLUMBER_DISABLE_GITHUB_API"

// EnvMetadataToken is the variable that, when set, supplies the token the metadata client uses
// to resolve third-party action versions. It takes precedence over the
// go-gh default chain (gh auth, GH_TOKEN, GITHUB_TOKEN) and is the
// supported way to resolve actions hosted in an org that gates the Actions
// GITHUB_TOKEN behind an IP allow list (ISSUE-228); it also carries the
// 5,000/hr user rate limit. A token with public-repository read is
// sufficient.
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
	// answered that the ref does not exist (no tag, branch or object of
	// that name on a readable repo). It stays false when the ref could not be verified (private
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
	// RefIsImmutableRelease is true ONLY when the ref is a tag and the
	// GitHub release for that exact tag reports immutable=true: the tag
	// can then never be moved or deleted, so ISSUE-701 treats it as
	// pinned (#421). A tag without a release (a floating major such as
	// v4), a mutable release and a lookup that failed all leave it false,
	// so the ref keeps being flagged.
	RefIsImmutableRelease bool
	Advisories            []string
	// AdvisorySeverities maps each id of Advisories to its severity
	// (low, medium, high or critical), read off the same listing; an id
	// whose severity the listing did not give is absent.
	AdvisorySeverities map[string]string
	StargazersCount    int
	// RedirectedOwner is the owner the repository's current full_name
	// names, when it differs from the `uses` owner (case insensitive):
	// GitHub keeps resolving the old owner/repo path after a rename or
	// an organisation transfer, so this is who can actually change the
	// code. Empty when the names agree or the repository could not be
	// read.
	RedirectedOwner string
}

// GitHubMetadataClient resolves `owner/repo@ref` references against
// the GitHub GraphQL API (via github.com/cli/go-gh which reuses the
// installed `gh` CLI's stored credentials), in batches (Prefetch,
// metadata_graphql.go), and caches every answer so the collector never
// asks GitHub twice for the same key. Safe for concurrent use.
//
// When `gh` is not authenticated — or go-gh cannot find a token —
// the client operates in degraded mode: every lookup returns an
// empty GitHubMetadata and Available() returns false. Policies are
// expected to key their deny rules on the positive evidence the
// client surfaces, so the degraded-mode output is a zero-finding
// run rather than a crash.
type GitHubMetadataClient struct {
	// rest serves the definition reads, and on GitHub Enterprise Server
	// the advisory and immutable-release lookups (see dotcom).
	rest *api.RESTClient
	// gql sends the metadata queries (metadata_graphql.go), with the same
	// token as rest.
	gql *api.GraphQLClient
	// dotcom is true when the client talks to github.com, whose GraphQL
	// schema has the ACTIONS advisory ecosystem and Release.immutable. A
	// GitHub Enterprise Server may lack both, so those two lookups go
	// through REST there.
	dotcom bool
	// load fills the caches below for reqs and loadTags fills sha2tagCache;
	// queryRepos and queryTags, or a test's fake.
	load     func(reqs []repoRequest)
	loadTags func(repos []repoKey)
	// recordCost receives each query's rateLimit cost.
	recordCost func(graphQLCost)
	mu         sync.Mutex
	// repoCache maps "owner/repo" to archived state; populated lazily.
	repoCache map[string]repoCacheEntry
	// refCache maps "owner/repo@ref" to the resolved metadata.
	refCache    map[string]GitHubMetadata
	latestCache map[string]string
	// releases holds each repository's newest releases, newest first.
	releases map[string][]releaseFact
	// refFacts holds what GitHub said about each "owner/repo@ref".
	refFacts map[string]*refFacts
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
	// Severity is the advisory's own rating as the listing returns it,
	// lower-cased: low, medium, high or critical; empty when absent.
	Severity string
}

type repoCacheEntry struct {
	archived bool
	stars    int
	// fullName is the repository's current owner/repo, from the same
	// `GET repos/{owner}/{repo}` response as archived/stars: GitHub
	// keeps resolving the OLD owner/repo path after a rename or an
	// organisation transfer, so this is the one place that tells the
	// two apart.
	fullName string
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
		dotcom:        isDotcomHost(host),
		repoCache:     map[string]repoCacheEntry{},
		refCache:      map[string]GitHubMetadata{},
		latestCache:   map[string]string{},
		releases:      map[string][]releaseFact{},
		refFacts:      map[string]*refFacts{},
		advisoryCache: map[string][]advisoryInfo{},
		sha2tagCache:  map[string]map[string]string{},
		recordCost:    recordGraphQLCost,
	}
	c.load, c.loadTags = c.queryRepos, c.queryTags
	if v := os.Getenv(EnvDisableGitHubAPI); v == "1" || v == "true" {
		c.disabled = true
		return c
	}
	// Credential precedence (ISSUE-228):
	//   1. PLUMBER_METADATA_TOKEN, when supplied, wins. It resolves action
	//      versions from orgs that gate the Actions GITHUB_TOKEN behind an IP
	//      allow list, at the 5,000/hr user limit.
	//   2. otherwise the go-gh default chain (gh auth, GH_TOKEN, GITHUB_TOKEN).
	// GraphQL has no anonymous access, so without a token the client is
	// disabled. Empty Host and AuthToken resolve through the go-gh default
	// chain, exactly as api.DefaultRESTClient does.
	opts, _ := metadataClientOptions(host)
	rest, err := api.NewRESTClient(opts)
	if err != nil {
		c.disabled = true
		c.disableCause = err
		return c
	}
	gql, err := api.NewGraphQLClient(graphQLClientOptions(opts))
	if err != nil {
		c.disabled = true
		c.disableCause = err
		return c
	}
	c.rest, c.gql = rest, gql
	return c
}

// isDotcomHost reports whether host, as the metadata client takes it,
// names github.com rather than a GitHub Enterprise Server.
func isDotcomHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
	h = strings.TrimSuffix(h, "/")
	return h == "" || h == "github.com" || h == "api.github.com"
}

// graphQLClientOptions returns opts for the GraphQL client: same host and
// token, but sent through httpcount.DefaultTransport, which counts requests
// and never answers one from memory. The entrypoint prefetch decides from
// this answer that a file is missing, so the answer must come from GitHub
// each time, never from Memo.
func graphQLClientOptions(opts api.ClientOptions) api.ClientOptions {
	opts.Transport = httpcount.DefaultTransport
	return opts
}

// metadataClientOptions resolves the REST client options for the metadata
// client. When EnvMetadataToken is set its (trimmed) value is returned as
// both the AuthToken on opts and the second return value, signalling the
// caller to use it in preference to the go-gh default chain. token is empty
// otherwise. A non-empty host targets a GitHub Enterprise Server instance.
// Requests go through httpcount so the run can report what it sent.
func metadataClientOptions(host string) (opts api.ClientOptions, token string) {
	opts.Transport = httpcount.MemoTransport
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
// safeActionAPIRef reports whether owner, repo and ref can be placed into a
// GitHub REST path without reaching beyond the repository endpoint. owner and
// repo are single path segments (no slash); none of the three may carry a
// path-traversal, query, fragment, percent, backslash, space or control
// character. A ref may contain a slash (a branch like `release/1.0` is a real
// ref). The check is deliberately narrow: it keeps legitimately named owners
// (underscores, dots) resolving, and only screens out a reference crafted to
// steer the request elsewhere on the host.
func safeActionAPIRef(owner, repo, ref string) bool {
	for _, s := range []string{owner, repo, ref} {
		if s == "" || strings.Contains(s, "..") || strings.ContainsAny(s, "?#%\\ ") {
			return false
		}
		for _, r := range s {
			if r < 0x20 || r == 0x7f {
				return false
			}
		}
	}
	return !strings.Contains(owner, "/") && !strings.Contains(repo, "/")
}

func (c *GitHubMetadataClient) Resolve(ownerRepoRef string) GitHubMetadata {
	if c.disabled {
		return GitHubMetadata{}
	}
	owner, repo, ref, ok := splitActionRef(ownerRepoRef)
	if !ok || !safeActionAPIRef(owner, repo, ref) {
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
	if redirOwner, _, ok := strings.Cut(info.fullName, "/"); ok && redirOwner != "" && !strings.EqualFold(redirOwner, owner) {
		m.RedirectedOwner = redirOwner
	}
	if info.err != nil {
		// An unreadable repo yields the ZERO entry, and the fields it
		// feeds are only meaningful when they were actually read.
		// archived=false is the pass verdict for ISSUE-702, so a 403, a
		// rate limit or a since-deleted repo reported "not archived" for an
		// action nobody could look at - the one case where the control's
		// answer matters most.
		//
		// The rule fires only on archived==true, so it cannot be guarded
		// from the Rego side: the honest signal has to come from here.
		// (StargazersCount needs no equivalent; ISSUE-713 already abstains
		// on a zero count rather than treating it as untrusted.)
		c.recordDegradedMessage("repo:"+owner+"/"+repo, fmt.Sprintf(
			"%s/%s: the repository could not be read (%v), so the archived-repo check was skipped for this action",
			owner, repo, info.err,
		))
	}
	m.LatestTag = c.latestReleaseTag(owner, repo)
	if m.LatestTag != "" {
		if sha, ok := c.resolveTag(owner, repo, m.LatestTag); ok {
			m.LatestReleaseSha = sha
		}
	}
	m.Advisories = c.advisoriesForRef(owner, repo, ref)
	m.AdvisorySeverities = c.advisorySeverities(owner, repo, m.Advisories)

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
		m.RefIsImmutableRelease = c.releaseIsImmutable(owner, repo, ref)
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
		// A pin that names an annotated tag OBJECT is no commit.
		// Dereference that object before concluding anything (ISSUE-401):
		// the pin is immutable, resolves in GitHub Actions, and reporting
		// it as absent is a critical false positive.
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
		// A definitive absence answer on a repo we CAN read means the SHA
		// is not tag, branch, tag object, nor commit upstream — a genuine
		// impostor commit or typo. We require info.err == nil so a
		// private / missing repo (where no object is found either) is
		// never mistaken for an absent commit.
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

// advisorySeverities is the severity of each of ids, read off the
// advisory listing advisoriesForRef already fetched and cached for
// owner/repo: no further read. nil when none carries one.
func (c *GitHubMetadataClient) advisorySeverities(owner, repo string, ids []string) map[string]string {
	if len(ids) == 0 {
		return nil
	}
	var out map[string]string
	for _, a := range c.advisoriesForRepo(owner, repo) {
		if a.Severity == "" || !slices.Contains(ids, a.GhsaID) {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[a.GhsaID] = a.Severity
	}
	return out
}

// recordDegraded notes that the known-CVE check for owner/repo@ref could
// not be completed because the pinned commit did not resolve to a version.
// Deduped by ref so a heavily-reused action warns only once.
func (c *GitHubMetadataClient) recordDegraded(owner, repo, ref string) {
	key := owner + "/" + repo + "@" + ref
	c.recordDegradedMessage(key, fmt.Sprintf(
		"%s: tag list unavailable, could not resolve the pinned commit to a version, so the known-CVE check was skipped for this action",
		key,
	))
}

// recordDegradedMessage appends one "could not verify" line, deduped by key.
//
// Every path that cannot complete a check must come through here. The cost of
// not doing so is invisible: the check's result is a zero value, which reads
// downstream as a clean answer, and the control reports a pass over a lookup
// that never happened.
func (c *GitHubMetadataClient) recordDegradedMessage(key, msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.degradedSeen == nil {
		c.degradedSeen = map[string]struct{}{}
	}
	if _, dup := c.degradedSeen[key]; dup {
		return
	}
	c.degradedSeen[key] = struct{}{}
	c.degraded = append(c.degraded, msg)
}

// UnavailableReason explains why metadata enrichment did not run at all,
// or "" when it did.
//
// Without this the disable cause was recorded and never read: no token, a
// disabled API, or a client-construction error returned from enrichment
// before a single action was touched, leaving every metadata-driven control
// reporting passed over an empty result.
func (c *GitHubMetadataClient) UnavailableReason() string {
	if c == nil {
		return "GitHub API metadata enrichment did not run, so the checks that depend on it could not be completed"
	}
	if !c.disabled {
		return ""
	}
	if c.disableCause != nil {
		return fmt.Sprintf(
			"GitHub API metadata enrichment unavailable (%v), so the known-CVE, archived-repo, ref-existence and star-count checks were skipped for every action",
			c.disableCause,
		)
	}
	return "GitHub API metadata enrichment unavailable (no usable token), so the known-CVE, archived-repo, ref-existence and star-count checks were skipped for every action"
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

// advisoriesForRepo returns every GitHub Advisory Database entry for an
// `owner/repo` action package, one advisoryInfo per vulnerability entry,
// read once per package: from the GraphQL loader on github.com, over REST
// on GitHub Enterprise Server.
func (c *GitHubMetadataClient) advisoriesForRepo(owner, repo string) []advisoryInfo {
	key := owner + "/" + repo
	c.mu.Lock()
	if v, ok := c.advisoryCache[key]; ok {
		c.mu.Unlock()
		return v
	}
	c.mu.Unlock()
	if c.dotcom {
		c.load([]repoRequest{{owner: owner, repo: repo, advisories: true}})
		c.mu.Lock()
		defer c.mu.Unlock()
		v, ok := c.advisoryCache[key]
		if !ok {
			v = []advisoryInfo{}
			c.advisoryCache[key] = v
		}
		return v
	}
	// GitHub Enterprise Server: its GraphQL schema may lack the ACTIONS
	// ecosystem, so the advisories are read over REST.

	var resp []struct {
		GhsaID          string `json:"ghsa_id"`
		Severity        string `json:"severity"`
		Vulnerabilities []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			VulnerableVersionRange string `json:"vulnerable_version_range"`
			PatchedVersions        string `json:"patched_versions"`
		} `json:"vulnerabilities"`
	}
	out := []advisoryInfo{}
	// A failed lookup is NOT "this action has no advisories". Without the
	// else branch below an empty result was cached and served as an answer,
	// so a 403 secondary rate limit, a 5xx, or a GHES instance without the
	// endpoint made every action from that repo report clean on ISSUE-703 -
	// the one control whose whole purpose is knowing about published CVEs.
	//
	// The result is still cached on failure: retrying per action would turn
	// one rate limit into many. The warning is what stops it reading as a
	// pass.
	if err := c.rest.Get(fmt.Sprintf("advisories?ecosystem=actions&affects=%s/%s&per_page=100", owner, repo), &resp); err != nil {
		c.recordDegradedMessage("advisories:"+key, fmt.Sprintf(
			"%s: the GitHub Advisory Database could not be queried (%v), so the known-CVE check was skipped for this action",
			key, err,
		))
	} else {
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
					Severity:        strings.ToLower(a.Severity),
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

// apiBaseURLForHost returns the REST base the job-log reader builds its
// URL on. An empty host means github.com; any other host (GHES) is used
// as given, best effort.
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

// ResolveTagSha exposes the tag → SHA lookup publicly so the
// ref-version-mismatch enrichment can query the commented tag
// without going through the full Resolve() probe chain.
func (c *GitHubMetadataClient) ResolveTagSha(ownerRepo, tag string) string {
	if c.disabled || tag == "" {
		return ""
	}
	parts := strings.SplitN(ownerRepo, "/", 2)
	if len(parts) < 2 || !safeActionAPIRef(parts[0], parts[1], tag) {
		return ""
	}
	sha, ok := c.resolveTag(parts[0], parts[1], tag)
	if !ok {
		return ""
	}
	return sha
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
// action by hand or with a script (ISSUE-401), yet it is no commit.
//
// The lookup is scoped to the upstream repository, and the chain is read
// there down to the commit before the pin is called resolvable.
//
// Fork-network blind spot. GitHub serves every object in a fork network
// from the parent, so a tag object pushed only to a FORK of owner/repo
// still resolves here and is accepted (GraphQL's object(oid:) finds a
// fork-only commit on the parent as the REST commits endpoint did:
// checked on actions/checkout, 2026-11-24). The control already had this
// gap for commits (see impostor_commit.rego); resolving tag objects
// extends it to them, because before this change every tag object was
// reported and a fork-only one was caught as collateral of that bug
// rather than by any fork check.
//
// It cannot be closed by requiring the SHA to appear in the repo's own
// tag refs (git/matching-refs/tags/): a moving tag such as `v6` is
// repointed on each release, which orphans the previous tag object from
// every ref while leaving it a valid, immutable, resolvable pin. That
// check would reject those and reinstate the false positive this
// function exists to remove. Closing the gap needs a source that is not
// shared across the fork network.
//
// The tri-state contract matches commitResolves: checked is true ONLY
// on a definitive answer (a resolvable tag object, or an answer that rules
// one out). A failed lookup leaves checked false so impostor-commit
// (ISSUE-707) stays silent on a SHA we merely failed to reach.
func (c *GitHubMetadataClient) tagObjectResolves(owner, repo, ref string) (commitSha string, exists, checked bool) {
	// Only a SHA-shaped ref can name a tag object, so any other ref is
	// ruled out without asking.
	if !_isCommitSha(ref) {
		return "", false, true
	}
	f := c.ensureRef(owner, repo, ref)
	if f.failed || !f.objectChecked {
		return "", false, false
	}
	// No object, or one that is not a tag object: definitive for the ref
	// we were asked about, so the caller may fall through to "absent
	// upstream".
	if f.object == nil || f.object.Typename != "Tag" {
		return "", false, true
	}
	// Past this point the SHA plainly exists in the upstream repository.
	// `git rev-parse <tag>^{commit}` peels through however many tag
	// objects sit in the chain; the query read maxTagObjectDepth of them.
	// Anything we cannot turn into a commit abstains (checked=false)
	// rather than falling through to "does not exist upstream", which
	// would be a false statement at critical severity. A tag pointing at a
	// tree or blob is legal in git but is not something we can describe as
	// a commit pin.
	if sha := peeledCommit(f.object); sha != "" {
		return sha, true, true
	}
	return "", false, false
}

// releaseIsImmutableREST is releaseIsImmutable over REST, for GitHub
// Enterprise Server: a 404 (the tag has no release) is a definitive "no";
// any other failure is also "no", but is recorded as a degraded check.
func (c *GitHubMetadataClient) releaseIsImmutableREST(owner, repo, tag string) bool {
	var resp struct {
		Immutable bool `json:"immutable"`
	}
	err := c.rest.Get(fmt.Sprintf("repos/%s/%s/releases/tags/%s", owner, repo, tag), &resp)
	if err == nil {
		return resp.Immutable
	}
	var httpErr *api.HTTPError
	if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
		return false
	}
	c.recordReleaseUnread(owner, repo, tag, err)
	return false
}

// isZeroMetadata reports whether meta has no content. GitHubMetadata
// now carries a slice field, which Go refuses to compare with `==`,
// so we spell the zero-check out field by field.
func isZeroMetadata(meta GitHubMetadata) bool {
	if meta.RepoArchived || meta.RefExists || meta.RefIsAmbiguous || meta.RefKnownAbsent || meta.RefIsImmutableRelease {
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
	if meta.RedirectedOwner != "" {
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
