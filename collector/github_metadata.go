package collector

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/cli/go-gh/v2/pkg/api"
	version "github.com/hashicorp/go-version"
)

// EnvDisableGitHubAPI, when set to a truthy value, forces the
// GitHub metadata client into degraded mode regardless of gh auth
// state. Set to "1" by the test suite to keep unit tests offline
// and fast; production code does not read this variable.
const EnvDisableGitHubAPI = "PLUMBER_DISABLE_GITHUB_API"

// GitHubMetadata is the facts the API-backed policies need to know
// about a single `owner/repo@ref` action reference.
//
//   - RepoArchived:     the GitHub repo hosting the action is archived.
//   - RefExists:        the ref (tag / branch / commit SHA) resolves.
//   - RefKind:          "tag", "branch", "commit", "unknown".
//   - TagSha:           when RefKind=="tag", the commit SHA the tag
//                       currently points at.
//   - LatestTag:        the repo's newest release tag, "" when the
//                       API returns no releases.
//   - LatestReleaseSha: the SHA that tag resolves to upstream.
//   - RefIsAmbiguous:   the ref resolves as BOTH a tag and a branch
//                       (ref-confusion).
//   - Advisories:       security advisory identifiers from the
//                       GitHub Advisory Database whose affected
//                       version range covers this ref, if any.
//
// Zero value (all fields empty / false) is explicitly "unknown" — it
// is also what the policies see when the API call failed. They
// should treat zero value as "I don't know" and stay silent.
type GitHubMetadata struct {
	RepoArchived     bool
	RefExists        bool
	RefKind          string
	TagSha           string
	LatestTag        string
	LatestReleaseSha string
	RefIsAmbiguous   bool
	Advisories       []string
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
	mu   sync.Mutex
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
	fetched  bool
	err      error
}

// NewGitHubMetadataClient builds a client using the gh-CLI auth
// store. Returns a usable client even when authentication is
// missing — see Available() to check. Honors the
// PLUMBER_DISABLE_GITHUB_API env var which short-circuits the
// client into degraded mode regardless of auth state.
//
// Targets api.github.com by default. For GitHub Enterprise Server
// instances, use NewGitHubMetadataClientForHost with the GHES API
// host (e.g. "ghes.example.com" or "ghes.example.com/api/v3").
func NewGitHubMetadataClient() *GitHubMetadataClient {
	return NewGitHubMetadataClientForHost("")
}

// NewGitHubMetadataClientForHost is the GHES-aware constructor. When
// host is empty the client targets api.github.com via the default
// go-gh resolution chain (gh auth, GH_TOKEN, GITHUB_TOKEN). When
// host is non-empty the client is bound to that host — pair with a
// GH_TOKEN (or GH_ENTERPRISE_TOKEN) that has access to the GHES
// instance.
func NewGitHubMetadataClientForHost(host string) *GitHubMetadataClient {
	c := &GitHubMetadataClient{
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
	var rest *api.RESTClient
	var err error
	if host == "" {
		rest, err = api.DefaultRESTClient()
	} else {
		rest, err = api.NewRESTClient(api.ClientOptions{Host: host})
	}
	if err != nil {
		c.disabled = true
		c.disableCause = err
		return c
	}
	c.rest = rest
	return c
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
	m.RepoArchived = c.isRepoArchived(owner, repo)
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
	// (ISSUE-710) is about.
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
	if c.commitExists(owner, repo, ref) {
		m.RefKind = "commit"
		m.RefExists = true
		return m
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
// When the ref cannot be resolved to a comparable version (unknown
// tag, commit SHA that does not point at a release), the filter
// degrades to "keep advisories that reference this package at
// all" — better a false positive than a silent miss on a real CVE.
func (c *GitHubMetadataClient) advisoriesForRef(owner, repo, ref string) []string {
	infos := c.advisoriesForRepo(owner, repo)
	if len(infos) == 0 {
		return nil
	}
	refVersion := c.resolveRefToVersion(owner, repo, ref)
	out := []string{}
	seen := map[string]struct{}{}
	for _, a := range infos {
		if a.GhsaID == "" {
			continue
		}
		if _, dup := seen[a.GhsaID]; dup {
			continue
		}
		if refVersion == nil || _versionInRange(refVersion, a.VulnerableRange) {
			out = append(out, a.GhsaID)
			seen[a.GhsaID] = struct{}{}
		}
	}
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
// tag. Returns nil when the version cannot be determined — callers
// then fall back to "flag everything" so a genuine CVE does not slip
// past because Plumber could not match the SHA to a release.
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

var _shaOnly = regexp.MustCompile(`^[0-9a-f]{40}$`)

func _isCommitSha(ref string) bool {
	return _shaOnly.MatchString(ref)
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
func (c *GitHubMetadataClient) fetchAllTags(owner, repo string) map[string]string {
	out := map[string]string{}
	if c.rest == nil {
		return out
	}
	for page := 1; page <= 20; page++ { // hard cap 2000 tags
		var resp []struct {
			Name   string `json:"name"`
			Commit struct {
				Sha string `json:"sha"`
			} `json:"commit"`
		}
		path := fmt.Sprintf("repos/%s/%s/tags?per_page=100&page=%d", owner, repo, page)
		if err := c.rest.Get(path, &resp); err != nil || len(resp) == 0 {
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

func (c *GitHubMetadataClient) isRepoArchived(owner, repo string) bool {
	c.mu.Lock()
	cached, ok := c.repoCache[owner+"/"+repo]
	c.mu.Unlock()
	if ok && cached.fetched {
		return cached.archived
	}
	var resp struct {
		Archived bool `json:"archived"`
	}
	entry := repoCacheEntry{fetched: true}
	if err := c.rest.Get(fmt.Sprintf("repos/%s/%s", owner, repo), &resp); err != nil {
		entry.err = err
	} else {
		entry.archived = resp.Archived
	}
	c.mu.Lock()
	c.repoCache[owner+"/"+repo] = entry
	c.mu.Unlock()
	return entry.archived
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

func (c *GitHubMetadataClient) branchExists(owner, repo, ref string) bool {
	var resp json.RawMessage
	err := c.rest.Get(fmt.Sprintf("repos/%s/%s/branches/%s", owner, repo, ref), &resp)
	return err == nil
}

func (c *GitHubMetadataClient) commitExists(owner, repo, ref string) bool {
	// GitHub's commits endpoint accepts short SHAs too, but for
	// impostor-commit we specifically want to know if a full 40-
	// char SHA resolves. Narrower form than resolveTag — we only
	// need success vs failure.
	var resp json.RawMessage
	err := c.rest.Get(fmt.Sprintf("repos/%s/%s/commits/%s", owner, repo, ref), &resp)
	return err == nil
}

// isZeroMetadata reports whether meta has no content. GitHubMetadata
// now carries a slice field, which Go refuses to compare with `==`,
// so we spell the zero-check out field by field.
func isZeroMetadata(meta GitHubMetadata) bool {
	if meta.RepoArchived || meta.RefExists || meta.RefIsAmbiguous {
		return false
	}
	if meta.RefKind != "" || meta.TagSha != "" || meta.LatestTag != "" || meta.LatestReleaseSha != "" {
		return false
	}
	if len(meta.Advisories) > 0 {
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
