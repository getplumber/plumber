package github

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	version "github.com/hashicorp/go-version"
)

// errNotLoaded stands for an answer the loader did not give.
var errNotLoaded = errors.New("GitHub gave no answer for it")

// Prefetch loads, in as few queries as it can, what Resolve and
// ResolveTagSha will read for refs ("owner/repo[/path]@ref"): each
// repository's fields, releases and advisories, and the facts of each ref.
// The tag listing is loaded after, only for the repositories where a SHA
// pin meets advisories, the one place the advisory filter reads it. A
// reference outside GitHub's grammar is skipped, as Resolve skips it.
func (c *GitHubMetadataClient) Prefetch(refs []string) {
	if c.disabled {
		return
	}
	var reqs []repoRequest
	index := map[string]int{}
	var shaPins []repoKey
	for _, uses := range refs {
		owner, repo, ref, ok := splitActionRef(uses)
		if !ok || !safeActionAPIRef(owner, repo, ref) {
			continue
		}
		key := owner + "/" + repo
		i, seen := index[key]
		if !seen {
			c.mu.Lock()
			info := c.repoCache[key]
			_, advisories := c.advisoryCache[key]
			c.mu.Unlock()
			reqs = append(reqs, repoRequest{owner: owner, repo: repo, info: !info.fetched, advisories: c.dotcom && !advisories})
			i = len(reqs) - 1
			index[key] = i
		}
		if _isCommitSha(ref) && !slices.Contains(shaPins, repoKey{owner, repo}) {
			shaPins = append(shaPins, repoKey{owner, repo})
		}
		if c.cachedRef(key+"@"+ref) == nil && !slices.Contains(reqs[i].refs, ref) {
			reqs[i].refs = append(reqs[i].refs, ref)
		}
	}
	reqs = slices.DeleteFunc(reqs, func(r repoRequest) bool { return !r.info && !r.advisories && len(r.refs) == 0 })
	if len(reqs) > 0 {
		c.load(reqs)
	}

	// The latest release is known once the releases are read; its commit
	// is read off its tag, every repository's in one more load.
	var latest []repoRequest
	for _, r := range reqs {
		if !r.info {
			continue
		}
		if tag := c.latestReleaseTag(r.owner, r.repo); tag != "" && c.cachedRef(r.owner+"/"+r.repo+"@"+tag) == nil {
			latest = append(latest, repoRequest{owner: r.owner, repo: r.repo, refs: []string{tag}})
		}
	}
	if len(latest) > 0 {
		c.load(latest)
	}

	var tags []repoKey
	c.mu.Lock()
	for _, r := range shaPins {
		key := r.owner + "/" + r.repo
		if _, listed := c.sha2tagCache[key]; !listed && len(c.advisoryCache[key]) > 0 {
			tags = append(tags, r)
		}
	}
	c.mu.Unlock()
	if len(tags) > 0 {
		c.loadTags(tags)
	}
}

func (c *GitHubMetadataClient) cachedRef(key string) *refFacts {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refFacts[key]
}

// ensureRepo returns the repository's fields, loading them (with its
// releases and advisories) when no prefetch did.
func (c *GitHubMetadataClient) ensureRepo(owner, repo string) repoCacheEntry {
	key := owner + "/" + repo
	c.mu.Lock()
	entry := c.repoCache[key]
	_, advisories := c.advisoryCache[key]
	c.mu.Unlock()
	if entry.fetched {
		return entry
	}
	c.load([]repoRequest{{owner: owner, repo: repo, info: true, advisories: c.dotcom && !advisories}})
	c.mu.Lock()
	defer c.mu.Unlock()
	entry = c.repoCache[key]
	if !entry.fetched {
		entry = repoCacheEntry{fetched: true, err: errNotLoaded}
		c.repoCache[key] = entry
	}
	return entry
}

// ensureRef returns the facts of owner/repo@ref, loading them when no
// prefetch did.
func (c *GitHubMetadataClient) ensureRef(owner, repo, ref string) *refFacts {
	key := owner + "/" + repo + "@" + ref
	if f := c.cachedRef(key); f != nil {
		return f
	}
	c.load([]repoRequest{{owner: owner, repo: repo, refs: []string{ref}}})
	c.mu.Lock()
	defer c.mu.Unlock()
	f := c.refFacts[key]
	if f == nil {
		f = &refFacts{failed: true, err: errNotLoaded}
		c.refFacts[key] = f
	}
	return f
}

// repoInfo is the repository's archived flag, star count and current
// name, read once per owner/repo.
func (c *GitHubMetadataClient) repoInfo(owner, repo string) repoCacheEntry {
	return c.ensureRepo(owner, repo)
}

// latestReleaseTag returns the highest semver tag across a repo's newest
// 150 releases. `/releases/latest` alone is not reliable: many action
// repos (github/codeql-action, actions/download-artifact) publish
// out-of-band tags — internal bundle snapshots like
// `codeql-bundle-v2.25.2` or compatibility bridges like
// `v3.1.0-node20` — that rank as "latest" by date even though they
// are not the user-facing release. The date-sorted order is also
// misleading when maintainers backport a fix to an older line and
// republish it *after* a newer major (e.g. v3.1.0 republished after
// v8.0.1). ISSUE-709 is a semver-drift signal, so Plumber picks the
// highest semver among non-draft, non-prerelease tags whose semver
// itself has no prerelease segment.
func (c *GitHubMetadataClient) latestReleaseTag(owner, repo string) string {
	key := owner + "/" + repo
	c.mu.Lock()
	if v, ok := c.latestCache[key]; ok {
		c.mu.Unlock()
		return v
	}
	c.mu.Unlock()
	c.ensureRepo(owner, repo)
	c.mu.Lock()
	defer c.mu.Unlock()
	best := latestSemverRelease(c.releases[key])
	c.latestCache[key] = best
	return best
}

// latestSemverRelease is the highest semver tag of releases (see
// latestReleaseTag), "" when none qualifies.
func latestSemverRelease(releases []releaseFact) string {
	var best *version.Version
	bestTag := ""
	for _, r := range releases {
		if r.draft || r.prerelease {
			continue
		}
		parsed, err := version.NewVersion(strings.TrimPrefix(r.tag, "v"))
		if err != nil {
			continue
		}
		// Reject compatibility bridges / betas whose semver carries a
		// prerelease segment (e.g. `v3.1.0-node20`, `v1.0.0-beta`).
		// GitHub sometimes publishes these with `prerelease: false`, so
		// the API flag alone is not sufficient.
		if parsed.Prerelease() != "" {
			continue
		}
		if best == nil || parsed.GreaterThan(best) {
			best = parsed
			bestTag = r.tag
		}
	}
	return bestTag
}

// resolveTag returns (sha, true) when ref is a tag on the repo, with the
// SHA it points at: the commit, or for an annotated tag the object the tag
// object points at.
func (c *GitHubMetadataClient) resolveTag(owner, repo, ref string) (string, bool) {
	f := c.ensureRef(owner, repo, ref)
	if f.tag == nil || f.tag.Oid == "" {
		return "", false
	}
	if f.tag.Typename == "Tag" && f.tag.Target != nil && f.tag.Target.Oid != "" {
		return f.tag.Target.Oid, true
	}
	return f.tag.Oid, true
}

// branchExists reports whether a branch named EXACTLY ref exists upstream.
//
// GitHub keeps a renamed branch's old name as a redirect, and the REST
// branches endpoint followed it: on github/codeql-action, GET /branches/v2
// answered with the RENAMED branch ("releases/v2"), which made ISSUE-402
// call `github/codeql-action/init@v2` an ambiguous tag-and-branch ref
// (#482). The GraphQL lookup asks for refs/heads/<ref> by its qualified
// name and follows no redirect.
func (c *GitHubMetadataClient) branchExists(owner, repo, ref string) bool {
	return c.ensureRef(owner, repo, ref).branch
}

// commitResolves reports whether ref resolves to a commit upstream.
// The second return value, checked, is true ONLY when GitHub gave a
// definitive answer: exists=true for a commit, exists=false when the ref
// names no object or one that is not a commit. When the lookup failed, or
// could not be sent, checked is false and the caller must not conclude
// the commit is absent — impostor-commit (ISSUE-707) fires only on a
// confirmed absence, never on a SHA it merely failed to reach.
func (c *GitHubMetadataClient) commitResolves(owner, repo, ref string) (exists, checked bool) {
	f := c.ensureRef(owner, repo, ref)
	if f.failed || !f.objectChecked {
		return false, false
	}
	return f.object != nil && f.object.Typename == "Commit", true
}

// releaseIsImmutable reports whether the GitHub release published for
// tag is immutable. It fails closed: no release for the tag (the normal
// answer for a floating major such as v4) is a definitive "no"; a lookup
// that failed is also "no", but is recorded as a degraded check so the
// run says why a possibly-immutable tag was still flagged. GitHub
// Enterprise Server may lack the GraphQL field, so it asks REST there.
func (c *GitHubMetadataClient) releaseIsImmutable(owner, repo, tag string) bool {
	if !c.dotcom {
		return c.releaseIsImmutableREST(owner, repo, tag)
	}
	f := c.ensureRef(owner, repo, tag)
	if f.failed {
		c.recordReleaseUnread(owner, repo, tag, f.err)
		return false
	}
	return f.release != nil && *f.release
}

func (c *GitHubMetadataClient) recordReleaseUnread(owner, repo, tag string, err error) {
	key := owner + "/" + repo + "@" + tag
	c.recordDegradedMessage("release:"+key, fmt.Sprintf(
		"%s: the release for this tag could not be read (%v), so the immutable-release exemption of ISSUE-701 was not applied",
		key, err,
	))
}

// resolveCommitToTag returns the release tag pointing at the given
// commit SHA, or "" when the SHA is not the head of any published
// tag. The repo's full tag list is read once and cached.
func (c *GitHubMetadataClient) resolveCommitToTag(owner, repo, sha string) string {
	key := owner + "/" + repo
	c.mu.Lock()
	_, cached := c.sha2tagCache[key]
	c.mu.Unlock()
	if !cached {
		c.loadTags([]repoKey{{owner, repo}})
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sha2tagCache[key][strings.ToLower(sha)]
}
