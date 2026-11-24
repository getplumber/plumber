package github

// The metadata loader (plumber#637): every GitHub read the action
// enrichment needs, sent as aliased GraphQL queries, one batch of
// repositories per query. The lookups in github_metadata.go read the
// caches these queries fill and never send a request of their own, so the
// cost of a run grows per batch of repositories, not per action reference.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/sirupsen/logrus"

	"github.com/getplumber/plumber/internal/httpcount"
)

// recordGraphQLCost keeps a query's cost for the --debug report.
func recordGraphQLCost(gc graphQLCost) {
	httpcount.Default.RecordGraphQL(gc.Label, gc.Cost, gc.Remaining)
}

// metadataChunkSize is how many repositories one metadata query asks: each
// brings up to 100 releases and 100 advisories, far below GitHub's node
// limit.
const metadataChunkSize = 10

// tagsChunkSize is how many repositories one tag-listing query asks, 100
// tags each.
const tagsChunkSize = 10

// maxTagPages caps a repository's tag listing at 2000 tags, as the REST
// walk did.
const maxTagPages = 20

// errNoGraphQL is the answer of a client that has no GraphQL client: a
// disabled one, which no lookup should reach.
var errNoGraphQL = errors.New("no GitHub GraphQL client")

// metadataQueryTimeout bounds one batched query: it carries the work of
// many REST calls.
var metadataQueryTimeout = 60 * time.Second

// repoKey names one repository.
type repoKey struct{ owner, repo string }

// repoRequest is what one repository's part of a query asks: its own
// fields and releases (info), its advisories, and the facts of each ref.
type repoRequest struct {
	owner, repo      string
	info, advisories bool
	refs             []string
}

// gitObject is a git object as GraphQL answers it: a Tag carries the
// object it points at in Target, peeled as deep as the query asked.
type gitObject struct {
	Typename string     `json:"__typename"`
	Oid      string     `json:"oid"`
	Target   *gitObject `json:"target"`
}

// releaseFact is one release of the listing, newest first.
type releaseFact struct {
	tag               string
	draft, prerelease bool
}

// refFacts is what GitHub said about one ref of one repository.
//
//   - tag: the object refs/tags/<ref> points at, nil when there is no such tag.
//   - branch: refs/heads/<ref> exists, by that exact name.
//   - object: the object the ref names (a SHA by oid, a plain name by
//     expression), nil when there is none; only meaningful when
//     objectChecked, which is false when no lookup could be sent.
//   - release: the immutable flag of the release for that tag, nil when the
//     tag has no release.
//   - failed: the query did not answer for this repository, so nothing
//     above is known; err says why.
type refFacts struct {
	tag           *gitObject
	branch        bool
	objectChecked bool
	object        *gitObject
	release       *bool
	failed        bool
	err           error
}

// graphQLCost is the rateLimit cost GitHub reported for one query.
type graphQLCost struct {
	Label     string
	Cost      int
	Remaining int
}

// peelFields reads an object and, for an annotated tag, what it points at,
// four tags deep (maxTagObjectDepth).
const peelFields = "__typename oid ... on Tag { target { __typename oid ... on Tag { target { __typename oid ... on Tag { target { __typename oid ... on Tag { target { __typename oid } } } } } } } }"

// releasesFields leaves out Release.tagCommit: resolving it for each
// release made a query several times slower, and only the latest
// release's commit is read, from its tag (Prefetch).
const releasesFields = "nodes { tagName isDraft isPrerelease } pageInfo { hasNextPage endCursor }"

const releasesOrder = "orderBy: {field: CREATED_AT, direction: DESC}"

// queryRepos loads reqs, one query per chunk of repositories, then the
// second page of releases where there is one.
func (c *GitHubMetadataClient) queryRepos(reqs []repoRequest) {
	var more []releasesPage
	for start := 0; start < len(reqs); start += metadataChunkSize {
		more = append(more, c.queryReposChunk(reqs[start:min(start+metadataChunkSize, len(reqs))])...)
	}
	for start := 0; start < len(more); start += metadataChunkSize {
		c.queryReleasesPage(more[start:min(start+metadataChunkSize, len(more))])
	}
}

// releasesPage is a repository whose release listing goes on after cursor.
type releasesPage struct {
	key    repoKey
	cursor string
}

func (c *GitHubMetadataClient) queryReposChunk(reqs []repoRequest) []releasesPage {
	var q strings.Builder
	var params []string
	vars := map[string]any{}
	q.WriteString("{ rateLimit { cost remaining }")
	for i, r := range reqs {
		ri := strconv.Itoa(i)
		if r.info || len(r.refs) > 0 {
			vars["o"+ri], vars["n"+ri] = r.owner, r.repo
			params = append(params, "$o"+ri+": String!", "$n"+ri+": String!")
			q.WriteString(" r" + ri + ": repository(owner: $o" + ri + ", name: $n" + ri + ") {")
			if r.info {
				q.WriteString(" nameWithOwner isArchived stargazerCount releases(first: 100, " + releasesOrder + ") { " + releasesFields + " }")
			}
			for j, ref := range r.refs {
				rj := strconv.Itoa(j)
				v := ri + "_" + rj
				vars["t"+v], vars["h"+v] = "refs/tags/"+ref, "refs/heads/"+ref
				params = append(params, "$t"+v+": String!", "$h"+v+": String!")
				q.WriteString(" t" + rj + ": ref(qualifiedName: $t" + v + ") { target { " + peelFields + " } }")
				q.WriteString(" h" + rj + ": ref(qualifiedName: $h" + v + ") { name }")
				switch {
				case _isCommitSha(ref):
					vars["x"+v] = strings.ToLower(ref)
					params = append(params, "$x"+v+": GitObjectID!")
					q.WriteString(" x" + rj + ": object(oid: $x" + v + ") { " + peelFields + " }")
				case prefetchRefGrammar.MatchString(ref):
					vars["x"+v] = ref
					params = append(params, "$x"+v+": String!")
					q.WriteString(" x" + rj + ": object(expression: $x" + v + ") { " + peelFields + " }")
				}
				if c.dotcom {
					vars["g"+v] = ref
					params = append(params, "$g"+v+": String!")
					q.WriteString(" l" + rj + ": release(tagName: $g" + v + ") { immutable }")
				}
			}
			q.WriteString(" }")
		}
		if r.advisories && c.dotcom {
			vars["p"+ri] = r.owner + "/" + r.repo
			params = append(params, "$p"+ri+": String!")
			q.WriteString(" a" + ri + ": securityVulnerabilities(ecosystem: ACTIONS, package: $p" + ri + ", first: 100) { nodes { advisory { ghsaId severity } package { name } vulnerableVersionRange firstPatchedVersion { identifier } } }")
		}
	}
	q.WriteString(" }")

	data, failed, err := c.graphQL(fmt.Sprintf("action metadata: %d repositories", len(reqs)), params, q.String(), vars)
	if data == nil && len(reqs) > 1 && unfinished(err) {
		h := len(reqs) / 2
		return append(c.queryReposChunk(reqs[:h]), c.queryReposChunk(reqs[h:])...)
	}
	var more []releasesPage
	for i, r := range reqs {
		ri := strconv.Itoa(i)
		key := r.owner + "/" + r.repo
		if r.info || len(r.refs) > 0 {
			repoErr := aliasError("r"+ri, data, failed, err)
			var fields map[string]json.RawMessage
			if repoErr == nil {
				repoErr = json.Unmarshal(data["r"+ri], &fields)
			}
			if r.info {
				if page := c.storeRepo(key, fields, repoErr); page != "" {
					more = append(more, releasesPage{repoKey{r.owner, r.repo}, page})
				}
			}
			for j, ref := range r.refs {
				c.storeRef(key+"@"+ref, ref, fields, strconv.Itoa(j), repoErr)
			}
		}
		if r.advisories && c.dotcom {
			c.storeAdvisories(r.owner, r.repo, data["a"+ri], aliasError("a"+ri, data, failed, err))
		}
	}
	return more
}

// unfinished reports whether err is GitHub giving up on a query rather than
// refusing it: a 5xx (a query past GitHub's time limit answers 502) or our
// own timeout. A smaller query may then succeed; an auth or rate-limit
// error would fail the same way.
func unfinished(err error) bool {
	var httpErr *api.HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode >= 500
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// aliasError is why alias has no usable answer, nil when it has one. A
// null answer with no error of its own is GitHub's "no such repository".
func aliasError(alias string, data map[string]json.RawMessage, failed map[string]error, err error) error {
	if data == nil {
		if err == nil {
			err = errors.New("no answer")
		}
		return err
	}
	if e := failed[alias]; e != nil {
		return e
	}
	if raw, ok := data[alias]; !ok || string(raw) == "null" {
		return fmt.Errorf("GitHub returned no %s", alias)
	}
	return nil
}

// storeRepo records a repository's fields and first page of releases, and
// returns the cursor of the next page when there is one.
func (c *GitHubMetadataClient) storeRepo(key string, fields map[string]json.RawMessage, repoErr error) string {
	entry := repoCacheEntry{fetched: true, err: repoErr}
	var releases []releaseFact
	next := ""
	if repoErr == nil {
		_ = json.Unmarshal(fields["nameWithOwner"], &entry.fullName)
		_ = json.Unmarshal(fields["isArchived"], &entry.archived)
		_ = json.Unmarshal(fields["stargazerCount"], &entry.stars)
		releases, next = decodeReleases(fields["releases"])
	}
	c.mu.Lock()
	c.repoCache[key] = entry
	c.releases[key] = releases
	c.mu.Unlock()
	return next
}

// decodeReleases reads a releases connection, and the cursor of its next
// page when there is one.
func decodeReleases(raw json.RawMessage) ([]releaseFact, string) {
	var conn struct {
		Nodes []struct {
			TagName      string `json:"tagName"`
			IsDraft      bool   `json:"isDraft"`
			IsPrerelease bool   `json:"isPrerelease"`
		} `json:"nodes"`
		PageInfo struct {
			HasNextPage bool   `json:"hasNextPage"`
			EndCursor   string `json:"endCursor"`
		} `json:"pageInfo"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &conn) != nil {
		return nil, ""
	}
	out := make([]releaseFact, 0, len(conn.Nodes))
	for _, n := range conn.Nodes {
		out = append(out, releaseFact{tag: n.TagName, draft: n.IsDraft, prerelease: n.IsPrerelease})
	}
	if !conn.PageInfo.HasNextPage {
		return out, ""
	}
	return out, conn.PageInfo.EndCursor
}

// storeRef records the facts of one ref from its repository's answer.
func (c *GitHubMetadataClient) storeRef(key, ref string, fields map[string]json.RawMessage, j string, repoErr error) {
	f := &refFacts{}
	if repoErr != nil {
		f.failed, f.err = true, repoErr
	} else {
		var tagRef struct {
			Target *gitObject `json:"target"`
		}
		if raw := fields["t"+j]; len(raw) > 0 && json.Unmarshal(raw, &tagRef) == nil {
			f.tag = tagRef.Target
		}
		if raw := fields["h"+j]; len(raw) > 0 && string(raw) != "null" {
			f.branch = true
		}
		if _isCommitSha(ref) || prefetchRefGrammar.MatchString(ref) {
			f.objectChecked = true
			_ = json.Unmarshal(fields["x"+j], &f.object)
		}
		var release *struct {
			Immutable bool `json:"immutable"`
		}
		if json.Unmarshal(fields["l"+j], &release) == nil && release != nil {
			f.release = &release.Immutable
		}
	}
	c.mu.Lock()
	c.refFacts[key] = f
	c.mu.Unlock()
}

// storeAdvisories records the advisories GitHub lists for owner/repo. A
// failed lookup is cached empty, as the REST one was, and recorded as a
// degraded check so it never reads as "no advisories".
func (c *GitHubMetadataClient) storeAdvisories(owner, repo string, raw json.RawMessage, lookupErr error) {
	key := owner + "/" + repo
	out := []advisoryInfo{}
	var conn struct {
		Nodes []struct {
			Advisory struct {
				GhsaID   string `json:"ghsaId"`
				Severity string `json:"severity"`
			} `json:"advisory"`
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			VulnerableVersionRange string `json:"vulnerableVersionRange"`
			FirstPatchedVersion    *struct {
				Identifier string `json:"identifier"`
			} `json:"firstPatchedVersion"`
		} `json:"nodes"`
	}
	if lookupErr == nil {
		lookupErr = json.Unmarshal(raw, &conn)
	}
	if lookupErr != nil {
		c.recordDegradedMessage("advisories:"+key, fmt.Sprintf(
			"%s: the GitHub Advisory Database could not be queried (%v), so the known-CVE check was skipped for this action",
			key, lookupErr,
		))
	} else {
		for _, n := range conn.Nodes {
			if !strings.EqualFold(n.Package.Name, key) {
				continue
			}
			a := advisoryInfo{
				GhsaID:          n.Advisory.GhsaID,
				VulnerableRange: n.VulnerableVersionRange,
				Severity:        advisorySeverity(n.Advisory.Severity),
			}
			if n.FirstPatchedVersion != nil {
				a.PatchedVersions = n.FirstPatchedVersion.Identifier
			}
			out = append(out, a)
		}
	}
	c.mu.Lock()
	c.advisoryCache[key] = out
	c.mu.Unlock()
}

// advisorySeverity maps GraphQL's severity to the REST word the policies
// read: GraphQL says MODERATE where REST says medium.
func advisorySeverity(s string) string {
	if strings.EqualFold(s, "MODERATE") {
		return "medium"
	}
	return strings.ToLower(s)
}

// queryReleasesPage reads the second page of releases, 50 more, so a
// repository's newest 150 are read as the REST walk did. A failure keeps
// the first page.
func (c *GitHubMetadataClient) queryReleasesPage(pages []releasesPage) {
	var q strings.Builder
	var params []string
	vars := map[string]any{}
	q.WriteString("{ rateLimit { cost remaining }")
	for i, p := range pages {
		ri := strconv.Itoa(i)
		vars["o"+ri], vars["n"+ri], vars["c"+ri] = p.key.owner, p.key.repo, p.cursor
		params = append(params, "$o"+ri+": String!", "$n"+ri+": String!", "$c"+ri+": String!")
		q.WriteString(" r" + ri + ": repository(owner: $o" + ri + ", name: $n" + ri + ") { releases(first: 50, after: $c" + ri + ", " + releasesOrder + ") { " + releasesFields + " } }")
	}
	q.WriteString(" }")
	data, failed, err := c.graphQL(fmt.Sprintf("releases, second page: %d repositories", len(pages)), params, q.String(), vars)
	for i, p := range pages {
		alias := "r" + strconv.Itoa(i)
		if aliasError(alias, data, failed, err) != nil {
			continue
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(data[alias], &fields) != nil {
			continue
		}
		more, _ := decodeReleases(fields["releases"])
		key := p.key.owner + "/" + p.key.repo
		c.mu.Lock()
		c.releases[key] = append(c.releases[key], more...)
		c.mu.Unlock()
	}
}

// queryTags lists the tags of repos and records, for each, the most
// specific tag of every commit a tag points at. A repository whose
// listing fails keeps the tags already read, and the failure is logged:
// the advisory filter then abstains on its SHA pins (ISSUE-228).
func (c *GitHubMetadataClient) queryTags(repos []repoKey) {
	type listing struct {
		key    repoKey
		cursor any // nil before the first page
		pages  int
		tags   map[string]string
	}
	all := make([]*listing, len(repos))
	for i, r := range repos {
		all[i] = &listing{key: r, tags: map[string]string{}}
	}
	pending := all
	for len(pending) > 0 {
		var next []*listing
		for start := 0; start < len(pending); start += tagsChunkSize {
			chunk := pending[start:min(start+tagsChunkSize, len(pending))]
			var q strings.Builder
			var params []string
			vars := map[string]any{}
			q.WriteString("{ rateLimit { cost remaining }")
			for i, l := range chunk {
				ri := strconv.Itoa(i)
				vars["o"+ri], vars["n"+ri], vars["c"+ri] = l.key.owner, l.key.repo, l.cursor
				params = append(params, "$o"+ri+": String!", "$n"+ri+": String!", "$c"+ri+": String")
				q.WriteString(" r" + ri + ": repository(owner: $o" + ri + ", name: $n" + ri + ") { refs(refPrefix: \"refs/tags/\", first: 100, after: $c" + ri + ") { nodes { name target { " + peelFields + " } } pageInfo { hasNextPage endCursor } } }")
			}
			q.WriteString(" }")
			data, failed, err := c.graphQL(fmt.Sprintf("tag listing: %d repositories", len(chunk)), params, q.String(), vars)
			for i, l := range chunk {
				alias := "r" + strconv.Itoa(i)
				l.pages++
				var answer struct {
					Refs struct {
						Nodes []struct {
							Name   string     `json:"name"`
							Target *gitObject `json:"target"`
						} `json:"nodes"`
						PageInfo struct {
							HasNextPage bool   `json:"hasNextPage"`
							EndCursor   string `json:"endCursor"`
						} `json:"pageInfo"`
					} `json:"refs"`
				}
				readErr := aliasError(alias, data, failed, err)
				if readErr == nil {
					readErr = json.Unmarshal(data[alias], &answer)
				}
				if readErr != nil {
					logrus.WithField("context", "collector").
						Warnf("could not fetch tags for %s/%s on page %d; advisory version checks for SHA-pinned refs will be skipped: %v", l.key.owner, l.key.repo, l.pages, readErr)
					continue
				}
				for _, n := range answer.Refs.Nodes {
					sha := peeledCommit(n.Target)
					if n.Name == "" || sha == "" {
						continue
					}
					if prev, ok := l.tags[sha]; ok {
						l.tags[sha] = _moreSpecificTag(prev, n.Name)
						continue
					}
					l.tags[sha] = n.Name
				}
				if answer.Refs.PageInfo.HasNextPage && l.pages < maxTagPages {
					l.cursor = answer.Refs.PageInfo.EndCursor
					next = append(next, l)
				}
			}
		}
		pending = next
	}
	c.mu.Lock()
	for _, l := range all {
		c.sha2tagCache[l.key.owner+"/"+l.key.repo] = l.tags
	}
	c.mu.Unlock()
}

// peeledCommit is the commit an object ends at once its tags are peeled,
// "" when it ends elsewhere (a tree, a blob) or deeper than was read.
func peeledCommit(o *gitObject) string {
	for range maxTagObjectDepth + 1 {
		switch {
		case o == nil:
			return ""
		case o.Typename == "Commit":
			return o.Oid
		case o.Typename != "Tag":
			return ""
		}
		o = o.Target
	}
	return ""
}

// graphQL sends one query and returns its top-level answers, the aliases
// GitHub tied an error to, and the error when the answer cannot be used
// at all (data is then nil). The query's cost goes to recordCost.
func (c *GitHubMetadataClient) graphQL(label string, params []string, body string, vars map[string]any) (map[string]json.RawMessage, map[string]error, error) {
	query := body
	if len(params) > 0 {
		query = "query(" + strings.Join(params, ", ") + ") " + body
	}
	if c.gql == nil {
		return nil, nil, errNoGraphQL
	}
	var data map[string]json.RawMessage
	ctx, cancel := context.WithTimeout(context.Background(), metadataQueryTimeout)
	defer cancel()
	err := c.gql.DoWithContext(ctx, query, vars, &data)
	var cost *struct {
		Cost      int `json:"cost"`
		Remaining int `json:"remaining"`
	}
	if json.Unmarshal(data["rateLimit"], &cost) == nil && cost != nil && c.recordCost != nil {
		c.recordCost(graphQLCost{Label: label, Cost: cost.Cost, Remaining: cost.Remaining})
	}
	failed, ok := aliasErrors(err)
	if !ok {
		return nil, nil, err
	}
	return data, failed, nil
}

// aliasErrors reads a query's error: the error of each top-level alias
// GitHub tied one to, and whether the rest of the answer can be used. A
// nil error leaves every alias usable. A GraphQL error whose every item
// names an alias spoils those aliases only; one without a path (rate
// limit, query error), or any other error, spoils the whole answer.
func aliasErrors(err error) (map[string]error, bool) {
	if err == nil {
		return nil, true
	}
	var gqlErr *api.GraphQLError
	if !errors.As(err, &gqlErr) {
		return nil, false
	}
	failed := map[string]error{}
	for _, item := range gqlErr.Errors {
		if len(item.Path) == 0 {
			return nil, false
		}
		alias, isString := item.Path[0].(string)
		if !isString {
			return nil, false
		}
		if failed[alias] == nil {
			failed[alias] = errors.New(item.Message)
		}
	}
	return failed, true
}
