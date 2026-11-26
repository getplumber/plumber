package github

// The entrypoint prefetch (plumber#618): the mutable-exec scan tries the
// usual entrypoint locations of every third-party action
// (entrypointCandidates), and most of them do not exist. One GraphQL
// query asks GitHub which do, for many actions at once, so a missing one
// costs no request. A null object there is GitHub's own answer for the
// token it accepted, with no CDN cache in between, so unlike a raw 404 it
// is final at any ref.

import (
	"context"
	"encoding/json"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/getplumber/plumber/internal/ir"
)

// prefetchChunkSize is how many references one query checks: with the
// four entrypoint candidates, 100 objects, far below GitHub's node limit.
const prefetchChunkSize = 25

// candidateRef is the files of one action at one ref a prefetch checks.
type candidateRef struct {
	owner, repo, ref string
	paths            []string
}

// candidateRefs lists, once per container, the entrypoint candidates the
// mutable-exec scan will try for the pipeline's third-party actions: the
// references resolveMutableExec scans, and that defs did not refuse.
func candidateRefs(pipeline *ir.NormalizedPipeline, defs *definitionFetcher) []candidateRef {
	var out []candidateRef
	seen := map[string]struct{}{}
	for i := range pipeline.Jobs {
		for _, action := range pipeline.Jobs[i].Uses {
			if action.Nested && defs.refuses(action.Uses) {
				continue
			}
			owner, repo, subpath, ref, ok := splitActionRefWithSubpath(action.Uses)
			if !ok || firstPartyOwners[strings.ToLower(owner)] {
				continue
			}
			key := containerKey(owner, repo, subpath, ref)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			c := candidateRef{owner: owner, repo: repo, ref: ref}
			for _, p := range entrypointCandidates {
				c.paths = append(c.paths, path.Join(subpath, p))
			}
			out = append(out, c)
		}
	}
	return out
}

// prefetchRefGrammar is the ref a prefetch puts in an object expression:
// a plain name. GraphQL evaluates the expression like `git rev-parse`, so
// a `:`, `^`, `~` or `{` would make it read another object than the raw
// host, which takes the ref literally.
var prefetchRefGrammar = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// prefetchAbsent asks GitHub which of refs' files exist and records the
// ones it says do not, which read then answers without a request. It
// needs the GraphQL client, which has a token (GraphQL has no anonymous
// access): with no token go-gh builds no client, so f.gql is nil and an
// anonymous run sends no query. A reference outside GitHub's grammar, a ref that is not a plain
// name (prefetchRefGrammar), or a path climbing out of the repository is
// left to the per-file reads.
//
// A name that is both a tag and a branch resolves to the tag here (rev-parse
// order), while the raw host may serve the branch: the two can disagree on
// which files exist. That ambiguity is ISSUE-402's finding, so it is
// accepted here rather than checked with another request.
func (f *definitionFetcher) prefetchAbsent(refs []candidateRef) {
	if f.gql == nil || APIDisabled() {
		return
	}
	var valid []candidateRef
	for _, r := range refs {
		if validActionReference(r.owner, r.repo, "", r.ref) && prefetchRefGrammar.MatchString(r.ref) && !slices.ContainsFunc(r.paths, escapesRoot) {
			valid = append(valid, r)
		}
	}
	for start := 0; start < len(valid); start += prefetchChunkSize {
		f.prefetchChunk(valid[start:min(start+prefetchChunkSize, len(valid))])
	}
}

// prefetchChunk sends one query for refs. Every value from the scanned
// workflows travels as a variable, never in the query text. An error tied
// to one repository (deleted, renamed, behind SAML SSO) drops that
// repository's answers only; any other error (a rate limit, a timeout, a
// 5xx) records nothing.
func (f *definitionFetcher) prefetchChunk(refs []candidateRef) {
	var q strings.Builder
	var params []string
	vars := map[string]any{}
	q.WriteString("{")
	for i, r := range refs {
		ri := strconv.Itoa(i)
		vars["o"+ri], vars["n"+ri] = r.owner, r.repo
		params = append(params, "$o"+ri+": String!", "$n"+ri+": String!")
		q.WriteString(" r" + ri + ": repository(owner: $o" + ri + ", name: $n" + ri + ") {")
		for j, p := range r.paths {
			e := "e" + ri + "_" + strconv.Itoa(j)
			vars[e] = r.ref + ":" + p
			params = append(params, "$"+e+": String!")
			q.WriteString(" p" + strconv.Itoa(j) + ": object(expression: $" + e + ") { __typename }")
		}
		q.WriteString(" }")
	}
	q.WriteString(" }")
	query := "query(" + strings.Join(params, ", ") + ") " + q.String()

	var data map[string]map[string]json.RawMessage
	ctx, cancel := context.WithTimeout(context.Background(), contentsFetchTimeout)
	defer cancel()
	failed, ok := failedAliases(f.gql.DoWithContext(ctx, query, vars, &data))
	if !ok {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.absent == nil {
		f.absent = map[string]struct{}{}
	}
	for i, r := range refs {
		alias := "r" + strconv.Itoa(i)
		objects := data[alias]
		if objects == nil || failed[alias] {
			continue // no such repository, or none the token can read
		}
		for j, p := range r.paths {
			if raw, ok := objects["p"+strconv.Itoa(j)]; ok && string(raw) == "null" {
				f.absent[containerKey(r.owner, r.repo, p, r.ref)] = struct{}{}
			}
		}
	}
}

// failedAliases reads a query's error: the top-level aliases GitHub tied
// an error to, and whether the rest of the answer can be used (see
// aliasErrors).
func failedAliases(err error) (map[string]bool, bool) {
	errs, ok := aliasErrors(err)
	if !ok || errs == nil {
		return nil, ok
	}
	failed := make(map[string]bool, len(errs))
	for alias := range errs {
		failed[alias] = true
	}
	return failed, true
}
