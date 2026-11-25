package github

// The scanned repository (plumber#637): on github.com, its full name,
// visibility, default branch, the branches the configuration names, with
// their protected flag, and the authors of its latest releases come from one
// GraphQL query, kept for the run. FetchGitHubDefaultBranch,
// FetchGitHubRepoIdentity, GitHubRepoVisible, FetchGitHubBranchProtection and
// the default token's effect route read that answer. The branch listing and
// each protected branch's protection details stay on REST. GitHub Enterprise
// Server keeps its REST requests: its schema may lack Ref.rules.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/cli/go-gh/v2/pkg/api"

	"github.com/getplumber/plumber/internal/httpcount"
	"github.com/getplumber/plumber/internal/ir"
)

// errRepoNotFound is a repository GitHub answers null for, as REST answers
// 404. isNotFound matches it.
var errRepoNotFound = errors.New("repository not found")

// errRepoForbidden is a repository GitHub refuses to show the token, as
// REST answers 403. isUnauthorized matches it.
var errRepoForbidden = errors.New("repository access forbidden")

// newScannedRepoGraphQL builds the GraphQL client of the scanned
// repository's reads: the same credentials as its REST client, the go-gh
// default chain, never PLUMBER_METADATA_TOKEN, and httpcount.DefaultTransport,
// which counts requests and never answers one from memory.
var newScannedRepoGraphQL = func(host string) (*api.GraphQLClient, error) {
	gql, err := api.NewGraphQLClient(api.ClientOptions{Host: host, Transport: httpcount.DefaultTransport})
	if err == nil {
		return gql, nil
	}
	if isAuthTokenMissing(err) {
		return nil, ErrAuthRequired
	}
	return nil, err
}

// protectionFields tell a protected branch: refUpdateRule is the classic
// rule a non-admin token can see, rules the rulesets that apply. REST's
// protected flag is true when either is there (checked on the 11 corpus
// repositories, 2026-11-25).
const protectionFields = "refUpdateRule { pattern } rules(first: 1) { totalCount }"

// branchFact is what the query answered for one branch.
type branchFact struct {
	exists, protected bool
	// err is set when GitHub could not answer for this branch.
	err error
}

// scannedRepo is the answer for one repository.
type scannedRepo struct {
	// err is set when the repository could not be read: errRepoNotFound,
	// errRepoForbidden, or the error of a query that failed as a whole.
	err                  error
	fullName, visibility string
	private              bool
	defaultBranch        string
	branches             map[string]branchFact
	botRelease           bool
}

// scannedRepos keeps each repository's answer for the run.
var scannedRepos = struct {
	sync.Mutex
	m map[string]*scannedRepo
}{m: map[string]*scannedRepo{}}

// resetScannedRepos forgets every answer.
func resetScannedRepos() {
	scannedRepos.Lock()
	defer scannedRepos.Unlock()
	scannedRepos.m = map[string]*scannedRepo{}
}

// PrefetchScannedRepo sends the scanned repository's query, with the
// branches the configuration names, before the reads that use it. It does
// nothing on GitHub Enterprise Server. A failure is kept for the reads,
// which report it under their own contract.
func PrefetchScannedRepo(host, owner, repo string, branches []string) {
	if !isDotcomHost(host) || owner == "" || repo == "" {
		return
	}
	_, _ = loadScannedRepo(host, owner, repo, branches)
}

// loadScannedRepo returns the repository's answer, sending the query on
// first use and one more for the branches it has not asked yet. The error
// is the GraphQL client's (ErrAuthRequired without a token); a failed query
// is kept in the answer's err instead.
func loadScannedRepo(host, owner, repo string, branches []string) (*scannedRepo, error) {
	scannedRepos.Lock()
	defer scannedRepos.Unlock()
	key := host + "|" + owner + "/" + repo
	r := scannedRepos.m[key]
	var missing []string
	seen := map[string]bool{}
	for _, b := range branches {
		if b == "" || seen[b] {
			continue
		}
		seen[b] = true
		if r != nil {
			if _, ok := r.branches[b]; ok {
				continue
			}
		}
		missing = append(missing, b)
	}
	if r != nil && (r.err != nil || len(missing) == 0) {
		return r, nil
	}
	gql, err := newScannedRepoGraphQL(host)
	if err != nil {
		return nil, err
	}
	if r == nil {
		r = queryScannedRepo(gql, owner, repo, missing, true)
		scannedRepos.m[key] = r
		return r, nil
	}
	more := queryScannedRepo(gql, owner, repo, missing, false)
	for _, b := range missing {
		if more.err != nil {
			r.branches[b] = branchFact{err: more.err}
			continue
		}
		r.branches[b] = more.branches[b]
	}
	return r, nil
}

// queryScannedRepo sends one query: the repository's own fields when full,
// and the facts of each branch. Every value travels as a variable.
func queryScannedRepo(gql *api.GraphQLClient, owner, repo string, branches []string, full bool) *scannedRepo {
	params := []string{"$owner: String!", "$name: String!"}
	vars := map[string]any{"owner": owner, "name": repo}
	var q strings.Builder
	q.WriteString("{ repository(owner: $owner, name: $name) {")
	if full {
		params = append(params, "$releases: Int!")
		vars["releases"] = defaultTokenRunsPerPage
		q.WriteString(" nameWithOwner visibility isPrivate defaultBranchRef { name " + protectionFields + " }")
		q.WriteString(" releases(first: $releases, orderBy: {field: CREATED_AT, direction: DESC}) { nodes { author { login } } }")
	}
	aliases := map[string]string{}
	for i, b := range branches {
		alias := "b" + strconv.Itoa(i)
		aliases[alias] = b
		params = append(params, "$"+alias+": String!")
		vars[alias] = "refs/heads/" + b
		fmt.Fprintf(&q, " %s: ref(qualifiedName: $%s) { name %s }", alias, alias, protectionFields)
	}
	q.WriteString(" } rateLimit { cost remaining } }")

	var data map[string]json.RawMessage
	ctx, cancel := context.WithTimeout(context.Background(), metadataQueryTimeout)
	defer cancel()
	err := gql.DoWithContext(ctx, "query("+strings.Join(params, ", ")+") "+q.String(), vars, &data)
	var cost *struct {
		Cost      int `json:"cost"`
		Remaining int `json:"remaining"`
	}
	if json.Unmarshal(data["rateLimit"], &cost) == nil && cost != nil {
		recordGraphQLCost(graphQLCost{Label: "scanned repository", Cost: cost.Cost, Remaining: cost.Remaining})
	}

	r := &scannedRepo{branches: map[string]branchFact{}}
	failed, repoErr := scannedRepoErrors(err)
	if repoErr != nil {
		r.err = repoErr
		return r
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data["repository"], &fields) != nil || fields == nil {
		r.err = errRepoNotFound
		return r
	}
	if full {
		decodeRepoFields(r, fields)
	}
	for alias, b := range aliases {
		if ferr := failed[alias]; ferr != nil {
			r.branches[b] = branchFact{err: ferr}
			continue
		}
		var ref *refAnswer
		if json.Unmarshal(fields[alias], &ref) != nil || ref == nil {
			r.branches[b] = branchFact{}
			continue
		}
		r.branches[b] = branchFact{exists: true, protected: ref.protected()}
	}
	return r
}

// refAnswer is one branch as the query answers it.
type refAnswer struct {
	Name          string `json:"name"`
	RefUpdateRule *struct {
		Pattern string `json:"pattern"`
	} `json:"refUpdateRule"`
	Rules *struct {
		TotalCount int `json:"totalCount"`
	} `json:"rules"`
}

// protected reports REST's protected flag: a classic rule or a ruleset.
func (a refAnswer) protected() bool {
	return a.RefUpdateRule != nil || (a.Rules != nil && a.Rules.TotalCount > 0)
}

// decodeRepoFields reads the repository's own fields into r. The default
// branch also counts as an asked branch.
func decodeRepoFields(r *scannedRepo, fields map[string]json.RawMessage) {
	_ = json.Unmarshal(fields["nameWithOwner"], &r.fullName)
	_ = json.Unmarshal(fields["visibility"], &r.visibility)
	_ = json.Unmarshal(fields["isPrivate"], &r.private)
	var def *refAnswer
	if json.Unmarshal(fields["defaultBranchRef"], &def) == nil && def != nil && def.Name != "" {
		r.defaultBranch = def.Name
		r.branches[def.Name] = branchFact{exists: true, protected: def.protected()}
	}
	var releases struct {
		Nodes []struct {
			Author *struct {
				Login string `json:"login"`
			} `json:"author"`
		} `json:"nodes"`
	}
	if json.Unmarshal(fields["releases"], &releases) == nil {
		for _, n := range releases.Nodes {
			if n.Author != nil && n.Author.Login == defaultTokenBotLogin {
				r.botRelease = true
			}
		}
	}
}

// scannedRepoErrors reads the query's error: the error of each branch alias
// GitHub tied one to, and the error that spoils the whole repository. An
// error on the repository itself maps to errRepoNotFound or
// errRepoForbidden by its type. One on another of its fields (releases)
// leaves that field empty. Any other error spoils the answer.
func scannedRepoErrors(err error) (map[string]error, error) {
	if err == nil {
		return nil, nil
	}
	var gqlErr *api.GraphQLError
	if !errors.As(err, &gqlErr) {
		return nil, err
	}
	failed := map[string]error{}
	for _, item := range gqlErr.Errors {
		if len(item.Path) == 0 || item.Path[0] != "repository" {
			return nil, err
		}
		if len(item.Path) == 1 {
			switch item.Type {
			case "NOT_FOUND":
				return nil, errRepoNotFound
			case "FORBIDDEN":
				return nil, errRepoForbidden
			}
			return nil, err
		}
		if alias, ok := item.Path[1].(string); ok && failed[alias] == nil {
			failed[alias] = errors.New(item.Message)
		}
	}
	return failed, nil
}

// branch reads one branch the way fetchBranchByName does over REST: nil
// when it does not exist, its protected flag otherwise, plus the protection
// details of a protected one, read over REST.
func (r *scannedRepo) branch(rest *api.RESTClient, owner, repo, name string) (*ir.Branch, error) {
	if r.err != nil {
		return nil, r.err
	}
	fact, ok := r.branches[name]
	switch {
	case !ok:
		return nil, fmt.Errorf("branch %q was not asked", name)
	case fact.err != nil:
		return nil, fact.err
	case !fact.exists:
		return nil, nil
	}
	out := &ir.Branch{Name: name, Protected: fact.protected}
	if !out.Protected {
		return out, nil
	}
	if err := addProtectionDetails(rest, owner, repo, out); err != nil {
		return nil, err
	}
	return out, nil
}
