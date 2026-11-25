package github

// Remote mode through GraphQL (plumber#637): the workflow listing and every
// workflow file of the scanned repository come from one tree query, and the
// local composites its workflows call from one more. A file GitHub does not
// give in full (truncated, binary) and a composite only another composite
// calls are read over the contents API, as before.

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cli/go-gh/v2/pkg/api"
)

// treeFields read a directory: each entry's name, path and git mode, and
// the text of each file.
const treeFields = "... on Tree { entries { name path mode object { " + blobFields + " } } }"

// blobFields read a file's text, and its oid to check the text against.
const blobFields = "... on Blob { oid text isTruncated isBinary }"

// Git modes of a regular and an executable file: the entries the contents
// API lists as "file". A symlink (0o120000) is "symlink" there, a
// submodule "submodule", and neither is a workflow.
const (
	modeFile       = 0o100644
	modeExecutable = 0o100755
)

// hexRef is a ref shaped like a commit SHA, which the tree query reads as
// written.
var hexRef = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)

// blobAnswer is a file as the query answers it.
type blobAnswer struct {
	Oid         string  `json:"oid"`
	Text        *string `json:"text"`
	IsTruncated bool    `json:"isTruncated"`
	IsBinary    bool    `json:"isBinary"`
}

// usable returns the file's text when GitHub gave it exactly: whole, and
// hashing to the blob's oid. Blob.text is not byte-faithful: on
// home-assistant/core 2026.11.2, detect-duplicate-issues.yml holds the
// literal text `\u0000-\u001F` and the answer carried `\^@-\^_`
// (checked 2026-11-25). A file that fails the check reads over REST.
func (b *blobAnswer) usable() (string, bool) {
	if b == nil || b.Text == nil || b.IsTruncated || b.IsBinary || gitBlobOID(*b.Text) != b.Oid {
		return "", false
	}
	return *b.Text, true
}

// gitBlobOID is git's object id of a file holding text: the SHA-1 of
// "blob <size>\x00" followed by the content.
func gitBlobOID(text string) string {
	h := sha1.New() //nolint:gosec // git's object id, not a security hash
	fmt.Fprintf(h, "blob %d\x00", len(text))
	h.Write([]byte(text))
	return hex.EncodeToString(h.Sum(nil))
}

// treeEntry is one entry of a directory.
type treeEntry struct {
	Name   string      `json:"name"`
	Path   string      `json:"path"`
	Mode   int         `json:"mode"`
	Object *blobAnswer `json:"object"`
}

// workflowTree is the scanned repository's .github/workflows at a ref.
type workflowTree struct {
	// rev is the expression of the ref the tree was read at
	// (refs/heads/x, refs/tags/x, the ref as written, or HEAD); the
	// composite query reads at the same one.
	rev string
	// files are the .yml/.yaml regular files, sorted by name.
	files       []treeEntry
	hasLockfile bool
}

// refCandidates are the expressions the contents API's ?ref= would read,
// in its order. A branch comes before a tag of the same name: on
// getplumber-examples/cli-working-lab (branch and tag
// test/2026-11-25-ref-precedence), the contents API and the raw host read
// the branch, while GraphQL's bare "name:path" read the tag. The ref as
// written comes last (a SHA, another ref). No ref is the default branch.
func refCandidates(ref string) []string {
	switch {
	case ref == "":
		return []string{"HEAD"}
	case strings.HasPrefix(ref, "refs/"):
		return []string{ref}
	}
	return []string{"refs/heads/" + ref, "refs/tags/" + ref, ref}
}

// treeQueryItem is one alias of a tree or composite query: the alias, the
// expression it reads, and the fields it asks.
type treeQueryItem struct{ alias, expr, fields string }

// queryObjects sends one query reading each item's object, with every
// expression as a variable, and returns the repository's fields and the
// aliases GitHub could not answer. A repository GitHub answers null for is
// errRepoNotFound.
func queryObjects(gql *api.GraphQLClient, label, owner, repo string, items []treeQueryItem) (map[string]json.RawMessage, map[string]error, error) {
	params := []string{"$owner: String!", "$name: String!"}
	vars := map[string]any{"owner": owner, "name": repo}
	var q strings.Builder
	q.WriteString("{ repository(owner: $owner, name: $name) {")
	for _, it := range items {
		params = append(params, "$"+it.alias+": String!")
		vars[it.alias] = it.expr
		fmt.Fprintf(&q, " %s: object(expression: $%s) { %s }", it.alias, it.alias, it.fields)
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
		recordGraphQLCost(graphQLCost{Label: label, Cost: cost.Cost, Remaining: cost.Remaining})
	}
	failed, repoErr := scannedRepoErrors(err)
	if repoErr != nil {
		return nil, nil, repoErr
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data["repository"], &fields) != nil || fields == nil {
		return nil, nil, errRepoNotFound
	}
	return fields, failed, nil
}

// isNull reports whether an alias answered null (or nothing).
func isNull(raw json.RawMessage) bool {
	return len(raw) == 0 || string(raw) == "null"
}

// loadWorkflowTree reads the scanned repository's workflows at ref. The
// first query asks each candidate's commit and the workflows tree of the
// branch and the tag (and of a SHA-shaped ref); a ref of another kind
// costs a second query for its tree. A missing repository or ref is the
// error the listing gave before (ISSUE #222); a missing directory is no
// workflows.
func loadWorkflowTree(gql *api.GraphQLClient, owner, repo, ref string) (workflowTree, error) {
	cands := refCandidates(ref)
	var items []treeQueryItem
	asked := map[int]bool{}
	for i, c := range cands {
		n := strconv.Itoa(i)
		items = append(items, treeQueryItem{"c" + n, c, "__typename"})
		if len(cands) == 1 || i < 2 || hexRef.MatchString(ref) {
			items = append(items, treeQueryItem{"t" + n, c + ":" + githubWorkflowsSubdir, treeFields})
			asked[i] = true
		}
	}
	fields, failed, err := queryObjects(gql, "remote workflows", owner, repo, items)
	switch {
	case errors.Is(err, errRepoNotFound):
		return workflowTree{}, fmt.Errorf("repository %s/%s not found", owner, repo)
	case err != nil:
		return workflowTree{}, err
	}
	for i, c := range cands {
		n := strconv.Itoa(i)
		if ferr := failed["c"+n]; ferr != nil {
			return workflowTree{}, ferr
		}
		if isNull(fields["c"+n]) {
			continue
		}
		raw := fields["t"+n]
		if !asked[i] {
			more, mfailed, merr := queryObjects(gql, "remote workflows", owner, repo,
				[]treeQueryItem{{"t0", c + ":" + githubWorkflowsSubdir, treeFields}})
			if merr != nil {
				return workflowTree{}, merr
			}
			raw, failed = more["t0"], map[string]error{"t" + n: mfailed["t0"]}
		}
		if ferr := failed["t"+n]; ferr != nil {
			return workflowTree{}, ferr
		}
		return workflowFiles(c, raw), nil
	}
	if ref == "" {
		// An empty repository has no default branch commit: no workflows.
		return workflowTree{rev: "HEAD"}, nil
	}
	return workflowTree{}, fmt.Errorf("branch or ref %q not found in %s/%s", ref, owner, repo)
}

// workflowFiles reads the directory's entries the way the contents
// listing was read: regular files only, the lockfile noted, .yml and
// .yaml kept, sorted by name.
func workflowFiles(rev string, raw json.RawMessage) workflowTree {
	out := workflowTree{rev: rev}
	var dir struct {
		Entries []treeEntry `json:"entries"`
	}
	if isNull(raw) || json.Unmarshal(raw, &dir) != nil {
		return out
	}
	for _, e := range dir.Entries {
		if e.Mode != modeFile && e.Mode != modeExecutable {
			continue
		}
		if e.Name == githubWorkflowLockfileName {
			out.hasLockfile = true
			continue
		}
		if !strings.HasSuffix(e.Name, ".yml") && !strings.HasSuffix(e.Name, ".yaml") {
			continue
		}
		out.files = append(out.files, e)
	}
	sort.Slice(out.files, func(i, j int) bool { return out.files[i].Name < out.files[j].Name })
	return out
}

// prefetchedFile is a composite definition the query answered: missing
// when GitHub answered null, blob otherwise.
type prefetchedFile struct {
	missing bool
	blob    *blobAnswer
}

// localCompositeDirs are the directories of the local composites
// (`uses: ./dir`) the jobs' steps call, under the rules of
// nestedWalk.containerFor: no expression, nothing outside the repository.
func localCompositeDirs(p []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, uses := range p {
		uses = strings.TrimSpace(uses)
		rel, ok := strings.CutPrefix(uses, "./")
		if !ok || strings.Contains(uses, "${{") || escapesRoot(rel) {
			continue
		}
		dir := path.Clean(rel)
		if dir == "." {
			dir = ""
		}
		if !seen[dir] {
			seen[dir] = true
			out = append(out, dir)
		}
	}
	return out
}

// prefetchLocalComposites reads action.yml and action.yaml of each
// directory at rev in one query, keyed by the path the nested walk reads
// (path.Join(dir, "action.yml")). A failed query or alias leaves the
// path out, so it reads over REST.
func prefetchLocalComposites(gql *api.GraphQLClient, owner, repo, rev string, dirs []string) map[string]prefetchedFile {
	out := map[string]prefetchedFile{}
	if len(dirs) == 0 {
		return out
	}
	var items []treeQueryItem
	paths := map[string]string{}
	for i, d := range dirs {
		for j, name := range []string{"action.yml", "action.yaml"} {
			alias := "f" + strconv.Itoa(i) + "_" + strconv.Itoa(j)
			p := path.Join(d, name)
			paths[alias] = p
			items = append(items, treeQueryItem{alias, rev + ":" + p, blobFields})
		}
	}
	fields, failed, err := queryObjects(gql, "local composites", owner, repo, items)
	if err != nil {
		return out
	}
	for alias, p := range paths {
		if failed[alias] != nil {
			continue
		}
		if isNull(fields[alias]) {
			out[p] = prefetchedFile{missing: true}
			continue
		}
		var b blobAnswer
		if json.Unmarshal(fields[alias], &b) == nil {
			out[p] = prefetchedFile{blob: &b}
		}
	}
	return out
}

// prefetchedReader reads a prefetched composite definition, and anything
// else, or a file GitHub did not give in full, through fallback.
func prefetchedReader(files map[string]prefetchedFile, fallback func(string) (string, fetchStatus)) func(string) (string, fetchStatus) {
	return func(rel string) (string, fetchStatus) {
		if f, ok := files[rel]; ok {
			if f.missing {
				return "", fetchMissing
			}
			if text, ok := f.blob.usable(); ok {
				return text, fetchOK
			}
		}
		return fallback(rel)
	}
}
