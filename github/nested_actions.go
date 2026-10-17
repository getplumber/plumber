package github

// The nested actions resolution stage (monorepo spec
// docs/superpowers/specs/2026-10-16-nested-actions-resolution-design.md,
// sections 3 and 4): every composite action a workflow step pulls in is
// expanded, recursively, into the same Job.Uses list, right after the
// entry that pulled it in, so every control runs on the pipeline the
// runner executes (R1).

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
	yamlv3 "gopkg.in/yaml.v3"

	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/utils"
)

// The bounds of the closure live here only. The control package names the
// one that tripped in the degraded reason (spec section 7).
const (
	// MaxNestedContainers bounds the API cost of the closure (R3, R7, R8):
	// it counts the NEW unique containers (composite actions, reusable
	// workflows) fetched in the run, never the direct references of the
	// workflows. One container costs one definition fetch plus, once its
	// steps are entries, the metadata resolve and the mutable-exec scan the
	// enrichment already pays per unique reference: about 15 calls with
	// ISSUE-714 on, about 7 with it off, so the worst case stays near 1,500
	// calls against the 5,000 per hour authenticated budget. A reference the
	// budget cut off is never enriched, so it costs nothing. A named
	// constant, not a .plumber.yaml key (R7): a knob would let a user
	// silence the degradation.
	MaxNestedContainers = 100

	// MaxNestedEntriesPerJob bounds the entries one job's closure appends.
	// The container budget bounds the fetches, not the paths: two paths to
	// one container are two entries (R5), so a lattice of a hundred
	// containers could otherwise multiply without end. Past it the rest is
	// listed with reason budget and the run degrades like a container
	// overflow (R3).
	MaxNestedEntriesPerJob = 10 * MaxNestedContainers

	// MaxNestedJobs bounds the jobs the called workflows of other
	// repositories append in the run. A workflow costs one fetch however
	// many calls reach it, and every call appends its own copy of the
	// callee's jobs (two calls are two sets of nested jobs), so a diamond of
	// calls would double the jobs at every level for a fixed fetch cost.
	// Past it the calls left are listed with reason budget and the run
	// degrades like a container overflow (R3).
	MaxNestedJobs = 1000
)

// contentsFetchTimeout is the deadline of one contents API read of a
// definition, the raw client's own (rawHTTPClient): a stalled API
// connection ends as a fetch error, never a hang.
var contentsFetchTimeout = 20 * time.Second

// actionDefinition is one action's definition file as the fetch found it:
// Path is the file that answered (or the last one tried), Text its body
// when Status is fetchOK.
type actionDefinition struct {
	Text   string
	Path   string
	Status fetchStatus
	// consumed is set once the mutable-exec scan read Text, then dropped.
	consumed bool
}

// fetchActionDefinition reads <subpath>/action.yml, then action.yaml, the
// way GitHub resolves an action. A fetch error on action.yml stops there
// (could-not-verify), as the mutable-exec scan always did.
func fetchActionDefinition(fetch rawFetcher, owner, repo, ref, subpath string) actionDefinition {
	ymlPath := path.Join(subpath, "action.yml")
	text, st := fetch(owner, repo, ref, ymlPath)
	if st == fetchOK || st == fetchError || st == fetchTooLarge {
		return actionDefinition{Text: text, Path: ymlPath, Status: st}
	}
	yamlPath := path.Join(subpath, "action.yaml")
	text, st = fetch(owner, repo, ref, yamlPath)
	return actionDefinition{Text: text, Path: yamlPath, Status: st}
}

// definitionFetcher is the one place a container's definition is read in
// a run (spec 4.2): the raw host first, then, for what the raw host does
// not serve (private repositories, GitHub Enterprise Server), the contents
// API through the metadata client's authenticated transport. Every answer
// is cached by container key, so a container costs one request however
// many paths reach it and whichever consumer asks first.
type definitionFetcher struct {
	raw rawFetcher
	// rawDefinition reads a definition from the raw host with the
	// definition bound, raw when nil (a test's stub).
	rawDefinition rawFetcher
	rest          *api.RESTClient

	mu      sync.Mutex
	actions map[string]actionDefinition
	// sealed is set once the container budget is passed: from then on an
	// action the walk did not admit is never fetched (spec 4.3, R8).
	sealed bool
	files  map[string]fileDefinition
}

// newDefinitionFetcher builds the run's fetcher over raw; client lends its
// authenticated transport for the contents API fallback when it has one.
// A nil raw reads through the contents API only (GitHub Enterprise Server,
// see definitionFetcherForHost).
func newDefinitionFetcher(raw rawFetcher, client *GitHubMetadataClient) *definitionFetcher {
	f := &definitionFetcher{raw: raw, actions: map[string]actionDefinition{}, files: map[string]fileDefinition{}}
	if client != nil && client.Available() {
		f.rest = client.rest
	}
	return f
}

// definitionFetcherForHost is the run's fetcher for the configured API
// host. On github.com it reads the raw host first. On a GitHub Enterprise
// Server host it never does (spec 4.2): raw.githubusercontent.com would
// answer for a homonymous public repository of github.com and receive a
// token scoped to the enterprise instance. It reads through the contents
// API of that host only, with a client of its own when the enrichment
// built none.
func definitionFetcherForHost(host string, client *GitHubMetadataClient) *definitionFetcher {
	if !isEnterpriseHost(host) {
		f := newDefinitionFetcher(httpRawFetcher, client)
		f.rawDefinition = rawFetcherWithLimit(maxWorkflowFileBytes + 1)
		return f
	}
	if client == nil {
		client = NewGitHubMetadataClientForHost(host)
	}
	return newDefinitionFetcher(nil, client)
}

// isEnterpriseHost reports whether host names an API other than github.com.
func isEnterpriseHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	h = strings.TrimSuffix(strings.TrimSuffix(h, "/"), "/api/v3")
	return h != "" && h != "api.github.com" && h != "github.com"
}

// escapesRoot reports whether a repository-relative path climbs out of its
// root after cleaning. Container content is untrusted input: such a path
// is never fetched (spec 3.3, the ingestion hardening rule).
func escapesRoot(p string) bool {
	c := path.Clean(p)
	return c == ".." || strings.HasPrefix(c, "../") || strings.HasPrefix(c, "/")
}

// containerKey is the visited-set key of a container (spec 4.3): owner and
// repo lower-cased, the subpath and the ref as written.
func containerKey(owner, repo, subpath, ref string) string {
	head := strings.ToLower(owner) + "/" + strings.ToLower(repo)
	if subpath != "" {
		head += "/" + subpath
	}
	return head + "@" + ref
}

// APIDisabled reports the offline switch both read paths honour (R6).
func APIDisabled() bool {
	v := os.Getenv(EnvDisableGitHubAPI)
	return v == "1" || v == "true"
}

// read is a rawFetcher: the raw host, then the contents API. A path that
// climbs out of the repository is refused without a request. The
// mutable-exec scan reads an entrypoint through it, with the raw host's
// own bound.
func (f *definitionFetcher) read(owner, repo, ref, p string) (string, fetchStatus) {
	return f.readWith(f.raw, owner, repo, ref, p)
}

// readDefinition reads a definition (an action.yml, a called workflow)
// with the bound of the scanned repository's own workflows
// (maxWorkflowFileBytes, spec 4.2, SECURITY item 2): past it the read is
// fetchTooLarge, that reference alone listed with reason fetch.
func (f *definitionFetcher) readDefinition(owner, repo, ref, p string) (string, fetchStatus) {
	raw := f.rawDefinition
	if raw == nil {
		raw = f.raw
	}
	text, st := f.readWith(raw, owner, repo, ref, p)
	if st == fetchOK && len(text) > maxWorkflowFileBytes {
		return "", fetchTooLarge
	}
	return text, st
}

func (f *definitionFetcher) readWith(raw rawFetcher, owner, repo, ref, p string) (string, fetchStatus) {
	if APIDisabled() {
		return "", fetchDisabled
	}
	if escapesRoot(p) {
		return "", fetchError
	}
	text, st := "", fetchMissing
	if raw != nil {
		text, st = raw(owner, repo, ref, p)
	}
	if st == fetchOK || f.rest == nil {
		return text, st
	}
	ctx, cancel := context.WithTimeout(context.Background(), contentsFetchTimeout)
	defer cancel()
	body, err := fetchFileContentContext(ctx, f.rest, owner, repo, p, ref)
	switch {
	case err == nil:
		return string(body), fetchOK
	case isNotFound(err):
		return "", fetchMissing
	}
	return "", fetchError
}

// seal stops every fetch of an action the walk did not admit: the
// container budget is passed (spec 4.3, R8), so the enrichment never reads
// past it.
func (f *definitionFetcher) seal() {
	f.mu.Lock()
	f.sealed = true
	f.mu.Unlock()
}

// refuses reports whether uses names an action this fetcher will not read:
// a reference outside GitHub's grammar, or one the walk did not admit once
// the budget was passed. The enrichment skips such a nested entry whole
// (metadata and mutable-exec), so it costs no request.
func (f *definitionFetcher) refuses(uses string) bool {
	if f == nil {
		return false
	}
	owner, repo, subpath, ref, ok := splitActionRefWithSubpath(uses)
	if !ok {
		return false
	}
	if !validActionReference(owner, repo, subpath, ref) {
		return true
	}
	key := containerKey(owner, repo, subpath, ref)
	f.mu.Lock()
	defer f.mu.Unlock()
	_, admitted := f.actions[key]
	return f.sealed && !admitted
}

// action is the cached definition of the action at owner/repo/subpath@ref.
// A reference outside GitHub's grammar, or, once the fetcher is sealed, a
// key it never read, is refused without a request (fetchMissing, nothing
// to scan).
func (f *definitionFetcher) action(owner, repo, subpath, ref string) actionDefinition {
	key := containerKey(owner, repo, subpath, ref)
	f.mu.Lock()
	d, ok := f.actions[key]
	sealed := f.sealed
	f.mu.Unlock()
	if ok && !d.consumed {
		return d
	}
	if !ok && (sealed || !validActionReference(owner, repo, subpath, ref)) {
		return actionDefinition{Status: fetchMissing}
	}
	d = fetchActionDefinition(f.readDefinition, owner, repo, ref, subpath)
	if ok {
		return d // a body already consumed is read again, never kept
	}
	f.mu.Lock()
	f.actions[key] = d
	f.mu.Unlock()
	return d
}

// consume is action for the mutable-exec scan, the last reader of a
// definition: the cache then keeps the status and the path only, so the
// run never holds every body to its end (SECURITY item 2).
func (f *definitionFetcher) consume(owner, repo, subpath, ref string) actionDefinition {
	d := f.action(owner, repo, subpath, ref)
	key := containerKey(owner, repo, subpath, ref)
	f.mu.Lock()
	if c, ok := f.actions[key]; ok && !c.consumed {
		f.actions[key] = actionDefinition{Path: c.Path, Status: c.Status, consumed: true}
	}
	f.mu.Unlock()
	return d
}

// fileDefinition is one fetched file (a reusable workflow).
type fileDefinition struct {
	Text   string
	Status fetchStatus
}

// file is the cached text of one file at owner/repo@ref.
func (f *definitionFetcher) file(owner, repo, ref, p string) fileDefinition {
	key := containerKey(owner, repo, p, ref)
	f.mu.Lock()
	d, ok := f.files[key]
	f.mu.Unlock()
	if ok {
		return d
	}
	text, st := f.readDefinition(owner, repo, ref, p)
	d = fileDefinition{Text: text, Status: st}
	f.mu.Lock()
	f.files[key] = d
	f.mu.Unlock()
	return d
}

var (
	// ownerGrammar is a GitHub user or organization login.
	ownerGrammar = regexp.MustCompile(`^[A-Za-z0-9-]{1,39}$`)
	// repoGrammar is a GitHub repository name.
	repoGrammar = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// validActionReference reports whether owner/repo/subpath@ref stays inside
// GitHub's grammar (SECURITY item 1, Task 1 ruling L4). A container's
// content is untrusted input, and every part of a reference ends up in an
// authenticated request path or query: an owner or repository outside the
// login and name grammars, a subpath segment holding `..`, or a ref outside
// a subset of git check-ref-format is never fetched.
func validActionReference(owner, repo, subpath, ref string) bool {
	if !ownerGrammar.MatchString(owner) || !repoGrammar.MatchString(repo) || repo == "." || repo == ".." {
		return false
	}
	if subpath != "" {
		for _, seg := range strings.Split(subpath, "/") {
			if strings.Contains(seg, "..") {
				return false
			}
		}
	}
	return validRef(ref)
}

// validRef is the subset of git check-ref-format a fetched ref must pass:
// not empty, not `@`, no `..`, `@{`, `?`, `#`, `%`, backslash, space or
// control character.
func validRef(ref string) bool {
	if ref == "" || ref == "@" || strings.Contains(ref, "..") || strings.Contains(ref, "@{") || strings.ContainsAny(ref, "?#%\\ ") {
		return false
	}
	for _, r := range ref {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// authenticated reports whether a read could tell a private file from an
// absent one: a token on the raw host or the contents API client.
func (f *definitionFetcher) authenticated() bool {
	return f.rest != nil || (f.raw != nil && rawFetchToken() != "")
}

// nestedScope is what the stage knows of the scanned repository.
// readLocal reads one of its files by repository-relative path: from disk
// in local mode (localOnDisk: no API cost, never counted), through the
// contents API at the scanned ref in remote mode (spec 3.3).
//
// aliases are the other names the scan knows for the scanned repository
// (review of PR 549), an old name kept after a rename or a transfer: a
// call naming projectPath or one of them is the repository's own. The
// API-canonical full name is only learned after the walk (control
// applyGitHubVisibility), and projectPath already is the origin remote's
// path locally and the requested path remotely, so both scans pass none.
type nestedScope struct {
	projectPath string
	aliases     []string
	readLocal   func(rel string) (string, fetchStatus)
	localOnDisk bool
}

// ownsRepo reports whether owner/repo names the scanned repository, its
// path or one of its aliases, compared case-insensitively as GitHub
// resolves names (review of PR 549).
func (s nestedScope) ownsRepo(owner, repo string) bool {
	name := owner + "/" + repo
	if strings.EqualFold(name, s.projectPath) {
		return true
	}
	for _, a := range s.aliases {
		if strings.EqualFold(name, a) {
			return true
		}
	}
	return false
}

// ownsCall reports whether a job calls a workflow of the scanned
// repository: a relative call of a scanned job, or an absolute one naming
// the repository (ownsRepo). "" is no call at all.
func (s nestedScope) ownsCall(job ir.Job) bool {
	owner, repo, _, _, ok := splitWorkflowRef(canonicalWorkflowRef(job))
	return !ok || s.ownsRepo(owner, repo)
}

// diskReader reads a file of the local checkout, never outside it. Only an
// absent file is fetchMissing (a silent leaf): a path escaping the
// checkout, a file past maxWorkflowFileBytes or any other read error is
// fetchError, listed with reason fetch (spec 4.3), never a silent pass.
func diskReader(rootDir string) func(rel string) (string, fetchStatus) {
	return func(rel string) (string, fetchStatus) {
		p, ok := resolveWithinRoot(rootDir, filepath.FromSlash(rel))
		if !ok {
			return "", fetchError
		}
		data, err := utils.ReadFileLimit(p, maxWorkflowFileBytes)
		switch {
		case err == nil:
			return string(data), fetchOK
		case errors.Is(err, fs.ErrNotExist):
			return "", fetchMissing
		}
		return "", fetchError
	}
}

// contentsReader reads a file of the scanned repository at ref through the
// remote scan's own REST client.
func contentsReader(rest *api.RESTClient, owner, repo, ref string) func(rel string) (string, fetchStatus) {
	return func(rel string) (string, fetchStatus) {
		body, err := fetchFileContent(rest, owner, repo, rel, ref)
		switch {
		case err == nil:
			return string(body), fetchOK
		case isNotFound(err):
			return "", fetchMissing
		}
		return "", fetchError
	}
}

// nestedStep is one `uses:` step of a composite action, in declared order.
type nestedStep struct {
	uses, name, ifCond, comment string
	with                        map[string]any
	line                        int
}

// parseCompositeSteps reads a definition (spec 4.2): runs.using ==
// composite yields its runs.steps[].uses in order with their lines; any
// other runs.using is a leaf (R2: JavaScript and Docker actions). A
// composite's run: steps are not entries (spec 3.3), the mutable-exec scan
// covers them.
//
// The runner resolves YAML aliases and merge keys before it runs a step,
// so each step is decoded (review of PR 549): uses: *ref, a whole-step
// alias - *step and a <<: *base merge key contributing uses: are all
// entries. The line stays the one written in the steps list: the uses:
// value's own line when the step writes the key (an alias there is the
// alias's line), else the step's own line (the alias's line for - *step,
// the first key's for a merged mapping), since that is the step the
// runner executes, the anchor being only where its text was borrowed.
func parseCompositeSteps(text string) (composite bool, steps []nestedStep, err error) {
	var doc struct {
		Runs struct {
			Using string        `yaml:"using"`
			Steps []yamlv3.Node `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yamlv3.Unmarshal([]byte(text), &doc); err != nil {
		return false, nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(doc.Runs.Using), "composite") {
		return false, nil, nil
	}
	left := maxCompositeAliasNodes
	for i := range doc.Runs.Steps {
		n := &doc.Runs.Steps[i]
		if err := boundAliases(n, false, &left, map[*yamlv3.Node]bool{}); err != nil {
			return false, nil, err
		}
		var st struct {
			Uses string         `yaml:"uses"`
			Name string         `yaml:"name"`
			If   string         `yaml:"if"`
			With map[string]any `yaml:"with"`
		}
		// A field of another shape is a type error the decoder reports
		// after filling the others: that field is read as absent, as when
		// the node kinds were walked by hand.
		if err := n.Decode(&st); err != nil {
			var te *yamlv3.TypeError
			if !errors.As(err, &te) {
				return false, nil, err
			}
		}
		s := nestedStep{uses: strings.TrimSpace(st.Uses), name: st.Name, ifCond: st.If, line: n.Line}
		if len(st.With) > 0 {
			s.with = st.With
		}
		if v := ownUses(n); v != nil {
			s.line, s.comment = v.Line, lineComment(v)
		} else if n.Kind == yamlv3.AliasNode && n.Alias != nil {
			if v := ownUses(n.Alias); v != nil {
				s.comment = lineComment(v)
			}
		}
		if s.uses != "" {
			steps = append(steps, s)
		}
	}
	return true, steps, nil
}

// maxCompositeAliasNodes bounds the nodes one definition's steps reach
// through YAML aliases (review of PR 549): the 1 MiB definition bound no
// longer bounds what a decode builds once aliases expand.
const maxCompositeAliasNodes = 1 << 16

var errCompositeAliasing = errors.New("composite steps alias themselves or expand past the alias bound")

// boundAliases walks n following aliases and fails on an alias back to a
// node on its own path or once the aliased nodes pass the bound, before
// any decode expands them.
func boundAliases(n *yamlv3.Node, aliased bool, left *int, onPath map[*yamlv3.Node]bool) error {
	if aliased {
		*left--
		if *left < 0 {
			return errCompositeAliasing
		}
	}
	if n.Kind == yamlv3.AliasNode {
		if n.Alias == nil || onPath[n.Alias] {
			return errCompositeAliasing
		}
		onPath[n.Alias] = true
		err := boundAliases(n.Alias, true, left, onPath)
		delete(onPath, n.Alias)
		return err
	}
	for _, c := range n.Content {
		if err := boundAliases(c, aliased, left, onPath); err != nil {
			return err
		}
	}
	return nil
}

// ownUses is the uses: value a step mapping writes itself, nil otherwise.
func ownUses(n *yamlv3.Node) *yamlv3.Node {
	if n.Kind != yamlv3.MappingNode {
		return nil
	}
	for k := 0; k+1 < len(n.Content); k += 2 {
		if n.Content[k].Value == "uses" {
			return n.Content[k+1]
		}
	}
	return nil
}

func lineComment(n *yamlv3.Node) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(n.LineComment), "#"))
}

// nestedContainer is one composite action of the closure.
type nestedContainer struct {
	key                       string
	owner, repo, subpath, ref string
	// local is a composite of the scanned repository at dir.
	local bool
	dir   string
	// direct is reached from a workflow step: never counted (spec 4.3).
	direct, queued bool
	defPath        string
	steps          []nestedStep
	// reason is why the container was not expanded, "" when it was read.
	reason string
	// invalid is a reference refused before any fetch (refused).
	invalid bool
}

// definedIn locates line in the container's definition (spec 3.1).
func (c *nestedContainer) definedIn(line int) string {
	if c.local {
		return "./" + c.defPath + ":" + strconv.Itoa(line)
	}
	return c.owner + "/" + c.repo + "@" + c.ref + ":" + c.defPath + ":" + strconv.Itoa(line)
}

// nestedWalk is one run's breadth-first walk over the containers.
type nestedWalk struct {
	defs  *definitionFetcher
	scope nestedScope
	byKey map[string]*nestedContainer
	queue []*nestedContainer
	// fetched counts the new unique containers fetched (the budget, R8).
	fetched int
	// attempted is true once a remote definition read was made.
	attempted bool
	// cause is why the closure could not be resolved at all (R6), "".
	cause    string
	overflow bool
	// unexpanded collects what a phase other than the splice could not
	// expand: a workflow of another repository that could not be read.
	unexpanded []ir.UnexpandedAction
	// workflows is the visited set of the called workflows (spec 4.3).
	workflows map[string]bool
	// nestedJobs counts the jobs the called workflows appended (the run-wide
	// cap, MaxNestedJobs), jobsCapped is set once a call did not fit, and
	// jobsOverflow holds the calls the cap left unexpanded, keyed like the
	// deduplicated list.
	nestedJobs   int
	jobsCapped   bool
	jobsOverflow map[string]bool
}

func (w *nestedWalk) remote(owner, repo, subpath, ref string) *nestedContainer {
	key := containerKey(owner, repo, subpath, ref)
	if c, ok := w.byKey[key]; ok {
		return c
	}
	c := &nestedContainer{key: key, owner: owner, repo: repo, subpath: subpath, ref: ref}
	w.byKey[key] = c
	return c
}

func (w *nestedWalk) localContainer(dir string) *nestedContainer {
	key := "local:" + dir
	if c, ok := w.byKey[key]; ok {
		return c
	}
	c := &nestedContainer{key: key, local: true, dir: dir}
	w.byKey[key] = c
	return c
}

// containerFor is the container a `uses:` names, wherever it is written
// (a workflow step, a composite, a called workflow's step). A
// relative `./x`, at any depth, is a composite of the SCANNED repository,
// because the runner resolves it against the job's workspace, never
// against the repository of the composite or workflow that wrote it
// (spec 3.3, ruled by a live probe on 2026-10-16). expr is true for an
// expression, which names none and is never guessed (spec 3.3). A
// docker:// image and an unparseable reference are leaves (nil).
func (w *nestedWalk) containerFor(uses string) (c *nestedContainer, expr bool) {
	uses = strings.TrimSpace(uses)
	switch {
	case strings.Contains(uses, "${{"):
		return nil, true
	case strings.HasPrefix(uses, "docker://"):
		return nil, false
	}
	if rel, ok := strings.CutPrefix(uses, "./"); ok {
		if escapesRoot(rel) {
			return w.refused(uses), false
		}
		dir := path.Clean(rel)
		if dir == "." {
			dir = ""
		}
		if w.scope.readLocal == nil {
			return nil, false
		}
		return w.localContainer(dir), false
	}
	owner, repo, subpath, ref, ok := splitActionRefWithSubpath(uses)
	if !ok {
		return nil, false
	}
	if (subpath != "" && escapesRoot(subpath)) || !validActionReference(owner, repo, subpath, ref) {
		return w.refused(uses), false
	}
	return w.remote(owner, repo, subpath, ref), false
}

// refused is the container of a reference whose path climbs out of its
// repository or that is outside GitHub's grammar (validActionReference):
// never queued, never fetched, listed with reason fetch. A reference outside
// the grammar carries the Invalid mark, from which the capped fetch warning
// of the control package names the reason, so it adds no line of its own.
func (w *nestedWalk) refused(uses string) *nestedContainer {
	key := "refused:" + uses
	if c, ok := w.byKey[key]; ok {
		return c
	}
	c := &nestedContainer{key: key, queued: true, reason: ir.UnexpandedFetch, invalid: true}
	w.byKey[key] = c
	return c
}

func (w *nestedWalk) enqueue(c *nestedContainer, direct bool) {
	if c == nil || c.queued {
		return
	}
	c.queued, c.direct = true, direct
	w.queue = append(w.queue, c)
}

// noteStatus records the R6 cause a remote read's status reveals. Only the
// FIRST remote read of the run decides it (coordinator ruling M1): a
// failure there (rate limit, network, air gap), or an absent file with no
// token to tell it from a private one, means the closure cannot be read
// at all. A later failure is that one reference's (reason fetch, see
// visit) and keeps every container already read. The offline switch is a
// cause whenever it is seen. The first cause wins. A definition past its
// bound (fetchTooLarge) is never a cause: the read answered.
func (w *nestedWalk) noteStatus(st fetchStatus) {
	first := !w.attempted
	w.attempted = true
	if w.cause != "" {
		return
	}
	switch {
	case st == fetchDisabled:
		w.cause = "the GitHub API is disabled (" + EnvDisableGitHubAPI + ")"
	case st == fetchError && first:
		w.cause = "the first action definition could not be fetched (rate limit or network)"
	case st == fetchMissing && first && !w.defs.authenticated():
		w.cause = "no token is available to read private actions"
	}
}

func (w *nestedWalk) readDefinition(c *nestedContainer) (string, fetchStatus) {
	if c.local {
		c.defPath = path.Join(c.dir, "action.yml")
		text, st := w.scope.readLocal(c.defPath)
		if st == fetchMissing {
			c.defPath = path.Join(c.dir, "action.yaml")
			text, st = w.scope.readLocal(c.defPath)
		}
		return text, st
	}
	def := w.defs.action(c.owner, c.repo, c.subpath, c.ref)
	c.defPath = def.Path
	w.noteStatus(def.Status)
	return def.Text, def.Status
}

// visit reads one container and queues the containers its steps name.
func (w *nestedWalk) visit(c *nestedContainer) {
	if !c.local && w.cause != "" {
		c.reason = ir.UnexpandedAPIDisabled
		return
	}
	counted := !c.direct && (!c.local || !w.scope.localOnDisk)
	if counted && w.fetched >= MaxNestedContainers {
		c.reason = ir.UnexpandedBudget
		w.overflow = true
		w.defs.seal()
		return
	}
	text, st := w.readDefinition(c)
	if !c.local && w.cause != "" {
		c.reason = ir.UnexpandedAPIDisabled
		return
	}
	if counted {
		w.fetched++
	}
	switch {
	case st == fetchOK:
	case st == fetchError, st == fetchTooLarge:
		c.reason = ir.UnexpandedFetch
		return
	case st == fetchMissing && !c.local && !w.defs.authenticated():
		// Past the first read, an absent definition with no token may be a
		// private one: that reference alone is unverified (ruling M1).
		c.reason = ir.UnexpandedFetch
		return
	default:
		return // not an action at that path: a leaf, silently (spec 4.3)
	}
	composite, steps, err := parseCompositeSteps(text)
	if err != nil {
		c.reason = ir.UnexpandedFetch
		return
	}
	if !composite {
		return
	}
	c.steps = steps
	for _, s := range steps {
		child, _ := w.containerFor(s.uses)
		w.enqueue(child, false)
	}
}

// discardRemote marks the whole remote closure unresolved (R6): every
// direct reference is judged as today and listed api_disabled. The scanned
// repository's own composites still expand (local mode offline).
func (w *nestedWalk) discardRemote() {
	for _, c := range w.byKey {
		if !c.local {
			c.steps = nil
			c.reason = ir.UnexpandedAPIDisabled
		}
	}
}

// jobSplice is one job's resolved list under construction.
type jobSplice struct {
	out        []ir.Action
	unexpanded []ir.UnexpandedAction
	left       int
}

// splice rebuilds job.Uses in runner order: each entry, then what its
// container pulls in, depth first, at the entry's line (R9).
func (w *nestedWalk) splice(job *ir.Job) []ir.UnexpandedAction {
	s := &jobSplice{left: MaxNestedEntriesPerJob}
	for _, e := range job.Uses {
		s.out = append(s.out, e)
		c, _ := w.containerFor(e.Uses)
		if c == nil {
			continue
		}
		chain := append(slices.Clone(e.Via), e.Uses)
		w.expand(s, c, e, chain, map[string]bool{c.key: true})
	}
	job.Uses = s.out
	return s.unexpanded
}

func viaOf(chain []string) []string {
	if len(chain) <= 1 {
		return nil
	}
	return slices.Clone(chain[:len(chain)-1])
}

// expand appends c's steps after outer. onChain is the cycle guard of one
// path: a step back to a container already on it is the runner's own
// loop and is not listed again (spec 4.3).
func (w *nestedWalk) expand(s *jobSplice, c *nestedContainer, outer ir.Action, chain []string, onChain map[string]bool) {
	if c.reason != "" {
		s.unexpanded = append(s.unexpanded, ir.UnexpandedAction{Uses: chain[len(chain)-1], Via: viaOf(chain), Reason: c.reason, Invalid: c.invalid && c.reason == ir.UnexpandedFetch})
		return
	}
	for _, step := range c.steps {
		child, expr := w.containerFor(step.uses)
		if expr {
			s.unexpanded = append(s.unexpanded, ir.UnexpandedAction{Uses: step.uses, Via: slices.Clone(chain), Reason: ir.UnexpandedExpression})
			continue
		}
		if child != nil && onChain[child.key] {
			continue
		}
		if s.left == 0 {
			s.unexpanded = append(s.unexpanded, ir.UnexpandedAction{Uses: step.uses, Via: slices.Clone(chain), Reason: ir.UnexpandedBudget})
			w.overflow = true
			continue
		}
		s.left--
		s.out = append(s.out, ir.Action{
			Uses: step.uses, Name: step.name, If: step.ifCond, With: step.with, Comment: step.comment,
			Line: outer.Line, Nested: true, Via: slices.Clone(chain), DefinedIn: c.definedIn(step.line),
		})
		if child == nil {
			continue
		}
		onChain[child.key] = true
		w.expand(s, child, outer, append(slices.Clone(chain), step.uses), onChain)
		delete(onChain, child.key)
	}
}

// unexpandedKey is what makes two unexpanded references the same one.
func unexpandedKey(u ir.UnexpandedAction) string {
	return u.Reason + "\x00" + u.Uses + "\x00" + strings.Join(u.Via, "\x00")
}

func dedupeUnexpanded(in []ir.UnexpandedAction) []ir.UnexpandedAction {
	seen := map[string]bool{}
	var out []ir.UnexpandedAction
	for _, u := range in {
		k := unexpandedKey(u)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, u)
	}
	return out
}

// resolveNestedActions is the stage (spec 4.1): breadth-first over the
// containers the jobs' direct references name, then each job's list
// rebuilt in runner order. Records on the pipeline what could not be
// expanded, whether the budget was exceeded (R3) and why the closure could
// not be resolved at all (R6).
func resolveNestedActions(pipeline *ir.NormalizedPipeline, defs *definitionFetcher, scope nestedScope) {
	if pipeline == nil || defs == nil {
		return
	}
	w := &nestedWalk{defs: defs, scope: scope, byKey: map[string]*nestedContainer{}}
	// One queue and one budget (R3, R8): the composites of the scanned
	// workflows first, then the workflows called in other repositories,
	// then the containers their jobs name. enqueue is idempotent, so the
	// second drain queues only what the appended jobs bring.
	drain := func() {
		for _, job := range pipeline.Jobs {
			for _, e := range job.Uses {
				c, _ := w.containerFor(e.Uses)
				w.enqueue(c, !job.Nested)
			}
		}
		for len(w.queue) > 0 {
			c := w.queue[0]
			w.queue = w.queue[1:]
			w.visit(c)
		}
	}
	drain()
	w.resolveWorkflows(pipeline)
	drain()
	if w.cause != "" {
		// R6: the whole closure is unresolved, the jobs of other repositories
		// included. The list is rebuilt from the direct references only, so
		// a nested call's reason and a direct call's earlier fetch never
		// show next to the api_disabled line of the same reference.
		pipeline.Jobs = slices.DeleteFunc(pipeline.Jobs, func(j ir.Job) bool { return j.Nested })
		w.unexpanded = nil
		for _, j := range pipeline.Jobs {
			if !scope.ownsCall(j) {
				w.unexpanded = append(w.unexpanded, ir.UnexpandedAction{Uses: j.ReusableWorkflowUses, Reason: ir.UnexpandedAPIDisabled})
			}
		}
		w.discardRemote()
	}
	unexpanded := slices.Clone(w.unexpanded)
	for i := range pipeline.Jobs {
		unexpanded = append(unexpanded, w.splice(&pipeline.Jobs[i])...)
	}
	pipeline.UnexpandedActions = dedupeUnexpanded(unexpanded)
	pipeline.NestedBudgetExceeded = w.overflow
	pipeline.NestedJobsOverflow = len(w.jobsOverflow)
	pipeline.NestedUnresolvedCause = w.cause
}
