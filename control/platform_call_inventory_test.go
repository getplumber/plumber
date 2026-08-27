package control

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/platform"
)

// Issue #368's third acceptance criterion is the one that cannot be
// desk-checked: "every collection goes through its lane, no direct
// extended-rights API call from the runner". Reading the source answers it
// for the call sites you think to look at. This answers it for the ones you
// do not, by running the real collection against a GitLab that records
// every request and comparing the result against a written-down ledger.
//
// The ledger is deliberately a full equality assertion rather than a
// "must not contain" list. A new collector added to the analysis flow shows
// up here as a diff, which is the point: the migration's failure mode is a
// call nobody remembered was there.
//
// It also counts REQUESTS, not call sites. The include loop issues one
// GraphQL merge per include and the version/ref probes fire per component,
// so the source reads like a handful of calls while a project with ten
// includes pays for dozens.

// gitlabRecorder is a stand-in GitLab that answers plausibly and records
// what it was asked for.
type gitlabRecorder struct {
	mu    sync.Mutex
	calls []string
	sha   string
	// failRefProbes makes the single-ref tag/branch lookups fail rather
	// than answer, which is what a token that can read this project but not
	// the include's SOURCE project produces.
	failRefProbes bool
}

// A ledger has to name ENDPOINTS, not URLs, or the same run against a
// different project produces a different ledger and the two cannot be
// compared. These collapse the parts that vary: the project identifier
// (numeric id, or a percent-encoded path), the file path in a raw-file
// read, and the ref in a single-ref probe.
//
// The project identifier is read off r.URL.EscapedPath rather than
// r.URL.Path: go-gitlab sends "group%2Fproject" as ONE segment, and the
// decoded form is indistinguishable from two path segments, which is how a
// project path silently escapes normalization.
var (
	numericID   = regexp.MustCompile(`/\d+(/|$)`)
	encodedPath = regexp.MustCompile(`/[^/]*%2[Ff][^/]*`)
	rawFileSeg  = regexp.MustCompile(`(/repository/files/)[^/]+`)
	singleRef   = regexp.MustCompile(`(/repository/(?:tags|branches)/)[^/]+`)
	gqlField    = regexp.MustCompile(`query\s+([A-Za-z_][A-Za-z0-9_]*)`)
)

func (g *gitlabRecorder) record(label string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls = append(g.calls, label)
}

// ledger returns "<count>x <request>" lines, sorted, so a test failure
// reads as a diff of endpoints rather than a wall of URLs.
func (g *gitlabRecorder) ledger() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	counts := map[string]int{}
	for _, c := range g.calls {
		counts[c]++
	}
	out := make([]string, 0, len(counts))
	for call, n := range counts {
		out = append(out, fmt.Sprintf("%dx %s", n, call))
	}
	sort.Strings(out)
	return out
}

func (g *gitlabRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if path == "/api/graphql" {
		var body struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		op := "unknown"
		if m := gqlField.FindStringSubmatch(body.Query); len(m) == 2 {
			op = m[1]
		}
		// One query name covers two very different collections: the merge
		// of the project's own CI config, and the per-include merge the
		// origin loop runs to learn which jobs each include contributes.
		// The ledger has to tell them apart, because platform mode is
		// supposed to have replaced the first and has not touched the
		// second. The content being merged is what distinguishes them.
		if op == "getCiConfig" {
			content, _ := body.Variables["content"].(string)
			if strings.Contains(content, "local_job") {
				op = "getCiConfig (project config merge)"
			} else {
				op = "getCiConfig (per-include merge)"
			}
		}
		g.record("POST /api/graphql " + op)
		g.graphql(w, op, body.Variables)
		return
	}

	normalized := rawFileSeg.ReplaceAllString(r.URL.EscapedPath(), "$1:file")
	normalized = singleRef.ReplaceAllString(normalized, "$1:ref")
	normalized = encodedPath.ReplaceAllString(normalized, "/:id")
	normalized = numericID.ReplaceAllString(normalized, "/:id$1")
	g.record(r.Method + " " + normalized)

	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.HasSuffix(path, "/repository/commits"):
		_, _ = fmt.Fprintf(w, `[{"id":%q}]`, g.sha)
	case strings.Contains(path, "/repository/files/"):
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(rootCIConfig))
	case strings.HasSuffix(path, "/repository/branches"):
		_, _ = w.Write([]byte(`[{"name":"main"}]`))
	case strings.HasSuffix(path, "/repository/tags"):
		_, _ = w.Write([]byte(`[]`))
	case strings.Contains(path, "/repository/tags/"), strings.Contains(path, "/repository/branches/"):
		if g.failRefProbes {
			// NOT a 404. A 404 means "not that kind of ref", which is an
			// answer; this is the probe failing to complete at all. 403 is
			// the realistic shape (a token that can read this project but
			// not the include's source) and, unlike a 5xx, the GitLab
			// client does not spend its retry budget on it.
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"403 Forbidden"}`))
			return
		}
		// Single-ref probes (ref-confusion): "not that kind of ref".
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"404 Not Found"}`))
	case strings.HasSuffix(path, "/protected_branches"):
		_, _ = w.Write([]byte(`[]`))
	case strings.HasSuffix(path, "/approval_rules"):
		_, _ = w.Write([]byte(`[]`))
	case strings.HasSuffix(path, "/approvals"):
		_, _ = w.Write([]byte(`{}`))
	case strings.HasSuffix(path, "/members/all"):
		_, _ = w.Write([]byte(`[]`))
	default:
		// GET /projects/:id — the project payload.
		_, _ = fmt.Fprintf(w, `{"id":42,"name":"project","path_with_namespace":%q,"default_branch":"main","archived":false,"namespace":{"id":9,"kind":"group"}}`, testProjectPath)
	}
}

func (g *gitlabRecorder) graphql(w http.ResponseWriter, op string, _ map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	switch op {
	case "getCiConfig (project config merge)":
		// The project's own merge. It echoes back the SAME include the
		// platform snapshot carries, so both modes walk an identical
		// include list and the two ledgers differ only where the lane
		// split made them differ.
		_, _ = w.Write(ciConfigResponse(mergedYAML, []any{map[string]any{
			"location":       "$CI_SERVER_FQDN/vendor/components/build@1.0.0",
			"type":           "component",
			"contextProject": testProjectPath,
			"blob":           "blobsha",
		}}))
	case "getCiConfig (per-include merge)":
		// What one include contributes, resolved on its own.
		_, _ = w.Write(ciConfigResponse("component_job:\n  script:\n    - echo component\n", []any{}))
	case "getCIComponentResource":
		_, _ = w.Write([]byte(`{"data":{"ciCatalogResource":null}}`))
	case "getSecurityPolicyProject":
		_, _ = w.Write([]byte(`{"data":{"project":{"securityPolicyProject":null}}}`))
	default:
		// The three variable queries and anything else: an empty listing.
		_, _ = w.Write([]byte(`{"data":{"project":{"ciVariables":{"nodes":[],"pageInfo":{"hasNextPage":false}}}}}`))
	}
}

// ciConfigResponse renders GitLab's ciConfig GraphQL payload.
func ciConfigResponse(merged string, includes []any) []byte {
	out, _ := json.Marshal(map[string]any{
		"data": map[string]any{
			"ciConfig": map[string]any{
				"mergedYaml": merged,
				"errors":     []string{},
				"status":     "VALID",
				"includes":   includes,
			},
		},
	})
	return out
}

const testProjectPath = "group/project"

// rootCIConfig is the project's own .gitlab-ci.yml: one hardcoded job and
// one component include, so the include loop has something to walk.
const rootCIConfig = `include:
  - component: $CI_SERVER_FQDN/vendor/components/build@1.0.0

local_job:
  image: alpine:latest
  script:
    - echo local
`

// mergedYAML is what the platform's snapshot serves: the resolved result of
// rootCIConfig, carrying both jobs.
const mergedYAML = `local_job:
  image: alpine:latest
  script:
    - echo local
component_job:
  image: alpine:3.20
  script:
    - echo component
`

// allControlsEnabled turns on every GitLab control that gates a collection,
// so the ledger is the WORST case rather than whatever the shipped default
// happens to enable. A control that ships disabled would otherwise hide its
// collection from this inventory.
const allControlsEnabled = `version: "2.0"
gitlab:
  controls:
    branchMustBeProtected:
      enabled: true
      defaultMustBeProtected: true
    mergeRequestApprovalRulesMustRequireMinimumApprovals:
      enabled: true
      minimumApprovals: 1
    mergeRequestApprovalRulesMustCoverAllProtectedBranches:
      enabled: true
    mergeRequestApprovalSettingsMustBeCompliant:
      enabled: true
    mergeRequestSettingsMustBeCompliant:
      enabled: true
      mergeMethod: ff
    cicdVariablesMustBeProtected:
      enabled: true
    cicdVariablesMustBeMasked:
      enabled: true
    projectMustHaveSecurityPolicySource:
      enabled: true
    containerImageMustNotUseForbiddenTags:
      enabled: true
      tags: [latest]
    pipelineMustNotIncludeHardcodedJobs:
      enabled: true
    includesMustBeUpToDate:
      enabled: true
    externalRefsMustNotCollide:
      enabled: true
    includesMustNotUseForbiddenVersions:
      enabled: true
    pipelineMustNotOverrideJobVariables:
      enabled: true
`

// platformSnapshot builds the RunContext a fully-served platform run has:
// a merged configuration whose digest matched the anchor, plus the
// per-include attribution that goes with it.
func platformSnapshot(t *testing.T, sha string) *platform.RunContext {
	t.Helper()

	include, err := json.Marshal(map[string]any{
		"location":       "$CI_SERVER_FQDN/vendor/components/build@1.0.0",
		"type":           "component",
		"contextProject": testProjectPath,
		"blob":           "blobsha",
	})
	if err != nil {
		t.Fatalf("marshaling the snapshot include: %v", err)
	}

	collected := time.Now().UTC()
	return &platform.RunContext{
		Endpoint:    "https://platform.test",
		ProjectPath: testProjectPath,
		Context: &platform.ProjectContext{
			Project: testProjectPath,
			Policies: []platform.Policy{
				{ID: "11111111-1111-1111-1111-111111111111", Name: "P", Enforcement: platform.EnforcementReport},
			},
			Snapshot: platform.Snapshot{
				CollectedAt: &collected,
				Data: &platform.SnapshotData{
					SchemaVersion:    platform.SnapshotSchemaV2,
					CiConfigPath:     ".gitlab-ci.yml",
					MergedYaml:       mergedYAML,
					Includes:         []json.RawMessage{include},
					BranchProtection: json.RawMessage(`{"branches":["main"],"protections":[]}`),
					MrApprovals:      json.RawMessage(`{"rules":[],"settings":{}}`),
					Variables:        json.RawMessage(`{"items":[]}`),
					ResolutionAnchor: &platform.ResolutionAnchor{
						Ref: "main", Sha: sha,
						ConfigDigest: "abc", DigestVersion: platform.LocalDigestVersion,
					},
				},
			},
		},
		Config: &platform.ConfigResolution{
			Source:        platform.SourceSnapshot,
			MergedYAML:    mergedYAML,
			Digest:        platform.DigestMatch,
			LocalDigest:   "abc",
			DigestVersion: platform.LocalDigestVersion,
			AnchorRef:     "main",
			AnchorSha:     sha,
			AnchorDigest:  "abc",
			Valid:         true,
		},
	}
}

func inventoryConf(t *testing.T, serverURL string) *configuration.Configuration {
	t.Helper()
	pc, _, _, err := configuration.LoadPlumberConfigFromBytes([]byte(allControlsEnabled), "inventory-test")
	if err != nil {
		t.Fatalf("loading the test config: %v", err)
	}
	conf := configuration.NewDefaultConfiguration()
	conf.GitlabURL = serverURL
	conf.GitlabToken = "glpat-inventory"
	conf.ProjectPath = testProjectPath
	conf.HTTPClientTimeout = 10 * time.Second
	// One attempt per request: the retry wrapper would multiply a
	// deliberate 404 probe into three ledger entries and say nothing about
	// which endpoints a run touches.
	conf.GitlabRetryMaxRetries = 0
	conf.PlumberConfig = pc
	return conf
}

// platformSnapshotWithObservations is platformSnapshot plus the upstream
// observations a host serves for each include: whether the pinned ref names a
// tag and a branch in the SOURCE project, and that project's raw catalogue
// listing.
//
// These are the only facts in the run that cannot be answered from the
// scanned project. Supplying them is what lets a runner with no credential
// for the source project still evaluate ISSUE-401 and ISSUE-402, and the
// ledger below measures the difference.
func platformSnapshotWithObservations(t *testing.T, sha string) *platform.RunContext {
	t.Helper()
	run := platformSnapshot(t, sha)

	include, err := json.Marshal(map[string]any{
		"location":       "$CI_SERVER_FQDN/vendor/components/build@1.0.0",
		"type":           "component",
		"contextProject": testProjectPath,
		"blob":           "blobsha",

		// A determined pair: the pin is a tag and not a branch, so the ref
		// is unambiguous. Note this is an ANSWER, not an absence - the
		// control renders a verdict from it rather than abstaining.
		"ref_exists_as_tag":    true,
		"ref_exists_as_branch": false,

		// The catalogue verbatim. 2.0.0 exists but dropped the component,
		// so the newest version still carrying "build" is 1.0.0 and the pin
		// is current. A host that reduced this to a latest_version field
		// would have had to pick, and picking 2.0.0 reports an upgrade to a
		// version without the component.
		"source_catalog": map[string]any{
			"versions": []any{
				map[string]any{"name": "2.0.0", "components": []any{map[string]any{"name": "other"}}},
				map[string]any{"name": "1.0.0", "components": []any{map[string]any{"name": "build"}}},
			},
		},

		// The attribution the host already resolved. jobs_known is what
		// permits the CLI to skip its own per-include config merge; an empty
		// list with jobs_known true would be just as authoritative.
		"jobs":       []any{"component_job"},
		"jobs_known": true,
	})
	if err != nil {
		t.Fatalf("marshaling the observed include: %v", err)
	}
	run.Context.Snapshot.Data.Includes = []json.RawMessage{include}
	return run
}

// runInventoryWithObservations is runInventory's platform half, served the
// upstream observations as well as the lanes.
func runInventoryWithObservations(t *testing.T) []string {
	t.Helper()
	rec := &gitlabRecorder{sha: "0123456789abcdef0123456789abcdef01234567"}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	conf := inventoryConf(t, srv.URL)
	conf.PlatformRun = platformSnapshotWithObservations(t, rec.sha)
	if _, err := RunAnalysis(conf); err != nil {
		t.Fatalf("analysis failed: %v", err)
	}
	return rec.ledger()
}

// runInventory performs one analysis against a recording GitLab and
// returns the ledger of requests it made.
func runInventory(t *testing.T, platformMode bool) []string {
	t.Helper()
	rec := &gitlabRecorder{sha: "0123456789abcdef0123456789abcdef01234567"}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	conf := inventoryConf(t, srv.URL)
	if platformMode {
		conf.PlatformRun = platformSnapshot(t, rec.sha)
	}
	if _, err := RunAnalysis(conf); err != nil {
		t.Fatalf("analysis failed (platformMode=%v): %v", platformMode, err)
	}
	return rec.ledger()
}

// TestGitLabCallInventory is the standing answer to "which GitLab endpoints
// does a run still hit, and which of them has the platform taken over".
//
// Both halves analyse the same project with the same controls enabled, and
// the platform half is served a COMPLETE snapshot: merged configuration,
// include attribution, branch protection, MR approvals and variables. Any
// request that still appears on the platform side is therefore a collection
// the lane split has not taken over, never a lane the platform failed to
// serve.
//
// Update these ledgers deliberately. A line leaving the platform ledger is
// progress on #368 step 3; a line arriving in it is a runner making a call
// the platform was supposed to have made already.
func TestGitLabCallInventory(t *testing.T) {
	standalone := runInventory(t, false)
	platformRun := runInventory(t, true)

	t.Logf("standalone GitLab requests (%d):\n  %s", totalRequests(standalone), strings.Join(standalone, "\n  "))
	t.Logf("platform-mode GitLab requests (%d):\n  %s", totalRequests(platformRun), strings.Join(platformRun, "\n  "))

	// Two requests for GET /projects/:id is not a miscount: RunAnalysis
	// fetches the project payload once for its own identity fields, and the
	// protection collection fetches the same payload again for the merge
	// settings. Two for getProjectVariables likewise: the image collection
	// reads the VALUES to expand image refs, and the settings-variable
	// collection reads the FLAGS.
	wantStandalone := []string{
		"1x GET /api/v4/projects/:id/approval_rules",
		"1x GET /api/v4/projects/:id/approvals",
		"1x GET /api/v4/projects/:id/protected_branches",
		"1x GET /api/v4/projects/:id/repository/branches",
		"1x GET /api/v4/projects/:id/repository/branches/:ref",
		"1x GET /api/v4/projects/:id/repository/commits",
		"1x GET /api/v4/projects/:id/repository/files/:file/raw",
		"1x GET /api/v4/projects/:id/repository/tags/:ref",
		"1x POST /api/graphql getCIComponentResource",
		"1x POST /api/graphql getCiConfig (per-include merge)",
		"1x POST /api/graphql getCiConfig (project config merge)",
		"1x POST /api/graphql getProjectGroupsVariables",
		"1x POST /api/graphql getSecurityPolicyProject",
		"2x GET /api/v4/projects/:id",
		"2x POST /api/graphql getProjectVariables",
	}
	if diff := ledgerDiff(wantStandalone, standalone); diff != "" {
		t.Errorf("standalone call inventory changed:\n%s", diff)
	}

	// What the platform has taken over: the project's config merge, branch
	// protection, MR approval rules and settings, the settings-variable
	// flags, and the security-policy read (which no lane can feed, so the
	// runner no longer spends a credential discovering that).
	//
	// What is left, and why each one is still here:
	//
	//   GET /projects/:id + /repository/commits
	//     the project's identity, default branch, CI config path and head
	//     sha. Inside CI the predefined CI_* variables carry most of this;
	//     `archived` has no predefined equivalent and no snapshot lane.
	//   /repository/files/:file/raw
	//     the project's OWN (unmerged) CI file, which hardcoded-job
	//     detection compares the merged pipeline against. A run with a
	//     checkout reads it from disk instead; this fixture has none.
	//   getCiConfig (per-include merge)
	//     ONE PER INCLUDE. Attribution of jobs to the include that
	//     contributed them is derived by re-merging each include on its
	//     own. The snapshot's includes[] says which includes exist, not
	//     which jobs each one brought.
	//   getCIComponentResource, /repository/tags/:ref, /repository/branches/:ref
	//     per component: the upstream latest version (ISSUE-401) and
	//     whether the pinned ref is both a tag and a branch (ISSUE-402).
	//     Both query the include's SOURCE project, not this one.
	//
	// The variable-VALUE reads are gone: inside CI the job's own
	// environment already holds them, reduced across every scope and
	// filtered to what this job may see, so the platform serving variable
	// NAMES and the job supplying the values is sufficient. A reference
	// that still does not resolve is marked and the image rules abstain on
	// it rather than judging a placeholder.
	wantPlatform := []string{
		"1x GET /api/v4/projects/:id",
		"1x GET /api/v4/projects/:id/repository/branches/:ref",
		"1x GET /api/v4/projects/:id/repository/commits",
		"1x GET /api/v4/projects/:id/repository/files/:file/raw",
		"1x GET /api/v4/projects/:id/repository/tags/:ref",
		"1x POST /api/graphql getCIComponentResource",
		"1x POST /api/graphql getCiConfig (per-include merge)",
	}
	if diff := ledgerDiff(wantPlatform, platformRun); diff != "" {
		t.Errorf("platform-mode call inventory changed:\n%s", diff)
	}
}

// TestPlatformModeRemovesMostGitLabRequests states the headline as an
// assertion rather than leaving it to be read off two ledgers. It is the
// measurement #368's third criterion is scored against, so it should be the
// thing that fails when the score changes.
//
// The remaining requests are NOT a rounding error: they are the project
// identity read, the project's own CI file, and the per-include and
// variable-value enrichment. The first two are closable inside the CLI
// (predefined CI variables, the job checkout); the rest need the platform
// to serve data it does not serve today.
func TestPlatformModeRemovesMostGitLabRequests(t *testing.T) {
	standalone := totalRequests(runInventory(t, false))
	platformRun := totalRequests(runInventory(t, true))

	const wantStandaloneTotal = 17
	const wantPlatformTotal = 7

	if standalone != wantStandaloneTotal || platformRun != wantPlatformTotal {
		t.Errorf("GitLab request totals changed: standalone %d (want %d), platform %d (want %d).\n"+
			"A LOWER platform number is progress on #368 step 3 and this constant should be updated; "+
			"a higher one means a collection came back.",
			standalone, wantStandaloneTotal, platformRun, wantPlatformTotal)
	}
}

// totalRequests sums a ledger's counts back into a request total.
func totalRequests(ledger []string) int {
	total := 0
	for _, line := range ledger {
		var n int
		if _, err := fmt.Sscanf(line, "%dx ", &n); err == nil {
			total += n
		}
	}
	return total
}

// ledgerDiff renders the two ledgers as +/- lines. A plain reflect.DeepEqual
// failure prints two 14-line slices and leaves the reader to spot the one
// that moved.
func ledgerDiff(want, got []string) string {
	wantSet := map[string]bool{}
	for _, w := range want {
		wantSet[w] = true
	}
	gotSet := map[string]bool{}
	for _, g := range got {
		gotSet[g] = true
	}
	var b strings.Builder
	for _, w := range want {
		if !gotSet[w] {
			fmt.Fprintf(&b, "  - %s (expected, not made)\n", w)
		}
	}
	for _, g := range got {
		if !wantSet[g] {
			fmt.Fprintf(&b, "  + %s (made, not expected)\n", g)
		}
	}
	return b.String()
}

// TestSwitchedLanesReportTheSameVerdicts is the other half of the ledger.
//
// Removing a call is only progress if the verdict survives it. The fake
// GitLab and the snapshot fixture describe the SAME project - one branch
// named main, no branch protections, no approval rules, no settings
// variables - so a lane that moved from the API to the snapshot must
// produce the identical finding it produced before.
//
// The rule this enforces is the one `scripts/platform-e2e/compare.sh`
// enforces against a real project: platform mode may report LESS than a
// standalone run, never something DIFFERENT. Fewer findings is a lane
// honestly saying it has no data. A finding that changes, or appears, is a
// lane that went missing and left a field WRONG rather than absent.
func TestSwitchedLanesReportTheSameVerdicts(t *testing.T) {
	verdicts := func(platformMode bool) (map[string]int, map[string]string) {
		rec := &gitlabRecorder{sha: "0123456789abcdef0123456789abcdef01234567"}
		srv := httptest.NewServer(rec)
		defer srv.Close()

		conf := inventoryConf(t, srv.URL)
		if platformMode {
			conf.PlatformRun = platformSnapshot(t, rec.sha)
		}
		result, err := RunAnalysis(conf)
		if err != nil {
			t.Fatalf("analysis failed (platformMode=%v): %v", platformMode, err)
		}
		counts := map[string]int{}
		for _, f := range result.Findings {
			counts[f.Code]++
		}
		return counts, result.NotEvaluable
	}

	standalone, _ := verdicts(false)
	platformRun, notEvaluable := verdicts(true)

	t.Logf("standalone findings: %v", standalone)
	t.Logf("platform findings:   %v", platformRun)
	t.Logf("platform not_evaluable: %v", notEvaluable)

	// ISSUE-501 is the switched lane's own verdict: main exists and is
	// unprotected, in both the API fixture and the snapshot fixture. If the
	// snapshot lane silently produced no branches this would vanish, which
	// is the false pass the whole lane split has to avoid.
	if standalone["ISSUE-501"] == 0 {
		t.Fatal("fixture no longer produces ISSUE-501 standalone; the parity check below would be vacuous")
	}
	if platformRun["ISSUE-501"] != standalone["ISSUE-501"] {
		t.Errorf("branchMustBeProtected changed verdict across the lane switch: standalone %d, platform %d",
			standalone["ISSUE-501"], platformRun["ISSUE-501"])
	}

	for code, n := range platformRun {
		if before := standalone[code]; n > before {
			t.Errorf("platform mode reported MORE %s than standalone (%d vs %d); "+
				"a lane went missing and left a field wrong rather than absent", code, n, before)
		}
	}

	// Every control that lost findings must say why, rather than reading as
	// a clean pass.
	for code, before := range standalone {
		if platformRun[code] < before {
			info := LookupCode(ErrorCode(code))
			if info == nil {
				t.Errorf("%s lost findings in platform mode and has no control to attribute that to", code)
				continue
			}
			if _, marked := notEvaluable[info.ControlName]; !marked {
				t.Errorf("%s went from %d findings to %d in platform mode without %s being marked not_evaluable",
					code, before, platformRun[code], info.ControlName)
			}
		}
	}
}

// inCIJob sets the predefined variables GitLab defines in every job, and
// gives the run a checkout holding the project's own CI file. Together they
// are what platform mode substitutes for the project lookup and the raw-file
// read.
func inCIJob(t *testing.T, conf *configuration.Configuration, sha string) {
	t.Helper()
	checkout := t.TempDir()
	if err := os.WriteFile(filepath.Join(checkout, ".gitlab-ci.yml"), []byte(rootCIConfig), 0o600); err != nil {
		t.Fatalf("writing the checkout's CI file: %v", err)
	}
	conf.GitRepoRoot = checkout
	conf.CheckoutIsAnalyzedProject = true
	conf.Branch = "main"

	t.Setenv("CI", "true")
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_PROJECT_ID", "42")
	t.Setenv("CI_PROJECT_NAME", "project")
	t.Setenv("CI_PROJECT_PATH", testProjectPath)
	t.Setenv("CI_DEFAULT_BRANCH", "main")
	t.Setenv("CI_COMMIT_REF_NAME", "main")
	t.Setenv("CI_COMMIT_SHA", sha)
	t.Setenv("CI_CONFIG_PATH", ".gitlab-ci.yml")
	// A CI/CD variable the analysed pipeline expands into an image
	// reference. In a real job GitLab exports it; here it stands for the
	// whole class, and it is why the three variable-value queries are gone.
	t.Setenv("CI_REGISTRY_IMAGE", "registry.example.com/group/project")
}

// TestTokenlessCIRunCompletes is the acceptance test for #368's own words:
// a CI job holding only its OIDC id-token, with no GITLAB_TOKEN at all,
// must produce a report rather than an error.
//
// Every GitLab request in this test is refused. Before the migration that
// was fatal on the first one - the project lookup is the first call a run
// makes, a 401 is not a network error, and the run aborted with no report
// at all. What must happen instead is a complete analysis of everything the
// platform served, with the collections that have not moved yet reporting
// not_evaluable under their own reason.
func TestTokenlessCIRunCompletes(t *testing.T) {
	rec := &gitlabRecorder{sha: "0123456789abcdef0123456789abcdef01234567"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r.Method + " " + r.URL.EscapedPath())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"401 Unauthorized"}`))
	}))
	defer srv.Close()

	conf := inventoryConf(t, srv.URL)
	conf.GitlabToken = ""
	conf.PlatformRun = platformSnapshot(t, rec.sha)
	inCIJob(t, conf, rec.sha)

	result, err := RunAnalysis(conf)
	if err != nil {
		t.Fatalf("a tokenless platform run must produce a report, not an error: %v", err)
	}
	if result == nil {
		t.Fatal("no result")
	}
	if !result.CiValid || result.CiMissing {
		t.Fatalf("the pipeline came from the snapshot and must be valid: CiValid=%v CiMissing=%v", result.CiValid, result.CiMissing)
	}

	// Exit code 3 fails the GitLab job, so a run that reports honestly and
	// still fails the pipeline has not solved the problem. The merged
	// pipeline came from the platform and holds every job; the per-include
	// merges that failed cost ATTRIBUTION, not jobs, and that loss is
	// already carried by the not_evaluable marks below. Degrading on top of
	// it would withhold the score for a loss that did not happen.
	if result.DataCollectionDegraded {
		t.Errorf("a tokenless platform run must not be degraded: %v", result.DegradedReasons)
	}

	t.Logf("GitLab requests attempted (all refused): %v", rec.ledger())
	t.Logf("not_evaluable: %v", result.NotEvaluable)

	codes := map[string]int{}
	for _, f := range result.Findings {
		codes[f.Code]++
	}
	t.Logf("findings: %v", codes)

	// The lanes the platform served must produce real verdicts. ISSUE-501 is
	// branch protection, straight out of the snapshot; ISSUE-504 is the MR
	// approval rules. Neither needed GitLab.
	for _, code := range []string{"ISSUE-501", "ISSUE-504"} {
		if codes[code] == 0 {
			t.Errorf("%s should have been evaluated from the snapshot, with no token", code)
		}
	}

	// Everything that still needs GitLab must SAY it could not be
	// evaluated. A control that silently passes here is the failure this
	// whole design is about.
	for _, control := range []string{
		"pipelineMustNotIncludeHardcodedJobs",
		"externalRefsMustNotCollide",
		"includesMustBeUpToDate",
		"projectMustHaveSecurityPolicySource",
		"mergeRequestSettingsMustBeCompliant",
	} {
		if _, marked := result.NotEvaluable[control]; !marked {
			t.Errorf("%s could not be evaluated without a token and must say so, not pass", control)
		}
	}
}

// TestTokenlessCIRunMakesFewRequests records what a CI job still asks GitLab
// for. Everything here is blocked on the platform serving data it does not
// serve yet (see message-platform-snapshot-gaps.md); when it does, this
// number goes to zero and the run needs no GitLab access whatsoever.
func TestTokenlessCIRunMakesFewRequests(t *testing.T) {
	rec := &gitlabRecorder{sha: "0123456789abcdef0123456789abcdef01234567"}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	conf := inventoryConf(t, srv.URL)
	conf.PlatformRun = platformSnapshot(t, rec.sha)
	inCIJob(t, conf, rec.sha)

	if _, err := RunAnalysis(conf); err != nil {
		t.Fatalf("analysis failed: %v", err)
	}

	got := rec.ledger()
	t.Logf("platform-mode-in-CI GitLab requests (%d):\n  %s", totalRequests(got), strings.Join(got, "\n  "))

	// The project lookup, its commit lookup and the raw-file read are gone:
	// the job's own environment and its checkout answer all three. What is
	// left is per-include work against OTHER projects, which only the
	// platform can pre-collect.
	want := []string{
		"1x GET /api/v4/projects/:id/repository/branches/:ref",
		"1x GET /api/v4/projects/:id/repository/tags/:ref",
		"1x POST /api/graphql getCIComponentResource",
		"1x POST /api/graphql getCiConfig (per-include merge)",
	}
	if diff := ledgerDiff(want, got); diff != "" {
		t.Errorf("tokenless CI call inventory changed:\n%s", diff)
	}
}

// TestAnalyzedRefDecidesWhetherTheHeadShaIsCorrected covers a substitution
// that is right almost always, which is what makes the exception dangerous.
//
// $CI_COMMIT_SHA is the head of the ref the JOB is building. That is the
// analysed ref whenever the run does not name a different one - the normal
// case, and the component's default. Name a different one and the two come
// apart: the run would read release/2.0's CI file while resolving its
// include:local entries against the sha of main. Both configurations parse,
// so nothing downstream notices.
func TestAnalyzedRefDecidesWhetherTheHeadShaIsCorrected(t *testing.T) {
	const otherSha = "fedcba9876543210fedcba9876543210fedcba98"

	run := func(t *testing.T, branch string) ([]string, string) {
		t.Helper()
		rec := &gitlabRecorder{sha: otherSha}
		srv := httptest.NewServer(rec)
		defer srv.Close()

		conf := inventoryConf(t, srv.URL)
		conf.PlatformRun = platformSnapshot(t, "0123456789abcdef0123456789abcdef01234567")
		inCIJob(t, conf, "0123456789abcdef0123456789abcdef01234567")
		conf.Branch = branch

		result, err := RunAnalysis(conf)
		if err != nil {
			t.Fatalf("analysis failed: %v", err)
		}
		return rec.ledger(), result.HeadCommitSha
	}

	t.Run("analysing the ref the job built: no extra request", func(t *testing.T) {
		ledger, sha := run(t, "main") // == CI_COMMIT_REF_NAME
		for _, line := range ledger {
			if strings.Contains(line, "/repository/commits") {
				t.Errorf("the environment already carries this ref's sha; no lookup should happen: %v", ledger)
			}
		}
		if sha != "0123456789abcdef0123456789abcdef01234567" {
			t.Errorf("head sha = %q, want $CI_COMMIT_SHA", sha)
		}
	})

	t.Run("analysing a different ref: the sha must be looked up", func(t *testing.T) {
		ledger, sha := run(t, "release/2.0")
		found := false
		for _, line := range ledger {
			if strings.Contains(line, "/repository/commits") {
				found = true
			}
		}
		if !found {
			t.Errorf("analysing a ref the job did not build needs its own sha: %v", ledger)
		}
		if sha == "0123456789abcdef0123456789abcdef01234567" {
			t.Error("the job's own commit was used for a different ref; its include:local entries would resolve against the wrong tree")
		}
	})
}

// TestCIRunWithNoCheckoutStaysUseful covers the job that has no working
// tree: GIT_STRATEGY none, a sparse checkout, or a ci_config_path pointing
// into another project.
//
// The project's own UNMERGED CI file is then unreadable, and it used to
// take the whole analysis with it - the run returned before the rule engine
// and before the lane marking, so it produced no findings AND no
// explanation for their absence. An empty report that says nothing is the
// least useful outcome available, and it failed the job on top.
//
// The merged pipeline comes from the platform and is what almost every rule
// reads, so the run is still worth having. What is genuinely lost is the
// pre-merge document, which two controls compare against - and both of them
// fail SILENTLY without it, which is why they have to be marked rather than
// left to report nothing.
func TestCIRunWithNoCheckoutStaysUseful(t *testing.T) {
	rec := &gitlabRecorder{sha: "0123456789abcdef0123456789abcdef01234567"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r.Method + " " + r.URL.EscapedPath())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"401 Unauthorized"}`))
	}))
	defer srv.Close()

	conf := inventoryConf(t, srv.URL)
	conf.GitlabToken = ""
	conf.PlatformRun = platformSnapshot(t, rec.sha)
	inCIJob(t, conf, rec.sha)
	conf.CheckoutIsAnalyzedProject = false
	conf.GitRepoRoot = ""

	result, err := RunAnalysis(conf)
	if err != nil {
		t.Fatalf("a run with no checkout must still report: %v", err)
	}
	if !result.CiValid {
		t.Error("the merged pipeline came from the platform and is analysable")
	}
	if result.DataCollectionDegraded {
		t.Errorf("nothing the platform served went missing: %v", result.DegradedReasons)
	}
	if len(result.Findings) == 0 {
		t.Error("the controls the snapshot feeds must still produce verdicts")
	}

	reason, marked := result.NotEvaluable["pipelineMustNotOverrideJobVariables"]
	if !marked {
		t.Fatal("this control compares against the pre-merge file; with the file unread it must abstain, not pass")
	}
	if reason != ReasonRawConfigUnavailable {
		t.Errorf("reason = %q, want %q", reason, ReasonRawConfigUnavailable)
	}
}

// TestAnalyzedRefFollowsTheCheckoutWhenNoBranchIsNamed covers a mislabelling
// that produces a perfectly normal-looking report.
//
// ToProjectInfo defaults AnalyzeBranch to the project's DEFAULT branch,
// which is the right guess for a run that had to ask the API what it was
// looking at. A CI job knows better: it analyses the ref it checked out. Get
// this wrong and the findings are correct while every source link points at
// a ref that does not contain them.
func TestAnalyzedRefFollowsTheCheckoutWhenNoBranchIsNamed(t *testing.T) {
	rec := &gitlabRecorder{sha: "0123456789abcdef0123456789abcdef01234567"}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	conf := inventoryConf(t, srv.URL)
	conf.PlatformRun = platformSnapshot(t, rec.sha)
	inCIJob(t, conf, rec.sha)

	// A feature-branch pipeline: the job checked out feature/x, the default
	// branch is still main, and the run names no branch of its own.
	conf.Branch = ""
	t.Setenv("CI_COMMIT_REF_NAME", "feature/x")

	result, err := RunAnalysis(conf)
	if err != nil {
		t.Fatalf("analysis failed: %v", err)
	}
	if result.AnalyzeBranch != "feature/x" {
		t.Errorf("AnalyzeBranch = %q, want the ref the job checked out; source links follow this", result.AnalyzeBranch)
	}
	if result.DefaultBranch != "main" {
		t.Errorf("DefaultBranch = %q, want main; the two are different facts", result.DefaultBranch)
	}
}

// TestExternalCIConfigPathIsNotFetched covers a ci_config_path that names
// another project. It is a supported GitLab setting, $CI_CONFIG_PATH exports
// it verbatim, and this project's file API cannot serve it - so fetching it
// spends a request that can only 404.
func TestExternalCIConfigPathIsNotFetched(t *testing.T) {
	rec := &gitlabRecorder{sha: "0123456789abcdef0123456789abcdef01234567"}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	conf := inventoryConf(t, srv.URL)
	conf.PlatformRun = platformSnapshot(t, rec.sha)
	inCIJob(t, conf, rec.sha)
	// No checkout, so the read would otherwise fall through to the API.
	conf.CheckoutIsAnalyzedProject = false
	conf.GitRepoRoot = ""
	conf.CIConfigPathOverride = "shared.yml@platform/ci-templates"

	result, err := RunAnalysis(conf)
	if err != nil {
		t.Fatalf("analysis failed: %v", err)
	}
	for _, line := range rec.ledger() {
		if strings.Contains(line, "/repository/files/") {
			t.Errorf("the config lives in another project; this request can only 404: %v", rec.ledger())
		}
	}
	// The merged pipeline still came from the platform, so the run is real.
	if !result.CiValid {
		t.Error("an external config must not invalidate the run; the merged pipeline is intact")
	}
	if _, marked := result.NotEvaluable["pipelineMustNotOverrideJobVariables"]; !marked {
		t.Error("the pre-merge document is unavailable, so the control that compares against it must abstain")
	}
}

// TestSuppliedObservationsRemoveTheUpstreamProbes measures the aggregator
// boundary (#368). The three requests that leave are the only ones in the run
// aimed at a project OTHER than the one being scanned: the include's source.
//
// That is what makes them different in kind. Every other call can be answered
// by a CI job's own credentials, or read from the checkout. These cannot, so a
// tokenless runner either receives them from a host that could ask, or the two
// include controls have no evidence.
func TestSuppliedObservationsRemoveTheUpstreamProbes(t *testing.T) {
	probed := runInventory(t, true)
	observed := runInventoryWithObservations(t)

	t.Logf("platform, probing upstream (%d):\n  %s", totalRequests(probed), strings.Join(probed, "\n  "))
	t.Logf("platform, observations served (%d):\n  %s", totalRequests(observed), strings.Join(observed, "\n  "))

	// What remains is the scanned project's own identity and its unmerged CI
	// file. Everything aimed at an include's SOURCE project is gone, and so
	// is the per-include merge: the host resolved the attribution, so the
	// runner does not resolve it again.
	wantObserved := []string{
		"1x GET /api/v4/projects/:id",
		"1x GET /api/v4/projects/:id/repository/commits",
		"1x GET /api/v4/projects/:id/repository/files/:file/raw",
	}
	if diff := ledgerDiff(wantObserved, observed); diff != "" {
		t.Errorf("call inventory with observations served changed:\n%s", diff)
	}

	// Named individually rather than by count, so a future change that
	// removes one of these and adds an unrelated request cannot pass.
	for _, gone := range []string{
		"1x GET /api/v4/projects/:id/repository/tags/:ref",
		"1x GET /api/v4/projects/:id/repository/branches/:ref",
		"1x POST /api/graphql getCIComponentResource",
		"1x POST /api/graphql getCiConfig (per-include merge)",
	} {
		if slices.Contains(observed, gone) {
			t.Errorf("%q should not be requested when the host supplied the observation", gone)
		}
		if !slices.Contains(probed, gone) {
			t.Errorf("%q is missing from the probing run, so this test proves nothing", gone)
		}
	}
}

// TestObservationsReachTheSameVerdictAsProbing is the other half, and the one
// that matters more: fewer requests are worthless if they were bought by
// abstaining.
//
// The same includes, judged from supplied observations and from live probes,
// must produce the same findings and the same not-evaluable set. They do
// because the JUDGEMENT is the same code either way - only the source of the
// facts changed. That is the property the aggregator boundary buys, and it is
// exactly what a host serving conclusions instead cannot guarantee.
func TestObservationsReachTheSameVerdictAsProbing(t *testing.T) {
	verdicts := func(observed bool) (map[string]int, map[string]string) {
		rec := &gitlabRecorder{sha: "0123456789abcdef0123456789abcdef01234567"}
		srv := httptest.NewServer(rec)
		defer srv.Close()

		conf := inventoryConf(t, srv.URL)
		if observed {
			conf.PlatformRun = platformSnapshotWithObservations(t, rec.sha)
		} else {
			conf.PlatformRun = platformSnapshot(t, rec.sha)
		}
		result, err := RunAnalysis(conf)
		if err != nil {
			t.Fatalf("analysis failed (observed=%v): %v", observed, err)
		}
		counts := map[string]int{}
		for _, f := range result.Findings {
			counts[f.Code]++
		}
		return counts, result.NotEvaluable
	}

	probedFindings, probedGaps := verdicts(false)
	observedFindings, observedGaps := verdicts(true)

	if !maps.Equal(probedFindings, observedFindings) {
		t.Errorf("findings differ:\n  probed:   %v\n  observed: %v", probedFindings, observedFindings)
	}
	if !maps.Equal(probedGaps, observedGaps) {
		t.Errorf("not_evaluable differs:\n  probed:   %v\n  observed: %v", probedGaps, observedGaps)
	}
	if len(observedFindings) == 0 {
		t.Fatal("both runs found nothing, so agreeing proves nothing")
	}
}

// TestSuppliedAmbiguityIsActedOnWithoutProbing proves the observations are
// CONSUMED rather than merely permitting the probe to be skipped.
//
// The previous two tests would both pass against an implementation that
// ignored the supplied values and abstained. Here the host reports a ref that
// is both a tag and a branch, which nothing else in the fixture would produce,
// and ISSUE-402 must appear without a single request to the source project.
func TestSuppliedAmbiguityIsActedOnWithoutProbing(t *testing.T) {
	rec := &gitlabRecorder{sha: "0123456789abcdef0123456789abcdef01234567"}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	conf := inventoryConf(t, srv.URL)
	run := platformSnapshotWithObservations(t, rec.sha)

	include, err := json.Marshal(map[string]any{
		"location":       "$CI_SERVER_FQDN/vendor/components/build@1.0.0",
		"type":           "component",
		"contextProject": testProjectPath,
		"blob":           "blobsha",
		// The collision: the pin resolves upstream as a tag AND a branch.
		"ref_exists_as_tag":    true,
		"ref_exists_as_branch": true,
	})
	if err != nil {
		t.Fatalf("marshaling the ambiguous include: %v", err)
	}
	run.Context.Snapshot.Data.Includes = []json.RawMessage{include}
	conf.PlatformRun = run

	result, err := RunAnalysis(conf)
	if err != nil {
		t.Fatalf("analysis failed: %v", err)
	}

	var found bool
	for _, f := range result.Findings {
		if f.Code == string(CodeRefConfusion) {
			found = true
		}
	}
	if !found {
		t.Error("a supplied tag+branch collision must produce ISSUE-402; the observation was not consumed")
	}
	if reason, gap := result.NotEvaluable["externalRefsMustNotCollide"]; gap {
		t.Errorf("the control had its answer and must not abstain, got %q", reason)
	}
	for _, req := range rec.ledger() {
		if strings.Contains(req, "/repository/tags/") || strings.Contains(req, "/repository/branches/:ref") {
			t.Errorf("the source project was probed anyway: %s", req)
		}
	}
}

// TestStandaloneRunMarksItsOwnFailedProbes is the end-to-end guard for the
// wiring, not just the marker.
//
// The unit tests call MarkOwnCollectionGaps directly, so deleting its call
// site would leave them all green. This drives a real standalone
// RunAnalysis - no platform context anywhere - against a source project whose
// ref probes fail, and requires the control to withhold its verdict.
//
// Before the marker was lifted out of the platform gate, this run reported
// externalRefsMustNotCollide as a clean pass.
func TestStandaloneRunMarksItsOwnFailedProbes(t *testing.T) {
	rec := &gitlabRecorder{
		sha:           "0123456789abcdef0123456789abcdef01234567",
		failRefProbes: true,
	}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	conf := inventoryConf(t, srv.URL)
	// No conf.PlatformRun: this is the mode nearly every user runs.
	result, err := RunAnalysis(conf)
	if err != nil {
		t.Fatalf("analysis failed: %v", err)
	}

	reason, marked := result.NotEvaluable["externalRefsMustNotCollide"]
	if !marked {
		t.Fatalf("a standalone run whose ref probe failed must not report a pass, got notEvaluable=%v", result.NotEvaluable)
	}
	if reason != ReasonUpstreamProbeFailed {
		t.Errorf("reason = %q, want %q", reason, ReasonUpstreamProbeFailed)
	}
}
