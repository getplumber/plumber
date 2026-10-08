package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// --- One path per (entry kind, entry subject): one thing to fix is one
// path, however many jobs the entry runs in. Each entry job keeps its own
// walk and reach, and the path holds the strongest of them. ---

// multiJobPushSituation is one unprotected branch every job runs on: build
// holds a secret and publishes, scan holds a declared write token, lint
// holds nothing.
func multiJobPushSituation() *Situation {
	push := []EntryFact{{Kind: EntryUnprotectedPush, State: "proven", Evidence: "push: branches: [main]", Subject: "main"}}
	s := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{}}
	build := JobSituation{Push: push, Impact: []ImpactFact{{Kind: "publishes", State: "proven", Evidence: "npm publish"}}}
	build.Privilege.Secrets = []string{"NPM_TOKEN"}
	build.Privilege.SecretsState = "proven"
	s.Jobs["build"] = build
	s.Jobs["lint"] = JobSituation{Push: push}
	scan := JobSituation{Push: push}
	scan.Privilege.TokenWrite = []string{"security-events"}
	scan.Privilege.TokenWriteSource = "declared"
	s.Jobs["scan"] = scan
	return s
}

func pushFinding() opaengine.Finding {
	return finding(string(CodeBranchUnprotected), "", map[string]any{"branchName": "main"})
}

func TestOneEntryIntoSeveralJobsIsOnePath(t *testing.T) {
	paths := assemblePaths([]opaengine.Finding{pushFinding()}, multiJobPushSituation())
	if len(paths) != 1 {
		t.Fatalf("want one path for one branch every job runs on, got %d: %+v", len(paths), paths)
	}
	p := paths[0]
	sum := sha256.Sum256([]byte(string(EntryUnprotectedPush) + "|main"))
	if p.ID != hex.EncodeToString(sum[:])[:16] {
		t.Errorf("id = %s, want sha256(entryKind|subject)[:16]", p.ID)
	}
	if !reflect.DeepEqual(p.Jobs, []string{"build", "scan", "lint"}) {
		t.Errorf("jobs = %v, want every entry job, strongest first", p.Jobs)
	}
	if p.Tier != TierHigh || p.BaseTier != TierCritical || p.State != PathProven || !reflect.DeepEqual(p.Modifiers, []string{"push_entry_cap"}) {
		t.Errorf("path = %s/%s %s %v, want the build branch's tier and modifiers", p.Tier, p.BaseTier, p.State, p.Modifiers)
	}
	if !reflect.DeepEqual(p.Reach.Secrets, []string{"NPM_TOKEN"}) || p.ReachKind != "impact:publishes" {
		t.Errorf("reach = %+v (%s), want the build branch's", p.Reach, p.ReachKind)
	}
	if len(p.Branches) != 3 {
		t.Fatalf("branches = %+v, want one per entry job", p.Branches)
	}
	type row struct {
		job         string
		jobs        []string
		tier        PathTier
		state       PathState
		mods        []string
		write, secs int
	}
	want := []row{
		{"build", []string{"build"}, TierHigh, PathProven, []string{"push_entry_cap"}, 0, 1},
		{"scan", []string{"scan"}, TierHigh, PathProven, nil, 1, 0},
		{"lint", []string{"lint"}, TierHigh, PathProven, nil, 0, 0},
	}
	for i, w := range want {
		b := p.Branches[i]
		if b.Job != w.job || !reflect.DeepEqual(b.Jobs, w.jobs) || b.Tier != w.tier || b.State != w.state || len(b.Modifiers) != len(w.mods) {
			t.Errorf("branch %d = %+v, want %+v", i, b, w)
		}
		if len(b.Reach.TokenWrite) != w.write || len(b.Reach.Secrets) != w.secs {
			t.Errorf("branch %s reach = %+v, want its own job's only", b.Job, b.Reach)
		}
	}
}

// A job's attacker code does not get what another entry job holds: one
// job holding a secret and another deploying make two High branches, never
// one Critical.
func TestEachEntryJobKeepsItsOwnReach(t *testing.T) {
	s := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{}}
	holder := JobSituation{}
	holder.Privilege.Secrets = []string{"AWS_KEY"}
	holder.Privilege.SecretsState = "proven"
	s.Jobs["build"] = holder
	s.Jobs["deploy"] = JobSituation{Impact: []ImpactFact{{Kind: "deploys", State: "proven", Evidence: "kubectl apply -f production.yaml"}}}
	uses := map[string]any{"uses": "some/action@v1"}
	paths := assemblePaths([]opaengine.Finding{finding("ISSUE-703", "build", uses), finding("ISSUE-703", "deploy", uses)}, s)
	if len(paths) != 1 {
		t.Fatalf("want one path for one action, got %+v", paths)
	}
	p := paths[0]
	if p.Tier != TierHigh || len(p.Branches) != 2 || p.Branches[0].Tier != TierHigh || p.Branches[1].Tier != TierHigh {
		t.Errorf("path = %s with branches %+v, want High from two High branches", p.Tier, p.Branches)
	}
	if len(p.AnchorHashes) != 2 {
		t.Errorf("anchors = %v, want both findings", p.AnchorHashes)
	}
}

// A path is proven as soon as one of its entry jobs is; it is unverified
// only when every one of them is.
func TestAPathIsProvenWhenOneOfItsEntryJobsIs(t *testing.T) {
	s := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{}}
	unsure := JobSituation{Impact: []ImpactFact{{Kind: "deploys", State: "unresolvable", Evidence: "deploy.sh"}}}
	unsure.Privilege.Secrets = []string{"AWS_KEY"}
	unsure.Privilege.SecretsState = "proven"
	s.Jobs["deploy"] = unsure
	sure := JobSituation{}
	sure.Privilege.Secrets = []string{"NPM_TOKEN"}
	sure.Privilege.SecretsState = "proven"
	s.Jobs["build"] = sure
	uses := map[string]any{"uses": "some/action@v1"}
	both := []opaengine.Finding{finding("ISSUE-703", "build", uses), finding("ISSUE-703", "deploy", uses)}
	paths := assemblePaths(both, s)
	if len(paths) != 1 || paths[0].State != PathProven || paths[0].Tier != TierHigh {
		t.Fatalf("paths = %+v, want one proven High path", paths)
	}
	states := map[string]PathState{}
	for _, b := range paths[0].Branches {
		states[b.Job] = b.State
	}
	if states["build"] != PathProven || states["deploy"] != PathUnverified {
		t.Errorf("branch states = %v", states)
	}
	paths = assemblePaths(both[1:], s)
	if len(paths) != 1 || paths[0].State != PathUnverified {
		t.Errorf("paths = %+v, want the deploy branch alone unverified", paths)
	}
}

// The path lists its entry jobs first, then the jobs they feed; each
// branch walks its own entry job and the jobs it feeds.
func TestAPathListsItsEntryJobsThenTheFedJobs(t *testing.T) {
	s := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{}}
	s.Jobs["build"] = JobSituation{Feeds: []string{"publish"}}
	s.Jobs["lint"] = JobSituation{}
	pub := JobSituation{Impact: []ImpactFact{{Kind: "publishes", State: "proven", Evidence: "npm publish"}}}
	pub.Privilege.Secrets = []string{"NPM_TOKEN"}
	pub.Privilege.SecretsState = "proven"
	s.Jobs["publish"] = pub
	uses := map[string]any{"uses": "some/action@v1"}
	paths := assemblePaths([]opaengine.Finding{finding("ISSUE-703", "lint", uses), finding("ISSUE-703", "build", uses)}, s)
	if len(paths) != 1 {
		t.Fatalf("paths = %+v", paths)
	}
	p := paths[0]
	if !reflect.DeepEqual(p.Jobs, []string{"build", "lint", "publish"}) || p.Tier != TierCritical {
		t.Errorf("jobs = %v tier %s", p.Jobs, p.Tier)
	}
	if len(p.Branches) != 2 || !reflect.DeepEqual(p.Branches[0].Jobs, []string{"build", "publish"}) || !reflect.DeepEqual(p.Branches[1].Jobs, []string{"lint"}) {
		t.Errorf("branches = %+v", p.Branches)
	}
}

// Each branch carries, per job it feeds, the kinds of edge the facts give
// between the entry job and that job, and the JSON report says them under
// feedsVia; a branch feeding nothing carries no such key.
func TestABranchCarriesTheFeedKindsOfItsFedJobs(t *testing.T) {
	s := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{}}
	s.Jobs["build"] = JobSituation{Feeds: []string{"publish"}, FeedsVia: map[string][]string{"publish": {FeedArtifact, FeedCache}}}
	s.Jobs["lint"] = JobSituation{}
	pub := JobSituation{Impact: []ImpactFact{{Kind: "publishes", State: "proven", Evidence: "npm publish"}}}
	pub.Privilege.Secrets = []string{"NPM_TOKEN"}
	pub.Privilege.SecretsState = "proven"
	s.Jobs["publish"] = pub
	uses := map[string]any{"uses": "some/action@v1"}
	paths := assemblePaths([]opaengine.Finding{finding("ISSUE-703", "lint", uses), finding("ISSUE-703", "build", uses)}, s)
	if len(paths) != 1 || len(paths[0].Branches) != 2 {
		t.Fatalf("paths = %+v", paths)
	}
	want := map[string][]string{"publish": {FeedArtifact, FeedCache}}
	if got := paths[0].Branches[0].FeedsVia; !reflect.DeepEqual(got, want) {
		t.Errorf("build branch FeedsVia = %v, want %v", got, want)
	}
	if got := paths[0].Branches[1].FeedsVia; len(got) != 0 {
		t.Errorf("lint branch FeedsVia = %v, want none", got)
	}
	raw, err := json.Marshal(paths[0].Branches)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"feedsVia":{"publish":["artifact","cache"]}`) || strings.Count(string(raw), "feedsVia") != 1 {
		t.Errorf("branches JSON = %s, want feedsVia on the build branch only", raw)
	}
}

// A privilege finding on any entry job of the path rides the path, not
// the other findings, and the path lists it.
func TestAPrivilegeFindingOnAnyEntryJobRidesThePath(t *testing.T) {
	if RoleForCode("ISSUE-803") != RolePrivilege {
		t.Fatal("fixture drifted: ISSUE-803 is no privilege finding")
	}
	perms := finding("ISSUE-803", "lint", nil)
	findings := []opaengine.Finding{pushFinding(), perms}
	paths := assemblePaths(findings, multiJobPushSituation())
	score := ComputePlumberScoreV4(ScoreInputV4{Findings: findings, Paths: paths})
	if score.OtherFindings != nil {
		t.Errorf("other findings = %+v, want the lint job's privilege finding on the path", score.OtherFindings)
	}
	fillPathReportFields(paths, score.PathLosses, findings)
	if want := hashesOf(t, []opaengine.Finding{perms}); len(paths) != 1 || !slices.Contains(paths[0].FindingIDs, want[0]) {
		t.Errorf("paths = %+v, want one path listing the privilege finding", paths)
	}
}

// The JSON report carries one branch per entry job, with its own walk,
// reach, tier, state and modifiers; a path built by hand carries an empty
// list, never null.
func TestAttackPathJSONCarriesItsBranches(t *testing.T) {
	paths := assemblePaths([]opaengine.Finding{pushFinding()}, multiJobPushSituation())
	if len(paths) == 0 {
		t.Fatal("no path")
	}
	raw, err := json.Marshal(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Branches []map[string]json.RawMessage `json:"branches"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Branches) != 3 {
		t.Fatalf("branches = %s", raw)
	}
	var keys []string
	for k := range got.Branches[2] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if want := []string{"job", "jobs", "modifiers", "reach", "state", "tier"}; !reflect.DeepEqual(keys, want) {
		t.Errorf("branch keys = %v, want %v", keys, want)
	}
	if string(got.Branches[2]["modifiers"]) != "[]" {
		t.Errorf("modifiers = %s, want []", got.Branches[2]["modifiers"])
	}
	empty, _ := json.Marshal(AttackPath{ID: "p"})
	if !strings.Contains(string(empty), `"branches":[]`) {
		t.Errorf("hand-built path JSON = %s, want an empty branches list", empty)
	}
}

// Every entry job of a path can write the cache, not only the strongest:
// a dependency entering a job that holds a secret and a job that runs on
// push makes the push job a writer.
func TestAnyEntryJobOfAPathCanWriteTheCache(t *testing.T) {
	holder := JobSituation{}
	holder.Privilege.Secrets = []string{"AWS_KEY"}
	holder.Privilege.SecretsState = "proven"
	sit := cacheSituation(map[string]JobSituation{"ci/a-holder": holder, "ci/build": {RefTriggers: []string{"push"}, CacheScopes: defaultScope}})
	uses := map[string]any{"uses": "some/action@v1"}
	findings := []opaengine.Finding{cacheFinding(), finding("ISSUE-701", "ci/a-holder", uses), finding("ISSUE-701", "ci/build", uses)}
	paths := assemblePaths(findings, sit)
	cache := cachePaths(paths)
	if len(cache) != 1 {
		t.Fatalf("want the cache path, the push job writing it, got %+v", paths)
	}
	if b := NewPathBlock(cache[0], nil); b.EntryWriter != "a run of job `build` from workflow `ci` can write the cache" {
		t.Errorf("writer = %q", b.EntryWriter)
	}
}

// A settings variable any branch of a path reaches rides the path, not
// only one the strongest branch reaches.
func TestAVariableAnyBranchReachesRidesThePath(t *testing.T) {
	sit := multiJobPushSituation()
	lint := sit.Jobs["lint"]
	lint.Privilege.Secrets = []string{"DEPLOY_KEY"}
	lint.Privilege.SecretsState = "proven"
	sit.Jobs["lint"] = lint
	if RoleForCode("ISSUE-201") != RolePrivilege {
		t.Fatal("fixture drifted: ISSUE-201 is no privilege finding")
	}
	variable := opaengine.Finding{Code: "ISSUE-201", Data: map[string]any{"variableName": "DEPLOY_KEY"}}
	findings := []opaengine.Finding{pushFinding(), variable}
	paths := assemblePaths(findings, sit)
	if score := ComputePlumberScoreV4(ScoreInputV4{Findings: findings, Paths: paths}); score.OtherFindings != nil {
		t.Errorf("other findings = %+v, want the variable on the path", score.OtherFindings)
	}
}

// The table's job column lists the entry jobs of the path, strongest
// first, two at most and the count of the others, never the jobs they feed.
func TestThePathRowListsTheEntryJobs(t *testing.T) {
	paths := assemblePaths([]opaengine.Finding{pushFinding()}, multiJobPushSituation())
	if got := PathRowOf(paths[0]).Jobs; got != "build, scan, +1" {
		t.Errorf("jobs = %q, want %q", got, "build, scan, +1")
	}
	s := &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{
		"build": {Feeds: []string{"publish"}}, "lint": {}, "publish": {},
	}}
	uses := map[string]any{"uses": "some/action@v1"}
	paths = assemblePaths([]opaengine.Finding{finding("ISSUE-703", "lint", uses), finding("ISSUE-703", "build", uses)}, s)
	if got := PathRowOf(paths[0]).Jobs; got != "lint, build" {
		t.Errorf("jobs = %q, want the entry jobs only", got)
	}
}
