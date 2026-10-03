package situation_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/internal/testsupport/pipelines"
	"github.com/getplumber/plumber/policies/situation"
)

type entry struct {
	Kind, State, Evidence, Subject, File string
	Line                                 int
}
type privilege struct {
	Secrets              []string `json:"secrets"`
	SecretsState         string   `json:"secretsState"`
	SecretsInherit       bool     `json:"secretsInherit"`
	ProtectedSecrets     []string `json:"protectedSecrets"`
	TokenWrite           []string `json:"tokenWrite"`
	TokenWriteSource     string   `json:"tokenWriteSource"`
	PersistedCredentials string   `json:"persistedCredentials"`
	Environment          struct {
		Name      string `json:"name"`
		Protected string `json:"protected"`
	} `json:"environment"`
}
type impact struct {
	Kind, State, Evidence string
}
type jobFacts struct {
	Entries   []entry   `json:"entries"`
	Privilege privilege `json:"privilege"`
	Impact    []impact  `json:"impact"`
	Feeds     []string  `json:"feeds"`
}
type result struct {
	Exposure      string              `json:"exposure"`
	Jobs          map[string]jobFacts `json:"jobs"`
	DefaultBranch string              `json:"defaultBranch"`
}

func evaluate(t *testing.T, p *ir.NormalizedPipeline, cfg map[string]any) result {
	t.Helper()
	src, err := situation.SituationFS.ReadFile(situation.SituationModule)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := opaengine.New().EvaluateSituation(context.Background(), string(src), p, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var r result
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	return r
}

func githubFixture(t *testing.T, name, visibility string) *ir.NormalizedPipeline {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "github", name))
	if err != nil {
		t.Fatal(err)
	}
	p := pipelines.ParseGitHubWorkflow(t, data, ".github/workflows/"+name)
	p.Visibility = visibility
	return p
}

// githubFixtures parses several workflow files into one pipeline, the way
// the collector merges a repository's workflows.
func githubFixtures(t *testing.T, visibility string, names ...string) *ir.NormalizedPipeline {
	t.Helper()
	out := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Visibility: visibility}
	for _, name := range names {
		out.Jobs = append(out.Jobs, githubFixture(t, name, visibility).Jobs...)
	}
	return out
}

func gitlabFixture(t *testing.T, name, visibility string) *ir.NormalizedPipeline {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "gitlab", name))
	if err != nil {
		t.Fatal(err)
	}
	p := pipelines.ParseGitLabCI(t, data)
	p.Visibility = visibility
	return p
}

func kinds(entries []entry) map[string]entry {
	out := map[string]entry{}
	for _, e := range entries {
		out[e.Kind] = e
	}
	return out
}

func TestExposureIsCopiedFromThePipeline(t *testing.T) {
	for _, v := range []string{"public", "private", "unknown"} {
		r := evaluate(t, githubFixture(t, "fork_pr_injection.workflow.yml", v), nil)
		if r.Exposure != v {
			t.Errorf("exposure = %q, want %q", r.Exposure, v)
		}
	}
}

func TestForkPRInjectionEntries(t *testing.T) {
	r := evaluate(t, githubFixture(t, "fork_pr_injection.workflow.yml", "public"), nil)
	k := kinds(r.Jobs["build"].Entries)
	if e, ok := k["fork_pr"]; !ok || e.State != "proven" {
		t.Errorf("fork_pr missing or not proven: %+v", k)
	}
	if e, ok := k["untrusted_expression"]; !ok || e.Subject != "github.event.pull_request.title" || e.State != "proven" {
		t.Errorf("untrusted_expression: %+v", k["untrusted_expression"])
	}
	if _, ok := k["mutable_dependency"]; ok {
		t.Errorf("a SHA-pinned checkout is not a mutable dependency: %+v", k["mutable_dependency"])
	}
	if _, ok := k["pr_target"]; ok {
		t.Errorf("pull_request is not pr_target")
	}
}

func TestSameRepoGuardRemovesForkEntry(t *testing.T) {
	r := evaluate(t, githubFixture(t, "same_repo_guard.workflow.yml", "public"), nil)
	k := kinds(r.Jobs["build"].Entries)
	if _, ok := k["fork_pr"]; ok {
		t.Errorf("same-repo guard must remove fork_pr: %+v", k)
	}
	if _, ok := k["untrusted_expression"]; !ok {
		t.Errorf("the expression is still untrusted input (an insider can still craft a title)")
	}
}

// TestSameRepoGuardWithReversedOperands pins that same_repo_guard also
// recognizes the operands reversed (github.repository on the left,
// head.repo.full_name on the right), the same guard form ISSUE-802
// (dangerous_triggers.rego) and ISSUE-804
// (pull_request_target_head_checkout.rego) both recognize.
func TestSameRepoGuardWithReversedOperands(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:     "build",
			Triggers: []string{"pull_request"},
			If:       "${{ github.repository == github.event.pull_request.head.repo.full_name }}",
		}},
	}
	if _, ok := kinds(evaluate(t, p, nil).Jobs["build"].Entries)["fork_pr"]; ok {
		t.Errorf("a reversed-operand same-repo guard must remove fork_pr")
	}
}

// TestSameRepoGuardEveryForkFlagSpelling pins same_repo_guard_patterns'
// three fork-flag forms: head.repo.fork == false, head.repo.fork !=
// true, and the negated shorthand !github.event.pull_request.head.repo.fork.
// Each removes fork_pr from a pull_request job exactly like the
// full_name guard pinned above; a pull_request job with no guard at
// all still gets the entry.
func TestSameRepoGuardEveryForkFlagSpelling(t *testing.T) {
	cases := []struct {
		name string
		if_  string
	}{
		{"fork == false", "${{ github.event.pull_request.head.repo.fork == false }}"},
		{"fork != true", "${{ github.event.pull_request.head.repo.fork != true }}"},
		{"negated shorthand", "${{ !github.event.pull_request.head.repo.fork }}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &ir.NormalizedPipeline{
				Provider: ir.ProviderGitHub,
				Jobs: []ir.Job{{
					Name:     "build",
					Triggers: []string{"pull_request"},
					If:       tc.if_,
				}},
			}
			if _, ok := kinds(evaluate(t, p, nil).Jobs["build"].Entries)["fork_pr"]; ok {
				t.Errorf("%s must remove fork_pr", tc.name)
			}
		})
	}

	t.Run("unguarded", func(t *testing.T) {
		p := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs: []ir.Job{{
				Name:     "build",
				Triggers: []string{"pull_request"},
			}},
		}
		e, ok := kinds(evaluate(t, p, nil).Jobs["build"].Entries)["fork_pr"]
		if !ok || e.State != "proven" {
			t.Errorf("an unguarded pull_request job must still get fork_pr: %+v", e)
		}
	})
}

func TestPRTargetCheckoutEntry(t *testing.T) {
	r := evaluate(t, githubFixture(t, "pr_target_checkout.workflow.yml", "public"), nil)
	k := kinds(r.Jobs["build"].Entries)
	if e, ok := k["pr_target"]; !ok || e.State != "proven" || e.Subject != "github.event.pull_request.head.sha" {
		t.Errorf("pr_target: %+v", k["pr_target"])
	}
	if e, ok := k["mutable_dependency"]; !ok || e.Subject != "actions/checkout@v4" {
		t.Errorf("checkout@v4 is a mutable tag: %+v", k["mutable_dependency"])
	}
}

func TestReleaseMutableActionEntry(t *testing.T) {
	r := evaluate(t, githubFixture(t, "release_mutable_action.workflow.yml", "public"), nil)
	k := kinds(r.Jobs["release"].Entries)
	e, ok := k["mutable_dependency"]
	if !ok || e.Subject != "some/action@v1" || e.State != "proven" {
		t.Errorf("mutable_dependency: %+v", e)
	}
	if _, ok := k["fork_pr"]; ok {
		t.Errorf("a tag push is not a fork entry")
	}
	var mutable []entry
	for _, e := range r.Jobs["release"].Entries {
		if e.Kind == "mutable_dependency" {
			mutable = append(mutable, e)
		}
	}
	if len(mutable) != 1 {
		t.Errorf("a local action (./.github/actions/setup) must be skipped: %+v", mutable)
	}
}

// TestPushToUnprotectedDefaultBranch pins unprotected_push on GitHub. The
// fixture's on: push: branches: [main] reaches the IR as Job.PushBranches
// through the real YAML reading (pipelines.ParseGitHubWorkflow mirrors the production
// collector's extractGitHubPushFilters, PR #513 review), so a push to the
// default branch is proven on an unprotected default branch, not merely
// unresolvable; a protected default branch still removes the entry
// outright, and unknown protection (no branches collected) stays
// unresolvable. A second fixture whose branches: filter excludes the
// default branch entirely proves the YAML path can also rule the entry out,
// not merely let the "no filter" default carry it through by accident.
func TestPushToUnprotectedDefaultBranch(t *testing.T) {
	p := githubFixture(t, "push_unprotected.workflow.yml", "public")
	p.DefaultBranch = "main"
	p.Branches = []ir.Branch{{Name: "main", Protected: false}}
	r := evaluate(t, p, nil)
	k := kinds(r.Jobs["deploy"].Entries)
	if e, ok := k["unprotected_push"]; !ok || e.State != "proven" || e.Subject != "main" {
		t.Errorf("unprotected_push: %+v", e)
	}
	p.Branches = []ir.Branch{{Name: "main", Protected: true}}
	if _, ok := kinds(evaluate(t, p, nil).Jobs["deploy"].Entries)["unprotected_push"]; ok {
		t.Errorf("a protected default branch is not an entry")
	}
	p.Branches = nil
	if e, ok := kinds(evaluate(t, p, nil).Jobs["deploy"].Entries)["unprotected_push"]; !ok || e.State != "unresolvable" {
		t.Errorf("unknown protection must be unresolvable: %+v", e)
	}
}

// TestPushBranchesFilterExcludingDefaultBranchThroughYAML pins the other
// outcome of the same YAML path: a branches: filter that does not match the
// default branch at all removes the entry, whatever the branch's
// protection, because the push trigger itself never reaches that branch.
func TestPushBranchesFilterExcludingDefaultBranchThroughYAML(t *testing.T) {
	p := githubFixture(t, "push_branches_excluded.workflow.yml", "public")
	p.DefaultBranch = "main"
	p.Branches = []ir.Branch{{Name: "main", Protected: false}}
	if e, ok := kinds(evaluate(t, p, nil).Jobs["deploy"].Entries)["unprotected_push"]; ok {
		t.Errorf("unprotected_push: %+v, want none (branches: ['release/*'] does not reach main)", e)
	}
}

func TestGitLabMREntries(t *testing.T) {
	cfg := map[string]any{"imageMutableTag": map[string]any{"forbiddenTags": []string{"latest"}}}
	r := evaluate(t, gitlabFixture(t, "mr_injection.gitlab-ci.yml", "public"), cfg)
	k := kinds(r.Jobs["test"].Entries)
	if e, ok := k["untrusted_expression"]; !ok || e.Subject != "CI_MERGE_REQUEST_TITLE" {
		t.Errorf("untrusted_expression: %+v", e)
	}
	if _, ok := k["fork_pr"]; !ok {
		t.Errorf("an MR job without a fork restriction is a fork entry: %+v", k)
	}
	var mutable []entry
	for _, e := range r.Jobs["test"].Entries {
		if e.Kind == "mutable_dependency" {
			mutable = append(mutable, e)
		}
	}
	if len(mutable) != 2 {
		t.Fatalf("want two mutable dependencies (node:latest, curl | bash), got %+v", mutable)
	}
}

func TestGitLabPinnedReleaseHasNoEntry(t *testing.T) {
	r := evaluate(t, gitlabFixture(t, "release_protected.gitlab-ci.yml", "private"), nil)
	if n := len(r.Jobs["release"].Entries); n != 0 {
		t.Errorf("want no entry on a digest-pinned tag job, got %+v", r.Jobs["release"].Entries)
	}
}

// TestPRTargetWithMultipleTriggersAndCheckouts pins that pr_target never
// raises eval_conflict_error: a complete rule whose body can be satisfied by
// more than one (trigger, checkout) combination in the same job is rejected
// by OPA and fails the whole EvaluateSituation call. Two privileged triggers
// and two PR-head checkouts in one job must both still succeed and yield one
// pr_target entry per checkout.
func TestPRTargetWithMultipleTriggersAndCheckouts(t *testing.T) {
	r := evaluate(t, githubFixture(t, "pr_target_two_triggers.workflow.yml", "public"), nil)
	var prTargets []entry
	for _, e := range r.Jobs["build"].Entries {
		if e.Kind == "pr_target" {
			prTargets = append(prTargets, e)
		}
	}
	if len(prTargets) != 2 {
		t.Fatalf("want two pr_target entries (one per checkout of the PR head), got %+v", prTargets)
	}
}

// TestPRTargetRefMustBeThePRHeadNotAnyHead pins that the pr_target checkout
// match requires the literal "github.event.pull_request.head" expression,
// not a bare "head" substring: a checkout of a plain branch ref
// ("refs/heads/main") must not be mistaken for a checkout of the PR head.
func TestPRTargetRefMustBeThePRHeadNotAnyHead(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:     "build",
			Triggers: []string{"pull_request_target"},
			Uses: []ir.Action{{
				Uses: "actions/checkout@v4",
				With: map[string]any{"ref": "refs/heads/main"},
			}},
		}},
	}
	r := evaluate(t, p, nil)
	if _, ok := kinds(r.Jobs["build"].Entries)["pr_target"]; ok {
		t.Errorf("a checkout of refs/heads/main is not a checkout of the PR head")
	}
}

// TestMutableActionStatesFromMetadataTier pins the positive-signal states
// for a uses whose ref IS a 40-hex SHA: the entry fires only on a positive
// ActionMetadata.MutableRemoteExec signal, "unresolvable" when the
// action's own source could not be fetched to check (ISSUE-716,
// tier "unverified"), "proven" when the source was fetched and found to
// fetch-and-run mutable remote code despite the pin (ISSUE-714/715, tier
// "exec" or "obfuscated"). Any other tier (including "data", a non-exec
// mutable manifest, or no MutableRemoteExec at all) must not produce an
// entry: a pinned ref with no positive signal is not a mutable dependency.
func TestMutableActionStatesFromMetadataTier(t *testing.T) {
	const sha = "08c6903cd8c0fde910a37f88322edcfb5dd907a8"
	cases := []struct {
		name      string
		tier      string
		wantEntry bool
		wantState string
	}{
		{"unverified source is unresolvable", "unverified", true, "unresolvable"},
		{"exec tier is proven", "exec", true, "proven"},
		{"obfuscated tier is proven", "obfuscated", true, "proven"},
		{"data tier produces no entry", "data", false, ""},
		{"no signal produces no entry", "", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var metadata *ir.ActionMetadata
			if tc.tier != "" {
				metadata = &ir.ActionMetadata{MutableRemoteExec: &ir.MutableRemoteExec{Tier: tc.tier}}
			}
			p := &ir.NormalizedPipeline{
				Provider: ir.ProviderGitHub,
				Jobs: []ir.Job{{
					Name: "build",
					Uses: []ir.Action{{
						Uses:     "some/action@" + sha,
						Metadata: metadata,
					}},
				}},
			}
			r := evaluate(t, p, nil)
			e, ok := kinds(r.Jobs["build"].Entries)["mutable_dependency"]
			if ok != tc.wantEntry {
				t.Fatalf("mutable_dependency present = %v, want %v: %+v", ok, tc.wantEntry, e)
			}
			if ok && e.State != tc.wantState {
				t.Errorf("state = %q, want %q", e.State, tc.wantState)
			}
		})
	}
}

// TestUnresolvedImageIsUnresolvable pins the image counterpart: a job image
// that still held an unresolved `$VARIABLE` reference when it was parsed
// (ir.Image.Unresolved) cannot be judged as mutable or not, so it is an
// unresolvable entry, never a proven one, with the raw (placeholder) image
// string as its subject.
func TestUnresolvedImageIsUnresolvable(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{{
			Name:  "deploy",
			Image: &ir.Image{Name: "$IMAGE_NAME", Unresolved: true},
		}},
	}
	r := evaluate(t, p, nil)
	e, ok := kinds(r.Jobs["deploy"].Entries)["mutable_dependency"]
	if !ok || e.State != "unresolvable" || e.Subject != "$IMAGE_NAME" {
		t.Errorf("mutable_dependency: %+v", e)
	}
}

// TestMutableImageForbiddenTagFiresEvenWithADigest pins the OR in
// mutable_image (situation.rego): an image with BOTH a digest and a tag
// matching a forbidden glob is still a mutable_dependency entry. The
// no-digest branch and the forbidden-tag branch are independent checks,
// not a package deal, so a digest must never gate the forbidden-tag
// branch off.
func TestMutableImageForbiddenTagFiresEvenWithADigest(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{{
			Name:  "deploy",
			Image: &ir.Image{Name: "foo", Tag: "latest", Digest: digest},
		}},
	}
	r := evaluate(t, p, nil)
	e, ok := kinds(r.Jobs["deploy"].Entries)["mutable_dependency"]
	wantSubject := "foo:latest@" + digest
	if !ok || e.State != "proven" || e.Subject != wantSubject {
		t.Errorf("mutable_dependency: %+v, want proven %q", e, wantSubject)
	}
}

// TestFetchedScriptsRegexExclusionsAndInclusions pins the fetched-script
// regex boundaries: a checksum-verification pipe must not be mistaken for
// a fetch-and-execute pipe, and an npx package reference is only mutable
// when it carries no pinned version.
func TestFetchedScriptsRegexExclusionsAndInclusions(t *testing.T) {
	cases := []struct {
		name      string
		script    string
		wantEntry bool
	}{
		{"curl piped into a checksum check is not an entry", `curl -sL https://example.com/x.sh | sha256sum -c`, false},
		{"unversioned npx is not an entry (mirrors control 411)", `npx cowsay`, false},
		{"versioned npx with a flag is not an entry", `npx -y pkg@1.2.3`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &ir.NormalizedPipeline{
				Provider: ir.ProviderGitLab,
				Jobs:     []ir.Job{{Name: "test", Scripts: []string{tc.script}}},
			}
			r := evaluate(t, p, nil)
			_, ok := kinds(r.Jobs["test"].Entries)["mutable_dependency"]
			if ok != tc.wantEntry {
				t.Errorf("%s: mutable_dependency present = %v, want %v", tc.script, ok, tc.wantEntry)
			}
		})
	}
}

// TestEntriesCarryFileAndLine pins that an entry's file/line come from the
// job's origin by default, and from the action's own line when the uses
// step is the more precise origin (mutable_actions overrides it).
func TestEntriesCarryFileAndLine(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:       "build",
			OriginFile: ".github/workflows/ci.yml",
			OriginLine: 7,
			Triggers:   []string{"pull_request"},
			Scripts:    []string{"echo ${{ github.event.pull_request.title }}"},
			Uses:       []ir.Action{{Uses: "some/action@v1", Line: 12}},
		}},
	}
	r := evaluate(t, p, nil)
	k := kinds(r.Jobs["build"].Entries)
	if e, ok := k["untrusted_expression"]; !ok || e.File != ".github/workflows/ci.yml" || e.Line != 7 {
		t.Errorf("untrusted_expression origin: %+v", e)
	}
	if e, ok := k["mutable_dependency"]; !ok || e.Line != 12 {
		t.Errorf("mutable_dependency origin: %+v", e)
	}
}

// TestReleasePrivilegeAndImpact pins the core per-job facts: what the
// release job holds (a secret, write permissions, an environment, surviving
// checkout credentials) and what it can change (it publishes, it deploys
// because it has an environment, and it signs/releases because it holds
// id-token: write).
func TestReleasePrivilegeAndImpact(t *testing.T) {
	r := evaluate(t, githubFixture(t, "release_mutable_action.workflow.yml", "public"), nil)
	j := r.Jobs["release"]
	if !reflect.DeepEqual(j.Privilege.Secrets, []string{"NPM_TOKEN"}) || j.Privilege.SecretsState != "proven" {
		t.Errorf("secrets: %+v", j.Privilege)
	}
	if !containsAll(j.Privilege.TokenWrite, "contents", "id-token") {
		t.Errorf("tokenWrite = %v", j.Privilege.TokenWrite)
	}
	if j.Privilege.PersistedCredentials != "proven" {
		t.Errorf("checkout without persist-credentials: false must be proven, got %q", j.Privilege.PersistedCredentials)
	}
	if j.Privilege.Environment.Name != "production" || j.Privilege.Environment.Protected != "unknown" {
		t.Errorf("environment: %+v", j.Privilege.Environment)
	}
	kinds := map[string]impact{}
	for _, i := range j.Impact {
		kinds[i.Kind] = i
	}
	if i, ok := kinds["publishes"]; !ok || i.Evidence != "npm publish" || i.State != "proven" {
		t.Errorf("publishes: %+v", kinds)
	}
	if _, ok := kinds["deploys"]; !ok {
		t.Errorf("an environment is a deploy impact: %+v", kinds)
	}
	if _, ok := kinds["signs_or_releases"]; !ok {
		t.Errorf("id-token: write is a signing impact: %+v", kinds)
	}
}

// TestForkPRJobHoldsNothing pins the empty-handed case: a read-only,
// credential-stripped job with no publish/deploy/write/sign behavior must
// produce no privilege and no impact, not zero-valued placeholders.
func TestForkPRJobHoldsNothing(t *testing.T) {
	r := evaluate(t, githubFixture(t, "fork_pr_injection.workflow.yml", "public"), nil)
	j := r.Jobs["build"]
	if len(j.Privilege.Secrets) != 0 || len(j.Privilege.TokenWrite) != 0 || j.Privilege.PersistedCredentials != "absent" || len(j.Impact) != 0 {
		t.Errorf("want an empty-handed job, got %+v / %+v", j.Privilege, j.Impact)
	}
}

// TestArtifactChainFeeds pins the artifact half of feeds: build produces the
// "dist" artifact that publish downloads by the same name, and build also
// appears in publish's needs, so build feeds publish; publish feeds nothing.
func TestArtifactChainFeeds(t *testing.T) {
	r := evaluate(t, githubFixture(t, "artifact_chain.workflow.yml", "public"), nil)
	if got := r.Jobs["build"].Feeds; !reflect.DeepEqual(got, []string{"publish"}) {
		t.Errorf("build.feeds = %v", got)
	}
	if got := r.Jobs["publish"].Feeds; len(got) != 0 {
		t.Errorf("publish feeds nothing, got %v", got)
	}
	// export is not a needs target of collect, so this isolates the
	// artifact half of feeds from the needs edge build/publish already
	// prove above.
	if got := r.Jobs["export"].Feeds; !reflect.DeepEqual(got, []string{"collect"}) {
		t.Errorf("export.feeds = %v, want artifact-only feed to collect", got)
	}
}

// TestCacheKeyFeeds pins the cache half of feeds: a job that saves a cache
// key feeds every job that restores the same key, under any save/restore
// mode combination, with no needs and no artifacts involved. A restore of an
// empty key, or of a different key, feeds nothing: the empty-key guard
// matters even when the saving job also saved under an empty key, which
// would otherwise satisfy a plain equality check.
func TestCacheKeyFeeds(t *testing.T) {
	for _, saveMode := range []string{"save", "both"} {
		for _, restoreMode := range []string{"restore", "both"} {
			p := &ir.NormalizedPipeline{
				Provider: ir.ProviderGitHub,
				Jobs: []ir.Job{
					{Name: "a", Caches: []ir.CacheRef{{Key: "deps", Mode: saveMode}}},
					{Name: "b", Caches: []ir.CacheRef{{Key: "deps", Mode: restoreMode}}},
				},
			}
			r := evaluate(t, p, nil)
			if got := r.Jobs["a"].Feeds; !reflect.DeepEqual(got, []string{"b"}) {
				t.Errorf("save %s / restore %s: a.feeds = %v, want [b]", saveMode, restoreMode, got)
			}
		}
	}

	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{
			{Name: "a", Caches: []ir.CacheRef{{Key: "deps", Mode: "save"}}},
			{Name: "other-key", Caches: []ir.CacheRef{{Key: "unrelated", Mode: "restore"}}},
			{Name: "empty-saver", Caches: []ir.CacheRef{{Key: "", Mode: "save"}}},
			{Name: "empty-restorer", Caches: []ir.CacheRef{{Key: "", Mode: "restore"}}},
		},
	}
	r := evaluate(t, p, nil)
	if got := r.Jobs["a"].Feeds; len(got) != 0 {
		t.Errorf("a different key must feed nothing, got %v", got)
	}
	if got := r.Jobs["empty-saver"].Feeds; len(got) != 0 {
		t.Errorf("an empty key must feed nothing even when another job restores an empty key, got %v", got)
	}
}

// TestCacheRestorePrefixFeeds pins the restore-keys half of the cache
// edges: a restore entry marked as a prefix (actions/cache restore-keys)
// restores any saved key that starts with it, so the job saving such a key
// feeds the job restoring the prefix. A prefix that no saved key starts
// with, an exact (non-prefix) restore of a longer key, and an empty prefix
// feed nothing.
func TestCacheRestorePrefixFeeds(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{
			{Name: "pr", Caches: []ir.CacheRef{{Key: "Linux-pip-${{ hashFiles('requirements.txt') }}", Mode: "both"}}},
			{Name: "release", Caches: []ir.CacheRef{
				{Key: "Linux-pip-release", Mode: "restore"},
				{Key: "Linux-pip-", Mode: "restore", Prefix: true},
			}},
			{Name: "unrelated", Caches: []ir.CacheRef{{Key: "Linux-npm-", Mode: "restore", Prefix: true}}},
			{Name: "exact", Caches: []ir.CacheRef{{Key: "Linux-pip-", Mode: "restore"}}},
			{Name: "empty", Caches: []ir.CacheRef{{Key: "", Mode: "restore", Prefix: true}}},
		},
	}
	r := evaluate(t, p, nil)
	if got := r.Jobs["pr"].Feeds; !reflect.DeepEqual(got, []string{"release"}) {
		t.Errorf("pr.feeds = %v, want [release] (restore-keys prefix match only)", got)
	}
}

// TestCacheKeyFeedsAcrossGitHubWorkflowFiles pins finding E of the round-9
// review: unlike a GitHub artifact name (unique only within the one
// workflow run that declared it, see same_workflow_if_github), a GitHub
// cache key is cross-workflow by design, so a cache saved in one workflow
// file and restored in another still wires the two jobs together. This
// guards against same_workflow_if_github ever being applied to the cache
// branch of feeds_job, which only exists for the artifact branch.
func TestCacheKeyFeedsAcrossGitHubWorkflowFiles(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{
			{Name: "a", OriginFile: ".github/workflows/a.yml", Caches: []ir.CacheRef{{Key: "deps", Mode: "save"}}},
			{Name: "b", OriginFile: ".github/workflows/b.yml", Caches: []ir.CacheRef{{Key: "deps", Mode: "restore"}}},
		},
	}
	r := evaluate(t, p, nil)
	if got := r.Jobs["a"].Feeds; !reflect.DeepEqual(got, []string{"b"}) {
		t.Errorf("a.feeds = %v, want [b] (caches are cross-workflow, unlike artifacts)", got)
	}
}

// TestDefaultPermissionsAreAssumedPermissive pins that a job with no
// permissions: block at all (workflow or job level) is assumed to hold the
// repository-default permissive scopes, not an empty set.
func TestDefaultPermissionsAreAssumedPermissive(t *testing.T) {
	r := evaluate(t, githubFixture(t, "push_unprotected.workflow.yml", "public"), nil)
	if got := r.Jobs["deploy"].Privilege.TokenWrite; !reflect.DeepEqual(got, []string{"contents", "packages"}) {
		t.Errorf("no permissions block means the permissive default: %v", got)
	}
	if !reflect.DeepEqual(r.Jobs["deploy"].Privilege.Secrets, []string{"DEPLOY_KEY"}) {
		t.Errorf("secrets = %v", r.Jobs["deploy"].Privilege.Secrets)
	}
}

// TestGitLabEnvironmentProtected pins environment.protected on GitLab: true
// when a protected branch shares the environment's name, true when a
// settings variable scoped to the environment is protected, and unknown
// when neither signal is present.
func TestGitLabEnvironmentProtected(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Branches: []ir.Branch{{Name: "production", Protected: true}},
		Jobs:     []ir.Job{{Name: "release", Environment: "production"}},
	}
	if got := evaluate(t, p, nil).Jobs["release"].Privilege.Environment.Protected; got != "true" {
		t.Errorf("a protected branch sharing the environment name: got %q, want true", got)
	}

	p = &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs:     []ir.Job{{Name: "release", Environment: "production"}},
		SettingsVariables: []ir.SettingsVariable{
			{Name: "DEPLOY_TOKEN", Type: "env_var", Environment: "production", Protected: true},
		},
	}
	if got := evaluate(t, p, nil).Jobs["release"].Privilege.Environment.Protected; got != "true" {
		t.Errorf("a protected settings variable scoped to the environment: got %q, want true", got)
	}

	p = &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs:     []ir.Job{{Name: "release", Environment: "production"}},
	}
	if got := evaluate(t, p, nil).Jobs["release"].Privilege.Environment.Protected; got != "unknown" {
		t.Errorf("neither signal present: got %q, want unknown", got)
	}
}

// TestGitLabSettingsVariablesArePrivilege pins the GitLab secrets source:
// the protected or masked settings variables in scope of the job's
// environment (scoped "*", the same name, or a wildcard scope matching
// it), unresolvable when the listing itself could not be fetched
// authoritatively. A plain variable (neither protected nor masked) is
// configuration, not a secret. protectedSecrets keeps the protected ones.
func TestGitLabSettingsVariablesArePrivilege(t *testing.T) {
	p := gitlabFixture(t, "release_protected.gitlab-ci.yml", "private")
	p.SettingsVariablesKnown = true
	p.SettingsVariables = []ir.SettingsVariable{
		{Name: "NPM_TOKEN", Type: "env_var", Environment: "*", Protected: true, Masked: true},
		{Name: "SENTRY_DSN", Type: "env_var", Environment: "*", Masked: true},
		{Name: "DOCKER_DRIVER", Type: "env_var", Environment: "*"},
		{Name: "STAGING_URL", Type: "env_var", Environment: "staging", Protected: true},
		{Name: "REVIEW_TOKEN", Type: "env_var", Environment: "review/*", Protected: true},
	}
	r := evaluate(t, p, nil)
	j := r.Jobs["release"]
	if !reflect.DeepEqual(j.Privilege.Secrets, []string{"NPM_TOKEN", "SENTRY_DSN"}) || j.Privilege.SecretsState != "proven" {
		t.Errorf("secrets = %+v", j.Privilege)
	}
	if !reflect.DeepEqual(j.Privilege.ProtectedSecrets, []string{"NPM_TOKEN"}) {
		t.Errorf("protectedSecrets = %v", j.Privilege.ProtectedSecrets)
	}
	p.Jobs[0].Environment = "review/feature-x"
	j = evaluate(t, p, nil).Jobs["release"]
	if !reflect.DeepEqual(j.Privilege.Secrets, []string{"NPM_TOKEN", "REVIEW_TOKEN", "SENTRY_DSN"}) {
		t.Errorf("a review/* scope covers review/feature-x: secrets = %v", j.Privilege.Secrets)
	}
	if !reflect.DeepEqual(j.Privilege.ProtectedSecrets, []string{"NPM_TOKEN", "REVIEW_TOKEN"}) {
		t.Errorf("protectedSecrets = %v", j.Privilege.ProtectedSecrets)
	}
	p.Jobs[0].Environment = ""
	p.SettingsVariablesKnown = false
	if got := evaluate(t, p, nil).Jobs["release"].Privilege.SecretsState; got != "unresolvable" {
		t.Errorf("unknown settings variables must be unresolvable, got %q", got)
	}
}

// TestGitLabMergeRequestOnlyJobHoldsNoProtectedVariable pins the "whether
// the protection that gates them applies to this run" half of the GitLab
// secrets fact: GitLab exports a protected variable only to pipelines on a
// protected branch or tag, so a job whose every way to run is a merge
// request pipeline (rules on $CI_PIPELINE_SOURCE == "merge_request_event"
// or the presence of $CI_MERGE_REQUEST_IID, or only: [merge_requests])
// never holds one, whoever opened the merge request. A job that also runs
// on a branch push, or that has no rules at all, still does.
func TestGitLabMergeRequestOnlyJobHoldsNoProtectedVariable(t *testing.T) {
	vars := []ir.SettingsVariable{
		{Name: "PYPI_TOKEN", Type: "env_var", Environment: "*", Protected: true, Masked: true},
		{Name: "SENTRY_DSN", Type: "env_var", Environment: "*", Masked: true},
	}
	mrRule := map[string]any{"if": `$CI_PIPELINE_SOURCE == "merge_request_event"`}
	iidRule := map[string]any{"if": `$CI_MERGE_REQUEST_IID`}
	never := map[string]any{"if": `$CI_COMMIT_TAG`, "when": "never"}
	mainRule := map[string]any{"if": `$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`}
	either := map[string]any{"if": `$CI_PIPELINE_SOURCE == "merge_request_event" || $CI_COMMIT_BRANCH == "main"`}
	p := &ir.NormalizedPipeline{
		Provider:               ir.ProviderGitLab,
		DefaultBranch:          "main",
		SettingsVariablesKnown: true,
		SettingsVariables:      vars,
		Jobs: []ir.Job{
			{Name: "mr_rules", Rules: []map[string]any{never, mrRule}},
			{Name: "mr_iid", Rules: []map[string]any{iidRule}},
			{Name: "mr_only_keyword", Only: []string{"merge_requests"}},
			{Name: "mr_and_main", Rules: []map[string]any{mrRule, mainRule}},
			{Name: "or_in_one_rule", Rules: []map[string]any{either}},
			{Name: "no_rules"},
		},
	}
	r := evaluate(t, p, nil)
	for name, want := range map[string][]string{
		"mr_rules":        {"SENTRY_DSN"},
		"mr_iid":          {"SENTRY_DSN"},
		"mr_only_keyword": {"SENTRY_DSN"},
		"mr_and_main":     {"PYPI_TOKEN", "SENTRY_DSN"},
		"or_in_one_rule":  {"PYPI_TOKEN", "SENTRY_DSN"},
		"no_rules":        {"PYPI_TOKEN", "SENTRY_DSN"},
	} {
		if got := r.Jobs[name].Privilege.Secrets; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: secrets = %v, want %v", name, got, want)
		}
	}
	if got := r.Jobs["mr_rules"].Privilege.ProtectedSecrets; len(got) != 0 {
		t.Errorf("mr_rules: protectedSecrets = %v, want none (it holds no protected variable)", got)
	}
}

// TestGitLabWildcardEnvironmentScopeCrossesSlash pins GitLab's own glob
// semantics for a settings variable's environment scope: "*" matches any
// characters, including "/", so a "review/*" scope covers "review/a/b",
// not just one path segment past the slash. A scope with no wildcard match
// at all ("prod") must still not match an unrelated environment
// ("production").
func TestGitLabWildcardEnvironmentScopeCrossesSlash(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs:     []ir.Job{{Name: "release", Environment: "review/a/b"}},
		SettingsVariables: []ir.SettingsVariable{
			{Name: "REVIEW_TOKEN", Type: "env_var", Environment: "review/*", Protected: true},
		},
	}
	if got := evaluate(t, p, nil).Jobs["release"].Privilege.Secrets; !reflect.DeepEqual(got, []string{"REVIEW_TOKEN"}) {
		t.Errorf("review/* must match review/a/b across the slash, secrets = %v", got)
	}

	p.Jobs[0].Environment = "production"
	p.SettingsVariables = []ir.SettingsVariable{
		{Name: "PROD_TOKEN", Type: "env_var", Environment: "prod", Protected: true},
	}
	if got := evaluate(t, p, nil).Jobs["release"].Privilege.Secrets; len(got) != 0 {
		t.Errorf("prod must not match production, secrets = %v", got)
	}
}

func impactKinds(impacts []impact) map[string]impact {
	out := map[string]impact{}
	for _, i := range impacts {
		out[i.Kind] = i
	}
	return out
}

// TestDefaultPermissionsWritesRepoIsUnresolvable pins that an assumed token
// write (no permissions: block at all) never reads as proven. A job with no permissions that nonetheless runs git push
// only holds contents: write by the permissive-default guess, so the
// writes_repo impact it produces is unresolvable, not proven, and
// tokenWriteSource must say so.
func TestDefaultPermissionsWritesRepoIsUnresolvable(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:    "deploy",
			Scripts: []string{"git push origin main"},
		}},
	}
	r := evaluate(t, p, nil)
	j := r.Jobs["deploy"]
	if j.Privilege.TokenWriteSource != "default" {
		t.Errorf("tokenWriteSource = %q, want default", j.Privilege.TokenWriteSource)
	}
	if i, ok := impactKinds(j.Impact)["writes_repo"]; !ok || i.State != "unresolvable" {
		t.Errorf("writes_repo: %+v", impactKinds(j.Impact))
	}
}

// TestDeclaredPermissionsWritesRepoIsProven is the positive counterpart: an
// explicit permissions: {contents: write} is a real declaration, not a
// guess, so the same git push evidence is proven and tokenWriteSource
// says declared.
func TestDeclaredPermissionsWritesRepoIsProven(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:        "deploy",
			Permissions: map[string]any{"contents": "write"},
			Scripts:     []string{"git push origin main"},
		}},
	}
	r := evaluate(t, p, nil)
	j := r.Jobs["deploy"]
	if j.Privilege.TokenWriteSource != "declared" {
		t.Errorf("tokenWriteSource = %q, want declared", j.Privilege.TokenWriteSource)
	}
	if i, ok := impactKinds(j.Impact)["writes_repo"]; !ok || i.State != "proven" {
		t.Errorf("writes_repo: %+v", impactKinds(j.Impact))
	}
}

// TestPublishDryRunIsExcluded pins honoring publishScriptExcludePatterns:
// a dry-run invocation never actually publishes, so it must not count as
// a publishes impact even though it matches the publish pattern.
func TestPublishDryRunIsExcluded(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs:     []ir.Job{{Name: "release", Scripts: []string{"npm publish --dry-run"}}},
	}
	r := evaluate(t, p, nil)
	if _, ok := impactKinds(r.Jobs["release"].Impact)["publishes"]; ok {
		t.Errorf("npm publish --dry-run must not be a publishes impact")
	}

	p.Jobs[0].Scripts = []string{"npm publish"}
	r = evaluate(t, p, nil)
	if _, ok := impactKinds(r.Jobs["release"].Impact)["publishes"]; !ok {
		t.Errorf("npm publish must be a publishes impact")
	}
}

// TestDeployPatternEveryAlternative pins every one of deploy_pattern's nine
// regex alternatives, not just kubectl apply (the only one previously
// exercised): a change narrowing any single alternative (for example,
// dropping the "ssh\s.*deploy" branch, or requiring a flag kubectl apply
// does not always carry) would fail exactly the row it breaks here instead
// of passing unnoticed.
func TestDeployPatternEveryAlternative(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"kubectl apply", "kubectl apply -f k8s/"},
		{"helm upgrade", "helm upgrade --install app ./chart"},
		{"terraform apply", "terraform apply -auto-approve"},
		{"aws deploy", "aws ecs deploy --cluster prod"},
		{"gcloud deploy", "gcloud run deploy api --image x"},
		{"az deploy", "az webapp deploy --name app"},
		{"ansible-playbook", "ansible-playbook site.yml"},
		{"ssh deploy", "ssh deploy@host ./deploy.sh"},
		{"rsync to host:path", "rsync -az dist/ deploy@host:/srv/app"},
	}
	for _, c := range cases {
		p := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs:     []ir.Job{{Name: "deploy", Scripts: []string{c.line}}},
		}
		i, ok := impactKinds(evaluate(t, p, nil).Jobs["deploy"].Impact)["deploys"]
		if !ok || i.State != "proven" {
			t.Errorf("%s (%q): deploys impact = %+v, want a proven one", c.name, c.line, i)
		}
	}
}

// TestPublishPatternsEveryDefault pins every one of publish_patterns'
// default alternatives, not just npm publish (the only one previously
// exercised): a change narrowing any single alternative would fail
// exactly the row it breaks here instead of passing unnoticed.
func TestPublishPatternsEveryDefault(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"npm publish", "npm publish"},
		{"twine upload", "twine upload dist/*"},
		{"cargo publish", "cargo publish"},
		{"gem push", "gem push pkg.gem"},
		{"docker push", "docker push ghcr.io/o/i:1"},
		{"mvn deploy", "mvn deploy"},
		{"gradle publish", "gradle publish"},
		{"goreleaser release", "goreleaser release --clean"},
		{"helm push", "helm push chart.tgz oci://r"},
	}
	for _, c := range cases {
		p := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs:     []ir.Job{{Name: "release", Scripts: []string{c.line}}},
		}
		i, ok := impactKinds(evaluate(t, p, nil).Jobs["release"].Impact)["publishes"]
		if !ok || i.State != "proven" {
			t.Errorf("%s (%q): publishes impact = %+v, want a proven one", c.name, c.line, i)
		}
	}
}

// TestGitHubArtifactsFeedOnlyWithinOneWorkflow pins that a GitHub artifact
// feed stays inside its own workflow file: upload-artifact/download-artifact
// names are only unique within a single workflow run, so two unrelated
// workflows that happen to share an artifact name must not be wired
// together. Built directly in Go; its twin from fixture files is
// TestGitHubArtifactsFeedOnlyWithinOneWorkflowYAML.
func TestGitHubArtifactsFeedOnlyWithinOneWorkflow(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{
			{
				Name:       "build",
				OriginFile: ".github/workflows/a.yml",
				Artifacts:  []ir.ArtifactRef{{Name: "dist", Mode: "produce"}},
			},
			{
				Name:       "deploy",
				OriginFile: ".github/workflows/b.yml",
				Artifacts:  []ir.ArtifactRef{{Name: "dist", Mode: "consume"}},
			},
		},
	}
	r := evaluate(t, p, nil)
	if got := r.Jobs["build"].Feeds; len(got) != 0 {
		t.Errorf("different workflow files must not feed, got %v", got)
	}

	p.Jobs[1].OriginFile = ".github/workflows/a.yml"
	r = evaluate(t, p, nil)
	if got := r.Jobs["build"].Feeds; !reflect.DeepEqual(got, []string{"deploy"}) {
		t.Errorf("same workflow file must feed, got %v", got)
	}
}

// TestSecretsRegexAnchoredToExpression pins that secrets.X only counts
// inside a ${{ ... }} expression, not any text that happens to contain the
// literal substring "secrets.", and that two references in the same
// expression, or two separate expressions on the same line, each yield
// their name (a single greedy pass across the line would undercount).
func TestSecretsRegexAnchoredToExpression(t *testing.T) {
	cases := []struct {
		name   string
		script string
		want   []string
	}{
		{"plain text mentioning secrets.txt is not a secret reference", "cat secrets.txt", nil},
		{"an actual expression is", "echo ${{ secrets.NPM_TOKEN }}", []string{"NPM_TOKEN"}},
		{"two names in one expression", "echo ${{ secrets.A || secrets.B }}", []string{"A", "B"}},
		{"two separate expressions", "echo ${{ secrets.A }} and ${{ secrets.B }}", []string{"A", "B"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &ir.NormalizedPipeline{
				Provider: ir.ProviderGitHub,
				Jobs:     []ir.Job{{Name: "build", Scripts: []string{tc.script}}},
			}
			r := evaluate(t, p, nil)
			got := r.Jobs["build"].Privilege.Secrets
			if tc.want == nil {
				if len(got) != 0 {
					t.Errorf("secrets = %v, want none", got)
				}
			} else if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("secrets = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDockerBuildPushActionDefaultIsNotPublish pins that
// docker/build-push-action's own default for push: is false,
// unlike every other publish action, so an invocation that never sets
// push: true does not count as a publishes impact.
func TestDockerBuildPushActionDefaultIsNotPublish(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name: "build",
			Uses: []ir.Action{{Uses: "docker/build-push-action@v5"}},
		}},
	}
	r := evaluate(t, p, nil)
	if _, ok := impactKinds(r.Jobs["build"].Impact)["publishes"]; ok {
		t.Errorf("docker/build-push-action without push: true must not be a publishes impact")
	}

	p.Jobs[0].Uses[0].With = map[string]any{"push": true}
	r = evaluate(t, p, nil)
	if _, ok := impactKinds(r.Jobs["build"].Impact)["publishes"]; !ok {
		t.Errorf("docker/build-push-action with push: true must be a publishes impact")
	}
}

// TestWriteAllGrantsSigningImpact pins that permissions: write-all implies id-token: write exactly like an explicit
// map would, so it must also produce the signs_or_releases impact.
func TestWriteAllGrantsSigningImpact(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs:     []ir.Job{{Name: "release", Permissions: "write-all"}},
	}
	r := evaluate(t, p, nil)
	j := r.Jobs["release"]
	if j.Privilege.TokenWriteSource != "declared" {
		t.Errorf("tokenWriteSource = %q, want declared", j.Privilege.TokenWriteSource)
	}
	i, ok := impactKinds(j.Impact)["signs_or_releases"]
	if !ok || i.Evidence != "permissions: write-all" || i.State != "proven" {
		t.Errorf("signs_or_releases: %+v", i)
	}
}

// TestRepoWriterActionGrantsWritesRepoImpact pins the action-list branch of
// writes_repo: a job that uses a known repo-writing action (not a git push
// script line) and declares contents: write is a proven writes_repo impact,
// with the action ref itself as the evidence.
func TestRepoWriterActionGrantsWritesRepoImpact(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:        "open-pr",
			Permissions: map[string]any{"contents": "write"},
			Uses:        []ir.Action{{Uses: "peter-evans/create-pull-request@v7"}},
		}},
	}
	r := evaluate(t, p, nil)
	i, ok := impactKinds(r.Jobs["open-pr"].Impact)["writes_repo"]
	if !ok || i.State != "proven" || i.Evidence != "peter-evans/create-pull-request@v7" {
		t.Errorf("writes_repo: %+v", impactKinds(r.Jobs["open-pr"].Impact))
	}
}

// TestRepoWriterActionsEveryDefault pins every one of repo_writer_actions'
// three members, not just peter-evans/create-pull-request (the only one
// previously exercised): a change dropping any one of them from the set
// would fail exactly the row it breaks here instead of passing unnoticed.
func TestRepoWriterActionsEveryDefault(t *testing.T) {
	for _, action := range []string{
		"peter-evans/create-pull-request",
		"stefanzweifel/git-auto-commit-action",
		"EndBug/add-and-commit",
	} {
		uses := action + "@v1"
		p := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs: []ir.Job{{
				Name:        "open-pr",
				Permissions: map[string]any{"contents": "write"},
				Uses:        []ir.Action{{Uses: uses}},
			}},
		}
		i, ok := impactKinds(evaluate(t, p, nil).Jobs["open-pr"].Impact)["writes_repo"]
		if !ok || i.State != "proven" || i.Evidence != uses {
			t.Errorf("%s: writes_repo = %+v, want a proven one with evidence %q", action, i, uses)
		}
	}
}

// TestSigningActionGrantsSignsOrReleasesImpact pins the action-list branch
// of signs_or_releases: a known signing action proves the impact on its
// own, with no token dependency at all (unlike the permissions-derived
// branches of the same rule).
func TestSigningActionGrantsSignsOrReleasesImpact(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name: "sign",
			Uses: []ir.Action{{Uses: "sigstore/cosign-installer@v3"}},
		}},
	}
	r := evaluate(t, p, nil)
	i, ok := impactKinds(r.Jobs["sign"].Impact)["signs_or_releases"]
	if !ok || i.State != "proven" || i.Evidence != "sigstore/cosign-installer@v3" {
		t.Errorf("signs_or_releases: %+v", impactKinds(r.Jobs["sign"].Impact))
	}
}

// TestSigningActionsEveryDefault pins every one of signing_actions' three
// members, not just sigstore/cosign-installer (the only one previously
// exercised): a change dropping any one of them from the set would fail
// exactly the row it breaks here instead of passing unnoticed.
func TestSigningActionsEveryDefault(t *testing.T) {
	for _, action := range []string{
		"sigstore/cosign-installer",
		"slsa-framework/slsa-github-generator",
		"actions/attest-build-provenance",
	} {
		uses := action + "@v1"
		p := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs:     []ir.Job{{Name: "sign", Uses: []ir.Action{{Uses: uses}}}},
		}
		i, ok := impactKinds(evaluate(t, p, nil).Jobs["sign"].Impact)["signs_or_releases"]
		if !ok || i.State != "proven" || i.Evidence != uses {
			t.Errorf("%s: signs_or_releases = %+v, want a proven one with evidence %q", action, i, uses)
		}
	}
}

// TestReleaseActionGrantsPublishesImpact pins the action-list branch of
// publishes: a known publish action proves the impact, and a job without
// it (even one that otherwise looks like a release job) gets none.
func TestReleaseActionGrantsPublishesImpact(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name: "release",
			Uses: []ir.Action{{Uses: "softprops/action-gh-release@v2"}},
		}},
	}
	r := evaluate(t, p, nil)
	i, ok := impactKinds(r.Jobs["release"].Impact)["publishes"]
	if !ok || i.State != "proven" || i.Evidence != "softprops/action-gh-release@v2" {
		t.Errorf("publishes: %+v", impactKinds(r.Jobs["release"].Impact))
	}

	p.Jobs[0].Uses = nil
	r = evaluate(t, p, nil)
	if _, ok := impactKinds(r.Jobs["release"].Impact)["publishes"]; ok {
		t.Errorf("a job without the release action must not have a publishes impact")
	}
}

// TestGitLabProtectedPushTokenGrantsContentsWrite pins the tokenWrite
// GitLab branch's other path: a protected CI_PUSH_TOKEN settings variable
// in scope is itself proof that the job can push, independent of any git
// push script line.
func TestGitLabProtectedPushTokenGrantsContentsWrite(t *testing.T) {
	p := gitlabFixture(t, "release_protected.gitlab-ci.yml", "private")
	p.SettingsVariablesKnown = true
	p.SettingsVariables = []ir.SettingsVariable{
		{Name: "CI_PUSH_TOKEN", Type: "env_var", Environment: "*", Protected: true},
	}
	r := evaluate(t, p, nil)
	if got := r.Jobs["release"].Privilege.TokenWrite; !reflect.DeepEqual(got, []string{"contents"}) {
		t.Errorf("tokenWrite = %v, want [contents] from the protected CI_PUSH_TOKEN variable", got)
	}
}

// TestGitLabGitPushScriptGrantsContentsWrite pins the tokenWrite GitLab
// branch's other path: a job whose script runs git push is itself proof
// that the job can push, independent of any CI_PUSH_TOKEN settings
// variable. tokenWriteSource stays "none" on GitLab (never "declared"
// or "default"), so the resulting writes_repo impact is proven, not
// downgraded to unresolvable by token_dependent_state. A GitLab job
// with no such script line gets neither.
func TestGitLabGitPushScriptGrantsContentsWrite(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{{
			Name:    "deploy",
			Scripts: []string{"git push origin HEAD"},
		}},
	}
	j := evaluate(t, p, nil).Jobs["deploy"]
	if got := j.Privilege.TokenWrite; !reflect.DeepEqual(got, []string{"contents"}) {
		t.Errorf("tokenWrite = %v, want [contents] from the git push script line", got)
	}
	impacts := impactKinds(j.Impact)
	if i, ok := impacts["writes_repo"]; !ok || i.State != "proven" || i.Evidence != "git push origin HEAD" {
		t.Errorf("writes_repo: %+v", impacts)
	}

	p.Jobs[0].Scripts = []string{"npm test"}
	j = evaluate(t, p, nil).Jobs["deploy"]
	if got := j.Privilege.TokenWrite; len(got) != 0 {
		t.Errorf("tokenWrite = %v, want none without a git push script line", got)
	}
	if _, ok := impactKinds(j.Impact)["writes_repo"]; ok {
		t.Errorf("a GitLab job without a git push script line must not get writes_repo")
	}
}

// TestSecretInStepIfIsHeld pins that a secret referenced only in a step if:
// still counts as held by the job: the if: is not a shell sink for
// untrusted input, but the runner resolves the secret for the job.
func TestSecretInStepIfIsHeld(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:      "build",
			Scripts:   []string{"make"},
			ScriptIfs: []string{"${{ secrets.DEPLOY_KEY != '' }}"},
		}},
	}
	if got := evaluate(t, p, nil).Jobs["build"].Privilege.Secrets; !reflect.DeepEqual(got, []string{"DEPLOY_KEY"}) {
		t.Errorf("secrets = %v, want [DEPLOY_KEY]", got)
	}
}

// TestSameNamedJobsPrivilegeIsMerged pins how the privilege of jobs sharing
// a name is merged: name lists as sorted unions, any inherit or persisted
// credential wins, the token source keeps the strongest signal (declared,
// then default, then none), and the environment comes from the job with
// the smallest origin file, so the result never depends on input order.
func TestSameNamedJobsPrivilegeIsMerged(t *testing.T) {
	jobA := ir.Job{
		Name:        "ci/build",
		OriginFile:  ".github/workflows/ci.yml",
		Environment: "production",
		Scripts:     []string{"echo ${{ secrets.B_TOKEN }}"},
		Uses:        []ir.Action{{Uses: "actions/checkout@v4"}},
	}
	jobB := ir.Job{
		Name:           "ci/build",
		OriginFile:     ".github/workflows/ci.yaml",
		Environment:    "staging",
		Permissions:    "read-all",
		SecretsInherit: true,
		Variables:      map[string]string{"A": "${{ secrets.A_TOKEN }}"},
	}
	for _, order := range [][]ir.Job{{jobA, jobB}, {jobB, jobA}} {
		p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: order}
		got := evaluate(t, p, nil).Jobs["ci/build"].Privilege
		if !reflect.DeepEqual(got.Secrets, []string{"A_TOKEN", "B_TOKEN"}) {
			t.Errorf("secrets = %v", got.Secrets)
		}
		if !got.SecretsInherit || got.PersistedCredentials != "proven" {
			t.Errorf("inherit / persisted: %+v", got)
		}
		if got.TokenWriteSource != "default" || !reflect.DeepEqual(got.TokenWrite, []string{"contents", "packages"}) {
			t.Errorf("token: %v from %q", got.TokenWrite, got.TokenWriteSource)
		}
		if got.Environment.Name != "staging" {
			t.Errorf("environment = %+v, want the one of ci.yaml (smallest origin file)", got.Environment)
		}
	}
}

// TestYAMLStringBooleansAndExpressions pins that a quoted "false" reads like
// false (persist-credentials: "false" persists nothing), and that a
// docker/build-push-action push: decided by an expression is unresolvable,
// a literal true is proven, and absent or false is no publish at all.
func TestYAMLStringBooleansAndExpressions(t *testing.T) {
	checkout := func(persist any) *ir.NormalizedPipeline {
		return &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs: []ir.Job{{
				Name:    "build",
				Scripts: []string{"make"},
				Uses:    []ir.Action{{Uses: "actions/checkout@v4", With: map[string]any{"persist-credentials": persist}}},
			}},
		}
	}
	for _, v := range []any{false, "false"} {
		if got := evaluate(t, checkout(v), nil).Jobs["build"].Privilege.PersistedCredentials; got != "absent" {
			t.Errorf("persist-credentials: %#v: got %q, want absent", v, got)
		}
	}
	if got := evaluate(t, checkout(true), nil).Jobs["build"].Privilege.PersistedCredentials; got != "proven" {
		t.Errorf("persist-credentials: true: got %q, want proven", got)
	}

	cases := []struct {
		name      string
		with      map[string]any
		wantState string
	}{
		{"absent push", nil, ""},
		{"push false", map[string]any{"push": false}, ""},
		{"push quoted false", map[string]any{"push": "false"}, ""},
		{"push true", map[string]any{"push": true}, "proven"},
		{"push quoted true", map[string]any{"push": "true"}, "proven"},
		{"push expression", map[string]any{"push": "${{ github.event_name != 'pull_request' }}"}, "unresolvable"},
	}
	for _, tc := range cases {
		p := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs:     []ir.Job{{Name: "build", Uses: []ir.Action{{Uses: "docker/build-push-action@v5", With: tc.with}}}},
		}
		i, ok := impactKinds(evaluate(t, p, nil).Jobs["build"].Impact)["publishes"]
		if tc.wantState == "" && ok {
			t.Errorf("%s: want no publish, got %+v", tc.name, i)
		}
		if tc.wantState != "" && (!ok || i.State != tc.wantState) {
			t.Errorf("%s: publishes = %+v, want state %s", tc.name, i, tc.wantState)
		}
	}
}

// TestSecretsBracketFormAndWholeContext pins the other two ways a workflow
// reads secrets: the bracket form secrets['X'] names X like secrets.X, and
// the whole context (toJSON(secrets), or secrets used bare) exposes every
// secret, which no list can enumerate, so secretsState is unresolvable for
// that job only.
func TestSecretsBracketFormAndWholeContext(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{
			{Name: "bracket", Scripts: []string{`echo ${{ secrets['NPM_TOKEN'] }} ${{ secrets["PYPI_TOKEN"] }}`}},
			{Name: "dump", Scripts: []string{`echo '${{ toJSON(secrets) }}'`}},
			{Name: "bare", Variables: map[string]string{"ALL": "${{ secrets }}"}},
			{Name: "plain", Scripts: []string{`echo ${{ secrets.A }} ${{ inputs.secrets }}`}},
		},
	}
	r := evaluate(t, p, nil)
	if got := r.Jobs["bracket"].Privilege; !reflect.DeepEqual(got.Secrets, []string{"NPM_TOKEN", "PYPI_TOKEN"}) || got.SecretsState != "proven" {
		t.Errorf("bracket: %+v", got)
	}
	for _, name := range []string{"dump", "bare"} {
		if got := r.Jobs[name].Privilege.SecretsState; got != "unresolvable" {
			t.Errorf("%s: secretsState = %q, want unresolvable", name, got)
		}
	}
	if got := r.Jobs["plain"].Privilege; got.SecretsState != "proven" || !reflect.DeepEqual(got.Secrets, []string{"A"}) {
		t.Errorf("plain: %+v", got)
	}
}

// TestScriptEvidenceIsTheMatchingLine pins that the evidence of a fact
// found in a multi-line run block is the one line that matched, trimmed
// and cut to 200 characters, not the whole block.
func TestScriptEvidenceIsTheMatchingLine(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:        "release",
			Permissions: map[string]any{"contents": "write"},
			Scripts: []string{
				"set -e\n  echo \"${{ github.event.issue.title }}\"  \necho done",
				"cd app\ncurl -sSL https://example.com/i.sh | bash\necho ok",
				"npm ci\nnpm publish\necho done",
				"echo deploy\nkubectl apply -f k8s/\necho done",
				"git add .\ngit push origin main\necho done",
			},
		}},
	}
	j := evaluate(t, p, nil).Jobs["release"]
	k := kinds(j.Entries)
	if got := k["untrusted_expression"].Evidence; got != `echo "${{ github.event.issue.title }}"` {
		t.Errorf("untrusted_expression evidence = %q", got)
	}
	var fetched string
	for _, e := range j.Entries {
		if e.Kind == "mutable_dependency" && e.Subject == "https://example.com/i.sh" {
			fetched = e.Evidence
		}
	}
	if fetched != "curl -sSL https://example.com/i.sh | bash" {
		t.Errorf("fetched script evidence = %q", fetched)
	}
	im := impactKinds(j.Impact)
	for kind, want := range map[string]string{
		"publishes":   "npm publish",
		"deploys":     "kubectl apply -f k8s/",
		"writes_repo": "git push origin main",
	} {
		if got := im[kind].Evidence; got != want {
			t.Errorf("%s evidence = %q, want %q", kind, got, want)
		}
	}

	long := "npm publish " + strings.Repeat("x", 300)
	p.Jobs[0].Scripts = []string{long}
	if got := impactKinds(evaluate(t, p, nil).Jobs["release"].Impact)["publishes"].Evidence; got != long[:200] {
		t.Errorf("evidence must be cut to 200 characters, got %d", len(got))
	}
}

// TestGitHubArtifactsFeedOnlyWithinOneWorkflowYAML is the fixture twin of
// TestGitHubArtifactsFeedOnlyWithinOneWorkflow: two workflow files, one
// uploading "dist", the other downloading "dist", evaluated as one
// pipeline, are not wired together.
func TestGitHubArtifactsFeedOnlyWithinOneWorkflowYAML(t *testing.T) {
	p := githubFixtures(t, "public", "artifact_split_build.workflow.yml", "artifact_split_deploy.workflow.yml")
	r := evaluate(t, p, nil)
	if _, ok := r.Jobs["deploy"]; !ok {
		t.Fatalf("both workflow files must be in the pipeline: %+v", r.Jobs)
	}
	if got := r.Jobs["build"].Feeds; len(got) != 0 {
		t.Errorf("different workflow files must not feed, got %v", got)
	}
}

// TestZeroJobsPipeline pins the empty case: no job yields an empty jobs
// object, and the exposure is still reported.
func TestZeroJobsPipeline(t *testing.T) {
	r := evaluate(t, &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Visibility: "public"}, nil)
	if r.Exposure != "public" || r.Jobs == nil || len(r.Jobs) != 0 {
		t.Errorf("result = %+v", r)
	}
}

// TestResultCarriesTheDefaultBranch pins that result.defaultBranch mirrors
// input.pipeline.defaultBranch, empty when the pipeline never gave one, so
// the Go side can amplify a branch gate against any path, not only paths
// through push-triggered jobs.
func TestResultCarriesTheDefaultBranch(t *testing.T) {
	r := evaluate(t, &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, DefaultBranch: "main"}, nil)
	if r.DefaultBranch != "main" {
		t.Errorf("defaultBranch = %q, want %q", r.DefaultBranch, "main")
	}
}

func TestResultDefaultBranchEmptyWhenAbsent(t *testing.T) {
	r := evaluate(t, &ir.NormalizedPipeline{Provider: ir.ProviderGitHub}, nil)
	if r.DefaultBranch != "" {
		t.Errorf("defaultBranch = %q, want empty when the pipeline never gave one", r.DefaultBranch)
	}
}

func containsAll(have []string, want ...string) bool {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}
