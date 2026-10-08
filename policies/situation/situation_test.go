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
	AllSecrets           bool     `json:"allSecrets"`
	ProtectedSecrets     []string `json:"protectedSecrets"`
	TokenWrite           []string `json:"tokenWrite"`
	TokenWriteSource     string   `json:"tokenWriteSource"`
	PersistedCredentials string   `json:"persistedCredentials"`
	Environment          struct {
		Name      string `json:"name"`
		Protected string `json:"protected"`
		Reviewers string `json:"reviewers"`
	} `json:"environment"`
}
type impact struct {
	Kind, State, Evidence, Source, Via string
}
type jobFacts struct {
	ForkPR             []entry             `json:"forkPR"`
	PrivilegedTriggers []string            `json:"privilegedTriggers"`
	RefTriggers        []string            `json:"refTriggers"`
	Push               []entry             `json:"push"`
	Privilege          privilege           `json:"privilege"`
	Impact             []impact            `json:"impact"`
	Feeds              []string            `json:"feeds"`
	FeedsVia           map[string][]string `json:"feedsVia"`
	Caches             []cacheFact         `json:"caches"`
}
type cacheFact struct {
	Key    string `json:"key"`
	Family string `json:"family"`
	Mode   string `json:"mode"`
	Prefix bool   `json:"prefix"`
	Uses   string `json:"uses"`
	Line   int    `json:"line"`
}
type includeFact struct {
	Subject string   `json:"subject"`
	Source  string   `json:"source"`
	File    string   `json:"file"`
	Line    int      `json:"line"`
	Jobs    []string `json:"jobs"`
}
type result struct {
	Exposure      string              `json:"exposure"`
	Jobs          map[string]jobFacts `json:"jobs"`
	DefaultBranch string              `json:"defaultBranch"`
	Provider      string              `json:"provider"`
	Includes      []includeFact       `json:"includes"`
}

func evaluate(t *testing.T, p *ir.NormalizedPipeline, cfg map[string]any) result {
	t.Helper()
	var r result
	evaluateInto(t, p, cfg, &r)
	return r
}

// evaluateInto runs the facts policy on p and decodes its result into out,
// for a test reading facts the shared result type does not carry.
func evaluateInto(t *testing.T, p *ir.NormalizedPipeline, cfg map[string]any, out any) {
	t.Helper()
	src, err := situation.SituationFS.ReadFile(situation.SituationModule)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := opaengine.New().EvaluateSituation(context.Background(), string(src), p, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
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

// firstEntry is the first of a job's trigger facts, if it has one.
func firstEntry(entries []entry) (entry, bool) {
	if len(entries) == 0 {
		return entry{}, false
	}
	return entries[0], true
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
	if e, ok := firstEntry(r.Jobs["build"].ForkPR); !ok || e.State != "proven" {
		t.Errorf("fork_pr missing or not proven: %+v", r.Jobs["build"].ForkPR)
	}
}

// TestPrivilegedTriggersAreTheJobsOwn pins the privileged trigger fact: a
// job running on pull_request_target (or another event that runs with the
// base repository's secrets) carries it whatever its checkout or guard; a
// plain pull_request job carries none.
func TestPrivilegedTriggersAreTheJobsOwn(t *testing.T) {
	r := evaluate(t, githubFixture(t, "privileged_trigger_injection.workflow.yml", "public"), nil)
	if got := r.Jobs["build"].PrivilegedTriggers; !reflect.DeepEqual(got, []string{"pull_request_target"}) {
		t.Errorf("privileged triggers = %v, want [pull_request_target]", got)
	}
	if _, ok := firstEntry(r.Jobs["build"].ForkPR); !ok {
		t.Errorf("the pull_request trigger is still a fork entry: %+v", r.Jobs["build"])
	}
	plain := evaluate(t, githubFixture(t, "fork_pr_injection.workflow.yml", "public"), nil)
	if got := plain.Jobs["build"].PrivilegedTriggers; len(got) != 0 {
		t.Errorf("a plain pull_request job has no privileged trigger: %v", got)
	}
}

// TestRefTriggersAreTheEventsThatRunOnTheRepositorysOwnRefs pins the ref
// trigger fact: a push, a schedule, a release or a manual run runs the
// workflow on a branch or a tag of the repository itself, so what it saves
// to the cache is in that ref's scope. A pull request run is not one, and a
// GitLab job carries none.
func TestRefTriggersAreTheEventsThatRunOnTheRepositorysOwnRefs(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{
			{Name: "ci", Triggers: []string{"pull_request", "push"}},
			{Name: "nightly", Triggers: []string{"workflow_dispatch", "schedule", "release"}},
			{Name: "pr", Triggers: []string{"pull_request", "pull_request_target"}},
		},
	}
	r := evaluate(t, p, nil)
	for name, want := range map[string][]string{
		"ci":      {"push"},
		"nightly": {"release", "schedule", "workflow_dispatch"},
		"pr":      {},
	} {
		if got := r.Jobs[name].RefTriggers; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: ref triggers = %v, want %v", name, got, want)
		}
	}
	gl := evaluate(t, &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, Jobs: []ir.Job{{Name: "build"}}}, nil)
	if got := gl.Jobs["build"].RefTriggers; len(got) != 0 {
		t.Errorf("gitlab: ref triggers = %v, want none", got)
	}
}

func TestSameRepoGuardRemovesForkEntry(t *testing.T) {
	r := evaluate(t, githubFixture(t, "same_repo_guard.workflow.yml", "public"), nil)
	if got := r.Jobs["build"].ForkPR; len(got) != 0 {
		t.Errorf("same-repo guard must remove fork_pr: %+v", got)
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
	if _, ok := firstEntry(evaluate(t, p, nil).Jobs["build"].ForkPR); ok {
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
			if _, ok := firstEntry(evaluate(t, p, nil).Jobs["build"].ForkPR); ok {
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
		e, ok := firstEntry(evaluate(t, p, nil).Jobs["build"].ForkPR)
		if !ok || e.State != "proven" {
			t.Errorf("an unguarded pull_request job must still get fork_pr: %+v", e)
		}
	})
}

func TestTagPushIsNotAForkEntry(t *testing.T) {
	r := evaluate(t, githubFixture(t, "release_mutable_action.workflow.yml", "public"), nil)
	if got := r.Jobs["release"].ForkPR; len(got) != 0 {
		t.Errorf("a tag push is not a fork entry: %+v", got)
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
	if e, ok := firstEntry(r.Jobs["deploy"].Push); !ok || e.State != "proven" || e.Subject != "main" {
		t.Errorf("unprotected_push: %+v", e)
	}
	p.Branches = []ir.Branch{{Name: "main", Protected: true}}
	if _, ok := firstEntry(evaluate(t, p, nil).Jobs["deploy"].Push); ok {
		t.Errorf("a protected default branch is not an entry")
	}
	p.Branches = nil
	if e, ok := firstEntry(evaluate(t, p, nil).Jobs["deploy"].Push); !ok || e.State != "unresolvable" {
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
	if e, ok := firstEntry(evaluate(t, p, nil).Jobs["deploy"].Push); ok {
		t.Errorf("unprotected_push: %+v, want none (branches: ['release/*'] does not reach main)", e)
	}
}

func TestGitLabMREntries(t *testing.T) {
	r := evaluate(t, gitlabFixture(t, "mr_injection.gitlab-ci.yml", "public"), nil)
	if _, ok := firstEntry(r.Jobs["test"].ForkPR); !ok {
		t.Errorf("an MR job without a fork restriction is a fork entry: %+v", r.Jobs["test"])
	}
}

// TestEntriesCarryFileAndLine pins that a trigger fact's file/line come
// from the job's origin.
func TestEntriesCarryFileAndLine(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:       "build",
			OriginFile: ".github/workflows/ci.yml",
			OriginLine: 7,
			Triggers:   []string{"pull_request"},
		}},
	}
	r := evaluate(t, p, nil)
	if e, ok := firstEntry(r.Jobs["build"].ForkPR); !ok || e.File != ".github/workflows/ci.yml" || e.Line != 7 {
		t.Errorf("fork_pr origin: %+v", e)
	}
}

// TestReleasePrivilegeAndImpact pins the core per-job facts: what the
// release job holds (a secret, write permissions, an environment, surviving
// checkout credentials) and what it can change (it publishes). An
// environment is a fact, never an impact by itself: it protects the job,
// it is not what an attacker gains, and whether it requires an approval is
// unknown from the workflow. id-token: write is a privilege only: with no
// signing or release step the job has no signs_or_releases impact.
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
	if j.Privilege.Environment.Name != "production" || j.Privilege.Environment.Protected != "unknown" || j.Privilege.Environment.Reviewers != "unknown" {
		t.Errorf("environment: %+v", j.Privilege.Environment)
	}
	kinds := map[string]impact{}
	for _, i := range j.Impact {
		kinds[i.Kind] = i
	}
	if i, ok := kinds["publishes"]; !ok || i.Evidence != "npm publish" || i.State != "proven" {
		t.Errorf("publishes: %+v", kinds)
	}
	if i, ok := kinds["deploys"]; ok {
		t.Errorf("an environment alone is no deploy impact: %+v", i)
	}
	if _, ok := kinds["signs_or_releases"]; ok {
		t.Errorf("id-token: write without a signing or release step is a privilege, not an impact: %+v", kinds)
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
	// A rule gated on $CI_MERGE_REQUEST_IID == null runs on branch pushes,
	// NOT inside a merge request (that variable is only ever set inside
	// one): the opposite condition of the bare-presence form above, so
	// this job must keep its protected variable like any other
	// branch-push job, not have it stripped as merge-request-only.
	iidNullRule := map[string]any{"if": `$CI_MERGE_REQUEST_IID == null`}
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
			{Name: "mr_iid_null", Rules: []map[string]any{iidNullRule}},
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
		"mr_iid_null":     {"PYPI_TOKEN", "SENTRY_DSN"},
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
		// A read-only token, so the publish can only come from the script.
		Jobs: []ir.Job{{Name: "release", Permissions: "read-all", Scripts: []string{"npm publish --dry-run"}}},
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
			Name:        "build",
			Permissions: "read-all", // the publish can only come from the action
			Uses:        []ir.Action{{Uses: "docker/build-push-action@v5"}},
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

// TestWriteTokenScopesAreImpacts pins that the job token's own write
// scopes are what code running in the job can change: contents write
// writes to the repository, packages write publishes, deployments write
// deploys, write-all gives all three. Only a token whose permissions are
// declared gives them: the assumed repository default (no permissions
// block) is a guess about scopes Plumber cannot read, so it stays a
// privilege only. Every other scope is a privilege only.
func TestWriteTokenScopesAreImpacts(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{
			{Name: "all", Permissions: "write-all"},
			{Name: "contents", Permissions: map[string]any{"contents": "write", "pull-requests": "write"}},
			{Name: "deployments", Permissions: map[string]any{"deployments": "write"}},
			{Name: "packages", Permissions: map[string]any{"packages": "write"}},
			{Name: "other", Permissions: map[string]any{
				"actions": "write", "checks": "write", "id-token": "write", "issues": "write",
				"pull-requests": "write", "security-events": "write", "statuses": "write",
			}},
			{Name: "default"},
			{Name: "read", Permissions: "read-all"},
		},
	}
	r := evaluate(t, p, nil)
	for name, want := range map[string]map[string]string{
		"all":         {"writes_repo": "proven", "publishes": "proven", "deploys": "proven"},
		"contents":    {"writes_repo": "proven"},
		"deployments": {"deploys": "proven"},
		"packages":    {"publishes": "proven"},
		"other":       {},
		"default":     {},
		"read":        {},
	} {
		got := map[string]string{}
		for _, i := range r.Jobs[name].Impact {
			if i.Source != "token" {
				t.Errorf("%s: an impact with no script behind it comes from the token: %+v", name, i)
			}
			got[i.Kind] = i.State
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: impacts = %v, want %v (%+v)", name, got, want, r.Jobs[name].Impact)
		}
	}
	if i := impactKinds(r.Jobs["all"].Impact)["deploys"]; i.Evidence != "permissions: write-all" {
		t.Errorf("write-all evidence = %q", i.Evidence)
	}
	if i := impactKinds(r.Jobs["contents"].Impact)["writes_repo"]; i.Evidence != "permissions: contents: write" {
		t.Errorf("contents evidence = %q", i.Evidence)
	}
	if got := r.Jobs["default"].Privilege; got.TokenWriteSource != "default" || len(got.TokenWrite) == 0 {
		t.Errorf("the default token stays a privilege: %+v", got)
	}
}

// TestOneImpactSourcePerKind pins that a kind the job's own script or
// action already proves is not counted a second time from the token, and
// that a token proving a kind replaces a script fact of that kind that
// could not be resolved.
func TestOneImpactSourcePerKind(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{
			{Name: "publish", Permissions: "write-all", Scripts: []string{"npm publish"}},
			{
				Name:        "image",
				Permissions: map[string]any{"packages": "write"},
				Uses:        []ir.Action{{Uses: "docker/build-push-action@v5", With: map[string]any{"push": "${{ inputs.push }}"}}},
			},
			{Name: "push", Scripts: []string{"git push origin main"}},
		},
	}
	r := evaluate(t, p, nil)
	count := func(job, kind string) (n int, last impact) {
		for _, i := range r.Jobs[job].Impact {
			if i.Kind == kind {
				n, last = n+1, i
			}
		}
		return n, last
	}
	if n, i := count("publish", "publishes"); n != 1 || i.Source == "token" || i.Evidence != "npm publish" {
		t.Errorf("publish: want the script's publish alone, got %d, %+v", n, r.Jobs["publish"].Impact)
	}
	if n, i := count("publish", "writes_repo"); n != 1 || i.Source != "token" || i.State != "proven" {
		t.Errorf("publish: want the token's repository write, got %+v", r.Jobs["publish"].Impact)
	}
	if n, i := count("image", "publishes"); n != 1 || i.Source != "token" || i.State != "proven" {
		t.Errorf("image: want the declared token's proven publish in place of the unresolved push, got %+v", r.Jobs["image"].Impact)
	}
	if n, i := count("push", "writes_repo"); n != 1 || i.Source == "token" || i.State != "unresolvable" {
		t.Errorf("push: want the git push alone, unresolvable on a default token, got %+v", r.Jobs["push"].Impact)
	}
}

// TestWriteAllGrantsNoSigningImpact pins that permissions: write-all
// expands to every write scope, id-token included, as a declared token, but
// grants no signs_or_releases impact by itself: the impact needs a signing
// or release step.
func TestWriteAllGrantsNoSigningImpact(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs:     []ir.Job{{Name: "release", Permissions: "write-all"}},
	}
	r := evaluate(t, p, nil)
	j := r.Jobs["release"]
	if j.Privilege.TokenWriteSource != "declared" || !containsAll(j.Privilege.TokenWrite, "id-token") {
		t.Errorf("privilege = %+v, want a declared token carrying id-token", j.Privilege)
	}
	if i, ok := impactKinds(j.Impact)["signs_or_releases"]; ok {
		t.Errorf("write-all alone must not be a signing impact: %+v", i)
	}
}

// TestIDTokenWriteAloneIsAPrivilegeOnly pins that id-token: write stays in
// tokenWrite (the job can mint an OIDC token) but is no signs_or_releases
// impact without a signing or release step: logging in to a cloud or
// pushing a score holds a token, it does not sign or release anything.
func TestIDTokenWriteAloneIsAPrivilegeOnly(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:        "plumber",
			Permissions: map[string]any{"contents": "read", "id-token": "write"},
			Scripts:     []string{"plumber analyze"},
		}},
	}
	j := evaluate(t, p, nil).Jobs["plumber"]
	if !reflect.DeepEqual(j.Privilege.TokenWrite, []string{"id-token"}) {
		t.Errorf("tokenWrite = %v, want [id-token]", j.Privilege.TokenWrite)
	}
	if i, ok := impactKinds(j.Impact)["signs_or_releases"]; ok {
		t.Errorf("id-token: write alone must not be a signing impact: %+v", i)
	}
}

// TestSigningOrReleaseScriptGrantsSignsOrReleasesImpact pins the script
// branch of signs_or_releases: each signing or release command is the
// impact, with the matching line as evidence. The state is proven when the
// job declares id-token: write, and follows the token-dependent rule
// otherwise (an assumed default token is unresolvable). slsa-verifier is
// deliberately not in this list: it only checks a provenance file, see
// TestSlsaVerifierOnlyVerifiesAndGrantsNoImpact.
func TestSigningOrReleaseScriptGrantsSignsOrReleasesImpact(t *testing.T) {
	for _, line := range []string{
		"cosign sign --yes ghcr.io/o/app@sha256:abc",
		"cosign attest --predicate sbom.json ghcr.io/o/app",
		"gh release create v1.2.3 dist/*",
		"gh release upload v1.2.3 dist/app.tar.gz",
		"npm publish --access public --provenance",
	} {
		declared := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs:     []ir.Job{{Name: "sign", Permissions: map[string]any{"id-token": "write"}, Scripts: []string{line}}},
		}
		i, ok := impactKinds(evaluate(t, declared, nil).Jobs["sign"].Impact)["signs_or_releases"]
		if !ok || i.State != "proven" || i.Evidence != line {
			t.Errorf("%q with id-token: write: signs_or_releases = %+v, want proven with the line as evidence", line, i)
		}
		assumed := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs:     []ir.Job{{Name: "sign", Scripts: []string{line}}},
		}
		i, ok = impactKinds(evaluate(t, assumed, nil).Jobs["sign"].Impact)["signs_or_releases"]
		if !ok || i.State != "unresolvable" {
			t.Errorf("%q with the default token: signs_or_releases = %+v, want unresolvable", line, i)
		}
	}
	none := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs:     []ir.Job{{Name: "sign", Permissions: map[string]any{"id-token": "write"}, Scripts: []string{"gh release view v1.2.3", "cosign verify ghcr.io/o/app"}}},
	}
	if i, ok := impactKinds(evaluate(t, none, nil).Jobs["sign"].Impact)["signs_or_releases"]; ok {
		t.Errorf("reading a release or verifying a signature is not a signing impact: %+v", i)
	}
}

// TestCommentedOrQuotedSigningCommandGrantsNoImpact pins that the script
// branch of signs_or_releases reads the command a line runs, not its
// comments or its quoted text: a commented-out command, a trailing comment
// and a command only printed inside a quoted string sign and release
// nothing. A real command with a quoted argument or a trailing comment
// still counts, with the whole line as evidence.
func TestCommentedOrQuotedSigningCommandGrantsNoImpact(t *testing.T) {
	inert := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{Name: "build", Permissions: map[string]any{"id-token": "write"}, Scripts: []string{
			"# cosign sign --yes ghcr.io/o/app\n  # gh release create v1.2.3\nmake build # then: gh release upload v1 dist/app",
			"echo \"run: gh release create v1.2.3 dist/*\"",
			"echo 'cosign sign --yes IMAGE'",
		}}},
	}
	if i, ok := impactKinds(evaluate(t, inert, nil).Jobs["build"].Impact)["signs_or_releases"]; ok {
		t.Errorf("a commented-out or quoted command signs and releases nothing: %+v", i)
	}
	for _, line := range []string{
		"cosign sign --yes \"$IMAGE\" # keyless",
		"gh release create \"$TAG\" dist/*",
	} {
		real := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs:     []ir.Job{{Name: "sign", Permissions: map[string]any{"id-token": "write"}, Scripts: []string{line}}},
		}
		i, ok := impactKinds(evaluate(t, real, nil).Jobs["sign"].Impact)["signs_or_releases"]
		if !ok || i.State != "proven" || i.Evidence != line {
			t.Errorf("%q: signs_or_releases = %+v, want proven with the line as evidence", line, i)
		}
	}
}

// TestSlsaVerifierOnlyVerifiesAndGrantsNoImpact pins that a bare `slsa-`
// script match is gone: slsa-verifier verify(-artifact) only checks a
// provenance file against an artifact, it signs or releases nothing, so it
// must not grant signs_or_releases. The SLSA generator still does, through
// slsa-framework/slsa-github-generator in signing_actions (the
// reusable-workflow shape every project calls it as, never a script line).
func TestSlsaVerifierOnlyVerifiesAndGrantsNoImpact(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:        "verify",
			Permissions: map[string]any{"id-token": "write"},
			Scripts:     []string{"slsa-verifier verify-artifact app --provenance-path app.intoto.jsonl --source-uri github.com/o/r"},
		}},
	}
	if i, ok := impactKinds(evaluate(t, p, nil).Jobs["verify"].Impact)["signs_or_releases"]; ok {
		t.Errorf("slsa-verifier only verifies, it must not grant signs_or_releases: %+v", i)
	}
}

// TestReleaseStepIsCountedOnce pins that one step is one impact: a
// release action is a signs_or_releases impact and never also publishes,
// whether or not the configured publish list names it; a release command
// matching a publish pattern (goreleaser) stays publishes only, like the
// goreleaser action.
func TestReleaseStepIsCountedOnce(t *testing.T) {
	for _, tc := range []struct {
		name string
		job  ir.Job
	}{
		{"goreleaser action", ir.Job{Name: "release", Uses: []ir.Action{{Uses: "goreleaser/goreleaser-action@v6"}}}},
		{"goreleaser command", ir.Job{Name: "release", Scripts: []string{"goreleaser release --clean"}}},
	} {
		p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{tc.job}}
		kinds := impactKinds(evaluate(t, p, nil).Jobs["release"].Impact)
		if _, ok := kinds["publishes"]; !ok {
			t.Errorf("%s: want a publishes impact, got %+v", tc.name, kinds)
		}
		if _, ok := kinds["signs_or_releases"]; ok {
			t.Errorf("%s: a publish step must not also count as signs_or_releases: %+v", tc.name, kinds)
		}
	}
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs:     []ir.Job{{Name: "release", Permissions: map[string]any{"contents": "write", "id-token": "write"}, Uses: []ir.Action{{Uses: "ncipollo/release-action@v1"}}}},
	}
	for _, cfg := range []map[string]any{
		nil,
		{"cachePoisoning": map[string]any{"publishActions": []any{"pypa/gh-action-pypi-publish"}}},
		{"cachePoisoning": map[string]any{"publishActions": []any{"ncipollo/release-action"}}},
	} {
		kinds := impactKinds(evaluate(t, p, cfg).Jobs["release"].Impact)
		if i, ok := kinds["signs_or_releases"]; !ok || i.State != "proven" || i.Evidence != "ncipollo/release-action@v1" {
			t.Errorf("config %v: a release action is a signs_or_releases impact, got %+v", cfg, kinds)
		}
		if i, ok := kinds["publishes"]; ok && i.Source != "token" {
			t.Errorf("config %v: a release action is not a publishes impact: %+v", cfg, kinds)
		}
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
// of signs_or_releases: a known signing action is the impact, proven when
// the job declares id-token: write and unresolvable on an assumed default
// token (the token-dependent rule every signing step follows).
func TestSigningActionGrantsSignsOrReleasesImpact(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:        "sign",
			Permissions: map[string]any{"id-token": "write"},
			Uses:        []ir.Action{{Uses: "actions/attest-build-provenance@v1"}},
		}},
	}
	r := evaluate(t, p, nil)
	i, ok := impactKinds(r.Jobs["sign"].Impact)["signs_or_releases"]
	if !ok || i.State != "proven" || i.Evidence != "actions/attest-build-provenance@v1" {
		t.Errorf("signs_or_releases: %+v", impactKinds(r.Jobs["sign"].Impact))
	}
	p.Jobs[0].Permissions = nil
	i, ok = impactKinds(evaluate(t, p, nil).Jobs["sign"].Impact)["signs_or_releases"]
	if !ok || i.State != "unresolvable" {
		t.Errorf("a signing action on the default token: signs_or_releases = %+v, want unresolvable", i)
	}
}

// TestSigningActionsEveryDefault pins every one of signing_actions'
// members, not just actions/attest-build-provenance (the only one
// previously exercised): a change dropping any one of them from the set
// would fail exactly the row it breaks here instead of passing unnoticed.
// sigstore/cosign-installer is deliberately not in this set, see
// TestCosignInstallerAloneGrantsNoSigningImpact: installing the cosign
// binary signs nothing by itself.
func TestSigningActionsEveryDefault(t *testing.T) {
	for _, action := range []string{
		"slsa-framework/slsa-github-generator",
		"actions/attest-build-provenance",
	} {
		uses := action + "@v1"
		p := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs:     []ir.Job{{Name: "sign", Permissions: map[string]any{"id-token": "write"}, Uses: []ir.Action{{Uses: uses}}}},
		}
		i, ok := impactKinds(evaluate(t, p, nil).Jobs["sign"].Impact)["signs_or_releases"]
		if !ok || i.State != "proven" || i.Evidence != uses {
			t.Errorf("%s: signs_or_releases = %+v, want a proven one with evidence %q", action, i, uses)
		}
	}
}

// TestCosignInstallerAloneGrantsNoSigningImpact pins that installing the
// cosign binary is not itself a signing step: sigstore/cosign-installer is
// the usual setup step ahead of both `cosign sign` and `cosign verify`, so
// keeping it in signing_actions would give a verify-only job the same
// false signs_or_releases impact the slsa- script pattern gave
// slsa-verifier (TestSlsaVerifierOnlyVerifiesAndGrantsNoImpact). A job that
// installs cosign and only verifies gets no impact at all; the script
// branch (TestSigningOrReleaseScriptGrantsSignsOrReleasesImpact) is still
// what proves the impact once the job actually signs or attests.
func TestCosignInstallerAloneGrantsNoSigningImpact(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:        "verify",
			Permissions: map[string]any{"id-token": "write"},
			Uses:        []ir.Action{{Uses: "sigstore/cosign-installer@v3"}},
			Scripts:     []string{"cosign verify ghcr.io/o/app"},
		}},
	}
	if i, ok := impactKinds(evaluate(t, p, nil).Jobs["verify"].Impact)["signs_or_releases"]; ok {
		t.Errorf("installing cosign to verify must not grant signs_or_releases: %+v", i)
	}
}

// TestReleaseActionGrantsReleaseImpact pins the action-list branch of
// signs_or_releases: a known release action proves the impact (a
// read-all token is declared, so its state is proven), and a job without
// it (even one that otherwise looks like a release job) gets none.
func TestReleaseActionGrantsReleaseImpact(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:        "release",
			Permissions: "read-all", // the release can only come from the action
			Uses:        []ir.Action{{Uses: "softprops/action-gh-release@v2"}},
		}},
	}
	r := evaluate(t, p, nil)
	i, ok := impactKinds(r.Jobs["release"].Impact)["signs_or_releases"]
	if !ok || i.State != "proven" || i.Evidence != "softprops/action-gh-release@v2" {
		t.Errorf("signs_or_releases: %+v", impactKinds(r.Jobs["release"].Impact))
	}

	p.Jobs[0].Uses = nil
	r = evaluate(t, p, nil)
	if len(r.Jobs["release"].Impact) != 0 {
		t.Errorf("a job without the release action must have no impact, got %+v", r.Jobs["release"].Impact)
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
	// GitLab declares no token scope, so the push token is a privilege only.
	for _, i := range r.Jobs["release"].Impact {
		if i.Source == "token" {
			t.Errorf("a push token nobody declared gives no impact: %+v", i)
		}
	}
}

// TestGitLabMergeRequestOnlyJobHoldsNoProtectedPushToken mirrors
// TestGitLabMergeRequestOnlyJobHoldsNoProtectedVariable on the tokenWrite
// side: gitlab_contents_write's CI_PUSH_TOKEN branch must apply
// variable_reaches_job the same way the secrets side does, so a job whose
// every way to run is a merge request pipeline never receives the
// protected token and holds no contents tokenWrite. A job that runs on a
// protected branch instead (no merge-request-only rule) still does.
func TestGitLabMergeRequestOnlyJobHoldsNoProtectedPushToken(t *testing.T) {
	vars := []ir.SettingsVariable{
		{Name: "CI_PUSH_TOKEN", Type: "env_var", Environment: "*", Protected: true},
	}
	mrRule := map[string]any{"if": `$CI_PIPELINE_SOURCE == "merge_request_event"`}
	mainRule := map[string]any{"if": `$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`}
	p := &ir.NormalizedPipeline{
		Provider:               ir.ProviderGitLab,
		DefaultBranch:          "main",
		SettingsVariablesKnown: true,
		SettingsVariables:      vars,
		Jobs: []ir.Job{
			{Name: "mr_only", Rules: []map[string]any{mrRule}},
			{Name: "protected_branch", Rules: []map[string]any{mainRule}},
		},
	}
	r := evaluate(t, p, nil)
	if got := r.Jobs["mr_only"].Privilege.TokenWrite; len(got) != 0 {
		t.Errorf("mr_only: tokenWrite = %v, want none (the job never receives the protected CI_PUSH_TOKEN)", got)
	}
	if got := r.Jobs["protected_branch"].Privilege.TokenWrite; !reflect.DeepEqual(got, []string{"contents"}) {
		t.Errorf("protected_branch: tokenWrite = %v, want [contents]", got)
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
			Jobs:     []ir.Job{{Name: "build", Permissions: "read-all", Uses: []ir.Action{{Uses: "docker/build-push-action@v5", With: tc.with}}}},
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

// TestSecretsBracketFormAndWholeContext pins the other ways a workflow
// reads secrets: the bracket form secrets['X'] names X like secrets.X, and
// the whole context (toJSON(secrets), or secrets used bare), like a
// reusable workflow call with secrets: inherit, holds every secret of the
// repository: no list can enumerate them, and none needs to, so the fact
// is allSecrets, proven.
func TestSecretsBracketFormAndWholeContext(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{
			{Name: "bracket", Scripts: []string{`echo ${{ secrets['NPM_TOKEN'] }} ${{ secrets["PYPI_TOKEN"] }}`}},
			{Name: "dump", Scripts: []string{`echo '${{ toJSON(secrets) }}'`}},
			{Name: "bare", Variables: map[string]string{"ALL": "${{ secrets }}"}},
			{Name: "with", Uses: []ir.Action{{Uses: "acme/act@v1", With: map[string]any{"all": "${{ toJson(secrets) }}"}}}},
			{Name: "inherit", ReusableWorkflowUses: "acme/wf/.github/workflows/deploy.yml@main", SecretsInherit: true},
			{Name: "plain", Scripts: []string{`echo ${{ secrets.A }} ${{ inputs.secrets }}`}},
		},
	}
	r := evaluate(t, p, nil)
	if got := r.Jobs["bracket"].Privilege; !reflect.DeepEqual(got.Secrets, []string{"NPM_TOKEN", "PYPI_TOKEN"}) || got.SecretsState != "proven" || got.AllSecrets {
		t.Errorf("bracket: %+v", got)
	}
	for _, name := range []string{"dump", "bare", "with", "inherit"} {
		if got := r.Jobs[name].Privilege; !got.AllSecrets || got.SecretsState != "proven" {
			t.Errorf("%s: want every secret, proven, got %+v", name, got)
		}
	}
	if got := r.Jobs["plain"].Privilege; got.SecretsState != "proven" || !reflect.DeepEqual(got.Secrets, []string{"A"}) || got.AllSecrets {
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
				"npm ci\nnpm publish\necho done",
				"echo deploy\nkubectl apply -f k8s/\necho done",
				"git add .\ngit push origin main\necho done",
			},
		}},
	}
	j := evaluate(t, p, nil).Jobs["release"]
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

// TestStructuralTriggerFacts pins the two trigger facts no control
// reports: a fork pull request reaching the job, and the job running on a
// push to the default branch while that branch is not known protected.
func TestStructuralTriggerFacts(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitHub,
		DefaultBranch: "main",
		Branches:      []ir.Branch{{Name: "main", Protected: false}},
		Jobs: []ir.Job{
			{Name: "ci/build", Triggers: []string{"pull_request"}},
			{Name: "ci/deploy", Triggers: []string{"push"}},
		},
	}
	r := evaluate(t, p, nil)
	if r.Provider != "github" {
		t.Errorf("provider = %q", r.Provider)
	}
	if got := r.Jobs["ci/build"].ForkPR; len(got) != 1 || got[0].Kind != "fork_pr" || got[0].Evidence != "on: pull_request" {
		t.Errorf("ci/build forkPR = %+v", got)
	}
	if got := r.Jobs["ci/build"].Push; len(got) != 0 {
		t.Errorf("ci/build push = %+v, want none", got)
	}
	if got := r.Jobs["ci/deploy"].Push; len(got) != 1 || got[0].State != "proven" || got[0].Subject != "main" {
		t.Errorf("ci/deploy push = %+v", got)
	}
}

// TestIncludesNameTheJobsTheyShape pins the include attachment: the jobs
// whose origin file is the include's source, or every job when none is.
func TestIncludesNameTheJobsTheyShape(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Includes: []ir.Include{
			{Kind: "local", Source: "ci/build.yml"},
			{Kind: "project", Source: "group/templates", Ref: "main", OriginFile: ".gitlab-ci.yml", OriginLine: 3},
		},
		Jobs: []ir.Job{{Name: "build", OriginFile: "ci/build.yml"}, {Name: "test", OriginFile: ".gitlab-ci.yml"}},
	}
	want := []includeFact{
		{Subject: "ci/build.yml", Source: "ci/build.yml", Jobs: []string{"build"}},
		{Subject: "group/templates@main", Source: "group/templates", File: ".gitlab-ci.yml", Line: 3, Jobs: []string{"build", "test"}},
	}
	if got := evaluate(t, p, nil).Includes; !reflect.DeepEqual(got, want) {
		t.Errorf("includes = %+v, want %+v", got, want)
	}
}
