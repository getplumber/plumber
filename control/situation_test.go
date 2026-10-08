package control

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/internal/testsupport/pipelines"
	"github.com/sirupsen/logrus"
)

func TestEvaluateSituationDecodesTheRegoResult(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider:   ir.ProviderGitHub,
		Visibility: ir.VisibilityPublic,
		Jobs: []ir.Job{{
			Name:     "build",
			Triggers: []string{"pull_request"},
			Scripts:  []string{`echo "${{ github.event.pull_request.title }}"`},
			Uses:     []ir.Action{{Uses: "actions/checkout@v4", Line: 7}},
		}, {
			Name:        "release",
			Permissions: map[string]any{"contents": "write"},
		}},
	}
	s, err := EvaluateSituation(context.Background(), p, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Exposure != ir.VisibilityPublic {
		t.Errorf("exposure = %q", s.Exposure)
	}
	j, ok := s.Jobs["build"]
	if !ok {
		t.Fatalf("no facts for build: %+v", s.Jobs)
	}
	if len(j.ForkPR) != 1 || j.ForkPR[0].Kind != EntryForkPR {
		t.Errorf("forkPR = %+v", j.ForkPR)
	}
	if j.Privilege.PersistedCredentials != "proven" {
		t.Errorf("persistedCredentials = %q", j.Privilege.PersistedCredentials)
	}
	// build declares no permissions block: the permissive repository
	// default is a guess, not a declaration.
	if j.Privilege.TokenWriteSource != "default" {
		t.Errorf("build tokenWriteSource = %q", j.Privilege.TokenWriteSource)
	}
	r, ok := s.Jobs["release"]
	if !ok {
		t.Fatalf("no facts for release: %+v", s.Jobs)
	}
	// release declares an explicit permissions object: a real declaration.
	if r.Privilege.TokenWriteSource != "declared" {
		t.Errorf("release tokenWriteSource = %q", r.Privilege.TokenWriteSource)
	}
}

// TestEvaluateSituationDecodesTheDefaultBranch pins the default-branch
// decoding rule: the Rego result carries the pipeline's default branch
// under "defaultBranch", decoded onto Situation.DefaultBranch, so
// gatesOnPath can match a branch gate against it regardless of which jobs
// are walked.
func TestEvaluateSituationDecodesTheDefaultBranch(t *testing.T) {
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, DefaultBranch: "main"}
	s, err := EvaluateSituation(context.Background(), p, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if s.DefaultBranch != "main" {
		t.Errorf("DefaultBranch = %q, want %q", s.DefaultBranch, "main")
	}
}

func TestEvaluateSituationDefaultBranchEmptyWhenAbsent(t *testing.T) {
	s, err := EvaluateSituation(context.Background(), &ir.NormalizedPipeline{Provider: ir.ProviderGitHub}, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if s.DefaultBranch != "" {
		t.Errorf("DefaultBranch = %q, want empty when the pipeline never gave one", s.DefaultBranch)
	}
}

func TestEvaluateSituationNeverPanicsOnEmptyPipeline(t *testing.T) {
	s, err := EvaluateSituation(context.Background(), &ir.NormalizedPipeline{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.Exposure != ir.VisibilityUnknown || len(s.Jobs) != 0 {
		t.Errorf("empty pipeline: %+v", s)
	}
}

// withSituationSource overrides the situationSource seam for the duration
// of the test and restores it on cleanup, so one test's module cannot leak
// into another.
func withSituationSource(t *testing.T, f func() (string, error)) {
	t.Helper()
	orig := situationSource
	situationSource = f
	t.Cleanup(func() { situationSource = orig })
}

func assertEmptyDegradedSituation(t *testing.T, s *Situation, err error) {
	t.Helper()
	if s == nil {
		t.Fatal("situation is nil, want a degraded empty one")
	}
	if s.Exposure != ir.VisibilityUnknown {
		t.Errorf("exposure = %q, want %q", s.Exposure, ir.VisibilityUnknown)
	}
	if len(s.Jobs) != 0 {
		t.Errorf("jobs = %+v, want empty", s.Jobs)
	}
	if err == nil {
		t.Error("err = nil, want non-nil")
	}
}

func TestEvaluateSituationSourceErrorDegrades(t *testing.T) {
	withSituationSource(t, func() (string, error) {
		return "", fmt.Errorf("boom: no module on disk")
	})
	s, err := EvaluateSituation(context.Background(), &ir.NormalizedPipeline{}, nil)
	assertEmptyDegradedSituation(t, s, err)
	if !strings.Contains(err.Error(), "boom: no module on disk") {
		t.Errorf("err = %q, want it to wrap the source error", err)
	}
}

func TestEvaluateSituationMissingResultRuleDegrades(t *testing.T) {
	withSituationSource(t, func() (string, error) {
		return "package situation\n\nfoo := 1\n", nil
	})
	s, err := EvaluateSituation(context.Background(), &ir.NormalizedPipeline{}, nil)
	assertEmptyDegradedSituation(t, s, err)
	if !strings.Contains(err.Error(), "data.situation.result") {
		t.Errorf("err = %q, want it to mention data.situation.result", err)
	}
}

func TestEvaluateSituationUndecodableResultDegrades(t *testing.T) {
	withSituationSource(t, func() (string, error) {
		return `package situation

result := {"exposure": 1}
`, nil
	})
	s, err := EvaluateSituation(context.Background(), &ir.NormalizedPipeline{}, nil)
	assertEmptyDegradedSituation(t, s, err)
	if !strings.Contains(err.Error(), "decode situation") {
		t.Errorf("err = %q, want it to come from the decode", err)
	}
}

func TestAttachSituationRecordsTheWarningOnAFailingSeam(t *testing.T) {
	withSituationSource(t, func() (string, error) {
		return "", fmt.Errorf("seam unavailable for this test")
	})
	pipeline := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub}
	result := &AnalysisResult{}
	attachSituation(logrus.NewEntry(logrus.New()), defaultConf(t), "github", pipeline, result)
	if result.Situation == nil {
		t.Fatal("result.Situation is nil, want the degraded empty value")
	}
	var found bool
	for _, w := range result.Warnings {
		if strings.HasPrefix(w, "situation facts unavailable:") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("warnings = %v, want one starting with %q", result.Warnings, "situation facts unavailable:")
	}
}

// TestAttachSituationSuccessAppendsNoWarning pins attachSituation's success
// path, previously untested (only the degraded seam-failure path above
// was): a real configuration and a small GitLab pipeline must leave
// result.Situation populated with the job present, and must append no
// "situation facts unavailable:" warning.
func TestAttachSituationSuccessAppendsNoWarning(t *testing.T) {
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs:     []ir.Job{{Name: "build", Scripts: []string{"echo hello"}}},
	}
	result := &AnalysisResult{}
	attachSituation(logrus.NewEntry(logrus.New()), defaultConf(t), "gitlab", pipeline, result)
	if result.Situation == nil {
		t.Fatal("result.Situation is nil, want the populated value")
	}
	if _, ok := result.Situation.Jobs["build"]; !ok {
		t.Errorf("jobs = %+v, want build present", result.Situation.Jobs)
	}
	for _, w := range result.Warnings {
		if strings.HasPrefix(w, "situation facts unavailable:") {
			t.Errorf("warnings = %v, want none starting with %q on the success path", result.Warnings, "situation facts unavailable:")
		}
	}
}

// TestAttachSituationThreadsTheControlsConfig pins that attachSituation
// feeds the situation module the SAME controls config the Go controls
// see, via buildEngineConfig: a GitHub
// ReleaseWorkflowsMustNotRestoreUntrustedCache.PublishScriptPatterns of
// [my-release] must replace the module's own default list, not merge
// with it. A job whose script runs my-release gets the publishes impact;
// a job whose script runs npm publish (on the module's default list, but
// absent from the configured one) gets none.
func TestAttachSituationThreadsTheControlsConfig(t *testing.T) {
	conf := defaultConf(t)
	cache := conf.PlumberConfig.ControlsFor("github").ReleaseWorkflowsMustNotRestoreUntrustedCache
	if cache == nil {
		t.Fatal("fixture drifted: the default config carries no cache poisoning control")
	}
	cache.PublishScriptPatterns = []string{"my-release"}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{
			// Read-only tokens, so a publish can only come from the script.
			{Name: "configured-pattern", Permissions: "read-all", Scripts: []string{"my-release --all"}},
			{Name: "default-pattern", Permissions: "read-all", Scripts: []string{"npm publish"}},
		},
	}
	result := &AnalysisResult{}
	attachSituation(logrus.NewEntry(logrus.New()), conf, "github", pipeline, result)
	if result.Situation == nil {
		t.Fatal("result.Situation is nil")
	}
	publishes := func(job string) bool {
		for _, i := range result.Situation.Jobs[job].Impact {
			if i.Kind == "publishes" {
				return true
			}
		}
		return false
	}
	if !publishes("configured-pattern") {
		t.Errorf("configured-pattern impact = %+v, want publishes for my-release", result.Situation.Jobs["configured-pattern"].Impact)
	}
	if publishes("default-pattern") {
		t.Errorf("default-pattern impact = %+v, want no publishes: the configured list replaced the module's default, npm publish is no longer in it", result.Situation.Jobs["default-pattern"].Impact)
	}
}

// TestDecodeSituationCarriesTheStructuralFacts pins the Go mirror of the
// structural facts: the provider, the includes and their jobs, and each
// job's fork pull request and push facts.
func TestDecodeSituationCarriesTheStructuralFacts(t *testing.T) {
	raw := []byte(`{"exposure":"public","provider":"gitlab","defaultBranch":"main",
		"includes":[{"subject":"group/ci@main","source":"group/ci","file":".gitlab-ci.yml","line":3,"jobs":["build"]}],
		"jobs":{"build":{"entries":[],
			"forkPR":[{"kind":"fork_pr","state":"proven","evidence":"rules: merge_request_event","subject":"merge_request_event"}],
			"push":[{"kind":"unprotected_push","state":"unresolvable","evidence":"on push; default branch main unresolvable","subject":"main"}],
			"privilege":{},"impact":[],"feeds":[]}}}`)
	s, err := DecodeSituation(raw)
	if err != nil {
		t.Fatal(err)
	}
	if s.Provider != "gitlab" {
		t.Errorf("provider = %q", s.Provider)
	}
	want := []IncludeFact{{Subject: "group/ci@main", File: ".gitlab-ci.yml", Line: 3, Jobs: []string{"build"}}}
	if !reflect.DeepEqual(s.Includes, want) {
		t.Errorf("includes = %+v", s.Includes)
	}
	b := s.Jobs["build"]
	if len(b.ForkPR) != 1 || b.ForkPR[0].Kind != EntryForkPR {
		t.Errorf("forkPR = %+v", b.ForkPR)
	}
	if len(b.Push) != 1 || b.Push[0].State != "unresolvable" || b.Push[0].Subject != "main" {
		t.Errorf("push = %+v", b.Push)
	}
}

// TestEvaluateSituationCarriesTheFeedKinds pins that each fed job reaches
// the Go side with the kinds of edge that link it to its feeder: an
// artifact and a cache together on one pair, a job output read through
// needs on another.
func TestEvaluateSituationCarriesTheFeedKinds(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{
			{Name: "build", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "produce"}}, Caches: []ir.CacheRef{{Key: "deps", Mode: "save"}}},
			{Name: "publish", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "consume"}}, Caches: []ir.CacheRef{{Key: "deps", Mode: "restore"}}},
			{Name: "notify", Needs: []string{"build"}, Scripts: []string{"echo ${{ needs.build.outputs.version }}"}},
		},
	}
	s, err := EvaluateSituation(context.Background(), p, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"notify": {FeedOutput}, "publish": {FeedArtifact, FeedCache}}
	if got := s.Jobs["build"].FeedsVia; !reflect.DeepEqual(got, want) {
		t.Errorf("build.FeedsVia = %v, want %v", got, want)
	}
}

// No runner is told apart as self-hosted: a job's runs-on, whatever its
// labels, adds nothing to what the job changes.
func TestARunnerLabelIsNoImpact(t *testing.T) {
	file := filepath.Join(t.TempDir(), "ci.yml")
	workflow := "on: pull_request_target\njobs:\n  build:\n    runs-on: [self-hosted, linux]\n    permissions: {}\n    steps:\n      - uses: some/action@v1\n"
	if err := os.WriteFile(file, []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}
	sit, err := EvaluateSituation(context.Background(), pipelines.GitHubFromFiles(t, []string{file}), nil)
	if err != nil {
		t.Fatal(err)
	}
	job, ok := sit.Jobs["ci/build"]
	if !ok {
		t.Fatalf("want job ci/build, got %+v", sit.Jobs)
	}
	if len(job.Impact) != 0 {
		t.Errorf("a runner label is no impact, got %+v", job.Impact)
	}
}

// TestEvaluateSituationCarriesTheNewJobFacts pins that the facts a path
// reads about a job reach the Go side: the calls of a reusable workflow's
// job and what each gives it, an impact done through a called job (Via),
// the cache scopes of its runs, a cache's family beside its key, a job
// that never runs, the environment's unknown reviewers.
func TestEvaluateSituationCarriesTheNewJobFacts(t *testing.T) {
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "acme/app", DefaultBranch: "main", Jobs: []ir.Job{
		{
			Name: "nightly/upload", OriginFile: ".github/workflows/nightly.yml", Triggers: []string{"schedule"},
			Permissions:          map[string]any{"contents": "read"},
			ReusableWorkflowUses: "./.github/workflows/_upload.yml",
			ReusableSecrets:      map[string]string{"R2_KEY": "${{ secrets.R2_KEY }}"},
			ReusableCallees:      []string{"_upload/upload"},
			Environment:          "nightly",
		},
		{
			Name: "_upload/upload", OriginFile: ".github/workflows/_upload.yml", Triggers: []string{"workflow_call"},
			Scripts: []string{"twine upload dist/*"}, Variables: map[string]string{"R2": "${{ secrets.R2_KEY }}"},
			Caches: []ir.CacheRef{{Key: "setup-python-pip (a.txt)", Family: "setup-python-pip", Mode: "both"}},
			Callers: []ir.ReusableCaller{{Job: "nightly/upload", Permissions: map[string]any{"contents": "read"}, Triggers: []string{"schedule"},
				Secrets: map[string]string{"R2_KEY": "${{ secrets.R2_KEY }}"}}},
		},
		{Name: "ci/off", OriginFile: ".github/workflows/ci.yml", Triggers: []string{"push"}, Dead: true},
	}}
	s, err := EvaluateSituation(context.Background(), p, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	callee := s.Jobs["_upload/upload"]
	want := []CallerFact{{Job: "nightly/upload", TokenWrite: []string{}, TokenWriteSource: "declared", Secrets: []string{"R2_KEY"}, Triggers: []string{"schedule"}}}
	if !reflect.DeepEqual(callee.Callers, want) {
		t.Errorf("callers = %+v, want %+v", callee.Callers, want)
	}
	if !reflect.DeepEqual(callee.CacheScopes, []string{"default"}) {
		t.Errorf("cacheScopes = %v, want the caller's default-branch scope", callee.CacheScopes)
	}
	if len(callee.Caches) != 1 || callee.Caches[0].Family != "setup-python-pip" || callee.Caches[0].Key != "setup-python-pip (a.txt)" {
		t.Errorf("caches = %+v", callee.Caches)
	}
	caller := s.Jobs["nightly/upload"]
	var via string
	for _, i := range caller.Impact {
		if i.Kind == "publishes" {
			via = i.Via
		}
	}
	if via != "_upload/upload" {
		t.Errorf("caller impact = %+v, want the called job's publish", caller.Impact)
	}
	if caller.Privilege.Environment.Name != "nightly" || caller.Privilege.Environment.Reviewers != "unknown" {
		t.Errorf("environment = %+v", caller.Privilege.Environment)
	}
	if !s.Jobs["ci/off"].Dead || caller.Dead {
		t.Errorf("dead: off=%v caller=%v", s.Jobs["ci/off"].Dead, caller.Dead)
	}
}
