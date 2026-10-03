package control

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
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
	var kinds []EntryKind
	for _, e := range j.Entries {
		kinds = append(kinds, e.Kind)
	}
	want := map[EntryKind]bool{EntryForkPR: true, EntryUntrustedExpression: true, EntryMutableDependency: true}
	for _, k := range kinds {
		delete(want, k)
	}
	if len(want) != 0 {
		t.Errorf("missing entries %v in %v", want, kinds)
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

// TestEvaluateSituationDecodesTheDefaultBranch pins S5: the Rego result
// carries the pipeline's default branch under "defaultBranch", decoded onto
// Situation.DefaultBranch, so gatesOnPath can match a branch gate against it
// regardless of which jobs are walked.
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
// see, via buildEngineConfig: a GitLab PipelineMustNotUseUnsafeVariableExpansion.
// DangerousVariables of [MY_VAR] must replace the module's own hardcoded
// default list, not merge with it. A job whose script reads $MY_VAR gets
// the untrusted_expression entry; a job whose script reads
// $CI_COMMIT_REF_NAME (a name on the module's default list,
// situation.rego:203, but absent from the configured list) gets none.
func TestAttachSituationThreadsTheControlsConfig(t *testing.T) {
	conf := defaultConf(t)
	conf.PlumberConfig.ControlsFor("gitlab").PipelineMustNotUseUnsafeVariableExpansion.DangerousVariables = []string{"MY_VAR"}
	pipeline := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{
			{Name: "configured-var", Scripts: []string{"echo $MY_VAR"}},
			{Name: "default-list-var", Scripts: []string{"echo $CI_COMMIT_REF_NAME"}},
		},
	}
	result := &AnalysisResult{}
	attachSituation(logrus.NewEntry(logrus.New()), conf, "gitlab", pipeline, result)
	if result.Situation == nil {
		t.Fatal("result.Situation is nil")
	}
	configured := result.Situation.Jobs["configured-var"]
	var hasUntrustedExpression bool
	for _, e := range configured.Entries {
		if e.Kind == EntryUntrustedExpression {
			hasUntrustedExpression = true
		}
	}
	if !hasUntrustedExpression {
		t.Errorf("configured-var entries = %+v, want an untrusted_expression entry for $MY_VAR", configured.Entries)
	}
	defaultListVar := result.Situation.Jobs["default-list-var"]
	for _, e := range defaultListVar.Entries {
		if e.Kind == EntryUntrustedExpression {
			t.Errorf("default-list-var entries = %+v, want no untrusted_expression entry: the configured list replaced the module's default, CI_COMMIT_REF_NAME is no longer in it", defaultListVar.Entries)
		}
	}
}
