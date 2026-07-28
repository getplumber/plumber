package control

import (
	"testing"

	"github.com/getplumber/plumber/configuration"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/sirupsen/logrus"
)

func codeSet(findings []opaengine.Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range findings {
		m[f.Code] = true
	}
	return m
}

// getplumber/plumber#349: a GitHub-only control's rego can fire on a GitLab
// pipeline (it reads generic IR fields with no provider guard), and nothing on
// the GitLab side benches or config-disables it, so its finding used to survive
// FilterFindingsByEnabledControls and inflate plumberScore.counts on GitLab.
// The provider-applicability gate must drop it, while keeping controls that DO
// apply to the run's provider.
func TestFilterFindingsByEnabledControls_ProviderApplicability(t *testing.T) {
	pc, _, _, err := configuration.LoadPlumberConfig("../.plumber.yaml")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	// Plumber's own self-scan config (../.plumber.yaml) is GitHub-only — the
	// repo runs no GitLab CI — so it declares no GitLab controls to exercise the
	// GitLab gate. Build a minimal GitLab controls config with a cross-provider
	// control enabled to probe the gate directly, independent of the self-scan
	// file's provider coverage.
	enabled := true
	glControls := &configuration.ControlsConfig{
		PipelineMustNotIncludeHardcodedJobs: &configuration.HardcodedJobsControlConfig{Enabled: &enabled},
	}

	// ISSUE-214 -> workflowMustPinPackageInstalls (GitHub-only).
	// ISSUE-401 -> pipelineMustNotIncludeHardcodedJobs (both providers).
	// ISSUE-701 -> actionsMustBePinnedByCommitSha (GitHub-only, not benched).
	glFindings := []opaengine.Finding{{Code: "ISSUE-214"}, {Code: "ISSUE-401"}, {Code: "ISSUE-701"}}
	gl := codeSet(FilterFindingsByEnabledControls(glFindings, "gitlab", glControls, nil, nil))
	if gl["ISSUE-214"] {
		t.Error("ISSUE-214 (GitHub-only) leaked onto a GitLab run")
	}
	if gl["ISSUE-701"] {
		t.Error("ISSUE-701 (GitHub-only) leaked onto a GitLab run")
	}
	if !gl["ISSUE-401"] {
		t.Error("ISSUE-401 (cross-provider) was wrongly dropped on a GitLab run (over-drop)")
	}

	// The gate must NOT over-drop on the provider a control DOES apply to:
	// ISSUE-701 (actionsMustBePinnedByCommitSha) is GitHub-only, enabled and
	// not benched, so it survives a GitHub run. (Cross-provider controls like
	// ISSUE-401 are a poor probe here — several are benched on GitHub and
	// would drop for that reason, not the gate; the invariant test below
	// covers every catalog control instead.)
	gh := codeSet(FilterFindingsByEnabledControls([]opaengine.Finding{{Code: "ISSUE-701"}}, "github", pc.ControlsFor("github"), nil, nil))
	if !gh["ISSUE-701"] {
		t.Error("ISSUE-701 was wrongly dropped on a GitHub run (over-drop)")
	}
}

// The no-over-drop invariant that makes the #349 gate safe: every control the
// per-provider catalog can render MUST be marked applicable to that provider in
// controlsMeta, otherwise the gate would drop its findings before any surface
// sees them. Locks the registry completeness the fix relies on — a future
// catalog entry added without a matching controlsMeta provider fails here.
func TestEveryCatalogControlIsApplicableToItsProvider(t *testing.T) {
	pc, _, _, err := configuration.LoadPlumberConfig("../.plumber.yaml")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	for _, e := range GitLabControls(pc) {
		if !configuration.IsControlApplicableTo(e.ControlName, "gitlab") {
			t.Errorf("GitLab catalog control %q is not applicable to gitlab in controlsMeta; the #349 gate would drop its findings", e.ControlName)
		}
	}
	for _, e := range GitHubControls(pc) {
		if !configuration.IsControlApplicableTo(e.ControlName, "github") {
			t.Errorf("GitHub catalog control %q is not applicable to github in controlsMeta; the #349 gate would drop its findings", e.ControlName)
		}
	}
}

// End-to-end regression for the woob/woob shape: a GitLab pipeline with bare
// `pip install` steps. Before the fix, the GitHub-only ISSUE-214 fired and
// plumberScore.counts (which reads result.Findings) exceeded the findings any
// GitLab catalog surface could render. After the fix, every surviving finding
// is applicable to gitlab and the score total equals the renderable count.
func TestNoGitHubOnlyControlLeaksOnGitLabRun(t *testing.T) {
	pc, _, _, err := configuration.LoadPlumberConfig("../.plumber.yaml")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	var jobs []ir.Job
	for _, n := range []string{"build", "test", "docs"} {
		jobs = append(jobs, ir.Job{Name: n, OriginKind: "hardcoded", Scripts: []string{"pip install " + n + "tool"}})
	}
	pipeline := &ir.NormalizedPipeline{Provider: ir.Provider("gitlab"), ProjectPath: "woob/woob", DefaultBranch: "master", Jobs: jobs}
	conf := &configuration.Configuration{ProjectPath: "woob/woob", PlumberConfig: pc}

	findings := evaluatePolicies(logrus.NewEntry(logrus.New()), conf, "gitlab", pipeline)

	// Every surviving finding must belong to a control applicable to gitlab.
	for _, f := range findings {
		if info := LookupCode(ErrorCode(f.Code)); info != nil && info.ControlName != "" {
			if !configuration.IsControlApplicableTo(info.ControlName, "gitlab") {
				t.Errorf("finding %s (control %s) leaked onto a GitLab run", f.Code, info.ControlName)
			}
		}
	}

	// plumberScore.counts must equal what the GitLab catalog can render.
	result := &AnalysisResult{Findings: findings}
	score := ComputePlumberScore(AggregateIssueCodeCounts(result))
	total := score.Counts.Critical + score.Counts.High + score.Counts.Medium + score.Counts.Low

	catalog := map[string]bool{}
	for _, e := range GitLabControls(pc) {
		catalog[e.ControlName] = true
	}
	renderable := 0
	for ctl, fs := range FindingsByControl(findings) {
		if catalog[ctl] {
			renderable += len(fs)
		} else {
			t.Errorf("unrenderable control %s survived the GitLab filter with %d findings", ctl, len(fs))
		}
	}
	if total != renderable {
		t.Errorf("plumberScore.counts total %d != renderable %d (the #349 over-count)", total, renderable)
	}
}
