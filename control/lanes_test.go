package control

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/internal/platform"
	"github.com/getplumber/plumber/policies"
)

// attributionSignals are the IR fields that only exist because the git
// host's config-merge response reported where each include and job came
// from. A rule reading any of them cannot be trusted on a merged YAML
// document alone.
//
// originKind/overridden are on the list for a reason found the hard way:
// they are per-JOB attribution, and without it every component- or
// template-supplied job is classified "hardcoded". That does not merely
// hide findings, it INVENTS them — an upstream job's legitimate
// `when: never` reads as project-side tampering.
var attributionSignals = []string{
	"input.pipeline.includes",
	"originKind",
	".overridden",
	"overriddenKeys",
}

// TestControlsRequiringIncludeAttributionMatchesPolicies derives the set
// from the policy sources themselves and fails when the hand-maintained
// list drifts.
//
// The derivation is the definition: a rule reading any attribution signal
// needs the git host's merge response, which a platform-supplied merged
// document does not carry. A rule added later that reads one without being
// listed here would either pass silently over an empty include list or
// invent findings from misattributed jobs, on every platform-sourced run.
func TestControlsRequiringIncludeAttributionMatchesPolicies(t *testing.T) {
	codeRe := regexp.MustCompile(`"(ISSUE-\d+)"`)

	derived := map[string]bool{}
	err := fs.WalkDir(policies.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".rego" {
			return err
		}
		src, readErr := fs.ReadFile(policies.FS, path)
		if readErr != nil {
			return readErr
		}
		usesAttribution := false
		for _, signal := range attributionSignals {
			if strings.Contains(string(src), signal) {
				usesAttribution = true
				break
			}
		}
		if !usesAttribution {
			return nil
		}
		for _, m := range codeRe.FindAllStringSubmatch(string(src), -1) {
			info := LookupCode(ErrorCode(m[1]))
			if info == nil {
				t.Errorf("%s emits %s, which has no entry in the code registry", path, m[1])
				continue
			}
			derived[info.ControlName] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk policies: %v", err)
	}
	if len(derived) == 0 {
		t.Fatal("no policy reads input.pipeline.includes — the derivation is broken, not the list")
	}

	got := append([]string(nil), controlsRequiringIncludeAttribution...)
	sort.Strings(got)
	want := make([]string, 0, len(derived))
	for name := range derived {
		want = append(want, name)
	}
	sort.Strings(want)

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("controlsRequiringIncludeAttribution has drifted from the policies:\n"+
			" list:    %v\n derived: %v\n"+
			"Update the list in control/lanes.go to match the rules that read input.pipeline.includes.",
			got, want)
	}
}

// TestControlsIndependentOfMergedConfigAreRealControls: a typo here would
// silently reclassify nothing, and the control it meant to exempt would
// report not_evaluable on every run without a merged config.
func TestControlsIndependentOfMergedConfigAreRealControls(t *testing.T) {
	// Checked against the ISSUE-code registry rather than a catalog, which
	// needs a loaded config: a control name is real exactly when at least
	// one registered code is attributed to it.
	for name := range controlsIndependentOfMergedConfig {
		if len(CodesForControl(name)) == 0 {
			t.Errorf("controlsIndependentOfMergedConfig names %q, which no ISSUE code is registered to", name)
		}
	}
	for _, name := range controlsRequiringIncludeAttribution {
		if len(CodesForControl(name)) == 0 {
			t.Errorf("controlsRequiringIncludeAttribution names %q, which no ISSUE code is registered to", name)
		}
	}
}

func TestMarkNotEvaluable(t *testing.T) {
	t.Run("records the reason", func(t *testing.T) {
		r := &AnalysisResult{}
		r.MarkNotEvaluable("someControl", ReasonResolutionUnavailable)
		if r.NotEvaluable["someControl"] != ReasonResolutionUnavailable {
			t.Fatalf("got %v", r.NotEvaluable)
		}
	})

	t.Run("the first reason wins", func(t *testing.T) {
		r := &AnalysisResult{}
		r.MarkNotEvaluable("c", ReasonIncludeAttributionUnavailable)
		r.MarkNotEvaluable("c", ReasonResolutionUnavailable)
		if r.NotEvaluable["c"] != ReasonIncludeAttributionUnavailable {
			t.Fatalf("the earliest, most specific reason must survive, got %q", r.NotEvaluable["c"])
		}
	})

	t.Run("tolerates a nil result and an empty name", func(t *testing.T) {
		var r *AnalysisResult
		r.MarkNotEvaluable("c", "reason") // must not panic
		r2 := &AnalysisResult{}
		r2.MarkNotEvaluable("", "reason")
		if len(r2.NotEvaluable) != 0 {
			t.Fatalf("an empty control name must record nothing, got %v", r2.NotEvaluable)
		}
	})
}

func TestMarkMergedConfigUnavailable(t *testing.T) {
	entries := []ControlEntry{
		{ControlName: "branchMustBeProtected"},
		{ControlName: "pipelineMustNotEnableDebugTrace"},
		{ControlName: "pipelineMustIncludeComponent"},
		{ControlName: "containerImageMustNotUseForbiddenTags"},
	}
	r := &AnalysisResult{}
	r.MarkMergedConfigUnavailable(entries, ReasonResolutionUnavailable)

	if r.NotEvaluable["branchMustBeProtected"] != "" {
		t.Fatal("branchMustBeProtected reads the protection API, not the pipeline: an unavailable CI config says nothing about it")
	}
	for _, e := range entries {
		if controlsIndependentOfMergedConfig[e.ControlName] {
			continue
		}
		if r.NotEvaluable[e.ControlName] != ReasonResolutionUnavailable {
			t.Fatalf("%s reads the merged pipeline and must be not_evaluable without one", e.ControlName)
		}
	}
}

func TestMarkIncludeAttributionUnavailable(t *testing.T) {
	r := &AnalysisResult{}
	r.MarkIncludeAttributionUnavailable(nil)
	for _, name := range controlsRequiringIncludeAttribution {
		if r.NotEvaluable[name] != ReasonIncludeAttributionUnavailable {
			t.Fatalf("%s must be marked, got %q", name, r.NotEvaluable[name])
		}
	}
	// A merged config IS available in this state, so pipeline controls that
	// do not reason about includes must stay evaluable.
	if _, marked := r.NotEvaluable["pipelineMustNotEnableDebugTrace"]; marked {
		t.Fatal("a control reading only the merged pipeline must stay evaluable when only include attribution is missing")
	}
}

// TestStatusFor_NotEvaluableWinsInBothDirections pins the ordering.
//
// not_evaluable beats a findings count, which is the opposite of the
// general "findings win over degradation" rule elsewhere in StatusFor. The
// difference is what the missing data does: a run-wide degradation means
// data is ABSENT, so what was found is still real; a dead lane can mean
// data is WRONG. Without include attribution a component's job is
// indistinguishable from one the project wrote, and rules keyed on that
// distinction fire on upstream jobs behaving normally. Those findings are
// dropped (DropNotEvaluableFindings), so a non-zero count here can only be
// stale and must not be reported as a real failure.
func TestStatusFor_NotEvaluableWinsInBothDirections(t *testing.T) {
	entry := ControlEntry{ControlName: "pipelineMustNotEnableDebugTrace"}
	result := &AnalysisResult{
		CiValid:      true,
		NotEvaluable: map[string]string{"pipelineMustNotEnableDebugTrace": ReasonResolutionUnavailable},
	}

	if got := StatusFor(entry, result, 0); got != StatusError {
		t.Fatalf("an empty findings list on a dead lane must be %q, got %q", StatusError, got)
	}
	if got := StatusFor(entry, result, 2); got != StatusError {
		t.Fatalf("findings derived from a dead lane are not trustworthy: want %q, got %q", StatusError, got)
	}
	if got := StatusFor(ControlEntry{ControlName: "pipelineMustNotEnableDebugTrace", Skipped: true}, result, 0); got != StatusSkipped {
		t.Fatalf("an explicitly disabled control stays %q, got %q", StatusSkipped, got)
	}

	// A control NOT in the map is unaffected in both directions.
	other := ControlEntry{ControlName: "pipelineMustNotUseDockerInDocker"}
	if got := StatusFor(other, result, 0); got != StatusPassed {
		t.Fatalf("an unaffected control must still pass, got %q", got)
	}
	if got := StatusFor(other, result, 3); got != StatusFailed {
		t.Fatalf("an unaffected control must still report its findings, got %q", got)
	}
}

// TestDropNotEvaluableFindings: a control that could not be evaluated
// reports nothing, so fabricated findings never reach an artifact, the
// score, or the platform.
func TestDropNotEvaluableFindings(t *testing.T) {
	// ISSUE-410 belongs to securityJobsMustNotBeWeakened, ISSUE-103 to a
	// control that stays evaluable.
	result := &AnalysisResult{
		Findings: []opaengine.Finding{
			{Code: "ISSUE-410"}, {Code: "ISSUE-103"}, {Code: "ISSUE-410"},
		},
		NotEvaluable: map[string]string{
			"securityJobsMustNotBeWeakened": ReasonIncludeAttributionUnavailable,
		},
	}

	result.DropNotEvaluableFindings()

	if len(result.Findings) != 1 {
		t.Fatalf("want only the evaluable control's finding, got %d: %+v", len(result.Findings), result.Findings)
	}
	if result.Findings[0].Code != "ISSUE-103" {
		t.Fatalf("the surviving finding must be the evaluable one, got %q", result.Findings[0].Code)
	}
}

func TestDropNotEvaluableFindings_NoOpCases(t *testing.T) {
	t.Run("nothing marked keeps every finding", func(t *testing.T) {
		r := &AnalysisResult{Findings: []opaengine.Finding{{Code: "ISSUE-410"}}}
		r.DropNotEvaluableFindings()
		if len(r.Findings) != 1 {
			t.Fatalf("got %d", len(r.Findings))
		}
	})
	t.Run("an unregistered code is kept", func(t *testing.T) {
		// A code with no registry entry cannot be attributed to a control,
		// so it cannot be shown to be fabricated. Keeping it is the
		// conservative choice: dropping findings we cannot classify would
		// hide real ones.
		r := &AnalysisResult{
			Findings:     []opaengine.Finding{{Code: "ISSUE-NOT-REAL"}},
			NotEvaluable: map[string]string{"someControl": ReasonResolutionUnavailable},
		}
		r.DropNotEvaluableFindings()
		if len(r.Findings) != 1 {
			t.Fatalf("got %d", len(r.Findings))
		}
	})
	t.Run("nil result does not panic", func(t *testing.T) {
		var r *AnalysisResult
		r.DropNotEvaluableFindings()
	})
}

// The settings-level controls main gained while platform mode was in review
// read the protection / settings APIs, never the merged pipeline. If they
// are missing from controlsIndependentOfMergedConfig they get marked
// not_evaluable on a run whose CI config was unavailable but whose settings
// were collected perfectly well - findings silently withheld rather than
// invented, but wrong either way.
//
// This is the specific drift a long-lived branch produces: the list was
// correct when it was written and stale by the time it merged.
func TestSettingsControlsSurviveAnUnavailableMergedConfig(t *testing.T) {
	settingsControls := []string{
		"branchMustBeProtected",
		"cicdVariablesMustBeProtected",
		"cicdVariablesMustBeMasked",
		"mergeRequestApprovalRulesMustRequireMinimumApprovals",
		"mergeRequestApprovalRulesMustCoverAllProtectedBranches",
		"mergeRequestApprovalSettingsMustBeCompliant",
		"mergeRequestSettingsMustBeCompliant",
		"projectMustHaveSecurityPolicySource",
	}
	entries := make([]ControlEntry, 0, len(settingsControls)+1)
	for _, name := range settingsControls {
		entries = append(entries, ControlEntry{ControlName: name})
	}
	// One genuine pipeline control, which MUST be marked.
	entries = append(entries, ControlEntry{ControlName: "pipelineMustNotEnableDebugTrace"})

	r := &AnalysisResult{}
	r.MarkMergedConfigUnavailable(entries, ReasonResolutionUnavailable)

	for _, name := range settingsControls {
		if reason, marked := r.NotEvaluable[name]; marked {
			t.Errorf("%s reads a project setting, not the merged pipeline, but was marked %q when the config was unavailable", name, reason)
		}
	}
	if _, marked := r.NotEvaluable["pipelineMustNotEnableDebugTrace"]; !marked {
		t.Error("a genuine pipeline control must still be marked when no merged config is available")
	}
}

// Every control named in snapshotLaneControls / controlsWithNoPlatformLane
// must be a real registered control, or the mapping silently marks nothing.
func TestPlatformLaneMapsNameRealControls(t *testing.T) {
	check := func(name string) {
		t.Helper()
		if len(CodesForControl(name)) == 0 {
			t.Errorf("%q has no ISSUE code registered to it - a renamed or removed control leaves this mapping dead", name)
		}
	}
	for lane, names := range snapshotLaneControls {
		if lane == "" {
			t.Error("a lane identifier must not be empty")
		}
		for _, n := range names {
			check(n)
		}
	}
	for n := range controlsWithNoPlatformLane {
		check(n)
	}
}

// A lane the platform reports as a FAILED collection must mark its controls
// not_evaluable. The distinction it encodes: an absent-and-unlisted lane is
// honestly empty and a control may FAIL against it, which is exactly what
// the platform's own zero-protections fix restored.
func TestMarkDegradedSnapshotLanes(t *testing.T) {
	entries := []ControlEntry{
		{ControlName: "branchMustBeProtected"},
		{ControlName: "cicdVariablesMustBeMasked"},
		{ControlName: "cicdVariablesMustBeProtected"},
		{ControlName: "pipelineMustNotEnableDebugTrace"},
	}

	t.Run("a degraded lane marks only its own controls", func(t *testing.T) {
		r := &AnalysisResult{}
		r.MarkDegradedSnapshotLanes(entries, runWithDegraded(t, "2", "variables"))
		if r.NotEvaluable["cicdVariablesMustBeMasked"] != ReasonSnapshotLaneDegraded {
			t.Error("a degraded variables lane must mark the variable controls")
		}
		if r.NotEvaluable["cicdVariablesMustBeProtected"] != ReasonSnapshotLaneDegraded {
			t.Error("both variable controls read the same lane")
		}
		if _, marked := r.NotEvaluable["branchMustBeProtected"]; marked {
			t.Error("an unrelated lane must not be marked")
		}
		if _, marked := r.NotEvaluable["pipelineMustNotEnableDebugTrace"]; marked {
			t.Error("a pipeline control has no settings lane and must not be marked by this path")
		}
	})

	t.Run("a healthy snapshot marks no lane control", func(t *testing.T) {
		r := &AnalysisResult{}
		r.MarkDegradedSnapshotLanes(entries, runWithDegraded(t, "2"))
		for _, e := range entries {
			if e.ControlName == "projectMustHaveSecurityPolicySource" {
				continue
			}
			if _, marked := r.NotEvaluable[e.ControlName]; marked {
				t.Errorf("%s must evaluate normally when nothing is degraded", e.ControlName)
			}
		}
	})

	t.Run("a pre-v2 snapshot cannot report degradation", func(t *testing.T) {
		r := &AnalysisResult{}
		r.MarkDegradedSnapshotLanes(entries, runWithDegraded(t, "1", "variables"))
		if _, marked := r.NotEvaluable["cicdVariablesMustBeMasked"]; marked {
			t.Error("below schema v2 degraded_fields is not trustworthy and must not drive marking")
		}
	})

	t.Run("a control with no platform lane is always marked", func(t *testing.T) {
		r := &AnalysisResult{}
		withSecurity := append(entries, ControlEntry{ControlName: "projectMustHaveSecurityPolicySource"})
		r.MarkDegradedSnapshotLanes(withSecurity, runWithDegraded(t, "2"))
		if r.NotEvaluable["projectMustHaveSecurityPolicySource"] != ReasonLaneNotServed {
			t.Error("the snapshot carries no security-policy lane, so the control must report not_evaluable rather than pass")
		}
	})

	t.Run("a disabled control is never marked", func(t *testing.T) {
		r := &AnalysisResult{}
		disabled := []ControlEntry{{ControlName: "cicdVariablesMustBeMasked", Skipped: true}}
		r.MarkDegradedSnapshotLanes(disabled, runWithDegraded(t, "2", "variables"))
		if _, marked := r.NotEvaluable["cicdVariablesMustBeMasked"]; marked {
			t.Error("a control the operator turned off was not unevaluated")
		}
	})

	t.Run("standalone mode marks nothing", func(t *testing.T) {
		r := &AnalysisResult{}
		r.MarkDegradedSnapshotLanes(entries, nil)
		if len(r.NotEvaluable) != 0 {
			t.Errorf("without --platform nothing may be marked, got %v", r.NotEvaluable)
		}
	})
}

// runWithDegraded builds a platform RunContext whose snapshot reports the
// given schema version and degraded lanes, so the marking rules can be
// exercised without a live platform.
func runWithDegraded(t *testing.T, schemaVersion string, degraded ...string) *platform.RunContext {
	t.Helper()
	return &platform.RunContext{
		Context: &platform.ProjectContext{
			Snapshot: platform.Snapshot{Data: &platform.SnapshotData{
				SchemaVersion:  schemaVersion,
				DegradedFields: degraded,
				// Present so these cases isolate DEGRADATION. An absent
				// branch_protection or mr_approvals lane degrades its
				// controls on its own (lanesWhoseAbsenceIsAFailure), which
				// would mask what each case is actually asserting.
				BranchProtection: json.RawMessage(`{"branches":["main"],"protections":[]}`),
				MrApprovals:      json.RawMessage(`{"rules":[]}`),
			}},
		},
	}
}

// ReEvaluateForConfig shallow-copies the run's AnalysisResult so it can
// evaluate under a different config. A shallow copy SHARES the Findings
// slice and the NotEvaluable map with the caller, so a careless
// implementation would let one policy's evaluation rewrite the run's own
// verdict - and every later policy would then evaluate against corrupted
// state. This pins the isolation.
func TestReEvaluateForConfigDoesNotMutateTheRun(t *testing.T) {
	enabled := true
	local := &configuration.PlumberConfig{Version: "2.0", GitLab: &configuration.ProviderConfig{
		Controls: configuration.ControlsConfig{
			BranchMustBeProtected: &configuration.BranchProtectionControlConfig{Enabled: &enabled},
		}}}
	conf := &configuration.Configuration{PlumberConfig: local}

	result := &AnalysisResult{
		CiValid:  true,
		Pipeline: &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, ProjectPath: "grp/app"},
		Findings: []opaengine.Finding{{Code: "ISSUE-505", Message: "original"}},
	}
	result.MarkNotEvaluable("includesMustBeUpToDate", ReasonIncludeAttributionUnavailable)

	beforeFindings := len(result.Findings)
	beforeReason := result.NotEvaluable["includesMustBeUpToDate"]
	beforeMapLen := len(result.NotEvaluable)

	other := &configuration.PlumberConfig{Version: "2.0", GitLab: &configuration.ProviderConfig{
		Controls: configuration.ControlsConfig{
			CicdVariablesMustBeMasked: &configuration.EnabledOnlyControlConfig{Enabled: &enabled},
		}}}
	if _, _, ok := ReEvaluateForConfig(result, conf, "gitlab", other); !ok {
		t.Fatal("a result carrying a pipeline must be re-evaluable")
	}

	if len(result.Findings) != beforeFindings {
		t.Errorf("the run's findings were mutated: %d -> %d", beforeFindings, len(result.Findings))
	}
	if result.Findings[0].Message != "original" {
		t.Errorf("the run's finding content was rewritten: %q", result.Findings[0].Message)
	}
	if len(result.NotEvaluable) != beforeMapLen || result.NotEvaluable["includesMustBeUpToDate"] != beforeReason {
		t.Errorf("the run's NotEvaluable map was mutated: %v", result.NotEvaluable)
	}
	// The caller's Configuration must not have been repointed either.
	if conf.PlumberConfig != local {
		t.Error("the caller's Configuration had its PlumberConfig swapped")
	}
}

// Without a retained pipeline there is nothing to re-evaluate, and the
// caller must keep the run's own verdict rather than receive an empty one
// that would read as a clean pass.
func TestReEvaluateForConfigRefusesWithoutAPipeline(t *testing.T) {
	conf := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{Version: "2.0"}}
	cases := map[string]*AnalysisResult{
		"nil result":  nil,
		"no pipeline": {CiValid: true},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, ok := ReEvaluateForConfig(r, conf, "gitlab", conf.PlumberConfig); ok {
				t.Error("must report ok=false so the caller keeps the run's verdict")
			}
		})
	}
	if _, _, ok := ReEvaluateForConfig(&AnalysisResult{Pipeline: &ir.NormalizedPipeline{}}, nil, "gitlab", nil); ok {
		t.Error("a nil config must report ok=false")
	}
}

// TestReEvaluateForConfigWorksForGitHub covers the provider this function
// silently skipped.
//
// The two providers store their IR in different fields, and this read only
// result.Pipeline - nil on every GitHub run. So it returned ok=false, the
// caller kept the LOCAL config's findings, and pushed them labelled with the
// policy's effective_config. Nothing failed and nothing logged; the verdict
// was simply computed under parameters the policy never asked for.
//
// Platform mode runs for GitHub too, so this affected every GitHub policy
// carrying its own control tree.
func TestReEvaluateForConfigWorksForGitHub(t *testing.T) {
	conf := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{Version: "2.0"}}
	policy := &configuration.PlumberConfig{Version: "2.0"}

	result := &AnalysisResult{
		CiValid:        true,
		GitHubPipeline: &ir.NormalizedPipeline{Provider: ir.ProviderGitHub},
	}
	if _, _, ok := ReEvaluateForConfig(result, conf, "github", policy); !ok {
		t.Fatal("a GitHub run retains its IR in GitHubPipeline and must re-evaluate")
	}

	// The refusal must still hold when neither field is set, so the caller
	// keeps the run's own verdict rather than inventing an empty one.
	if _, _, ok := ReEvaluateForConfig(&AnalysisResult{CiValid: true}, conf, "github", policy); ok {
		t.Error("a run with no IR at all must still report ok=false")
	}
}

// TestReEvaluateForConfigMarksThePolicysOwnControls is the end-to-end half
// of TestPerPolicyMarkingUsesThePolicysOwnControls: it drives the real
// per-policy path rather than the marker in isolation.
//
// The run's not-evaluable set is computed against the LOCAL config, and
// every marker deliberately skips controls that config had DISABLED. A
// policy that ENABLES one of those is then evaluated with nothing marked
// for it, so its findings survive the drop and are pushed as that policy's
// verdict - computed over a lane that supplied nothing. Here the lane in
// question is include attribution on a digest-divergent branch, where the
// per-job origin is WRONG rather than absent, so the finding is fabricated.
func TestReEvaluateForConfigMarksThePolicysOwnControls(t *testing.T) {
	on, off := true, false

	local := &configuration.PlumberConfig{Version: "2.0", GitLab: &configuration.ProviderConfig{
		Controls: configuration.ControlsConfig{
			// Disabled locally, exactly as the shipped default has it.
			PipelineMustNotIncludeHardcodedJobs: &configuration.HardcodedJobsControlConfig{Enabled: &off},
		}}}
	policy := &configuration.PlumberConfig{Version: "2.0", GitLab: &configuration.ProviderConfig{
		Controls: configuration.ControlsConfig{
			PipelineMustNotIncludeHardcodedJobs: &configuration.HardcodedJobsControlConfig{Enabled: &on},
		}}}

	// A resolved (digest-divergent) config: the merged YAML is this
	// branch's, the snapshot's includes describe the anchor's, so
	// attribution cannot be trusted for either.
	conf := &configuration.Configuration{
		PlumberConfig: local,
		PlatformRun: &platform.RunContext{
			Context: &platform.ProjectContext{Snapshot: platform.Snapshot{Data: &platform.SnapshotData{
				SchemaVersion:    "2",
				Includes:         []json.RawMessage{json.RawMessage(`{"location":"gitlab.com/c/x@1.0.0","type":"component"}`)},
				BranchProtection: json.RawMessage(`{"branches":["main"],"protections":[]}`),
				MrApprovals:      json.RawMessage(`{"rules":[]}`),
			}}},
			Config: &platform.ConfigResolution{
				Source:     platform.SourceResolved,
				MergedYAML: "stages: [build]",
				Valid:      true,
			},
		},
	}

	// One job the rule fires on. Without attribution this classification is
	// exactly what cannot be trusted: an upstream component's job reads as
	// project-authored.
	result := &AnalysisResult{
		CiValid: true,
		Pipeline: &ir.NormalizedPipeline{
			Provider:    ir.ProviderGitLab,
			ProjectPath: "grp/app",
			Jobs:        []ir.Job{{Name: "build", OriginKind: "hardcoded"}},
		},
	}
	markPlatformLaneGaps(result, conf)

	scoped, _, ok := ReEvaluateForConfig(result, conf, "gitlab", policy)
	if !ok {
		t.Fatal("re-evaluation must succeed with a retained pipeline")
	}
	for _, f := range scoped.Findings {
		if f.Code == "ISSUE-401" {
			t.Fatalf("a control the policy enabled reported a finding over unavailable attribution: %+v", f)
		}
	}
	// Dropping the findings is only half the job. The mark is what StatusFor
	// reads, and without it a control whose lane died is pushed as `pass` -
	// the drop making it look clean instead of making it honest.
	if _, marked := scoped.NotEvaluable["pipelineMustNotIncludeHardcodedJobs"]; !marked {
		t.Fatalf("the policy's own not_evaluable marks must survive the return, got %v", scoped.NotEvaluable)
	}
}

// TestOwnCollectionGapsAreMarkedWithoutPlatformMode covers the honesty gap
// that survived on the mode almost everybody runs.
//
// A tag-vs-branch probe against an include's SOURCE project is a call this
// CLI makes itself, with its own credentials, in every mode. When it fails
// the failure was recorded and then read by nobody outside platform mode, so
// a plain `plumber analyze` reported externalRefsMustNotCollide as a clean
// pass on evidence it never obtained. A token that can read this project but
// not the upstream one hits it every time.
func TestOwnCollectionGapsAreMarkedWithoutPlatformMode(t *testing.T) {
	result := &AnalysisResult{
		CiValid: true,
		PipelineOriginData: &gitlab.GitlabPipelineOriginData{
			RefProbesFailed:      []string{"vendor/components@v1"},
			VersionLookupsFailed: []string{"vendor/components"},
		},
	}

	// No PlatformRun at all: this is the standalone path.
	MarkOwnCollectionGaps(result, nil)

	for _, name := range []string{"externalRefsMustNotCollide", "includesMustBeUpToDate"} {
		if _, marked := result.NotEvaluable[name]; !marked {
			t.Errorf("%s must report not_evaluable when its upstream check failed, got %v", name, result.NotEvaluable)
		}
	}
}

// TestOwnCollectionGapsRespectSkippedControls guards the one thing the
// extraction could have broken: a control the user disabled must stay
// skipped, not be resurrected as an error.
func TestOwnCollectionGapsRespectSkippedControls(t *testing.T) {
	result := &AnalysisResult{
		CiValid: true,
		PipelineOriginData: &gitlab.GitlabPipelineOriginData{
			RefProbesFailed: []string{"vendor/components@v1"},
		},
	}
	entries := []ControlEntry{{ControlName: "externalRefsMustNotCollide", Skipped: true}}

	MarkOwnCollectionGaps(result, entries)

	if _, marked := result.NotEvaluable["externalRefsMustNotCollide"]; marked {
		t.Error("a control the user disabled must stay skipped, not become an error")
	}
}

// TestOwnCollectionGapsStaySilentWhenNothingFailed is the negative case: a
// clean run must mark nothing, or every report grows a phantom error.
func TestOwnCollectionGapsStaySilentWhenNothingFailed(t *testing.T) {
	result := &AnalysisResult{
		CiValid:            true,
		PipelineOriginData: &gitlab.GitlabPipelineOriginData{},
	}
	MarkOwnCollectionGaps(result, nil)
	if len(result.NotEvaluable) != 0 {
		t.Errorf("a clean collection must mark nothing, got %v", result.NotEvaluable)
	}
}

// TestMarkFailedCollections pins the branch-protection collection-failure
// path (re-raised #431 review thread): an unreadable protection listing is
// indistinguishable from a project that protects nothing, which is the
// exact violation branchMustBeProtected reports, so the control must
// abstain and its findings must be dropped rather than fire the loudest
// possible false positive.
func TestMarkFailedCollections(t *testing.T) {
	entries := []ControlEntry{{ControlName: controlBranchMustBeProtected}}

	t.Run("unread listing marks the control and drops its findings", func(t *testing.T) {
		r := &AnalysisResult{
			ProtectionData: &gitlab.GitlabProtectionAnalysisData{BranchProtectionsKnown: false},
			Findings: []opaengine.Finding{
				{Code: "ISSUE-501", Message: "branch main unprotected"},
				{Code: "ISSUE-401", Message: "unrelated finding survives"},
			},
		}
		r.MarkFailedCollections(entries)
		reason, marked := r.NotEvaluableReason(controlBranchMustBeProtected)
		if !marked || reason != ReasonCollectionFailed {
			t.Fatalf("want collection_failed mark, got (%q, %v)", reason, marked)
		}
		codes := map[string]bool{}
		for _, f := range r.Findings {
			codes[f.Code] = true
		}
		if codes["ISSUE-501"] {
			t.Fatal("the branch-protection finding must be dropped: it was computed over data never read")
		}
		if !codes["ISSUE-401"] {
			t.Fatal("unrelated findings must survive the drop")
		}
	})

	t.Run("a read listing marks nothing", func(t *testing.T) {
		r := &AnalysisResult{ProtectionData: &gitlab.GitlabProtectionAnalysisData{BranchProtectionsKnown: true}}
		r.MarkFailedCollections(entries)
		if _, marked := r.NotEvaluableReason(controlBranchMustBeProtected); marked {
			t.Fatal("a successfully read listing must not be marked")
		}
	})

	t.Run("a disabled control is skipped, not marked", func(t *testing.T) {
		r := &AnalysisResult{ProtectionData: &gitlab.GitlabProtectionAnalysisData{BranchProtectionsKnown: false}}
		r.MarkFailedCollections([]ControlEntry{{ControlName: controlBranchMustBeProtected, Skipped: true}})
		if _, marked := r.NotEvaluableReason(controlBranchMustBeProtected); marked {
			t.Fatal("a control the operator disabled was not unevaluated, it was turned off")
		}
	})

	t.Run("no protection data at all marks nothing here", func(t *testing.T) {
		r := &AnalysisResult{}
		r.MarkFailedCollections(entries)
		if _, marked := r.NotEvaluableReason(controlBranchMustBeProtected); marked {
			t.Fatal("a collection that never ran is the other markers' concern, not this one's")
		}
	})
}
