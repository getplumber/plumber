package control

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/getplumber/plumber/configuration"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
	"github.com/sirupsen/logrus"
)

// healthyPolicy always emits one finding on a control enabled by default for
// GitHub (ISSUE-801, workflowsMustDeclarePermissions), on a job name of its
// own so it cannot be confused with the real policy's finding.
const healthyPolicy = `package healthy
import rego.v1
deny contains {"code": "ISSUE-801", "severity": "medium", "message": "healthy", "job": "healthy-job"} if { true }
`

// brokenPolicy trips eval_conflict_error the way artipacked did in #489 and
// declares ISSUE-307, so its failure must land on that code's control.
const brokenPolicy = `package broken
import rego.v1
pick(x) := 1 if { x == x }
pick(x) := 2 if { x == x }
deny contains {"code": "ISSUE-307", "severity": "low", "message": "never", "job": "build"} if { pick(1) == 1 }
`

// policiesPlus returns the embedded policies with extra modules.
func policiesPlus(t *testing.T, extra map[string]string) fs.FS {
	t.Helper()
	m := fstest.MapFS{}
	entries, err := fs.ReadDir(policies.FS, ".")
	if err != nil {
		t.Fatalf("read policies: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := fs.ReadFile(policies.FS, e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		m[e.Name()] = &fstest.MapFile{Data: data}
	}
	for name, source := range extra {
		m[name] = &fstest.MapFile{Data: []byte(source)}
	}
	return m
}

func defaultConf(t *testing.T) *configuration.Configuration {
	t.Helper()
	pc, _, _, err := configuration.LoadPlumberConfigFromBytes(defaultconfig.Get(), "built-in default")
	if err != nil {
		t.Fatalf("load default config: %v", err)
	}
	return &configuration.Configuration{PlumberConfig: pc}
}

// TestEvaluatePolicies_IsolatesFailingModule is the #489 runner guard: a
// policy that fails to evaluate is reported with the controls it declares,
// and the other policies' findings still come back instead of an empty list.
func TestEvaluatePolicies_IsolatesFailingModule(t *testing.T) {
	prev := policyFS
	policyFS = policiesPlus(t, map[string]string{"broken.rego": brokenPolicy, "healthy.rego": healthyPolicy})
	t.Cleanup(func() { policyFS = prev })

	pipeline := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{{Name: "build"}}}
	findings, failures := evaluatePolicies(logrus.NewEntry(logrus.New()), defaultConf(t), "github", pipeline)
	if len(failures) != 1 || failures[0].Module != "broken" {
		t.Fatalf("want the broken policy reported once, got %+v", failures)
	}
	wantControl := LookupCode(ErrorCode("ISSUE-307")).ControlName
	if len(failures[0].Controls) != 1 || failures[0].Controls[0] != wantControl {
		t.Fatalf("the failure must name the control of the code the policy declares (%s), got %v", wantControl, failures[0].Controls)
	}
	survived := false
	for _, f := range findings {
		if f.Code == "ISSUE-801" && f.Job == "healthy-job" {
			survived = true
		}
	}
	if !survived {
		t.Fatalf("the healthy policy's finding must survive a failing module, got %+v", findings)
	}
}

// TestApplyPolicyFailures_DegradesRunAndIsolatesControls pins what the run
// does with a failure: degraded (score withheld, exit 3) with a reason naming
// the policy, the declared control not evaluated, every other control keeping
// its real status.
func TestApplyPolicyFailures_DegradesRunAndIsolatesControls(t *testing.T) {
	result := &AnalysisResult{CiValid: true}
	applyPolicyFailures(result, []policyFailure{{
		Module:   "artipacked",
		Err:      errors.New("artipacked.rego:83: eval_conflict_error"),
		Controls: []string{"checkoutMustNotPersistCredentials"},
	}})

	if !result.DataCollectionDegraded {
		t.Fatal("a failed policy must degrade the run so the score is withheld")
	}
	if len(result.DegradedReasons) != 1 || !strings.Contains(result.DegradedReasons[0], "artipacked") || !strings.Contains(result.DegradedReasons[0], "eval_conflict_error") {
		t.Fatalf("the degraded reason must name the policy and its error, got %v", result.DegradedReasons)
	}
	if got := result.NotEvaluable["checkoutMustNotPersistCredentials"]; got != ReasonPolicyEvaluationFailed {
		t.Fatalf("the declared control must be marked %q, got %q", ReasonPolicyEvaluationFailed, got)
	}
	affected := ControlEntry{ControlName: "checkoutMustNotPersistCredentials"}
	if s := StatusFor(affected, result, 0); s != StatusError {
		t.Fatalf("the affected control reads not evaluated, got %s", s)
	}
	other := ControlEntry{ControlName: "workflowsMustDeclarePermissions"}
	if s := StatusFor(other, result, 0); s != StatusPassed {
		t.Fatalf("an unaffected control keeps its real status (passed), got %s: the policy-failure reason must not read as a whole-run failure", s)
	}
	if s := StatusFor(other, result, 2); s != StatusFailed {
		t.Fatalf("an unaffected control with findings keeps failed, got %s", s)
	}
}

// TestControlsDeclaredBy_EmittedCodesOnly pins the attribution: only the
// codes a policy EMITS count. artipacked cites ISSUE-802 and ISSUE-804 in
// its header comment to explain the threat model and dangerous_triggers
// cites ISSUE-804 to say what it leaves to another policy; neither may mark
// those other controls. A source emitting two controls' codes yields both,
// distinct, in first-seen order.
func TestControlsDeclaredBy_EmittedCodesOnly(t *testing.T) {
	read := func(name string) []byte {
		data, err := fs.ReadFile(policies.FS, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return data
	}
	if got := controlsDeclaredBy(read("artipacked.rego")); len(got) != 1 || got[0] != "checkoutMustNotPersistCredentials" {
		t.Fatalf("artipacked emits one control's codes; codes cited in its comments must not count, got %v", got)
	}
	if got := controlsDeclaredBy(read("dangerous_triggers.rego")); len(got) != 1 || got[0] != "workflowMustNotUseDangerousTriggers" {
		t.Fatalf("dangerous_triggers emits ISSUE-802 only; ISSUE-804 in its comments must not count, got %v", got)
	}
	two := []byte(`package two
# ISSUE-307 is mentioned here and must not count
deny contains {"code": "ISSUE-802", "severity": "high", "message": "a"} if { true }
deny contains {"code":"ISSUE-804", "severity": "high", "message": "b"} if { true }
deny contains {"code": "ISSUE-802", "severity": "high", "message": "again"} if { true }
`)
	got := controlsDeclaredBy(two)
	if len(got) != 2 || got[0] != "workflowMustNotUseDangerousTriggers" || got[1] != "pullRequestTargetMustNotCheckoutHead" {
		t.Fatalf("two emitted controls, distinct, in first-seen order, got %v", got)
	}
}

// TestReEvaluateForConfig_FailingModuleDegradesThePolicyNotTheRun covers
// the platform per-policy path: a module failing under a policy's
// configuration degrades THAT policy's scoped verdict and marks its control,
// while the run's own reasons and marks stay untouched for the next policy.
func TestReEvaluateForConfig_FailingModuleDegradesThePolicyNotTheRun(t *testing.T) {
	prev := policyFS
	policyFS = policiesPlus(t, map[string]string{"broken.rego": brokenPolicy})
	t.Cleanup(func() { policyFS = prev })

	enabled := true
	pc := &configuration.PlumberConfig{Version: "2.0", GitHub: &configuration.ProviderConfig{
		Controls: configuration.ControlsConfig{
			CheckoutMustNotPersistCredentials: &configuration.EnabledOnlyControlConfig{Enabled: &enabled},
		}}}
	conf := &configuration.Configuration{PlumberConfig: pc}
	// The run already carries one reason and one mark, and its reasons
	// slice has spare capacity: an append on an aliased backing array would
	// land the policy-failure reason in the run's own slice, which is what
	// the fresh copy in ReEvaluateForConfig exists to prevent.
	reasons := make([]string, 1, 8)
	reasons[0] = "branch protection could not be fetched (network or timeout)"
	result := &AnalysisResult{
		CiValid:                true,
		DataCollectionDegraded: true,
		DegradedReasons:        reasons,
		GitHubPipeline:         &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "acme/app", Jobs: []ir.Job{{Name: "build"}}},
	}
	result.MarkNotEvaluable("includesMustBeUpToDate", ReasonIncludeAttributionUnavailable)

	scoped, _, ok := ReEvaluateForConfig(result, conf, "github", pc)
	if !ok {
		t.Fatal("a result carrying a pipeline must be re-evaluable")
	}
	if !scoped.DataCollectionDegraded || len(scoped.DegradedReasons) != 2 || !strings.Contains(scoped.DegradedReasons[1], "broken") {
		t.Fatalf("the policy's verdict must carry the run's reason plus the broken module's, got %v", scoped.DegradedReasons)
	}
	if scoped.NotEvaluable["checkoutMustNotPersistCredentials"] != ReasonPolicyEvaluationFailed {
		t.Fatalf("the broken module's control must be marked on the scoped result, got %v", scoped.NotEvaluable)
	}
	if len(result.DegradedReasons) != 1 || result.DegradedReasons[0] != reasons[0] || reasons[:2:2][1] != "" {
		t.Fatalf("the run's reasons must stay exactly its own (no aliasing through the spare capacity), got %v / backing %v", result.DegradedReasons, reasons[:2])
	}
	if len(result.NotEvaluable) != 1 || result.NotEvaluable["includesMustBeUpToDate"] != ReasonIncludeAttributionUnavailable {
		t.Fatalf("the run's marks must stay exactly its own, got %v", result.NotEvaluable)
	}
}

// TestDropNotEvaluableFindings_KeepsSiblingModuleFindingsOnPolicyFailure
// covers a control whose codes are spread over two policy files (the
// template pair, the component pair, the branch pair): when one file fails,
// the other file's genuine finding must survive the not-evaluable mark,
// while a mark of any other kind still drops the control's findings.
func TestDropNotEvaluableFindings_KeepsSiblingModuleFindingsOnPolicyFailure(t *testing.T) {
	const control = "pipelineMustIncludeTemplate" // ISSUE-405 and ISSUE-406 live in two files
	mk := func(reason string) *AnalysisResult {
		r := &AnalysisResult{Findings: []opaengine.Finding{{Code: "ISSUE-405", Job: "build"}, {Code: "ISSUE-801", Job: "build"}}}
		r.MarkNotEvaluable(control, reason)
		return r
	}
	r := mk(ReasonPolicyEvaluationFailed)
	r.DropNotEvaluableFindings()
	if len(r.Findings) != 2 {
		t.Fatalf("a policy-failure mark keeps the sibling module's ISSUE-405, got %+v", r.Findings)
	}
	r = mk(ReasonIncludeAttributionUnavailable)
	r.DropNotEvaluableFindings()
	if len(r.Findings) != 1 || r.Findings[0].Code != "ISSUE-801" {
		t.Fatalf("a data-lane mark still drops the control's findings, got %+v", r.Findings)
	}
}

// TestRunGitHubAnalysis_FailingPolicyDegradesTheRun drives a broken module
// through the production entry point: the run is degraded with a reason
// naming the module, the module's control is not evaluated, and a healthy
// policy's finding is still reported. Dropping the applyPolicyFailures call
// at the entry point would fail this test.
func TestRunGitHubAnalysis_FailingPolicyDegradesTheRun(t *testing.T) {
	t.Setenv("PLUMBER_DISABLE_GITHUB_API", "1")
	prev := policyFS
	policyFS = policiesPlus(t, map[string]string{"broken.rego": brokenPolicy})
	t.Cleanup(func() { policyFS = prev })

	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// No permissions block: workflowsMustDeclarePermissions (ISSUE-801) fires.
	const workflow = "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v5\n"
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}
	enabled := true
	conf := &configuration.Configuration{
		ProjectPath: "owner/repo", Branch: "main", GitRepoRoot: tmp,
		PlumberConfig: &configuration.PlumberConfig{Version: "2.0", GitHub: &configuration.ProviderConfig{
			Controls: configuration.ControlsConfig{
				WorkflowsMustDeclarePermissions:   &configuration.EnabledOnlyControlConfig{Enabled: &enabled},
				CheckoutMustNotPersistCredentials: &configuration.EnabledOnlyControlConfig{Enabled: &enabled},
			}}},
	}
	result, err := RunGitHubAnalysis(conf)
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !result.DataCollectionDegraded || len(result.DegradedReasons) == 0 || !strings.Contains(strings.Join(result.DegradedReasons, "|"), "broken") {
		t.Fatalf("a failing policy must degrade the run naming the module, got degraded=%v reasons=%v", result.DataCollectionDegraded, result.DegradedReasons)
	}
	if result.NotEvaluable["checkoutMustNotPersistCredentials"] != ReasonPolicyEvaluationFailed {
		t.Fatalf("the broken module's control must be marked, got %v", result.NotEvaluable)
	}
	found := false
	for _, f := range result.Findings {
		if f.Code == "ISSUE-801" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the healthy policy's ISSUE-801 must survive, got %+v", result.Findings)
	}
}

// TestEvaluatePolicies_FailureOnInactiveControlIsDropped: a broken module
// whose only control the user disabled (or filtered out) must not degrade
// the run, exactly as that control's findings would not have counted.
func TestEvaluatePolicies_FailureOnInactiveControlIsDropped(t *testing.T) {
	prev := policyFS
	policyFS = policiesPlus(t, map[string]string{"broken.rego": brokenPolicy})
	t.Cleanup(func() { policyFS = prev })
	pipeline := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{{Name: "build"}}}

	off := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{Version: "2.0", GitHub: &configuration.ProviderConfig{}}}
	if _, failures := evaluatePolicies(logrus.NewEntry(logrus.New()), off, "github", pipeline); len(failures) != 0 {
		t.Fatalf("the broken module's control is disabled; its failure must be dropped, got %+v", failures)
	}
	skipped := defaultConf(t)
	skipped.SkipControlsFilter = []string{"checkoutMustNotPersistCredentials"}
	if _, failures := evaluatePolicies(logrus.NewEntry(logrus.New()), skipped, "github", pipeline); len(failures) != 0 {
		t.Fatalf("the broken module's control is skipped by filter; its failure must be dropped, got %+v", failures)
	}
	only := defaultConf(t)
	only.ControlsFilter = []string{"workflowsMustDeclarePermissions"}
	if _, failures := evaluatePolicies(logrus.NewEntry(logrus.New()), only, "github", pipeline); len(failures) != 0 {
		t.Fatalf("the broken module's control is outside the include-only filter; its failure must be dropped, got %+v", failures)
	}
	// checkoutMustNotPersistCredentials is a GitHub control: on the GitLab
	// provider the module's failure touches nothing this run evaluates.
	gitlabPipeline := &ir.NormalizedPipeline{Provider: ir.ProviderGitLab, Jobs: []ir.Job{{Name: "build"}}}
	if _, failures := evaluatePolicies(logrus.NewEntry(logrus.New()), defaultConf(t), "gitlab", gitlabPipeline); len(failures) != 0 {
		t.Fatalf("the broken module's control does not apply to gitlab; its failure must be dropped, got %+v", failures)
	}
	// And the positive side of the same gate: with the control active the
	// failure is reported.
	if _, failures := evaluatePolicies(logrus.NewEntry(logrus.New()), defaultConf(t), "github", pipeline); len(failures) != 1 {
		t.Fatalf("with the control active the failure must be reported once, got %+v", failures)
	}
}

// TestRunGitHubAnalysisRemote_FailingPolicyDegradesTheRun mirrors the local
// entry-point test on the remote path, which #489 was reported against.
func TestRunGitHubAnalysisRemote_FailingPolicyDegradesTheRun(t *testing.T) {
	swapRemoteScan(t, remoteScanStub)
	swapDefaultBranchFetch(t, func(host, owner, repo string) (string, error) { return "main", nil })
	prev := policyFS
	policyFS = policiesPlus(t, map[string]string{"broken.rego": brokenPolicy})
	t.Cleanup(func() { policyFS = prev })

	enabled := true
	conf := &configuration.Configuration{PlumberConfig: &configuration.PlumberConfig{Version: "2.0", GitHub: &configuration.ProviderConfig{
		Controls: configuration.ControlsConfig{
			CheckoutMustNotPersistCredentials: &configuration.EnabledOnlyControlConfig{Enabled: &enabled},
		}}}}
	result, err := RunGitHubAnalysisRemote(conf, "owner", "repo", "main")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !result.DataCollectionDegraded || !strings.Contains(strings.Join(result.DegradedReasons, "|"), "broken") {
		t.Fatalf("a failing policy must degrade the remote run naming the module, got degraded=%v reasons=%v", result.DataCollectionDegraded, result.DegradedReasons)
	}
	if result.NotEvaluable["checkoutMustNotPersistCredentials"] != ReasonPolicyEvaluationFailed {
		t.Fatalf("the broken module's control must be marked, got %v", result.NotEvaluable)
	}
}

// TestMarkNotEvaluable_DataLaneReasonOverridesPolicyFailure: the policy
// failure is recorded first and is the weakest claim; a data-lane gap marked
// later on the same control replaces it, so the control's findings are
// dropped as they would have been without the policy failure. Any other
// existing reason still wins over a later one.
func TestMarkNotEvaluable_DataLaneReasonOverridesPolicyFailure(t *testing.T) {
	const control = "pipelineMustIncludeTemplate"
	r := &AnalysisResult{Findings: []opaengine.Finding{{Code: "ISSUE-405", Job: "build"}}}
	r.MarkNotEvaluable(control, ReasonPolicyEvaluationFailed)
	r.MarkNotEvaluable(control, ReasonIncludeAttributionUnavailable)
	if got := r.NotEvaluable[control]; got != ReasonIncludeAttributionUnavailable {
		t.Fatalf("a data-lane reason must replace the policy-failure mark, got %q", got)
	}
	r.DropNotEvaluableFindings()
	if len(r.Findings) != 0 {
		t.Fatalf("with the data-lane reason in place the control's findings must be dropped, got %+v", r.Findings)
	}
	r2 := &AnalysisResult{}
	r2.MarkNotEvaluable(control, ReasonIncludeAttributionUnavailable)
	r2.MarkNotEvaluable(control, ReasonPolicyEvaluationFailed)
	if got := r2.NotEvaluable[control]; got != ReasonIncludeAttributionUnavailable {
		t.Fatalf("an existing data-lane reason must keep winning, got %q", got)
	}
}

// TestApplyPolicyFailures_WholeRunFailureLeavesEveryControlNotEvaluated:
// a failure with no declared controls (the policies did not load, the
// engine input could not be built) is a whole-run failure: degraded, and
// every control reads not evaluated rather than passed.
func TestApplyPolicyFailures_WholeRunFailureLeavesEveryControlNotEvaluated(t *testing.T) {
	result := &AnalysisResult{CiValid: true}
	applyPolicyFailures(result, []policyFailure{{Module: "engine", Err: errors.New("evaluate: build input: boom")}})
	if !result.DataCollectionDegraded || len(result.DegradedReasons) != 1 || !strings.Contains(result.DegradedReasons[0], "engine") {
		t.Fatalf("a whole-run failure must degrade the run naming the engine, got %v", result.DegradedReasons)
	}
	for _, name := range []string{"workflowsMustDeclarePermissions", "checkoutMustNotPersistCredentials", "pipelineMustIncludeTemplate"} {
		if s := StatusFor(ControlEntry{ControlName: name}, result, 0); s != StatusError {
			t.Fatalf("%s must read not evaluated after a whole-run failure, got %s", name, s)
		}
	}
}

// TestEvaluatePolicies_EngineErrorIsAWholeRunFailure: a nil pipeline cannot
// be evaluated at all; the failure names the engine and carries no controls.
func TestEvaluatePolicies_EngineErrorIsAWholeRunFailure(t *testing.T) {
	findings, failures := evaluatePolicies(logrus.NewEntry(logrus.New()), defaultConf(t), "github", nil)
	if len(findings) != 0 || len(failures) != 1 || failures[0].Module != "engine" || len(failures[0].Controls) != 0 {
		t.Fatalf("want one engine failure with no controls and no findings, got findings=%v failures=%+v", findings, failures)
	}
}
