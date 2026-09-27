package control

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/getplumber/plumber/configuration"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
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
