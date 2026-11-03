package control

import (
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/gitlab"
	"github.com/sirupsen/logrus"
)

// brokenPolicyGitLab trips eval_conflict_error and declares ISSUE-501, a code
// of branchMustBeProtected, which applies to GitLab.
const brokenPolicyGitLab = `package brokengl
import rego.v1
pick(x) := 1 if { x == x }
pick(x) := 2 if { x == x }
deny contains {"code": "ISSUE-501", "severity": "high", "message": "never", "branchName": "main"} if { pick(1) == 1 }
`

// TestRunRegoEngine_FailingPolicyDegradesTheRun drives a broken module
// through the GitLab engine entry point with no collected data: the run is
// degraded with a reason naming the module and the module's control is not
// evaluated. Dropping the applyPolicyFailures call there would fail this.
func TestRunRegoEngine_FailingPolicyDegradesTheRun(t *testing.T) {
	prev := policyFS
	policyFS = policiesPlus(t, map[string]string{"brokengl.rego": brokenPolicyGitLab})
	t.Cleanup(func() { policyFS = prev })

	enabled := true
	conf := &configuration.Configuration{ProjectPath: "grp/app", PlumberConfig: &configuration.PlumberConfig{Version: "2.0", GitLab: &configuration.ProviderConfig{
		Controls: configuration.ControlsConfig{
			BranchMustBeProtected: &configuration.BranchProtectionControlConfig{Enabled: &enabled},
		}}}}
	project := &gitlab.Project{DefaultBranch: "main"}
	result := &AnalysisResult{CiValid: true}
	runRegoEngine(logrus.NewEntry(logrus.New()), conf, project, nil, nil, nil, nil, nil, nil, result)

	if !result.DataCollectionDegraded || !strings.Contains(strings.Join(result.DegradedReasons, "|"), "brokengl") {
		t.Fatalf("a failing policy must degrade the GitLab run naming the module, got degraded=%v reasons=%v", result.DataCollectionDegraded, result.DegradedReasons)
	}
	if result.NotEvaluable["branchMustBeProtected"] != ReasonPolicyEvaluationFailed {
		t.Fatalf("the broken module's control must be marked, got %v", result.NotEvaluable)
	}
}
