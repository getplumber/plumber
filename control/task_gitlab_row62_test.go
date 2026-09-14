package control

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getplumber/plumber/configuration"
)

// row62OwnConfigDisabledYAML is the run's OWN configuration: every gated
// GitLab collection is explicitly off. Anything this test finds collected
// therefore came from the union with a resolved policy's tree, never from
// this config.
const row62OwnConfigDisabledYAML = `version: "2.0"
gitlab:
  controls:
    branchMustBeProtected:
      enabled: false
    cicdVariablesMustBeProtected:
      enabled: false
    cicdVariablesMustBeMasked:
      enabled: false
    projectMustHaveSecurityPolicySource:
      enabled: false
`

// row62ProtectionAndSecurityPolicyYAML is a resolved policy's tree that
// enables the protection and security-policy lanes but NOT the variables
// lane, so the union it forms with row62OwnConfigDisabledYAML proves both
// that an enabled lane is collected and that an untouched one is not.
const row62ProtectionAndSecurityPolicyYAML = `version: "2.0"
gitlab:
  controls:
    branchMustBeProtected:
      enabled: true
      defaultMustBeProtected: true
    projectMustHaveSecurityPolicySource:
      enabled: true
`

// row62VariablesOnlyYAML is a resolved policy's tree that enables only the
// CI/CD variables lane, the counterpart case to row62ProtectionAndSecurityPolicyYAML.
const row62VariablesOnlyYAML = `version: "2.0"
gitlab:
  controls:
    cicdVariablesMustBeProtected:
      enabled: true
`

// row62RunAnalysis loads pc as the run's own configuration and collecting
// as the (single) resolved-policy configuration RunAnalysis collects for,
// runs the analysis against a fresh recording fake GitLab, and returns the
// result.
func row62RunAnalysis(t *testing.T, ownYAML, collectingYAML string) *AnalysisResult {
	t.Helper()

	rec := &gitlabRecorder{sha: "0123456789abcdef0123456789abcdef01234567"}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	own, _, _, err := configuration.LoadPlumberConfigFromBytes([]byte(ownYAML), "row62-own")
	if err != nil {
		t.Fatalf("loading the run's own config: %v", err)
	}
	collecting, _, _, err := configuration.LoadPlumberConfigFromBytes([]byte(collectingYAML), "row62-collecting")
	if err != nil {
		t.Fatalf("loading the collecting config: %v", err)
	}

	conf := configuration.NewDefaultConfiguration()
	conf.GitlabURL = srv.URL
	conf.GitlabToken = "glpat-row62"
	conf.ProjectPath = testProjectPath
	conf.HTTPClientTimeout = 10 * time.Second
	conf.GitlabRetryMaxRetries = 0
	conf.PlumberConfig = own
	conf.CollectionConfigs = []*configuration.PlumberConfig{collecting}

	result, err := RunAnalysis(conf)
	if err != nil {
		t.Fatalf("analysis failed: %v", err)
	}
	return result
}

// TestRunAnalysis_Row62_CollectsForThePolicyUnion is the GitLab mirror of
// TestRunGitHubAnalysisRemote_Row62_CollectsForThePolicyUnion
// (control/task_github_test.go): it pins RunAnalysis's three gated GitLab
// collections (branch protection, CI/CD variables, security-policy linkage)
// onto the union of the collecting configurations, at the real entry point,
// rather than trusting collection_scope.go's own unit tests alone.
//
// It also pins the security-policy READ itself: RunAnalysis stores the
// collected SecurityPolicyData on the result (control/task.go), and the
// sole reader, ReEvaluateForConfig (control/lanes.go), is exercised only
// with hand-seeded AnalysisResult values in its own tests. Nothing before
// this test asserted that RunAnalysis actually populates the field a
// per-policy push depends on to render the Ultimate-tier caveat for
// projectMustHaveSecurityPolicySource.
func TestRunAnalysis_Row62_CollectsForThePolicyUnion(t *testing.T) {
	t.Run("a policy enabling branch protection and the security-policy linkage collects both, not variables", func(t *testing.T) {
		result := row62RunAnalysis(t, row62OwnConfigDisabledYAML, row62ProtectionAndSecurityPolicyYAML)

		if !result.CollectedLanes[laneGitLabProtection] {
			t.Errorf("the protection lane must be recorded as collected, got %v", result.CollectedLanes)
		}
		if !result.CollectedLanes[laneGitLabSecurityPolicy] {
			t.Errorf("the security-policy lane must be recorded as collected, got %v", result.CollectedLanes)
		}
		if result.CollectedLanes[laneGitLabVariables] {
			t.Errorf("no configuration in this run enables a variables control: the variables lane must stay unrecorded, got %v", result.CollectedLanes)
		}

		// The security-policy READ itself (row 62's other half): the
		// linkage was read authoritatively (the fake answers a null
		// securityPolicyProject, GitLab's "read, nothing linked" shape) and
		// RunAnalysis must have stored it on the result rather than leaving
		// ReEvaluateForConfig's per-policy caveat computed over a nil field.
		if result.SecurityPolicyData == nil {
			t.Fatal("RunAnalysis did not set result.SecurityPolicyData; the per-policy security-policy caveat has nothing to read")
		}
		if !result.SecurityPolicyData.Known {
			t.Errorf("expected the security-policy linkage to be read authoritatively (Known=true), got %+v", result.SecurityPolicyData)
		}
	})

	t.Run("a policy enabling only the variables control collects that lane alone", func(t *testing.T) {
		result := row62RunAnalysis(t, row62OwnConfigDisabledYAML, row62VariablesOnlyYAML)

		if !result.CollectedLanes[laneGitLabVariables] {
			t.Errorf("the variables lane must be recorded as collected, got %v", result.CollectedLanes)
		}
		if result.CollectedLanes[laneGitLabProtection] {
			t.Errorf("no configuration in this run enables branch protection: the protection lane must stay unrecorded, got %v", result.CollectedLanes)
		}
		if result.CollectedLanes[laneGitLabSecurityPolicy] {
			t.Errorf("no configuration in this run enables the security-policy control: that lane must stay unrecorded, got %v", result.CollectedLanes)
		}
	})
}
