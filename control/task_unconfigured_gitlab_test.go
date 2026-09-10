package control

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getplumber/plumber/configuration"
)

// bareBranchProtectionConfig enables a RequiresConfig GitLab control with
// no substantive field beyond `enabled`, the #459 case.
const bareBranchProtectionConfig = `version: "2.0"
gitlab:
  controls:
    branchMustBeProtected:
      enabled: true
`

// TestRunAnalysis_MarksUnconfiguredControlNotEvaluable pins
// MarkUnconfiguredControls' wiring into RunAnalysis (control/task.go), the
// GitLab mirror of TestRunGitHubAnalysis_MarksUnconfiguredControlNotEvaluable
// and TestRunGitHubAnalysisRemote_MarksUnconfiguredControlNotEvaluable in
// task_github_test.go: a RequiresConfig control enabled with no substantive
// field must surface as config_required at the real entry point, not just
// in the configuration package's own unit tests (#459). Deleting the
// MarkUnconfiguredControls call in RunAnalysis must fail this test.
//
// RunAnalysis has no offline seam lighter than a served GitLab, so this
// runs against the recording fake GitLab already built for the
// platform-call inventory (control/platform_call_inventory_test.go:
// gitlabRecorder, testProjectPath) rather than faking RunAnalysis itself.
func TestRunAnalysis_MarksUnconfiguredControlNotEvaluable(t *testing.T) {
	rec := &gitlabRecorder{sha: "0123456789abcdef0123456789abcdef01234567"}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	pc, _, _, err := configuration.LoadPlumberConfigFromBytes([]byte(bareBranchProtectionConfig), "unconfigured-test")
	if err != nil {
		t.Fatalf("loading the test config: %v", err)
	}
	conf := configuration.NewDefaultConfiguration()
	conf.GitlabURL = srv.URL
	conf.GitlabToken = "glpat-inventory"
	conf.ProjectPath = testProjectPath
	conf.HTTPClientTimeout = 10 * time.Second
	// One attempt per request, matching inventoryConf: a deliberate 404
	// ref probe should not multiply into retries here either.
	conf.GitlabRetryMaxRetries = 0
	conf.PlumberConfig = pc

	result, err := RunAnalysis(conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	reason, ok := result.NotEvaluableReason("branchMustBeProtected")
	if !ok || reason != ReasonConfigRequired {
		t.Fatalf("expected branchMustBeProtected to be config_required, got reason=%q ok=%v", reason, ok)
	}

	entry := findControlEntry(t, GitLabControls(conf.PlumberConfig), "branchMustBeProtected")
	findingCount := len(FindingsByControl(result.Findings)["branchMustBeProtected"])
	if got := StatusFor(entry, result, findingCount); got != StatusError {
		t.Errorf("expected StatusFor %q, got %q", StatusError, got)
	}
}
