package cmd

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/internal/platform"
	"github.com/getplumber/plumber/provider"
)

// row62LocalConfigDisablesVariables is the run's own .plumber.yaml: the
// CI/CD variables control this test's resolved policy enables is explicitly
// off here, so a passing test proves the collection scope came from the
// platform's policy, not from this file.
const row62LocalConfigDisablesVariables = `version: "2.0"
gitlab:
  controls:
    cicdVariablesMustBeProtected:
      enabled: false
`

// setAnalyzeFlagRow62 marks flag as explicitly set on the shared analyzeCmd,
// via cmd.Flags().Set so cmd.Flags().Changed(flag) reads true exactly as a
// real CLI invocation would leave it. analyzeCmd is the package's one
// registered command (cmd/analyze_gitlab.go's init), reused by runAnalyze in
// production, so driving runAnalyze in a test means touching its flags -
// t.Cleanup restores the flag's prior value AND its prior Changed state, so
// this test leaves no trace for whichever test runs next.
func setAnalyzeFlagRow62(t *testing.T, flag, value string) {
	t.Helper()
	f := analyzeCmd.Flags().Lookup(flag)
	if f == nil {
		t.Fatalf("no such analyze flag: %q", flag)
	}
	origValue := f.Value.String()
	origChanged := f.Changed
	if err := analyzeCmd.Flags().Set(flag, value); err != nil {
		t.Fatalf("setting --%s=%q: %v", flag, value, err)
	}
	t.Cleanup(func() {
		_ = f.Value.Set(origValue)
		f.Changed = origChanged
	})
}

// TestRunAnalyze_Row62_EstablishesCollectionScopeBeforeCollection is the
// GitLab mirror of TestRunGitHubAnalyze_Row62_EstablishesPlatformModeBeforeCollection
// (cmd/analyze_github_test.go): runAnalyze (cmd/analyze_gitlab.go) resolves
// platform mode and applyCollectionScope BEFORE collection begins, the same
// row-62 ordering GitHub's entry points observe at their own collection
// seam. Nothing drove runAnalyze itself with a resolved policy: removing or
// moving the applyCollectionScope(p, conf) call left every existing test
// green.
//
// Observed at the collection seam (gitlabAnalysis, added alongside this
// test to mirror githubAnalysis/githubAnalysisRemote): the stub records the
// Configuration it was handed and stops the run there, so a setup that
// happened afterwards is recorded as empty (platform decision row 62).
func TestRunAnalyze_Row62_EstablishesCollectionScopeBeforeCollection(t *testing.T) {
	t.Setenv("PLUMBER_ANALYZE_PLATFORM_TOKEN", "id-token")

	// A policy resolving the CI/CD-variables control, which the local
	// .plumber.yaml (row62LocalConfigDisablesVariables) turns off: a
	// collection scope of one proves it came from the policy union, not
	// from the run's own file.
	policy := policyWithTree("P", "cicdVariablesMustBeProtected", `{"enabled":true}`)
	contextBody, err := json.Marshal(platform.ProjectContext{Policies: []platform.Policy{policy}})
	if err != nil {
		t.Fatalf("marshal context: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/context") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(contextBody)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cfgPath := filepath.Join(t.TempDir(), ".plumber.yaml")
	if err := os.WriteFile(cfgPath, []byte(row62LocalConfigDisablesVariables), 0o644); err != nil {
		t.Fatalf("writing the local config: %v", err)
	}

	origPlatformURL, origPrint, origConfig, origExplicit := platformURL, printOutput, configFile, configExplicitlySet
	defer func() {
		platformURL, printOutput = origPlatformURL, origPrint
		configFile, configExplicitlySet = origConfig, origExplicit
	}()
	platformURL, printOutput = srv.URL, false
	configFile, configExplicitlySet = cfgPath, true

	setAnalyzeFlagRow62(t, "gitlab-url", "https://gitlab.example.com")
	setAnalyzeFlagRow62(t, "project", "group/project")

	// Stopping at the collection seam keeps the test to the ordering claim:
	// the run never reaches actual GitLab collection, presentation, scoring
	// or the push.
	stopped := errors.New("collection reached")
	orig := gitlabAnalysis
	var engagedAtCollection bool
	var collectionConfigsAtCollection int
	gitlabAnalysis = func(p provider.Provider, conf *configuration.Configuration) (*control.AnalysisResult, error) {
		engagedAtCollection = conf.PlatformRun.Engaged()
		collectionConfigsAtCollection = len(conf.CollectionConfigs)
		return nil, stopped
	}
	t.Cleanup(func() { gitlabAnalysis = orig })

	var runErr error
	_ = captureStderr(t, func() {
		runErr = runAnalyze(analyzeCmd, nil)
	})

	if !errors.Is(runErr, stopped) {
		t.Fatalf("want the run to stop at the collection seam, got %v", runErr)
	}
	if !engagedAtCollection {
		t.Fatal("platform mode was not established when collection began: the lanes collection has to fetch are decided by what the platform resolved")
	}
	if collectionConfigsAtCollection != 1 {
		t.Fatalf("collecting configurations at collection = %d, want the one resolved policy's tree", collectionConfigsAtCollection)
	}
}
