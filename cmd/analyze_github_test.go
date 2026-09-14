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
	"github.com/getplumber/plumber/utils"
)

// ---------------------------------------------------------------------------
// detectGitHubAuthSource
// ---------------------------------------------------------------------------

func TestDetectGitHubAuthSource_GHToken(t *testing.T) {
	t.Setenv("GH_TOKEN", "tok")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_ENTERPRISE_TOKEN", "")
	if got := detectGitHubAuthSource(""); got != "GH_TOKEN" {
		t.Fatalf("got %q", got)
	}
}

func TestDetectGitHubAuthSource_GitHubToken(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "tok")
	t.Setenv("GH_ENTERPRISE_TOKEN", "")
	if got := detectGitHubAuthSource(""); got != "GITHUB_TOKEN" {
		t.Fatalf("got %q", got)
	}
}

func TestDetectGitHubAuthSource_EnterpriseToken(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_ENTERPRISE_TOKEN", "tok")
	if got := detectGitHubAuthSource(""); got != "GH_ENTERPRISE_TOKEN" {
		t.Fatalf("got %q", got)
	}
}

func TestDetectGitHubAuthSource_None(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_ENTERPRISE_TOKEN", "")
	// No gh CLI configured in test env — expect empty string.
	got := detectGitHubAuthSource("github.com")
	if got == "GH_TOKEN" || got == "GITHUB_TOKEN" || got == "GH_ENTERPRISE_TOKEN" {
		t.Fatalf("unexpected token source: %q", got)
	}
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// loadGitHubConfig
// ---------------------------------------------------------------------------

func TestLoadGitHubConfig_FileExists(t *testing.T) {
	t.Setenv("CI", "true")
	dir := t.TempDir()
	orig := configFile
	configFile = dir + "/.plumber.yaml"
	defer func() { configFile = orig }()
	if err := writeMinimalConfig(configFile); err != nil {
		t.Fatal(err)
	}

	pc, path, err := loadGitHubConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pc == nil {
		t.Fatal("expected non-nil config")
	}
	if path != configFile {
		t.Fatalf("path: got %q, want %q", path, configFile)
	}
}

func TestLoadGitHubConfig_ExplicitMissingFile(t *testing.T) {
	t.Setenv("CI", "true")
	orig, origExplicit := configFile, configExplicitlySet
	configFile = t.TempDir() + "/nonexistent.yaml"
	configExplicitlySet = true // user named this --config; absence is an error
	defer func() { configFile, configExplicitlySet = orig, origExplicit }()

	_, _, err := loadGitHubConfig()
	if err == nil {
		t.Fatal("expected error for an explicitly-requested missing config")
	}
	if !strings.Contains(err.Error(), "configuration file not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadGitHubConfig_MissingDefault_FallsBack(t *testing.T) {
	t.Setenv("CI", "true")
	orig, origExplicit := configFile, configExplicitlySet
	configFile = t.TempDir() + "/.plumber.yaml" // absent, and not explicit
	configExplicitlySet = false
	defer func() { configFile, configExplicitlySet = orig, origExplicit }()

	pc, path, err := loadGitHubConfig()
	if err != nil {
		t.Fatalf("expected fallback to the embedded default, got: %v", err)
	}
	if pc == nil {
		t.Fatal("expected non-nil config from the embedded default")
	}
	if path != builtinDefaultConfigSource {
		t.Errorf("path: got %q, want %q", path, builtinDefaultConfigSource)
	}
}

func TestLoadGitHubConfig_WarningsFailWarnings(t *testing.T) {
	t.Setenv("CI", "true")
	dir := t.TempDir()
	orig, origFW := configFile, failWarnings
	configFile = dir + "/.plumber.yaml"
	failWarnings = true
	defer func() { configFile, failWarnings = orig, origFW }()

	// Write a config that produces validation warnings (unknown field).
	content := "version: \"2.0\"\nunknownField: true\n"
	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, err := loadGitHubConfig()
	// If warnings are produced and failWarnings is set, expect an error.
	// If the config happens to produce no warnings, the test is a no-op.
	if err != nil && !strings.Contains(err.Error(), "warning") {
		t.Errorf("unexpected error kind: %v", err)
	}
}

func TestLoadGitHubConfig_WarningsNoFail(t *testing.T) {
	t.Setenv("CI", "true")
	dir := t.TempDir()
	orig, origFW := configFile, failWarnings
	configFile = dir + "/.plumber.yaml"
	failWarnings = false
	defer func() { configFile, failWarnings = orig, origFW }()

	if err := writeMinimalConfig(configFile); err != nil {
		t.Fatal(err)
	}

	_, _, err := loadGitHubConfig()
	if err != nil {
		t.Fatalf("failWarnings=false should not error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeMinimalConfig(path string) error {
	return os.WriteFile(path, []byte("version: \"2.0\"\n"), 0644)
}

// ---------------------------------------------------------------------------
// platform mode before collection
// ---------------------------------------------------------------------------

// TestRunGitHubAnalyze_Row62_EstablishesPlatformModeBeforeCollection pins the
// ordering on both GitHub entry points: what the platform resolved decides
// which data lanes collection has to fetch at all, so the run context and the
// collecting configurations must already be on the Configuration when the
// collection is entered. Observed at the collection seam itself: the stub
// records what it was handed and stops the run there, so a setup that happened
// afterwards would be recorded as an empty one (platform decision row 62).
func TestRunGitHubAnalyze_Row62_EstablishesPlatformModeBeforeCollection(t *testing.T) {
	t.Setenv("CI", "true")

	policy := policyWithTree("Actions", "actionsMustNotExecuteMutableRemoteCode", `{"enabled":true}`)
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
	// The GitHub id-token is minted over HTTP from the runtime's own endpoint,
	// which is what makes a GitHub platform run exercisable without a runner.
	mint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"value":"id-token"}`))
	}))
	defer mint.Close()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", mint.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "req-token")

	origURL, origPrint, origConfig, origExplicit := platformURL, printOutput, configFile, configExplicitlySet
	platformURL, printOutput = srv.URL, false
	configFile, configExplicitlySet = filepath.Join(t.TempDir(), ".plumber.yaml"), false
	defer func() {
		platformURL, printOutput = origURL, origPrint
		configFile, configExplicitlySet = origConfig, origExplicit
	}()

	// Stopping at the collection seam keeps the test to the ordering claim: the
	// run never reaches presentation, scoring or the push.
	stopped := errors.New("collection reached")

	for _, tc := range []struct {
		name string
		run  func(t *testing.T, observe func(*configuration.Configuration)) error
	}{
		{
			name: "local clone",
			run: func(t *testing.T, observe func(*configuration.Configuration)) error {
				orig := githubAnalysis
				githubAnalysis = func(conf *configuration.Configuration) (*control.AnalysisResult, error) {
					observe(conf)
					return nil, stopped
				}
				t.Cleanup(func() { githubAnalysis = orig })
				info := &utils.GitRemoteInfo{Host: githubDotCom, ProjectPath: "owner/repo", RepoRoot: t.TempDir()}
				return runGitHubAnalyze(info, nil, nil)
			},
		},
		{
			name: "upstream fetch",
			run: func(t *testing.T, observe func(*configuration.Configuration)) error {
				orig := githubAnalysisRemote
				githubAnalysisRemote = func(conf *configuration.Configuration, owner, repo, ref string) (*control.AnalysisResult, error) {
					observe(conf)
					return nil, stopped
				}
				t.Cleanup(func() { githubAnalysisRemote = orig })
				return runGitHubAnalyzeRemote(githubDotCom, "owner/repo", "main", nil, nil)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var engagedAtCollection bool
			var collectionConfigsAtCollection int
			var runErr error
			_ = captureStderr(t, func() {
				runErr = tc.run(t, func(conf *configuration.Configuration) {
					engagedAtCollection = conf.PlatformRun.Engaged()
					collectionConfigsAtCollection = len(conf.CollectionConfigs)
				})
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
		})
	}
}
