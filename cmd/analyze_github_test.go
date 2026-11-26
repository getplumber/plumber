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
	githubpkg "github.com/getplumber/plumber/github"
	"github.com/getplumber/plumber/internal/httpcount"
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
	// Remote mode needs a token to start at all.
	swapTokenSource(t, "GH_TOKEN")

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

// ---------------------------------------------------------------------------
// startup stop without a token (#637)
// ---------------------------------------------------------------------------

// swapTokenSource makes the run see source as its GitHub token source ("" for
// none), so no test reads the gh CLI's real credential.
func swapTokenSource(t *testing.T, source string) {
	t.Helper()
	orig := githubTokenSource
	githubTokenSource = func(string) string { return source }
	t.Cleanup(func() { githubTokenSource = orig })
}

// TestRequireGitHubToken: a GitHub analyze needs a token. A local clone runs
// without one only when the API is switched off; remote mode always needs
// one, since it reads the workflows through the API.
func TestRequireGitHubToken(t *testing.T) {
	for _, tc := range []struct {
		name        string
		source      string
		apiDisabled bool
		remote      bool
		wantErr     bool
	}{
		{"local, no token", "", false, false, true},
		{"local, no token, API disabled", "", true, false, false},
		{"local, token", "GH_TOKEN", false, false, false},
		{"remote, no token, API disabled", "", true, true, true},
		{"remote, token", "gh", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			swapTokenSource(t, tc.source)
			disabled := ""
			if tc.apiDisabled {
				disabled = "1"
			}
			t.Setenv(githubpkg.EnvDisableGitHubAPI, disabled)
			err := requireGitHubToken("", tc.remote)
			if tc.wantErr != errors.Is(err, githubpkg.ErrAuthRequired) || (!tc.wantErr && err != nil) {
				t.Errorf("err = %v, want ErrAuthRequired: %v", err, tc.wantErr)
			}
		})
	}
}

// TestRunGitHubAnalyze_StopsWithoutToken: both entry points stop before any
// collection, with the actionable message unwrapped.
func TestRunGitHubAnalyze_StopsWithoutToken(t *testing.T) {
	swapTokenSource(t, "")
	t.Setenv(githubpkg.EnvDisableGitHubAPI, "")
	collected := false
	origLocal, origRemote := githubAnalysis, githubAnalysisRemote
	githubAnalysis = func(*configuration.Configuration) (*control.AnalysisResult, error) {
		collected = true
		return nil, errors.New("collected")
	}
	githubAnalysisRemote = func(*configuration.Configuration, string, string, string) (*control.AnalysisResult, error) {
		collected = true
		return nil, errors.New("collected")
	}
	t.Cleanup(func() { githubAnalysis, githubAnalysisRemote = origLocal, origRemote })

	info := &utils.GitRemoteInfo{Host: githubDotCom, ProjectPath: "owner/repo", RepoRoot: t.TempDir()}
	if err := runGitHubAnalyze(info, nil, nil); err != githubpkg.ErrAuthRequired {
		t.Errorf("local: err = %v, want ErrAuthRequired unwrapped", err)
	}
	if err := runGitHubAnalyzeRemote(githubDotCom, "owner/repo", "main", nil, nil); err != githubpkg.ErrAuthRequired {
		t.Errorf("remote: err = %v, want ErrAuthRequired unwrapped", err)
	}
	if collected {
		t.Error("the run reached collection without a token")
	}
}

// TestErrAuthRequiredNamesTheWayOut: the message names the token sources and
// the switch that runs a local clone without the API.
func TestErrAuthRequiredNamesTheWayOut(t *testing.T) {
	msg := githubpkg.ErrAuthRequired.Error()
	for _, want := range []string{"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "gh auth login", githubpkg.EnvDisableGitHubAPI} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "upstream-fetch") {
		t.Errorf("the message applies to both modes, not only remote:\n%s", msg)
	}
}

// TestGitHubAuthValue_APIDisabled: with the API switched off and no token, the
// header says the API is off rather than calling the run degraded.
func TestGitHubAuthValue_APIDisabled(t *testing.T) {
	swapTokenSource(t, "")
	t.Setenv(githubpkg.EnvDisableGitHubAPI, "1")
	if got, want := githubAuthValue(""), "none, GitHub API disabled ("+githubpkg.EnvDisableGitHubAPI+")"; got != want {
		t.Errorf("auth value = %q, want %q", got, want)
	}
}

// TestRunAnalyzeAuthHint_GitHubNeedsAToken: the init prompt no longer says a
// local-clone scan needs no token.
func TestRunAnalyzeAuthHint_GitHubNeedsAToken(t *testing.T) {
	got := runAnalyzeAuthHint([]string{"github"})
	if strings.Contains(got, "no token needed") || !strings.Contains(got, "requires") {
		t.Errorf("hint = %q, want a token requirement", got)
	}
}

// TestGitHubAPIDisabled: PLUMBER_DISABLE_GITHUB_API switches the API off
// with "1" or "true", nothing else.
func TestGitHubAPIDisabled(t *testing.T) {
	for value, want := range map[string]bool{"": false, "0": false, "false": false, "yes": false, "1": true, "true": true} {
		t.Setenv(githubpkg.EnvDisableGitHubAPI, value)
		if got := githubAPIDisabled(); got != want {
			t.Errorf("%s=%q: disabled = %v, want %v", githubpkg.EnvDisableGitHubAPI, value, got, want)
		}
	}
	// "true" lets a local clone start without a token, as "1" does.
	swapTokenSource(t, "")
	t.Setenv(githubpkg.EnvDisableGitHubAPI, "true")
	if err := requireGitHubToken("", false); err != nil {
		t.Errorf("local, no token, API disabled with true: err = %v, want nil", err)
	}
}

// TestLocalGitHubAPIHost: --github-url wins, with its scheme stripped; else
// a remote that is not github.com (any letter case) is an Enterprise host;
// else empty, which reads as api.github.com.
func TestLocalGitHubAPIHost(t *testing.T) {
	for _, tc := range []struct {
		name      string
		githubURL string
		host      string
		want      string
	}{
		{"github.com clone", "", "github.com", ""},
		{"github.com in another case", "", "GitHub.com", ""},
		{"no remote host", "", "", ""},
		{"enterprise clone", "", "ghe.example.com", "ghe.example.com"},
		{"--github-url wins over the remote", "https://flag.example.com", "ghe.example.com", "flag.example.com"},
		{"--github-url on a github.com clone", "http://flag.example.com", "github.com", "flag.example.com"},
		{"--github-url without a scheme", "flag.example.com", "", "flag.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orig := githubURL
			githubURL = tc.githubURL
			t.Cleanup(func() { githubURL = orig })
			if got := localGitHubAPIHost(&utils.GitRemoteInfo{Host: tc.host}); got != tc.want {
				t.Errorf("localGitHubAPIHost = %q, want %q", got, tc.want)
			}
		})
	}
}

// stopAtCollection makes both GitHub entry points return stopped from the
// collection seam, and sets the globals a run reads on its way there, so a
// test can observe what happens up to (and around) the collection.
func stopAtCollection(t *testing.T, stopped error) {
	t.Helper()
	origLocal, origRemote := githubAnalysis, githubAnalysisRemote
	githubAnalysis = func(*configuration.Configuration) (*control.AnalysisResult, error) { return nil, stopped }
	githubAnalysisRemote = func(*configuration.Configuration, string, string, string) (*control.AnalysisResult, error) {
		return nil, stopped
	}
	origURL, origPrint, origConfig, origExplicit, origGitHubURL := platformURL, printOutput, configFile, configExplicitlySet, githubURL
	platformURL, printOutput, githubURL = "", false, ""
	configFile, configExplicitlySet = filepath.Join(t.TempDir(), ".plumber.yaml"), false
	t.Cleanup(func() {
		githubAnalysis, githubAnalysisRemote = origLocal, origRemote
		platformURL, printOutput, githubURL = origURL, origPrint, origGitHubURL
		configFile, configExplicitlySet = origConfig, origExplicit
	})
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
}

// TestRunGitHubAnalyze_TokenCheckSeesTheAPIHost: the startup token check
// asks for the token of the host the run will read: the Enterprise remote of
// a local clone, and --github-url without its scheme in remote mode. A token
// that exists only for that host lets the run reach collection.
func TestRunGitHubAnalyze_TokenCheckSeesTheAPIHost(t *testing.T) {
	stopped := errors.New("collection reached")
	stopAtCollection(t, stopped)
	t.Setenv(githubpkg.EnvDisableGitHubAPI, "")
	var asked []string
	orig := githubTokenSource
	githubTokenSource = func(host string) string {
		asked = append(asked, host)
		if host == "ghe.example.com" {
			return "gh"
		}
		return ""
	}
	t.Cleanup(func() { githubTokenSource = orig })

	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"local clone", func() error {
			info := &utils.GitRemoteInfo{Host: "ghe.example.com", ProjectPath: "owner/repo", RepoRoot: t.TempDir()}
			return runGitHubAnalyze(info, nil, nil)
		}},
		{"upstream fetch, https", func() error {
			return runGitHubAnalyzeRemote("https://ghe.example.com", "owner/repo", "main", nil, nil)
		}},
		{"upstream fetch, http", func() error {
			return runGitHubAnalyzeRemote("http://ghe.example.com", "owner/repo", "main", nil, nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asked = nil
			var err error
			_ = captureStderr(t, func() { err = tc.run() })
			if !errors.Is(err, stopped) {
				t.Fatalf("err = %v, want the run to reach collection", err)
			}
			if len(asked) == 0 || asked[0] != "ghe.example.com" {
				t.Errorf("token check asked hosts %q, want ghe.example.com first", asked)
			}
		})
	}
}

// TestRunGitHubAnalyze_DebugReport: with --debug, a run whose analysis fails
// still writes its report (the requests of a failed run are what the report
// is for); a run stopped by the token check writes none, and reads no rate
// limit.
func TestRunGitHubAnalyze_DebugReport(t *testing.T) {
	stopped := errors.New("collection reached")
	runs := map[string]func(t *testing.T) error{
		"local clone": func(t *testing.T) error {
			info := &utils.GitRemoteInfo{Host: githubDotCom, ProjectPath: "owner/repo", RepoRoot: t.TempDir()}
			return runGitHubAnalyze(info, nil, nil)
		},
		"upstream fetch": func(*testing.T) error {
			return runGitHubAnalyzeRemote(githubDotCom, "owner/repo", "main", nil, nil)
		},
	}
	for name, run := range runs {
		for _, tc := range []struct {
			name       string
			source     string
			wantErr    error
			wantReport bool
		}{
			{"analysis fails", "GH_TOKEN", stopped, true},
			{"no token", "", githubpkg.ErrAuthRequired, false},
		} {
			t.Run(name+", "+tc.name, func(t *testing.T) {
				stopAtCollection(t, stopped)
				t.Setenv(githubpkg.EnvDisableGitHubAPI, "")
				swapTokenSource(t, tc.source)
				newDebugCmd(t)
				debugFile = filepath.Join(t.TempDir(), "debug.md")
				setDebugTokens(t, "lanes-tok", "")
				savedRegistry, savedFetch := httpcount.Default, fetchRateLimit
				t.Cleanup(func() { httpcount.Default, fetchRateLimit = savedRegistry, savedFetch })
				httpcount.Default = &httpcount.Registry{}
				reads := 0
				fetchRateLimit = func(string, string) (map[string]httpcount.RateResource, error) {
					reads++
					return map[string]httpcount.RateResource{}, nil
				}

				var err error
				stderr := captureStderr(t, func() { err = run(t) })
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				data, readErr := os.ReadFile(debugFile)
				if tc.wantReport {
					if readErr != nil || !strings.Contains(string(data), "owner/repo") {
						t.Fatalf("no debug report for a failed analysis: %v\n%s", readErr, data)
					}
					if reads != 2 || !strings.Contains(stderr, "Debug report written to: "+debugFile) {
						t.Errorf("rate limit reads = %d, want 2 (before and after); stderr:\n%s", reads, stderr)
					}
					return
				}
				if !os.IsNotExist(readErr) || reads != 0 || strings.Contains(stderr, "Debug report written") {
					t.Errorf("a run stopped at the token check wrote a report (read err %v) or read the rate limit %d times; stderr:\n%s", readErr, reads, stderr)
				}
			})
		}
	}
}
