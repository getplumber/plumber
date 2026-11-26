package cmd

import (
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/getplumber/plumber/configuration"
	githubpkg "github.com/getplumber/plumber/github"
	"github.com/getplumber/plumber/internal/httpcount"
)

// newDebugCmd binds --debug exactly as analyze does.
func newDebugCmd(t *testing.T) *cobra.Command {
	t.Helper()
	saved := debugFile
	t.Cleanup(func() { debugFile = saved })
	debugFile = ""
	c := &cobra.Command{Use: "analyze", RunE: func(*cobra.Command, []string) error { return nil }}
	c.Flags().StringVar(&debugFile, "debug", "", "")
	c.Flags().Lookup("debug").NoOptDefVal = defaultDebugFile
	return c
}

func TestDebugFlag(t *testing.T) {
	cases := []struct {
		name string
		args []string
		env  string
		want string
	}{
		{name: "off by default", want: ""},
		{name: "bare flag writes the default file", args: []string{"--debug"}, want: defaultDebugFile},
		{name: "flag with a path", args: []string{"--debug=out/requests.md"}, want: "out/requests.md"},
		{name: "env true", env: "true", want: defaultDebugFile},
		{name: "env 1", env: "1", want: defaultDebugFile},
		{name: "env false", env: "false", want: ""},
		{name: "env path", env: "report.md", want: "report.md"},
		{name: "flag wins over env", args: []string{"--debug=flag.md"}, env: "env.md", want: "flag.md"},
		// The flag reads a boolean like the env var: a wrapper forwarding
		// --debug=${{ inputs.debug }} must not write a file named false.
		{name: "flag false", args: []string{"--debug=false"}, want: ""},
		{name: "flag 0", args: []string{"--debug=0"}, want: ""},
		{name: "flag true", args: []string{"--debug=true"}, want: defaultDebugFile},
		{name: "flag false wins over env", args: []string{"--debug=false"}, env: "report.md", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newDebugCmd(t)
			t.Setenv(envKeys["debug"], tc.env)
			if err := c.ParseFlags(tc.args); err != nil {
				t.Fatal(err)
			}
			if err := resolveDebugFile(c); err != nil {
				t.Fatal(err)
			}
			if debugFile != tc.want {
				t.Fatalf("debugFile = %q, want %q", debugFile, tc.want)
			}
		})
	}
}

// Without --debug, starting and finishing the report does nothing: no
// rate-limit read, no request log, no file.
func TestStartGitHubDebugReport_off(t *testing.T) {
	newDebugCmd(t)
	t.Chdir(t.TempDir()) // where a bare --debug would write
	savedRegistry, savedFetch := httpcount.Default, fetchRateLimit
	t.Cleanup(func() { httpcount.Default, fetchRateLimit = savedRegistry, savedFetch })
	httpcount.Default = &httpcount.Registry{}
	fetchRateLimit = func(string, string) (map[string]httpcount.RateResource, error) {
		t.Error("rate limit read without --debug")
		return nil, nil
	}

	startGitHubDebugReport(&configuration.Configuration{ProjectPath: "o/r"}, "remote")()

	// A request sent after the start is counted, never logged.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	client := &http.Client{Transport: &httpcount.Transport{Registry: httpcount.Default}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if snap := httpcount.Default.Snapshot(); len(snap.Entries) != 0 || snap.Total() != 1 {
		t.Fatalf("logged %d requests of %d, want none", len(snap.Entries), snap.Total())
	}
	if files, err := os.ReadDir("."); err != nil || len(files) != 0 {
		t.Fatalf("files written without --debug: %v (%v)", files, err)
	}
}

// setDebugTokens sets the lanes' token (GH_TOKEN) and the metadata token.
// An empty lanes token leaves go-gh no gh config and no gh binary to fall
// back on, so the developer's own login never leaks in.
func setDebugTokens(t *testing.T, lanes, metadata string) {
	t.Helper()
	t.Setenv("GH_TOKEN", lanes)
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_ENTERPRISE_TOKEN", "")
	t.Setenv("GITHUB_ENTERPRISE_TOKEN", "")
	t.Setenv("GH_CONFIG_DIR", t.TempDir())
	t.Setenv("GH_PATH", filepath.Join(t.TempDir(), "no-gh"))
	t.Setenv(githubpkg.EnvMetadataToken, metadata)
}

func TestDebugCredentials(t *testing.T) {
	cases := []struct {
		name            string
		lanes, metadata string
		want            []debugCredential
		wantLabels      []string
	}{
		{
			name: "lanes and metadata tokens", lanes: "lanes-tok", metadata: " meta-tok ",
			want:       []debugCredential{{"GH_TOKEN", "lanes-tok"}, {githubpkg.EnvMetadataToken, "meta-tok"}},
			wantLabels: []string{"GitHub lanes: GH_TOKEN", "action metadata: " + githubpkg.EnvMetadataToken},
		},
		{
			name:       "anonymous",
			want:       []debugCredential{{"anonymous", ""}},
			wantLabels: []string{"GitHub lanes: none (anonymous)"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setDebugTokens(t, tc.lanes, tc.metadata)
			got, labels := debugCredentials(githubDotCom)
			if !slices.Equal(got, tc.want) || !slices.Equal(labels, tc.wantLabels) {
				t.Fatalf("debugCredentials = %+v, %q; want %+v, %q", got, labels, tc.want, tc.wantLabels)
			}
		})
	}
}

// Each token is named under both schemes go-gh can send it with; the
// anonymous lane has no key.
func TestCredentialNames(t *testing.T) {
	names := credentialNames([]debugCredential{{"anonymous", ""}, {"GH_TOKEN", "lanes-tok"}, {"META", "meta-tok"}})
	want := map[string]string{
		httpcount.CredentialKey("token lanes-tok"):  "GH_TOKEN",
		httpcount.CredentialKey("Bearer lanes-tok"): "GH_TOKEN",
		httpcount.CredentialKey("token meta-tok"):   "META",
		httpcount.CredentialKey("Bearer meta-tok"):  "META",
	}
	if !maps.Equal(names, want) {
		t.Fatalf("credentialNames = %v, want %v", names, want)
	}
}

// Each credential's rate limit is read with its own token before and after
// the run, and lands on its own row of the report.
func TestStartGitHubDebugReport_rateLimits(t *testing.T) {
	newDebugCmd(t)
	debugFile = filepath.Join(t.TempDir(), "debug.md")
	setDebugTokens(t, "lanes-tok", "meta-tok")

	// used is what each token's core quota reads, before then after.
	used := map[string][]int{"lanes-tok": {10, 13}, "meta-tok": {100, 107}}
	saved := fetchRateLimit
	t.Cleanup(func() { fetchRateLimit = saved })
	fetchRateLimit = func(_, token string) (map[string]httpcount.RateResource, error) {
		reads, ok := used[token]
		if !ok || len(reads) == 0 {
			return nil, fmt.Errorf("unexpected read with token %q", token)
		}
		used[token] = reads[1:]
		return map[string]httpcount.RateResource{"core": {Limit: 5000, Used: reads[0], Remaining: 5000 - reads[0], Reset: 1795000000}}, nil
	}

	startGitHubDebugReport(&configuration.Configuration{ProjectPath: "o/r"}, "remote")()

	data, err := os.ReadFile(debugFile)
	if err != nil {
		t.Fatal(err)
	}
	report := string(data)
	lanes, metadata := strings.Index(report, "### GH_TOKEN"), strings.Index(report, "### "+githubpkg.EnvMetadataToken)
	if lanes < 0 || metadata < lanes {
		t.Fatalf("missing or misordered credential sections:\n%s", report)
	}
	if row := "| core | 5000 | 10 | 13 | +3 |"; !strings.Contains(report[lanes:metadata], row) {
		t.Fatalf("GH_TOKEN section lacks %q:\n%s", row, report)
	}
	if row := "| core | 5000 | 100 | 107 | +7 |"; !strings.Contains(report[metadata:], row) {
		t.Fatalf("%s section lacks %q:\n%s", githubpkg.EnvMetadataToken, row, report)
	}
}

// TestStartGitHubDebugReport_logsTheRun: with --debug, a request the run
// sends between the start and the finish lands in the report's request
// log. It pins both the log being turned on and the run's snapshot being
// copied into the report.
func TestStartGitHubDebugReport_logsTheRun(t *testing.T) {
	newDebugCmd(t)
	debugFile = filepath.Join(t.TempDir(), "debug.md")
	setDebugTokens(t, "lanes-tok", "")
	savedRegistry, savedFetch := httpcount.Default, fetchRateLimit
	t.Cleanup(func() { httpcount.Default, fetchRateLimit = savedRegistry, savedFetch })
	httpcount.Default = &httpcount.Registry{}
	fetchRateLimit = func(string, string) (map[string]httpcount.RateResource, error) {
		return map[string]httpcount.RateResource{}, nil
	}

	finish := startGitHubDebugReport(&configuration.Configuration{ProjectPath: "o/r"}, "remote")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Resource", "core")
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.Header().Set("X-RateLimit-Used", "1")
	}))
	defer srv.Close()
	client := &http.Client{Transport: &httpcount.Transport{Registry: httpcount.Default}}
	resp, err := client.Get(srv.URL + "/repos/o/r")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	finish()

	data, err := os.ReadFile(debugFile)
	if err != nil {
		t.Fatal(err)
	}
	_, log, ok := strings.Cut(string(data), "## All requests")
	if !ok || strings.Contains(log, "_No request logged._") || !strings.Contains(log, "/repos/o/r") {
		t.Fatalf("the report's request log lacks GET /repos/o/r:\n%s", data)
	}
}
