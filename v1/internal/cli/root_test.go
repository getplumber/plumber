package cli

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/getplumber/plumber/v1/internal/cli/version"
	"github.com/getplumber/plumber/v1/internal/log"
)

// ansiCode matches the color codes zerolog writes, so the rows compare the
// text of a log line; internal/log tests the colors.
var ansiCode = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// stripANSI returns s without its color codes.
func stripANSI(s string) string {
	return ansiCode.ReplaceAllString(s, "")
}

func testInfo() version.BuildInfo {
	return version.BuildInfo{GoVersion: "go1.0", Version: "1.2.3", Commit: "abc", Date: "today"}
}

// newTestRootCommand returns a root command that writes its output, usage
// and logs to the returned buffers instead of os.Stdout and os.Stderr.
func newTestRootCommand(args []string) (c *rootCommand, stdout, stderr *bytes.Buffer) {
	stdout, stderr = &bytes.Buffer{}, &bytes.Buffer{}
	c = newRootCommand(testInfo())
	c.cmd.SetOut(stdout)
	c.cmd.SetErr(stderr)
	c.log = log.New(stderr)
	c.cmd.SetArgs(append([]string{}, args...)) // never nil: cobra would read os.Args.
	return c, stdout, stderr
}

// TestSetupEnv writes to the global viper and to the environment, so it
// doesn't run in parallel. Go runs it before it resumes the parallel tests.
func TestSetupEnv(t *testing.T) {
	t.Cleanup(viper.Reset)
	setupEnv()
	t.Setenv("PLUMBER_LOG_LEVEL", "debug")
	if got := viper.GetString("log_level"); got != "debug" {
		t.Errorf("log_level with PLUMBER_LOG_LEVEL=debug = %q, want debug", got)
	}
}

// TestNewRootCommandTwice checks that a root command keeps no state another
// one sees: a flag set on the first stays off on the second.
func TestNewRootCommandTwice(t *testing.T) {
	t.Parallel()
	first := newRootCommand(testInfo())
	first.cmd.InitDefaultHelpFlag()
	if err := first.cmd.Flags().Set("help", "true"); err != nil {
		t.Fatal(err)
	}
	second := newRootCommand(testInfo())
	second.cmd.InitDefaultHelpFlag()
	if got := second.cmd.Flags().Lookup("help").Value.String(); got != "false" {
		t.Errorf("help on a new root command = %s, want false", got)
	}
}

func TestRootCommandExecute(t *testing.T) {
	t.Parallel()
	const wantVersion = "plumber has version 1.2.3 built with go1.0 from abc on today\n"
	tests := []struct {
		name       string
		args       []string
		wantErr    bool
		wantStdout string // a prefix of stdout; empty means stdout is empty
		wantStderr string // stderr without its color codes
	}{
		{name: "version", args: []string{"version"}, wantStdout: wantVersion},
		{
			name:       "no --version flag",
			args:       []string{"--version"},
			wantErr:    true,
			wantStderr: "ERR unknown flag: --version\n",
		},
		{
			name:       "no -v shorthand",
			args:       []string{"-v"},
			wantErr:    true,
			wantStderr: "ERR unknown shorthand flag: 'v' in -v\n",
		},
		{name: "no argument prints the help", args: nil, wantStdout: "Plumber scans"},
		{
			name:       "unknown command",
			args:       []string{"bogus"},
			wantErr:    true,
			wantStderr: "ERR unknown command \"bogus\" for \"plumber\"\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, stdout, stderr := newTestRootCommand(tt.args)
			if err := c.Execute(); (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, want an error: %t", err, tt.wantErr)
			}
			got := stdout.String()
			if tt.wantStdout == "" && got != "" {
				t.Errorf("stdout = %q, want empty", got)
			}
			if !strings.HasPrefix(got, tt.wantStdout) {
				t.Errorf("stdout = %q, want a prefix %q", got, tt.wantStdout)
			}
			if got := stripANSI(stderr.String()); got != tt.wantStderr {
				t.Errorf("stderr = %q, want %q", got, tt.wantStderr)
			}
		})
	}
}
