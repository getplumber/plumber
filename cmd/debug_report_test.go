package cmd

import (
	"testing"

	"github.com/spf13/cobra"
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newDebugCmd(t)
			t.Setenv(envKeys["debug"], tc.env)
			if err := c.ParseFlags(tc.args); err != nil {
				t.Fatal(err)
			}
			if err := envDebugFallback(c); err != nil {
				t.Fatal(err)
			}
			if debugFile != tc.want {
				t.Fatalf("debugFile = %q, want %q", debugFile, tc.want)
			}
		})
	}
}

// Without --debug, starting and finishing the report does nothing: no
// rate-limit read, no file.
func TestStartGitHubDebugReport_off(t *testing.T) {
	newDebugCmd(t)
	startGitHubDebugReport(nil, "local")()
}
