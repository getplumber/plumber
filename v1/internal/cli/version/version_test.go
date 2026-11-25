package version

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func testInfo() BuildInfo {
	return BuildInfo{GoVersion: "go1.0", Version: "1.2.3", Commit: "abc", Date: "today"}
}

func TestNewCmd(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{name: "default", args: []string{}, want: "plumber has version 1.2.3 built with go1.0 from abc on today\n"},
		{name: "json", args: []string{"--json"}, want: `{"goVersion":"go1.0","version":"1.2.3","commit":"abc","date":"today"}` + "\n"},
		{name: "short", args: []string{"--short"}, want: "1.2.3\n"},
		{name: "argument", args: []string{"extra"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			cmd := NewCmd(testInfo())
			cmd.SetOut(&out)
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs(tt.args)
			err := cmd.ExecuteContext(t.Context())
			if (err != nil) != tt.wantErr {
				t.Fatalf("Execute() error = %v, want an error: %t", err, tt.wantErr)
			}
			if !tt.wantErr {
				if got := out.String(); got != tt.want {
					t.Errorf("output = %q, want %q", got, tt.want)
				}
			}
		})
	}
}

func TestJSONRoundTrip(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	cmd := NewCmd(testInfo())
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--json"})
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	var got BuildInfo
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got != testInfo() {
		t.Errorf("decoded = %+v, want %+v", got, testInfo())
	}
}

func TestBuildInfoString(t *testing.T) {
	t.Parallel()
	const want = "plumber has version 1.2.3 built with go1.0 from abc on today"
	if got := testInfo().String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// failingWriter fails every write.
type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestExecuteWriteError(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{}, {"--json"}, {"--short"}} {
		writeErr := errors.New("disk full")
		cmd := NewCmd(testInfo())
		cmd.SetOut(failingWriter{err: writeErr})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(args)
		if err := cmd.ExecuteContext(t.Context()); !errors.Is(err, writeErr) {
			t.Errorf("Execute(%q) = %v, want an error that wraps %v", args, err, writeErr)
		}
	}
}
