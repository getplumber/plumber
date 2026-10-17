package capability

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// Spec section 4.3 rule 4 (a script line): a `- |` entry is one string holding several
// lines, and each of its lines is a script line, so a newline (LF or CRLF) cuts segments
// exactly like `;`.
func TestCommandTokens_MultiLineEntry(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"echo start\ngitleaks detect\n", []string{"echo", "gitleaks"}},
		{"echo start\r\ngitleaks detect\r\n", []string{"echo", "gitleaks"}},
		{"set -e\n\n  FOO=1 trufflehog git file://.", []string{"set", "trufflehog"}},
	}
	for _, c := range cases {
		if got := commandTokens(c.line); !reflect.DeepEqual(got, c.want) {
			t.Errorf("commandTokens(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// Spec section 4.4: the wrapper rule follows a script called on any line of a `- |` entry,
// and a relative cd on an earlier line of the same entry still applies.
func TestWrapperPath_MultiLineEntry(t *testing.T) {
	cases := []struct {
		line string
		want string
		ok   bool
	}{
		{"set -e\n./scripts/scan.sh\n", "scripts/scan.sh", true},
		{"set -e\r\n./scripts/scan.sh\r\n", "scripts/scan.sh", true},
		{"cd ci\n./scan.sh\n", "ci/scan.sh", true},
	}
	for _, c := range cases {
		got, ok := wrapperPath(c.line)
		if got != c.want || ok != c.ok {
			t.Errorf("wrapperPath(%q) = (%q, %v), want (%q, %v)", c.line, got, ok, c.want, c.ok)
		}
	}
}

// Spec section 4.3 rule 4: script lines come from any analyzed project's CI config, so the
// `sh -c` unwrap is bounded to one level: a 256 KiB line of repeated `sh -c ` tokenizes in
// linear time instead of hanging the run.
func TestCommandTokens_ShCChainIsBounded(t *testing.T) {
	line := strings.Repeat("sh -c ", (256<<10)/len("sh -c "))
	done := make(chan struct{})
	go func() { commandTokens(line); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("commandTokens on a 256 KiB `sh -c` chain took over 2 s: the unwrap must not recurse on the remainder")
	}
	// one level of unwrap still reaches the quoted command
	if got := commandTokens(`sh -c "gitleaks detect"`); !reflect.DeepEqual(got, []string{"sh", "gitleaks"}) {
		t.Errorf("single-level unwrap: got %v, want [sh gitleaks]", got)
	}
}

func TestCommandTokens(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"gitleaks detect --source .", []string{"gitleaks"}},
		{"  ./bin/trufflehog git file://. && echo done", []string{"trufflehog", "echo"}},
		{"make build; detect-secrets scan | tee out.json || true", []string{"make", "detect-secrets", "tee", "true"}},
		{`sh -c "ggshield secret scan path ."`, []string{"sh", "ggshield"}},
		{`bash -c 'cd src && betterleaks dir .'`, []string{"bash", "cd", "betterleaks"}},
		{"", nil},
		{"   ", nil},
		{"FOO=bar gitleaks detect", []string{"gitleaks"}}, // a leading assignment is skipped
	}
	for _, c := range cases {
		if got := commandTokens(c.line); !reflect.DeepEqual(got, c.want) {
			t.Errorf("commandTokens(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

func TestWrapperPath(t *testing.T) {
	cases := []struct {
		line string
		want string
		ok   bool
	}{
		{"./scripts/scan.sh", "scripts/scan.sh", true},
		{"sh scripts/scan.sh --fast", "scripts/scan.sh", true},
		{"bash ./ci/secrets.bash", "ci/secrets.bash", true},
		{"source tools/env.sh", "tools/env.sh", true},
		{". ./tools/env.sh", "tools/env.sh", true},
		{"/usr/local/bin/scan.sh", "", false},                       // absolute: never under the root by construction
		{"../outside/scan.sh", "", false},                           // escapes the root
		{"gitleaks detect", "", false},                              // a command, not a script path
		{"sh -c \"gitleaks detect\"", "", false},                    // inline command, not a file
		{"python scripts/scan.py", "", false},                       // only .sh and .bash files are followed
		{"cd ci && ./scan.sh", "ci/scan.sh", true},                  // a later segment, under a relative cd
		{"make prep && ./scripts/scan.sh", "scripts/scan.sh", true}, // a later segment
		{"./scripts/scan.sh;", "scripts/scan.sh", true},             // a trailing `;`
		{"cd /opt && ./scan.sh", "", false},                         // an absolute cd leaves the root
		{"cd .. && ./scan.sh", "", false},                           // a cd that escapes the root
	}
	for _, c := range cases {
		got, ok := wrapperPath(c.line)
		if got != c.want || ok != c.ok {
			t.Errorf("wrapperPath(%q) = (%q, %v), want (%q, %v)", c.line, got, ok, c.want, c.ok)
		}
	}
}
