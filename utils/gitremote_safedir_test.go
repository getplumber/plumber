package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

// captureLogrus installs a test hook on the package-global logger at Debug level and restores
// the original level and hook set in t.Cleanup. logrus.StandardLogger() is process-global, so
// without this restoration a test that raises the level or adds a hook leaks both into every
// later test of the same binary.
func captureLogrus(t *testing.T) *test.Hook {
	t.Helper()
	std := logrus.StandardLogger()
	savedLevel := std.GetLevel()
	savedHooks := std.Hooks
	std.SetLevel(logrus.DebugLevel)
	hook := test.NewLocal(std)
	t.Cleanup(func() {
		std.ReplaceHooks(savedHooks)
		std.SetLevel(savedLevel)
	})
	return hook
}

// TestGitCommand_NamesTheDirectoryAsSafe pins #464: every git shell-out passes the inspected
// directory as protected safe.directory configuration, so a checkout owned by another uid (the
// GitLab docker executor clones as root, the image runs as uid 65532) is readable without a
// global git config the image does not carry. The one directory, never '*'.
func TestGitCommand_NamesTheDirectoryAsSafe(t *testing.T) {
	cmd := gitCommand("/builds/group/project", "rev-parse", "--show-toplevel")
	want := []string{"git", "-c", "safe.directory=/builds/group/project", "rev-parse", "--show-toplevel"}
	if strings.Join(cmd.Args, " ") != strings.Join(want, " ") {
		t.Fatalf("argv = %q, want %q", cmd.Args, want)
	}
	if cmd.Dir != "/builds/group/project" {
		t.Fatalf("Dir = %q, want the inspected directory", cmd.Dir)
	}
}

// fakeGit puts a fake `git` binary on PATH (via t.Setenv) that writes stderr and exits 128,
// mimicking a real git failure without depending on one being installed or on the test's own
// checkout state.
func fakeGit(t *testing.T, stderr string) {
	t.Helper()
	dir := t.TempDir()
	fake := filepath.Join(dir, "git")
	script := "#!/bin/sh\necho \"" + stderr + "\" >&2\nexit 128\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

// TestDetectGitRepoRoot_LogsTheGitErrorAtWarn pins #464: a git failure that is not the routine
// "not a git repository" case is no longer silent. A fake git on PATH exits 128 with the
// dubious-ownership message; the caller still gets "" (its contract) and the first stderr line
// is logged at Warn so the job log explains the degraded run.
func TestDetectGitRepoRoot_LogsTheGitErrorAtWarn(t *testing.T) {
	fakeGit(t, "fatal: detected dubious ownership in repository at '/builds/x'")
	hook := captureLogrus(t)

	if got := DetectGitRepoRoot(); got != "" {
		t.Fatalf("repo root = %q, want empty on git failure", got)
	}
	var foundWarn bool
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel && strings.Contains(e.Message, "dubious ownership") {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Fatalf("no Warn entry naming the git error; entries: %+v", hook.AllEntries())
	}
}

// TestDetectGitRepoRoot_NotAGitRepositoryLogsAtDebugOnly pins the noise fix: `plumber analyze`
// runs at Warn by default, and every invocation outside a git checkout is a routine, expected
// case, not a degraded run worth surfacing at Warn. A fake git emitting the ordinary
// "not a git repository" refusal must log at Debug and must NOT log at Warn.
func TestDetectGitRepoRoot_NotAGitRepositoryLogsAtDebugOnly(t *testing.T) {
	fakeGit(t, "fatal: not a git repository (or any of the parent directories): .git")
	hook := captureLogrus(t)

	if got := DetectGitRepoRoot(); got != "" {
		t.Fatalf("repo root = %q, want empty on git failure", got)
	}
	var foundDebug, foundWarn bool
	for _, e := range hook.AllEntries() {
		if strings.Contains(e.Message, "not a git repository") {
			switch e.Level {
			case logrus.DebugLevel:
				foundDebug = true
			case logrus.WarnLevel:
				foundWarn = true
			}
		}
	}
	if !foundDebug {
		t.Fatalf("no Debug entry naming the git error; entries: %+v", hook.AllEntries())
	}
	if foundWarn {
		t.Fatalf("a Warn entry was logged for the routine \"not a git repository\" case; entries: %+v", hook.AllEntries())
	}
}

// TestGitCommand_EmptyDirOmitsSafeDirectory pins the reason the argument is conditional: an
// empty `-c safe.directory=` does not name "nothing", it RESETS git's safe list, dropping the
// entries a real global config may legitimately carry. The two cwd callers derive dir from
// os.Getwd, which can fail, so the helper must never emit the empty value.
func TestGitCommand_EmptyDirOmitsSafeDirectory(t *testing.T) {
	cmd := gitCommand("", "rev-parse", "HEAD")
	want := []string{"git", "rev-parse", "HEAD"}
	if strings.Join(cmd.Args, " ") != strings.Join(want, " ") {
		t.Fatalf("argv = %q, want %q: an empty safe.directory value resets git's list", cmd.Args, want)
	}
	if cmd.Dir != "" {
		t.Fatalf("Dir = %q, want empty (git runs in the process cwd)", cmd.Dir)
	}
}

// TestRedactCredentials pins that a credential embedded in a remote URL never reaches a log
// line. git echoes the remote it was given back in its error messages, and a token in the
// userinfo segment (`https://oauth2:<token>@host/...`, or a bare `https://<token>@host/...`) is
// exactly what a CI job hands it.
func TestRedactCredentials(t *testing.T) {
	cases := []struct{ in, want string }{
		{
			"fatal: unable to access 'https://oauth2:glpat-secret@gitlab.example.com/g/p.git/': 403",
			"fatal: unable to access 'https://***@gitlab.example.com/g/p.git/': 403",
		},
		{
			"fatal: could not read Username for 'https://token@github.com'",
			"fatal: could not read Username for 'https://***@github.com'",
		},
		{
			// Two remotes in one line: every occurrence goes, not just the first.
			"https://a:b@one.example.com and https://c:d@two.example.com",
			"https://***@one.example.com and https://***@two.example.com",
		},
		{
			// The SSH form carries no secret, but the user name is redacted too:
			// telling "harmless user name" from "token used as the user" apart is
			// guesswork, and the log line needs neither.
			"ssh://git@gitlab.example.com/g/p.git",
			"ssh://***@gitlab.example.com/g/p.git",
		},
		{
			"fatal: detected dubious ownership in repository at '/builds/g/p'",
			"fatal: detected dubious ownership in repository at '/builds/g/p'",
		},
		{"", ""},
	}
	for _, c := range cases {
		if got := redactCredentials(c.in); got != c.want {
			t.Errorf("redactCredentials(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestRunGit_LogsRedactedStderr pins the redaction where it matters: on the log line itself, not
// only in the helper's own test. A fake git prints a remote URL carrying a token; the logged
// entry must not contain it.
func TestRunGit_LogsRedactedStderr(t *testing.T) {
	fakeGit(t, "fatal: unable to access 'https://oauth2:glpat-secret@gitlab.example.com/g/p.git/': 403")
	hook := captureLogrus(t)

	if _, err := runGit(t.TempDir(), "ls-remote"); err == nil {
		t.Fatal("runGit returned no error for a git exiting 128")
	}
	var found bool
	for _, e := range hook.AllEntries() {
		if strings.Contains(e.Message, "glpat-secret") {
			t.Fatalf("the log line carries the credential: %q", e.Message)
		}
		if strings.Contains(e.Message, "https://***@gitlab.example.com") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no log entry with the redacted remote; entries: %+v", hook.AllEntries())
	}
}

// TestGitOutput_IsRunGitsExportedForm pins that the exported helper carries the same
// safe.directory declaration and diagnostics as the package-internal callers: `plumber init`
// reads the origin remote through it, and a raw exec.Command there would keep the #464 failure
// mode (a root-owned checkout refused, silently).
func TestGitOutput_IsRunGitsExportedForm(t *testing.T) {
	fakeGit(t, "fatal: detected dubious ownership in repository at '/builds/g/p'")
	hook := captureLogrus(t)

	out, err := GitOutput(t.TempDir(), "config", "--get", "remote.origin.url")
	if err == nil {
		t.Fatal("GitOutput returned no error for a git exiting 128")
	}
	if out != "" {
		t.Fatalf("out = %q, want empty on failure", out)
	}
	var found bool
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel && strings.Contains(e.Message, "dubious ownership") {
			found = true
		}
	}
	if !found {
		t.Fatalf("GitOutput swallowed the git diagnostic; entries: %+v", hook.AllEntries())
	}
}

// TestRunGit_EmptyStderrLogsAtDebugOnly pins the wizard fix: `git config --get
// remote.origin.url` exits 1 with NOTHING on stderr in a repository that simply has no origin
// remote, which is an ordinary answer ("there is none"), not a degraded run. Warning about it
// printed a Warn line with an empty message in the middle of `plumber config init`.
func TestRunGit_EmptyStderrLogsAtDebugOnly(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "git")
	// Exit 1 with nothing on either stream: git's own behaviour for a config key that is not set.
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	hook := captureLogrus(t)

	if _, err := GitOutput(t.TempDir(), "config", "--get", "remote.origin.url"); err == nil {
		t.Fatal("no error returned for a git exiting 1")
	}
	var foundDebug bool
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel {
			t.Errorf("a Warn entry was logged for an empty-stderr failure: %q", e.Message)
		}
		if e.Level == logrus.DebugLevel && strings.Contains(e.Message, "config --get remote.origin.url") {
			foundDebug = true
		}
	}
	if !foundDebug {
		t.Fatalf("no Debug entry naming the failed command; entries: %+v", hook.AllEntries())
	}
}
