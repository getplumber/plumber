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
