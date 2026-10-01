package cmd

import (
	"errors"
	"strings"
	"testing"
)

// restoreAnalyzeFlags snapshots the analyze flags a positional target writes
// and restores them (value and Changed) when the test ends, so a run through
// the package-level command leaves nothing behind for the next test.
func restoreAnalyzeFlags(t *testing.T) {
	t.Helper()
	for _, name := range []string{"gitlab-url", "github-url", "project", "provider", "branch"} {
		f := analyzeCmd.Flags().Lookup(name)
		if f == nil {
			t.Fatalf("no such analyze flag: %q", name)
		}
		origValue, origChanged := f.Value.String(), f.Changed
		t.Cleanup(func() {
			_ = f.Value.Set(origValue)
			f.Changed = origChanged
		})
	}
	for _, env := range []string{"gitlab-url", "github-url", "project", "provider", "branch"} {
		t.Setenv(envKeys[env], "")
	}
}

// TestRunAnalyzeAppliesPositionalTarget drives runAnalyze itself with one
// positional argument. The test binary runs inside this repository's clone,
// whose origin is GitHub, so a run that ignored the argument would take the
// GitHub path: reaching the GitLab token check with the target's coordinates
// in the flags proves the argument, not the working directory, chose the
// repository. (Before this feature `plumber analyze <url>` did exactly that.)
func TestRunAnalyzeAppliesPositionalTarget(t *testing.T) {
	restoreAnalyzeFlags(t)
	t.Setenv("GITLAB_TOKEN", "")
	t.Setenv("CI_JOB_TOKEN", "")
	origPrint := printOutput
	printOutput = false
	t.Cleanup(func() { printOutput = origPrint })

	var runErr error
	_ = captureStderr(t, func() {
		runErr = runAnalyze(analyzeCmd, []string{"https://gitlab.com/group/sub/project/-/tree/release"})
	})
	if runErr == nil || !strings.Contains(runErr.Error(), "GITLAB_TOKEN") {
		t.Fatalf("want the run to stop at the GitLab token check, got %v", runErr)
	}
	for flag, want := range map[string]string{
		"gitlab-url": "https://gitlab.com",
		"project":    "group/sub/project",
		"branch":     "release",
	} {
		got, _ := analyzeCmd.Flags().GetString(flag)
		if got != want || !analyzeCmd.Flags().Changed(flag) {
			t.Errorf("--%s = %q (changed=%v), want %q set by the target", flag, got, analyzeCmd.Flags().Changed(flag), want)
		}
	}
	if analyzeCmd.Flags().Changed("github-url") {
		t.Error("a GitLab target must not touch --github-url")
	}
}

// TestRunAnalyzeRefusesTargetConflicts: the agreement check and the credential
// guard are reached through runAnalyze, not only through the unit helpers.
func TestRunAnalyzeRefusesTargetConflicts(t *testing.T) {
	t.Run("--project disagrees", func(t *testing.T) {
		restoreAnalyzeFlags(t)
		if err := analyzeCmd.Flags().Set("project", "other/thing"); err != nil {
			t.Fatal(err)
		}
		err := runAnalyze(analyzeCmd, []string{"github.com/owner/repo"})
		if err == nil || !strings.Contains(err.Error(), "other/thing") || !strings.Contains(err.Error(), "owner/repo") {
			t.Fatalf("want the conflict error naming both projects, got %v", err)
		}
	})
	t.Run("credential in the target", func(t *testing.T) {
		restoreAnalyzeFlags(t)
		err := runAnalyze(analyzeCmd, []string{"https://user:s3cret@github.com/owner/repo"})
		if !errors.Is(err, errTargetCredential) {
			t.Fatalf("want errTargetCredential, got %v", err)
		}
		if analyzeCmd.Flags().Changed("project") {
			t.Error("a refused target must not have set --project")
		}
	})
}
