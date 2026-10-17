package cmd

import (
	"os"
	"testing"

	githubpkg "github.com/getplumber/plumber/github"
)

// TestMain points the run cache at a directory of its own, so no test
// writes a report into the user's cache, and sets the GitHub offline
// switch so no test reaches the network: the GitHub workflow scan reads
// action definitions even with the metadata enrichment off (the nested
// actions stage). A test that needs the API on sets it back with t.Setenv.
func TestMain(m *testing.M) {
	if os.Getenv(githubpkg.EnvDisableGitHubAPI) == "" {
		_ = os.Setenv(githubpkg.EnvDisableGitHubAPI, "1")
	}
	dir, err := os.MkdirTemp("", "plumber-cmd-cache-")
	if err != nil {
		panic(err)
	}
	userCacheDir = func() (string, error) { return dir, nil }
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
