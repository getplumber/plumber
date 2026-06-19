package github

import (
	"os"
	"testing"
)

// TestMain disables the GitHub metadata enrichment for github package
// tests so they never hit the live API. Dedicated tests that need the
// client can override by unsetting PLUMBER_DISABLE_GITHUB_API in their
// t.Setenv scope.
func TestMain(m *testing.M) {
	if err := os.Setenv(EnvDisableGitHubAPI, "1"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
