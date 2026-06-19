package gitlab

import (
	"os"
	"testing"
)

// TestMain disables the GitHub metadata enrichment for collector
// tests. Dedicated tests that need the client can override by
// unsetting PLUMBER_DISABLE_GITHUB_API in their t.Setenv scope.
func TestMain(m *testing.M) {
	if err := os.Setenv("PLUMBER_DISABLE_GITHUB_API", "1"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
