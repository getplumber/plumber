package policies_test

import (
	"os"
	"testing"
)

// TestMain short-circuits the collector's GitHub API enrichment
// globally for the test suite. Unit tests drive the collector on
// temp fixtures that reference public actions like `actions/
// checkout@v4` — we do not want each fixture to trigger live API
// calls. Production binaries ignore this env var.
func TestMain(m *testing.M) {
	if err := os.Setenv("PLUMBER_DISABLE_GITHUB_API", "1"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
