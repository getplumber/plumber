package control

import (
	"os"
	"testing"
)

// TestMain disables the collector's GitHub API metadata enrichment
// globally for the control package's tests. See the matching file
// under policies/ for the rationale.
func TestMain(m *testing.M) {
	if err := os.Setenv("PLUMBER_DISABLE_GITHUB_API", "1"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
