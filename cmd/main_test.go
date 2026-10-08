package cmd

import (
	"os"
	"testing"
)

// TestMain points the run cache at a directory of its own, so no test
// writes a report into the user's cache.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "plumber-cmd-cache-")
	if err != nil {
		panic(err)
	}
	userCacheDir = func() (string, error) { return dir, nil }
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
