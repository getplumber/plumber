package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNotesNameGoldens checks that every note names a golden of test/v1/local.
func TestNotesNameGoldens(t *testing.T) {
	t.Parallel()
	for key, note := range notes() {
		if note == "" {
			t.Errorf("note for %s is empty", key)
		}
		path := filepath.Join("..", "..", "..", "test", "v1", "local", "testdata", "golden", key+".yaml")
		if _, err := os.Stat(path); err != nil {
			t.Errorf("note for %s: %v", key, err)
		}
	}
}
