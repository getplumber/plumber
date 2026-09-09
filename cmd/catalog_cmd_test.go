package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"
)

// The cobra wiring itself is part of the contract (#458): the command must be
// registered under the exact name the docs-site build invokes, and its RunE
// must emit the same document writeCatalogJSON produces, to stdout.
func TestCatalogCommandWiring(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"catalog"})
	if err != nil || cmd == nil || cmd.Use != "catalog" {
		t.Fatalf("catalog command not registered on rootCmd: %v", err)
	}

	// RunE writes to os.Stdout; capture it through a pipe. The document is
	// larger than a pipe buffer, so the reader must drain concurrently or
	// RunE deadlocks on a full pipe.
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	drained := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		drained <- buf.Bytes()
	}()
	runErr := cmd.RunE(cmd, nil)
	_ = w.Close()
	os.Stdout = orig
	out := <-drained
	if runErr != nil {
		t.Fatalf("RunE: %v", runErr)
	}

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("command stdout is not JSON: %v", err)
	}
	if doc["catalogVersion"] != float64(1) {
		t.Errorf("catalogVersion = %v, want 1", doc["catalogVersion"])
	}
	// The handler stamps the build version variable, whatever it holds now.
	if doc["cliVersion"] != Version {
		t.Errorf("cliVersion = %v, want the cmd.Version variable (%q)", doc["cliVersion"], Version)
	}
}
