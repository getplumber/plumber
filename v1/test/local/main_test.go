//go:build cli

// Package local holds the local CLI suite of the refactoring
// (getplumber/monorepo#640).
//
// The suite is a firewall: it runs the built plumber binary on the inputs we
// want to protect and compares each run with a golden file, so a refactoring
// that changes a behavior goes red. It is not a coverage gate.
//
// main_test.go builds the binary; run_test.go has the row type and runs a
// row, sandbox_test.go holds the sandbox a row runs in and golden_test.go
// reads and compares the golden files. Every other file is one command group
// with its own table-driven test (TestConfig in config_test.go, and so on).
// help_test.go has a --help row for every command, so a flag lost in the
// refactoring shows up. v1/test/e2e has its own copy of the sandbox: test
// files can't be imported by another package.
//
// A golden file is a YAML document that holds the fields of the golden
// struct: the call, its exit code, stdout, stderr and the files it wrote.
//
// Rows make no backend request: they run with no token and with every proxy
// pointed at a closed port, so a row that tries the network fails.
//
// The suite never writes a golden file: write or edit it by hand. A missing
// one fails its row.
package local

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var plumberBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "plumber-v1-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	plumberBin = filepath.Join(dir, "plumber")
	// -buildvcs=false keeps the version "dev". Outputs stay stable, and the
	// update check (cmd/update_check.go) skips dev builds.
	build := exec.CommandContext(context.Background(), "go", "build", "-buildvcs=false", "-o", plumberBin, "github.com/getplumber/plumber")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err = build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build plumber:", err)
		os.Exit(1)
	}
	code := m.Run()
	if err = os.RemoveAll(dir); err != nil {
		fmt.Fprintln(os.Stderr, "remove the build dir:", err)
	}
	os.Exit(code)
}
