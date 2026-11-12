//go:build cli

// Package test holds the CLI test suite of the refactoring (getplumber/monorepo#640).
//
// The suite is a firewall: it runs the built plumber binary on the inputs we
// want to protect and compares each run with a golden file, so a refactoring
// that changes a behavior goes red. It is not a coverage gate.
//
// main_test.go builds the binary and runs the rows; sandbox_test.go holds the
// sandbox a row runs in, and golden_test.go reads and compares the golden
// files. Every other file is one command group with its own table-driven
// test (TestConfig in config_test.go, and so on). help_test.go has a --help
// row for every command, so a flag lost in the refactoring shows up.
//
// A golden file is a YAML document that holds the fields of the golden
// struct: the call, its exit code, stdout, stderr and the files it wrote.
//
// Rows make no backend request: they run with no token and with every proxy
// pointed at a closed port, so a row that tries the network fails.
//
// The suite never writes a golden file: write or edit it by hand. A missing
// one fails its row.
package test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// cliCase is one row of a table: one plumber call and what it must produce.
type cliCase struct {
	name        string     // golden file: testdata/golden/<name>.yaml
	args        []string   // arguments of the plumber call under test
	exit        int        // expected exit code
	inputs      []string   // paths under testdata/inputs copied into the work dir
	setup       [][]string // plumber calls run first, in the same work dir and home (not compared)
	outputFiles []string   // files the call writes, compared with the golden
	// sortLines compares the output lines sorted, for a call that prints them
	// in random order (a CLI bug).
	sortLines bool
}

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

// runCase compares a run of tt with testdata/golden/<name>.yaml.
func runCase(t *testing.T, tt cliCase) {
	t.Helper()
	path := filepath.Join("testdata", "golden", tt.name+".yaml")
	want, err := readGolden(path)
	if err != nil {
		t.Fatal(err)
	}
	got := run(t, tt)
	if diff := want.cmp(got); diff != "" {
		t.Errorf("%s: output differs from %s:\n%s", got.Command, path, diff)
	}
}

// run runs the setup calls and the call under test in a fresh sandbox, checks
// the exit code, and returns the normalized result (exit code, stdout, stderr
// and the files the call wrote).
func run(t *testing.T, tt cliCase) *golden {
	t.Helper()
	sb := newSandbox(t, tt)

	for _, args := range tt.setup {
		if _, stderr, code := sb.runPlumber(t.Context(), args); code != 0 {
			t.Fatalf("setup `plumber %s` exited %d\nstderr:\n%s", strings.Join(args, " "), code, stderr)
		}
	}
	stdout, stderr, code := sb.runPlumber(t.Context(), tt.args)

	command := "plumber " + strings.Join(tt.args, " ")
	if code != tt.exit {
		t.Errorf("%s: exit code = %d, want %d", command, code, tt.exit)
	}

	got, err := sb.newGolden(tt, command, stdout, stderr, code)
	if err != nil {
		t.Fatal(err)
	}
	// Sort after normalizing, so the order doesn't depend on the sandbox paths.
	if tt.sortLines {
		got.Stdout, got.Stderr = sortLines(got.Stdout), sortLines(got.Stderr)
	}
	return got
}

// sortLines returns s with its lines sorted.
func sortLines(s string) string {
	lines := strings.Split(s, "\n")
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}
